// Multi-Model Authorization Microservice
// Copyright (c) 2024 Multi-Model Authorization Microservice
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// AccessControlModel represents the type of access control model
type AccessControlModel string

const (
	ModelACL   AccessControlModel = "acl"
	ModelRBAC  AccessControlModel = "rbac"
	ModelABAC  AccessControlModel = "abac"
	ModelReBAC AccessControlModel = "rebac"
)

// EnforceRequest represents an authorization enforcement request
type EnforceRequest struct {
	Model      AccessControlModel `json:"model"`
	Subject    string             `json:"subject"`
	Object     string             `json:"object"`
	Action     string             `json:"action"`
	Attributes map[string]string  `json:"attributes,omitempty"` // Attributes for ABAC
}

// PolicyRequest represents a policy management request
type PolicyRequest struct {
	Model   AccessControlModel `json:"model"`
	Subject string             `json:"subject"`
	Object  string             `json:"object"`
	Action  string             `json:"action"`
}

// RoleRequest represents a role assignment request
type RoleRequest struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// AttributeRequest represents an attribute assignment request for ABAC
type AttributeRequest struct {
	Subject    string            `json:"subject"`
	Attributes map[string]string `json:"attributes"`
}

// RelationshipRequest represents a relationship request for ReBAC
type RelationshipRequest struct {
	Subject      string `json:"subject"`
	Relationship string `json:"relationship"`
	Object       string `json:"object"`
}

// ResBACQueryRequest represents a ReBAC query request
type ResBACQueryRequest struct {
	Subject string `json:"subject"`
	Object  string `json:"object"`
	Action  string `json:"action"`
}

// ABACPolicy represents a policy in the ABAC policy engine
type ABACPolicy struct {
	ID          string            `json:"id" gorm:"primaryKey"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Effect      string            `json:"effect"` // "allow" or "deny"
	Priority    int               `json:"priority"`
	Conditions  []PolicyCondition `json:"conditions" gorm:"foreignKey:PolicyID"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// PolicyCondition represents a condition within a policy
type PolicyCondition struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	PolicyID string `json:"policy_id" gorm:"index"`
	Type     string `json:"type"`     // "user", "object", "environment", "action"
	Field    string `json:"field"`    // attribute name
	Operator string `json:"operator"` // "eq", "ne", "gt", "gte", "lt", "lte", "in", "contains", "startswith", "endswith"
	Value    string `json:"value"`    // comparison value
	LogicOp  string `json:"logic_op"` // "and", "or" (for combining with next condition)
}

// PolicyEvaluationContext holds all data needed for policy evaluation
type PolicyEvaluationContext struct {
	UserAttributes        map[string]string
	ObjectAttributes      map[string]string
	EnvironmentAttributes map[string]string
	ActionAttributes      map[string]string
	Subject               string
	Object                string
	Action                string
}

// PolicyEngine handles ABAC policy evaluation
type PolicyEngine struct {
	policies map[string]*ABACPolicy
	db       *gorm.DB
}

// EnforceResponse represents the response for an enforcement request
type EnforceResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
	Model   string `json:"model"`
	Path    string `json:"path,omitempty"` // ReBAC: relationship path for access permission
}

// Relationship represents a relationship in the ReBAC graph
type Relationship struct {
	Subject      string `json:"subject"`
	Relationship string `json:"relationship"`
	Object       string `json:"object"`
}

// RelationshipGraph manages relationships for ReBAC
type RelationshipGraph struct {
	relationships map[string][]Relationship
	objectTypes   map[string]string // Object type mappings
	db            *gorm.DB          // Database connection for persistence
	permissions   map[string][]string // Relationship to permissions mapping
}

// RelationshipRecord represents a relationship record in the database
type RelationshipRecord struct {
	ID           uint   `gorm:"primaryKey"`
	Subject      string `gorm:"index"`
	Relationship string `gorm:"index"`
	Object       string `gorm:"index"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserAttribute represents a user attribute record in the database
type UserAttribute struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index"`
	Attribute string `gorm:"index"`
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ObjectAttribute represents an object attribute record in the database
type ObjectAttribute struct {
	ID        uint   `gorm:"primaryKey"`
	ObjectID  string `gorm:"index"`
	Attribute string `gorm:"index"`
	Value     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewRelationshipGraph creates a new relationship graph for ReBAC with database persistence
func NewRelationshipGraph(db *gorm.DB) (*RelationshipGraph, error) {
	// Auto-migrate the relationship table
	err := db.AutoMigrate(&RelationshipRecord{})
	if err != nil {
		return nil, fmt.Errorf("failed to migrate relationship table: %v", err)
	}

	rg := &RelationshipGraph{
		relationships: make(map[string][]Relationship),
		objectTypes:   make(map[string]string),
		db:            db,
		permissions:   make(map[string][]string),
	}

	// Initialize default permission mappings following ReBAC best practices
	rg.initializeDefaultPermissions()

	// Load existing relationships from database
	err = rg.loadFromDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to load relationships from database: %v", err)
	}

	return rg, nil
}

// loadFromDatabase loads all relationships from the database into memory
func (rg *RelationshipGraph) loadFromDatabase() error {
	var records []RelationshipRecord
	result := rg.db.Find(&records)
	if result.Error != nil {
		return result.Error
	}

	// Clear existing relationships
	rg.relationships = make(map[string][]Relationship)

	// Load relationships into memory
	for _, record := range records {
		rel := Relationship{
			Subject:      record.Subject,
			Relationship: record.Relationship,
			Object:       record.Object,
		}

		key := fmt.Sprintf("%s:%s", record.Subject, record.Relationship)
		rg.relationships[key] = append(rg.relationships[key], rel)

		// Store reverse relationship for graph traversal
		reverseKey := fmt.Sprintf("%s:reverse_%s", record.Object, record.Relationship)
		rg.relationships[reverseKey] = append(rg.relationships[reverseKey], Relationship{
			Subject:      record.Object,
			Relationship: "reverse_" + record.Relationship,
			Object:       record.Subject,
		})
	}

	return nil
}

// initializeDefaultPermissions sets up the default relationship-to-permission mappings
// following ReBAC best practices where relationships define connections, not permissions
func (rg *RelationshipGraph) initializeDefaultPermissions() {
	// Owner relationship grants all permissions
	rg.permissions["owner"] = []string{"read", "write", "delete", "admin"}
	
	// Editor relationship grants read and write permissions
	rg.permissions["editor"] = []string{"read", "write", "edit"}
	
	// Viewer relationship grants read-only permission
	rg.permissions["viewer"] = []string{"read", "view"}
	
	// Member relationship inherits permissions from the group
	rg.permissions["member"] = []string{"inherit"}
	
	// Group access relationship defines what groups can access
	rg.permissions["group_access"] = []string{"read", "write"}
	
	// Parent relationship allows inheritance of permissions
	rg.permissions["parent"] = []string{"inherit"}
	
	// Friend relationship grants limited read access
	rg.permissions["friend"] = []string{"read_limited"}
	
	// Manager relationship grants administrative permissions
	rg.permissions["manager"] = []string{"read", "write", "delete", "manage"}
}

// GetPermissionsForRelationship returns the permissions associated with a relationship type
func (rg *RelationshipGraph) GetPermissionsForRelationship(relationship string) []string {
	if perms, exists := rg.permissions[relationship]; exists {
		return perms
	}
	return []string{}
}

// HasPermissionThroughRelationship checks if a relationship grants a specific permission
func (rg *RelationshipGraph) HasPermissionThroughRelationship(relationship, permission string) bool {
	perms := rg.GetPermissionsForRelationship(relationship)
	for _, perm := range perms {
		if perm == permission || perm == "admin" {
			return true
		}
	}
	return false
}

// saveToDatabase saves a relationship to the database
func (rg *RelationshipGraph) saveToDatabase(subject, relationship, object string) error {
	record := RelationshipRecord{
		Subject:      subject,
		Relationship: relationship,
		Object:       object,
	}

	result := rg.db.Create(&record)
	return result.Error
}

// deleteFromDatabase removes a relationship from the database
func (rg *RelationshipGraph) deleteFromDatabase(subject, relationship, object string) error {
	result := rg.db.Where("subject = ? AND relationship = ? AND object = ?", subject, relationship, object).Delete(&RelationshipRecord{})
	return result.Error
}

// AddRelationship adds a new relationship to the graph and persists it to database
func (rg *RelationshipGraph) AddRelationship(subject, relationship, object string) error {
	// Save to database first
	err := rg.saveToDatabase(subject, relationship, object)
	if err != nil {
		return fmt.Errorf("failed to save relationship to database: %v", err)
	}

	rel := Relationship{
		Subject:      subject,
		Relationship: relationship,
		Object:       object,
	}

	key := fmt.Sprintf("%s:%s", subject, relationship)
	rg.relationships[key] = append(rg.relationships[key], rel)

	// Store reverse relationship for graph traversal
	reverseKey := fmt.Sprintf("%s:reverse_%s", object, relationship)
	rg.relationships[reverseKey] = append(rg.relationships[reverseKey], Relationship{
		Subject:      object,
		Relationship: "reverse_" + relationship,
		Object:       subject,
	})

	return nil
}

// RemoveRelationship removes a relationship from the graph and database
func (rg *RelationshipGraph) RemoveRelationship(subject, relationship, object string) error {
	// Remove from database first
	err := rg.deleteFromDatabase(subject, relationship, object)
	if err != nil {
		return fmt.Errorf("failed to delete relationship from database: %v", err)
	}

	key := fmt.Sprintf("%s:%s", subject, relationship)
	relationships := rg.relationships[key]

	for i, rel := range relationships {
		if rel.Object == object {
			rg.relationships[key] = append(relationships[:i], relationships[i+1:]...)
			break
		}
	}

	// Remove reverse relationship as well
	reverseKey := fmt.Sprintf("%s:reverse_%s", object, relationship)
	reverseRelationships := rg.relationships[reverseKey]

	for i, rel := range reverseRelationships {
		if rel.Object == subject {
			rg.relationships[reverseKey] = append(reverseRelationships[:i], reverseRelationships[i+1:]...)
			break
		}
	}

	return nil
}

// HasDirectRelationship checks if a direct relationship exists between subject and object
func (rg *RelationshipGraph) HasDirectRelationship(subject, relationship, object string) bool {
	key := fmt.Sprintf("%s:%s", subject, relationship)
	relationships := rg.relationships[key]

	for _, rel := range relationships {
		if rel.Object == object {
			return true
		}
	}
	return false
}

// FindRelationshipPath searches for a relationship path using breadth-first search
func (rg *RelationshipGraph) FindRelationshipPath(subject, targetObject string, maxDepth int) (bool, string) {
	if maxDepth <= 0 {
		maxDepth = 5 // Default maximum depth
	}

	visited := make(map[string]bool)
	queue := []struct {
		node  string
		path  string
		depth int
	}{{subject, subject, 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth > maxDepth {
			continue
		}

		if current.node == targetObject {
			return true, current.path
		}

		if visited[current.node] {
			continue
		}
		visited[current.node] = true

		// Check all relationships
		for key, relationships := range rg.relationships {
			parts := strings.Split(key, ":")
			if len(parts) != 2 || parts[0] != current.node {
				continue
			}

			relationshipType := parts[1]
			if strings.HasPrefix(relationshipType, "reverse_") {
				continue // Exclude reverse relationships
			}

			for _, rel := range relationships {
				if !visited[rel.Object] {
					newPath := fmt.Sprintf("%s -[%s]-> %s", current.path, relationshipType, rel.Object)
					queue = append(queue, struct {
						node  string
						path  string
						depth int
					}{rel.Object, newPath, current.depth + 1})
				}
			}
		}
	}

	return false, ""
}

// CheckReBACAccess checks access permissions using ReBAC rules
// This method properly separates authorization logic from relationship queries
// following ReBAC best practices (like Google Zanzibar)
func (rg *RelationshipGraph) CheckReBACAccess(subject, object, action string) (bool, string) {
	// Map common actions to standardized permissions
	permission := rg.mapActionToPermission(action)
	
	// 1. Check all direct relationships and their associated permissions
	directRelationships := rg.GetDirectRelationships(subject, object)
	for _, rel := range directRelationships {
		if rg.HasPermissionThroughRelationship(rel.Relationship, permission) {
			return true, fmt.Sprintf("%s -[%s]-> %s", subject, rel.Relationship, object)
		}
	}

	// 2. Check access through group membership (indirect relationships)
	groupAccess, groupPath := rg.checkGroupAccess(subject, object, permission)
	if groupAccess {
		return true, groupPath
	}

	// 3. Check hierarchical access (parent-child relationships)
	hierarchicalAccess, hierarchicalPath := rg.checkHierarchicalAccess(subject, object, permission)
	if hierarchicalAccess {
		return true, hierarchicalPath
	}

	// 4. Check social relationships for limited access
	if permission == "read" || permission == "read_limited" {
		socialAccess, socialPath := rg.checkSocialAccess(subject, object, 3)
		if socialAccess {
			return true, socialPath
		}
	}

	return false, ""
}

// mapActionToPermission maps action strings to standardized permissions
func (rg *RelationshipGraph) mapActionToPermission(action string) string {
	// Normalize common action names to permissions
	switch action {
	case "view":
		return "read"
	case "edit", "update", "modify":
		return "write"
	case "remove":
		return "delete"
	case "manage", "administer":
		return "admin"
	default:
		return action
	}
}

// GetDirectRelationships returns all direct relationships between subject and object
func (rg *RelationshipGraph) GetDirectRelationships(subject, object string) []Relationship {
	var relationships []Relationship
	
	for key, rels := range rg.relationships {
		parts := strings.Split(key, ":")
		if len(parts) == 2 && parts[0] == subject && !strings.HasPrefix(parts[1], "reverse_") {
			for _, rel := range rels {
				if rel.Object == object {
					relationships = append(relationships, rel)
				}
			}
		}
	}
	
	return relationships
}

// checkGroupAccess checks if subject has access through group membership
func (rg *RelationshipGraph) checkGroupAccess(subject, object, permission string) (bool, string) {
	// Find all groups the subject is a member of
	memberKey := fmt.Sprintf("%s:member", subject)
	if groups, exists := rg.relationships[memberKey]; exists {
		for _, groupRel := range groups {
			groupName := groupRel.Object
			
			// Check if the group has the required permission on the object
			groupRelationships := rg.GetDirectRelationships(groupName, object)
			for _, rel := range groupRelationships {
				if rg.HasPermissionThroughRelationship(rel.Relationship, permission) {
					path := fmt.Sprintf("%s -[member]-> %s -[%s]-> %s", 
						subject, groupName, rel.Relationship, object)
					return true, path
				}
			}
		}
	}
	
	return false, ""
}

// checkHierarchicalAccess checks access through parent-child relationships
func (rg *RelationshipGraph) checkHierarchicalAccess(subject, object, permission string) (bool, string) {
	// Find parent objects
	for key, relationships := range rg.relationships {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || parts[1] != "parent" {
			continue
		}
		
		parentObject := parts[0]
		for _, rel := range relationships {
			if rel.Object == object {
				// Recursively check if subject has access to parent
				hasAccess, parentPath := rg.CheckReBACAccess(subject, parentObject, permission)
				if hasAccess {
					path := fmt.Sprintf("%s -> %s -[parent]-> %s", parentPath, parentObject, object)
					return true, path
				}
			}
		}
	}
	
	return false, ""
}

// checkSocialAccess checks access through social relationships (e.g., friend connections)
func (rg *RelationshipGraph) checkSocialAccess(subject, object string, maxDepth int) (bool, string) {
	found, path := rg.FindRelationshipPath(subject, object, maxDepth)
	if found && strings.Contains(path, "friend") {
		// Verify that the friend relationship grants the required permission
		if rg.HasPermissionThroughRelationship("friend", "read_limited") {
			return true, path
		}
	}
	return false, ""
}

// AuthService manages multiple authorization models
type AuthService struct {
	aclEnforcer       *casbin.Enforcer
	rbacEnforcer      *casbin.Enforcer
	abacEnforcer      *casbin.Enforcer
	userAttrs         map[string]map[string]string // User attributes cache for ABAC
	objectAttrs       map[string]map[string]string // Object attributes cache for ABAC
	relationshipGraph *RelationshipGraph           // Relationship graph for ReBAC
	policyEngine      *PolicyEngine                // ABAC policy engine
	db                *gorm.DB                     // Database connection for ABAC persistence
}

// ACL model definition
const aclModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act`

// RBAC model definition
const rbacModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`

// ABAC model definition (simplified version)
const abacModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = keyMatch(r.sub, p.sub) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)`

// NewAuthService creates a new authorization service with multiple models
func NewAuthService() (*AuthService, error) {
	// Connect to SQLite database
	db, err := gorm.Open(sqlite.Open("casbin.db"), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite database: %v", err)
	}

	// Create adapters for each model
	aclAdapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "acl_rules")
	if err != nil {
		return nil, fmt.Errorf("failed to create ACL adapter: %v", err)
	}

	rbacAdapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "rbac_rules")
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC adapter: %v", err)
	}

	abacAdapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "abac_rules")
	if err != nil {
		return nil, fmt.Errorf("failed to create ABAC adapter: %v", err)
	}

	// Create enforcers for each model
	aclModelObj, err := model.NewModelFromString(aclModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACL model: %v", err)
	}
	aclEnforcer, err := casbin.NewEnforcer(aclModelObj, aclAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACL enforcer: %v", err)
	}

	rbacModelObj, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC model: %v", err)
	}
	rbacEnforcer, err := casbin.NewEnforcer(rbacModelObj, rbacAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC enforcer: %v", err)
	}

	abacModelObj, err := model.NewModelFromString(abacModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create ABAC model: %v", err)
	}
	abacEnforcer, err := casbin.NewEnforcer(abacModelObj, abacAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create ABAC enforcer: %v", err)
	}

	// Load policies
	aclEnforcer.LoadPolicy()
	rbacEnforcer.LoadPolicy()
	abacEnforcer.LoadPolicy()

	// Enable auto-save feature
	aclEnforcer.EnableAutoSave(true)
	rbacEnforcer.EnableAutoSave(true)
	abacEnforcer.EnableAutoSave(true)

	// Auto-migrate ABAC attribute tables and policy engine tables
	err = db.AutoMigrate(&UserAttribute{}, &ObjectAttribute{}, &ABACPolicy{}, &PolicyCondition{})
	if err != nil {
		return nil, fmt.Errorf("failed to migrate ABAC tables: %v", err)
	}

	// Create relationship graph with database persistence
	relationshipGraph, err := NewRelationshipGraph(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create relationship graph: %v", err)
	}

	// Create and initialize policy engine
	policyEngine := NewPolicyEngine(db)
	err = policyEngine.LoadPolicies()
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %v", err)
	}

	service := &AuthService{
		aclEnforcer:       aclEnforcer,
		rbacEnforcer:      rbacEnforcer,
		abacEnforcer:      abacEnforcer,
		userAttrs:         make(map[string]map[string]string),
		objectAttrs:       make(map[string]map[string]string),
		relationshipGraph: relationshipGraph,
		policyEngine:      policyEngine,
		db:                db,
	}

	// Load ABAC attributes from database
	err = service.loadABACAttributes()
	if err != nil {
		return nil, fmt.Errorf("failed to load ABAC attributes: %v", err)
	}

	return service, nil
}

// loadABACAttributes loads user and object attributes from database into memory cache
func (s *AuthService) loadABACAttributes() error {
	// Load user attributes
	var userAttrs []UserAttribute
	result := s.db.Find(&userAttrs)
	if result.Error != nil {
		return fmt.Errorf("failed to load user attributes: %v", result.Error)
	}

	// Group user attributes by user ID
	for _, attr := range userAttrs {
		if s.userAttrs[attr.UserID] == nil {
			s.userAttrs[attr.UserID] = make(map[string]string)
		}
		s.userAttrs[attr.UserID][attr.Attribute] = attr.Value
	}

	// Load object attributes
	var objectAttrs []ObjectAttribute
	result = s.db.Find(&objectAttrs)
	if result.Error != nil {
		return fmt.Errorf("failed to load object attributes: %v", result.Error)
	}

	// Group object attributes by object ID
	for _, attr := range objectAttrs {
		if s.objectAttrs[attr.ObjectID] == nil {
			s.objectAttrs[attr.ObjectID] = make(map[string]string)
		}
		s.objectAttrs[attr.ObjectID][attr.Attribute] = attr.Value
	}

	return nil
}

// saveUserAttribute saves a user attribute to database and updates cache
func (s *AuthService) saveUserAttribute(userID, attribute, value string) error {
	// Check if attribute already exists
	var existingAttr UserAttribute
	result := s.db.Where("user_id = ? AND attribute = ?", userID, attribute).First(&existingAttr)
	
	if result.Error == nil {
		// Update existing attribute
		existingAttr.Value = value
		result = s.db.Save(&existingAttr)
	} else {
		// Create new attribute
		newAttr := UserAttribute{
			UserID:    userID,
			Attribute: attribute,
			Value:     value,
		}
		result = s.db.Create(&newAttr)
	}

	if result.Error != nil {
		return fmt.Errorf("failed to save user attribute: %v", result.Error)
	}

	// Update cache
	if s.userAttrs[userID] == nil {
		s.userAttrs[userID] = make(map[string]string)
	}
	s.userAttrs[userID][attribute] = value

	return nil
}

// saveObjectAttribute saves an object attribute to database and updates cache
func (s *AuthService) saveObjectAttribute(objectID, attribute, value string) error {
	// Check if attribute already exists
	var existingAttr ObjectAttribute
	result := s.db.Where("object_id = ? AND attribute = ?", objectID, attribute).First(&existingAttr)
	
	if result.Error == nil {
		// Update existing attribute
		existingAttr.Value = value
		result = s.db.Save(&existingAttr)
	} else {
		// Create new attribute
		newAttr := ObjectAttribute{
			ObjectID:  objectID,
			Attribute: attribute,
			Value:     value,
		}
		result = s.db.Create(&newAttr)
	}

	if result.Error != nil {
		return fmt.Errorf("failed to save object attribute: %v", result.Error)
	}

	// Update cache
	if s.objectAttrs[objectID] == nil {
		s.objectAttrs[objectID] = make(map[string]string)
	}
	s.objectAttrs[objectID][attribute] = value

	return nil
}

// getUserAttributesFromDB retrieves user attributes from database (bypassing cache)
func (s *AuthService) getUserAttributesFromDB(userID string) (map[string]string, error) {
	var attrs []UserAttribute
	result := s.db.Where("user_id = ?", userID).Find(&attrs)
	if result.Error != nil {
		return nil, result.Error
	}

	attributes := make(map[string]string)
	for _, attr := range attrs {
		attributes[attr.Attribute] = attr.Value
	}

	return attributes, nil
}

// NewPolicyEngine creates a new ABAC policy engine
func NewPolicyEngine(db *gorm.DB) *PolicyEngine {
	return &PolicyEngine{
		policies: make(map[string]*ABACPolicy),
		db:       db,
	}
}

// LoadPolicies loads all policies from database into memory
func (pe *PolicyEngine) LoadPolicies() error {
	var policies []ABACPolicy
	if err := pe.db.Preload("Conditions").Find(&policies).Error; err != nil {
		return fmt.Errorf("failed to load policies: %v", err)
	}

	pe.policies = make(map[string]*ABACPolicy)
	for _, policy := range policies {
		pe.policies[policy.ID] = &policy
	}

	return nil
}

// AddPolicy adds a new policy to the engine
func (pe *PolicyEngine) AddPolicy(policy *ABACPolicy) error {
	// Save to database
	if err := pe.db.Create(policy).Error; err != nil {
		return fmt.Errorf("failed to save policy: %v", err)
	}

	// Add to memory cache
	pe.policies[policy.ID] = policy
	return nil
}

// RemovePolicy removes a policy from the engine
func (pe *PolicyEngine) RemovePolicy(policyID string) error {
	// Remove from database
	if err := pe.db.Delete(&ABACPolicy{}, "id = ?", policyID).Error; err != nil {
		return fmt.Errorf("failed to delete policy: %v", err)
	}

	// Remove conditions
	if err := pe.db.Delete(&PolicyCondition{}, "policy_id = ?", policyID).Error; err != nil {
		return fmt.Errorf("failed to delete policy conditions: %v", err)
	}

	// Remove from memory cache
	delete(pe.policies, policyID)
	return nil
}

// Evaluate evaluates all policies against the given context
func (pe *PolicyEngine) Evaluate(ctx *PolicyEvaluationContext) (bool, string) {
	// Sort policies by priority (higher priority first)
	var sortedPolicies []*ABACPolicy
	for _, policy := range pe.policies {
		sortedPolicies = append(sortedPolicies, policy)
	}

	// Simple sort by priority (descending)
	for i := 0; i < len(sortedPolicies); i++ {
		for j := i + 1; j < len(sortedPolicies); j++ {
			if sortedPolicies[i].Priority < sortedPolicies[j].Priority {
				sortedPolicies[i], sortedPolicies[j] = sortedPolicies[j], sortedPolicies[i]
			}
		}
	}

	// Evaluate policies in priority order
	for _, policy := range sortedPolicies {
		if pe.evaluatePolicy(policy, ctx) {
			if policy.Effect == "allow" {
				return true, fmt.Sprintf("Access granted by policy: %s", policy.Name)
			} else if policy.Effect == "deny" {
				return false, fmt.Sprintf("Access denied by policy: %s", policy.Name)
			}
		}
	}

	// Default deny if no policy matches
	return false, "No policy grants access"
}

// evaluatePolicy evaluates a single policy against the context
func (pe *PolicyEngine) evaluatePolicy(policy *ABACPolicy, ctx *PolicyEvaluationContext) bool {
	if len(policy.Conditions) == 0 {
		return false
	}

	result := true
	currentLogicOp := "and" // Start with AND logic

	for i, condition := range policy.Conditions {
		conditionResult := pe.evaluateCondition(&condition, ctx)

		if i == 0 {
			result = conditionResult
		} else {
			if currentLogicOp == "and" {
				result = result && conditionResult
			} else { // "or"
				result = result || conditionResult
			}
		}

		// Set logic operator for next iteration
		if condition.LogicOp != "" {
			currentLogicOp = condition.LogicOp
		}
	}

	return result
}

// evaluateCondition evaluates a single condition
func (pe *PolicyEngine) evaluateCondition(condition *PolicyCondition, ctx *PolicyEvaluationContext) bool {
	var actualValue string

	// Get the actual value based on condition type
	switch condition.Type {
	case "user":
		actualValue = ctx.UserAttributes[condition.Field]
	case "object":
		actualValue = ctx.ObjectAttributes[condition.Field]
	case "environment":
		actualValue = ctx.EnvironmentAttributes[condition.Field]
	case "action":
		if condition.Field == "action" {
			actualValue = ctx.Action
		} else {
			actualValue = ctx.ActionAttributes[condition.Field]
		}
	case "subject":
		if condition.Field == "subject" {
			actualValue = ctx.Subject
		}
	case "resource":
		if condition.Field == "object" {
			actualValue = ctx.Object
		}
	default:
		return false
	}

	// Evaluate based on operator
	return pe.evaluateOperator(actualValue, condition.Operator, condition.Value)
}

// evaluateOperator performs the actual comparison
func (pe *PolicyEngine) evaluateOperator(actual, operator, expected string) bool {
	switch operator {
	case "eq":
		return actual == expected
	case "ne":
		return actual != expected
	case "gt":
		return pe.compareNumeric(actual, expected) > 0
	case "gte":
		return pe.compareNumeric(actual, expected) >= 0
	case "lt":
		return pe.compareNumeric(actual, expected) < 0
	case "lte":
		return pe.compareNumeric(actual, expected) <= 0
	case "in":
		return pe.evaluateIn(actual, expected)
	case "contains":
		return strings.Contains(actual, expected)
	case "startswith":
		return strings.HasPrefix(actual, expected)
	case "endswith":
		return strings.HasSuffix(actual, expected)
	case "regex":
		matched, _ := regexp.MatchString(expected, actual)
		return matched
	default:
		return false
	}
}

// compareNumeric compares two string values as numbers
func (pe *PolicyEngine) compareNumeric(actual, expected string) int {
	actualNum, err1 := strconv.ParseFloat(actual, 64)
	expectedNum, err2 := strconv.ParseFloat(expected, 64)

	if err1 != nil || err2 != nil {
		// Fallback to string comparison
		return strings.Compare(actual, expected)
	}

	if actualNum > expectedNum {
		return 1
	} else if actualNum < expectedNum {
		return -1
	}
	return 0
}

// evaluateIn checks if actual value is in the comma-separated list
func (pe *PolicyEngine) evaluateIn(actual, expectedList string) bool {
	values := strings.Split(expectedList, ",")
	for _, value := range values {
		if strings.TrimSpace(value) == actual {
			return true
		}
	}
	return false
}

// getObjectAttributes retrieves object attributes from cache
func (s *AuthService) getObjectAttributes(objectID string) map[string]string {
	// Return a copy of the attributes map to avoid concurrent modification issues
	if attrs, exists := s.objectAttrs[objectID]; exists {
		result := make(map[string]string)
		for k, v := range attrs {
			result[k] = v
		}
		return result
	}
	
	// Return nil if object attributes don't exist
	return nil
}

// Enforce performs authorization check for the given model
func (s *AuthService) Enforce(model AccessControlModel, subject, object, action string, attributes map[string]string) (bool, error) {
	// Set default model
	if model == "" {
		model = ModelRBAC
	}

	var allowed bool
	var err error

	switch model {
	case ModelACL, ModelRBAC:
		enforcer := s.getEnforcer(model)
		allowed, err = enforcer.Enforce(subject, object, action)
	case ModelABAC:
		// ABAC uses custom policy engine
		allowed = s.matchABACAttributes(subject, object, action, attributes)
	case ModelReBAC:
		// ReBAC uses relationship graph
		allowed, _ = s.relationshipGraph.CheckReBACAccess(subject, object, action)
	default:
		return false, fmt.Errorf("invalid model specified: %s", model)
	}

	return allowed, err
}

// getEnforcer returns the appropriate enforcer for the given model
func (s *AuthService) getEnforcer(model AccessControlModel) *casbin.Enforcer {
	switch model {
	case ModelACL:
		return s.aclEnforcer
	case ModelRBAC:
		return s.rbacEnforcer
	case ModelABAC:
		return s.abacEnforcer
	default:
		return s.rbacEnforcer // Default to RBAC
	}
}

// initializeData sets up initial data for demonstration purposes
func (s *AuthService) initializeData() error {
	// Initial data for ACL
	aclPolicies := [][]string{
		{"alice", "data1", "read"},
		{"alice", "data1", "write"},
		{"bob", "data2", "read"},
		{"charlie", "data1", "read"},
	}

	for _, policy := range aclPolicies {
		s.aclEnforcer.AddPolicy(policy)
	}

	// Initial data for RBAC
	rbacRoles := [][]string{
		{"alice", "admin"},
		{"bob", "user"},
		{"charlie", "guest"},
	}

	rbacPolicies := [][]string{
		{"admin", "data", "read"},
		{"admin", "data", "write"},
		{"admin", "data", "delete"},
		{"user", "data", "read"},
		{"user", "data", "write"},
		{"guest", "data", "read"},
	}

	for _, role := range rbacRoles {
		s.rbacEnforcer.AddRoleForUser(role[0], role[1])
	}

	for _, policy := range rbacPolicies {
		s.rbacEnforcer.AddPolicy(policy)
	}

	// No hardcoded initial data for ABAC
	// Users and objects will have attributes set dynamically via API

	// Initial data for ReBAC (relationship-based)
	// Only add if no relationships exist in database (first run)
	var count int64
	s.relationshipGraph.db.Model(&RelationshipRecord{}).Count(&count)
	if count == 0 {
		// Ownership relationships
		s.relationshipGraph.AddRelationship("alice", "owner", "document1")
		s.relationshipGraph.AddRelationship("bob", "owner", "document2")
		s.relationshipGraph.AddRelationship("charlie", "owner", "document3")

		// Editor relationships
		s.relationshipGraph.AddRelationship("alice", "editor", "document2")
		s.relationshipGraph.AddRelationship("bob", "editor", "document3")

		// Viewer relationships
		s.relationshipGraph.AddRelationship("charlie", "viewer", "document1")
		s.relationshipGraph.AddRelationship("charlie", "viewer", "document2")

		// Group memberships
		s.relationshipGraph.AddRelationship("alice", "member", "hr_team")
		s.relationshipGraph.AddRelationship("bob", "member", "dev_team")
		s.relationshipGraph.AddRelationship("charlie", "member", "sales_team")

		// Group access rights
		s.relationshipGraph.AddRelationship("hr_team", "group_access", "hr_documents")
		s.relationshipGraph.AddRelationship("dev_team", "group_access", "dev_documents")

		// Hierarchical relationships (folder structure)
		s.relationshipGraph.AddRelationship("project_folder", "parent", "document1")
		s.relationshipGraph.AddRelationship("project_folder", "parent", "document2")
		s.relationshipGraph.AddRelationship("alice", "owner", "project_folder")

		// Friend relationships (social feature demo)
		s.relationshipGraph.AddRelationship("alice", "friend", "bob")
		s.relationshipGraph.AddRelationship("bob", "friend", "charlie")
		s.relationshipGraph.AddRelationship("alice", "owner", "alice_post")
	}

	// Initialize ABAC policies
	err := s.initializeABACPolicies()
	if err != nil {
		return fmt.Errorf("failed to initialize ABAC policies: %v", err)
	}

	return nil
}

// initializeABACPolicies initializes an empty policy engine
func (s *AuthService) initializeABACPolicies() error {
	// No hardcoded policies - pure generic engine
	// Policies will be created dynamically via API
	return nil
}

// matchABACAttributes uses the policy engine to evaluate ABAC authorization
func (s *AuthService) matchABACAttributes(subject, object, action string, reqAttrs map[string]string) bool {
	// Get user attributes from persistent storage
	userAttrs, _ := s.getUserAttributesFromDB(subject)
	if userAttrs == nil {
		userAttrs = make(map[string]string)
	}

	// Get object attributes
	objectAttrs := s.getObjectAttributes(object)
	if objectAttrs == nil {
		objectAttrs = make(map[string]string)
	}

	// Create environment attributes
	envAttrs := map[string]string{
		"time": strconv.Itoa(time.Now().Hour()),
		"date": time.Now().Format("2006-01-02"),
		"day":  time.Now().Format("Monday"),
	}

	// Override with request attributes (including location if provided)
	for k, v := range reqAttrs {
		envAttrs[k] = v
	}

	// Use "hour" attribute from request if provided, otherwise use current time
	if hourStr, exists := reqAttrs["hour"]; exists {
		envAttrs["time"] = hourStr
	}

	// Create evaluation context
	ctx := &PolicyEvaluationContext{
		UserAttributes:        userAttrs,
		ObjectAttributes:      objectAttrs,
		EnvironmentAttributes: envAttrs,
		ActionAttributes:      make(map[string]string),
		Subject:               subject,
		Object:                object,
		Action:                action,
	}

	// Use policy engine to evaluate
	allowed, _ := s.policyEngine.Evaluate(ctx)
	return allowed
}

// enforceHandler handles authorization enforcement requests for all models
func (s *AuthService) enforceHandler(w http.ResponseWriter, r *http.Request) {
	var req EnforceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Set default model
	if req.Model == "" {
		req.Model = ModelRBAC
	}

	var allowed bool
	var err error
	var path string

	switch req.Model {
	case ModelACL, ModelRBAC:
		enforcer := s.getEnforcer(req.Model)
		allowed, err = enforcer.Enforce(req.Subject, req.Object, req.Action)
	case ModelABAC:
		// ABAC uses custom logic
		allowed = s.matchABACAttributes(req.Subject, req.Object, req.Action, req.Attributes)
	case ModelReBAC:
		// ReBAC uses relationship graph
		allowed, path = s.relationshipGraph.CheckReBACAccess(req.Subject, req.Object, req.Action)
	default:
		http.Error(w, "Invalid model specified", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Authorization check error: %v", err), http.StatusInternalServerError)
		return
	}

	response := EnforceResponse{
		Allowed: allowed,
		Model:   string(req.Model),
		Path:    path,
	}

	if !allowed {
		response.Message = "Access denied"
	} else {
		response.Message = "Access granted"
		if req.Model == ModelReBAC && path != "" {
			response.Message += fmt.Sprintf(" (relationship path: %s)", path)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// addRelationshipHandler handles adding new relationships for ReBAC
func (s *AuthService) addRelationshipHandler(w http.ResponseWriter, r *http.Request) {
	var req RelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	err := s.relationshipGraph.AddRelationship(req.Subject, req.Relationship, req.Object)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add relationship: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":      "Relationship added successfully",
		"subject":      req.Subject,
		"relationship": req.Relationship,
		"object":       req.Object,
		"model":        "rebac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// removeRelationshipHandler handles removing relationships for ReBAC
func (s *AuthService) removeRelationshipHandler(w http.ResponseWriter, r *http.Request) {
	var req RelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	err := s.relationshipGraph.RemoveRelationship(req.Subject, req.Relationship, req.Object)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove relationship: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":      "Relationship removed successfully",
		"subject":      req.Subject,
		"relationship": req.Relationship,
		"object":       req.Object,
		"model":        "rebac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getRelationshipsHandler retrieves relationships for ReBAC
func (s *AuthService) getRelationshipsHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")

	var relationships []Relationship

	if subject != "" {
		// Get relationships for specific subject only
		for key, rels := range s.relationshipGraph.relationships {
			parts := strings.Split(key, ":")
			if len(parts) == 2 && parts[0] == subject && !strings.HasPrefix(parts[1], "reverse_") {
				relationships = append(relationships, rels...)
			}
		}
	} else {
		// Get all relationships
		for key, rels := range s.relationshipGraph.relationships {
			parts := strings.Split(key, ":")
			if len(parts) == 2 && !strings.HasPrefix(parts[1], "reverse_") {
				relationships = append(relationships, rels...)
			}
		}
	}

	response := map[string]interface{}{
		"relationships": relationships,
		"subject":       subject,
		"model":         "rebac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// findPathHandler searches for relationship paths in ReBAC
func (s *AuthService) findPathHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	object := r.URL.Query().Get("object")
	maxDepthStr := r.URL.Query().Get("max_depth")

	if subject == "" || object == "" {
		http.Error(w, "subject and object parameters are required", http.StatusBadRequest)
		return
	}

	maxDepth := 5
	if maxDepthStr != "" {
		if d, err := strconv.Atoi(maxDepthStr); err == nil {
			maxDepth = d
		}
	}

	found, path := s.relationshipGraph.FindRelationshipPath(subject, object, maxDepth)

	response := map[string]interface{}{
		"found":     found,
		"path":      path,
		"subject":   subject,
		"object":    object,
		"max_depth": maxDepth,
		"model":     "rebac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// addPolicyHandler handles adding new policies for ACL/RBAC/ABAC models
func (s *AuthService) addPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if req.Model == "" {
		req.Model = ModelRBAC
	}

	if req.Model == ModelReBAC {
		http.Error(w, "For ReBAC, please use the addRelationship endpoint", http.StatusBadRequest)
		return
	}

	enforcer := s.getEnforcer(req.Model)
	added, err := enforcer.AddPolicy(req.Subject, req.Object, req.Action)
	if err != nil {
		http.Error(w, fmt.Sprintf("Policy addition error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"added":   added,
		"message": fmt.Sprintf("Policy added successfully for %s model", req.Model),
		"model":   req.Model,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// removePolicyHandler handles removing policies for ACL/RBAC/ABAC models
func (s *AuthService) removePolicyHandler(w http.ResponseWriter, r *http.Request) {
	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if req.Model == "" {
		req.Model = ModelRBAC
	}

	if req.Model == ModelReBAC {
		http.Error(w, "For ReBAC, please use the removeRelationship endpoint", http.StatusBadRequest)
		return
	}

	enforcer := s.getEnforcer(req.Model)
	removed, err := enforcer.RemovePolicy(req.Subject, req.Object, req.Action)
	if err != nil {
		http.Error(w, fmt.Sprintf("Policy removal error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"removed": removed,
		"message": fmt.Sprintf("Policy removed successfully for %s model", req.Model),
		"model":   req.Model,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// addRoleHandler assigns a role to a user (RBAC only)
func (s *AuthService) addRoleHandler(w http.ResponseWriter, r *http.Request) {
	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	added, err := s.rbacEnforcer.AddRoleForUser(req.User, req.Role)
	if err != nil {
		http.Error(w, fmt.Sprintf("Role addition error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"added":   added,
		"message": "Role added successfully",
		"model":   "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// setUserAttributesHandler sets user attributes for ABAC with database persistence
func (s *AuthService) setUserAttributesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	
	var req struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if len(req.Attributes) == 0 {
		http.Error(w, "attributes are required", http.StatusBadRequest)
		return
	}

	// Save each attribute to database and update cache
	for k, v := range req.Attributes {
		err := s.saveUserAttribute(userId, k, v)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to save user attribute: %v", err), http.StatusInternalServerError)
			return
		}
	}

	response := map[string]interface{}{
		"message":    "User attributes set successfully",
		"user":       userId,
		"attributes": s.userAttrs[userId],
		"count":      len(req.Attributes),
		"model":      "abac",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (s *AuthService) getPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	modelParam := r.URL.Query().Get("model")
	if modelParam == "" {
		modelParam = "rbac"
	}

	model := AccessControlModel(modelParam)

	if model == ModelReBAC {
		http.Error(w, "For ReBAC, please use the getRelationships endpoint", http.StatusBadRequest)
		return
	}

	enforcer := s.getEnforcer(model)
	policies, err := enforcer.GetPolicy()
	if err != nil {
		http.Error(w, fmt.Sprintf("Policy retrieval error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"policies": policies,
		"model":    model,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *AuthService) getUserRolesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]

	roles, err := s.rbacEnforcer.GetRolesForUser(userId)
	if err != nil {
		http.Error(w, fmt.Sprintf("Role retrieval error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user":  userId,
		"roles": roles,
		"count": len(roles),
		"model": "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *AuthService) getUserAttributesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]

	// Get attributes from database (ensures consistency)
	attributes, err := s.getUserAttributesFromDB(userId)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve user attributes: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user":       userId,
		"attributes": attributes,
		"count":      len(attributes),
		"model":      "abac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getModelsHandler returns information about supported authorization models
func (s *AuthService) getModelsHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"models": []map[string]string{
			{
				"name":        "acl",
				"description": "Access Control List - Direct user-resource mapping",
				"usage":       "Small-scale systems, simple permission management",
			},
			{
				"name":        "rbac",
				"description": "Role-Based Access Control - Role-based authorization",
				"usage":       "Enterprise systems, organizational permission management",
			},
			{
				"name":        "abac",
				"description": "Attribute-Based Access Control - Attribute-based authorization",
				"usage":       "Advanced security, dynamic permission control",
			},
			{
				"name":        "rebac",
				"description": "Relationship-Based Access Control - Graph-based authorization",
				"usage":       "Social media, collaboration platforms, hierarchical organizations",
			},
		},
		"default": "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// setObjectAttributesHandler sets attributes for an object (ABAC)
func (s *AuthService) setObjectAttributesHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Object     string            `json:"object"`
		Attributes map[string]string `json:"attributes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if request.Object == "" {
		http.Error(w, "Object is required", http.StatusBadRequest)
		return
	}

	if len(request.Attributes) == 0 {
		http.Error(w, "At least one attribute is required", http.StatusBadRequest)
		return
	}

	// Save each attribute to database
	for key, value := range request.Attributes {
		err := s.saveObjectAttribute(request.Object, key, value)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to save object attribute: %v", err), http.StatusInternalServerError)
			return
		}
	}

	response := map[string]interface{}{
		"message":    "Object attributes set successfully",
		"object":     request.Object,
		"attributes": request.Attributes,
		"model":      "abac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getObjectAttributesHandler retrieves attributes for an object (ABAC)
func (s *AuthService) getObjectAttributesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	objectId := vars["objectId"]

	// Get attributes from database
	attributes := s.getObjectAttributes(objectId)
	if attributes == nil {
		attributes = make(map[string]string)
	}

	response := map[string]interface{}{
		"object":     objectId,
		"attributes": attributes,
		"count":      len(attributes),
		"model":      "abac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// addABACPolicyHandler creates a new ABAC policy
func (s *AuthService) addABACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var policy ABACPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if policy.ID == "" || policy.Name == "" || policy.Effect == "" {
		http.Error(w, "ID, Name, and Effect are required", http.StatusBadRequest)
		return
	}

	// Validate effect
	if policy.Effect != "allow" && policy.Effect != "deny" {
		http.Error(w, "Effect must be 'allow' or 'deny'", http.StatusBadRequest)
		return
	}

	// Set timestamps
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	// Add policy to engine
	err := s.policyEngine.AddPolicy(&policy)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add policy: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message": "ABAC policy added successfully",
		"policy":  policy,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// deleteABACPolicyHandler removes an ABAC policy using path parameter
func (s *AuthService) deleteABACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyId := vars["id"]

	err := s.policyEngine.RemovePolicy(policyId)
	if err != nil {
		if err.Error() == "policy not found" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"removed": false,
				"message": "Policy not found",
				"id":      policyId,
			})
			return
		}
		http.Error(w, fmt.Sprintf("Failed to remove policy: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"removed": true,
		"message": "ABAC policy removed successfully",
		"id":      policyId,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// removeABACPolicyHandler removes an ABAC policy
func (s *AuthService) removeABACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	if request.ID == "" {
		http.Error(w, "Policy ID is required", http.StatusBadRequest)
		return
	}

	err := s.policyEngine.RemovePolicy(request.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove policy: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message":   "ABAC policy removed successfully",
		"policy_id": request.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getABACPoliciesHandler returns all ABAC policies
func (s *AuthService) getABACPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies := make([]*ABACPolicy, 0)
	for _, policy := range s.policyEngine.policies {
		policies = append(policies, policy)
	}

	response := map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getABACPolicyHandler returns a specific ABAC policy by ID
func (s *AuthService) getABACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	if policyID == "" {
		http.Error(w, "Policy ID is required", http.StatusBadRequest)
		return
	}

	policy, exists := s.policyEngine.policies[policyID]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// authorizationHandler handles authorization checks for all models
func (s *AuthService) authorizationHandler(w http.ResponseWriter, r *http.Request) {
	var request EnforceRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if request.Subject == "" || request.Object == "" || request.Action == "" {
		http.Error(w, "subject, object, and action are required", http.StatusBadRequest)
		return
	}

	allowed, err := s.Enforce(request.Model, request.Subject, request.Object, request.Action, request.Attributes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authorization error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"allowed": allowed,
		"message": map[bool]string{true: "Access granted", false: "Access denied"}[allowed],
		"model":   request.Model,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(map[bool]int{true: http.StatusOK, false: http.StatusForbidden}[allowed])
	json.NewEncoder(w).Encode(response)
}

// addACLPolicyHandler handles adding ACL policies
func (s *AuthService) addACLPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var request PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if request.Subject == "" || request.Object == "" || request.Action == "" {
		http.Error(w, "subject, object, and action are required", http.StatusBadRequest)
		return
	}

	added, err := s.aclEnforcer.AddPolicy(request.Subject, request.Object, request.Action)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add policy: %v", err), http.StatusInternalServerError)
		return
	}

	if !added {
		response := map[string]interface{}{
			"added":   false,
			"message": "Policy already exists",
			"policy": map[string]string{
				"subject": request.Subject,
				"object":  request.Object,
				"action":  request.Action,
			},
			"model": "acl",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}

	s.aclEnforcer.SavePolicy()

	response := map[string]interface{}{
		"added":   true,
		"message": "Policy added successfully",
		"policy": map[string]string{
			"subject": request.Subject,
			"object":  request.Object,
			"action":  request.Action,
		},
		"model": "acl",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// getACLPoliciesHandler retrieves all ACL policies
func (s *AuthService) getACLPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies, err := s.aclEnforcer.GetPolicy()
	if err != nil {
		http.Error(w, fmt.Sprintf("Policy retrieval error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
		"model":    "acl",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// deleteACLPolicyHandler removes an ACL policy
func (s *AuthService) deleteACLPolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyId := vars["id"]
	
	// Parse policy ID format: "subject:object:action"
	parts := strings.Split(policyId, ":")
	if len(parts) != 3 {
		http.Error(w, "Policy ID must be in format 'subject:object:action'", http.StatusBadRequest)
		return
	}

	removed, err := s.aclEnforcer.RemovePolicy(parts[0], parts[1], parts[2])
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove policy: %v", err), http.StatusInternalServerError)
		return
	}

	if !removed {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"removed": false,
			"message": "Policy not found",
			"model":   "acl",
		})
		return
	}

	s.aclEnforcer.SavePolicy()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"removed": true,
		"message": "Policy removed successfully",
		"model":   "acl",
	})
}

// addRBACPolicyHandler handles adding RBAC policies
func (s *AuthService) addRBACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var request PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if request.Subject == "" || request.Object == "" || request.Action == "" {
		http.Error(w, "subject, object, and action are required", http.StatusBadRequest)
		return
	}

	added, err := s.rbacEnforcer.AddPolicy(request.Subject, request.Object, request.Action)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add policy: %v", err), http.StatusInternalServerError)
		return
	}

	if !added {
		response := map[string]interface{}{
			"added":   false,
			"message": "Policy already exists",
			"policy": map[string]string{
				"subject": request.Subject,
				"object":  request.Object,
				"action":  request.Action,
			},
			"model": "rbac",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}

	s.rbacEnforcer.SavePolicy()

	response := map[string]interface{}{
		"added":   true,
		"message": "Policy added successfully",
		"policy": map[string]string{
			"subject": request.Subject,
			"object":  request.Object,
			"action":  request.Action,
		},
		"model": "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// getRBACPoliciesHandler retrieves all RBAC policies
func (s *AuthService) getRBACPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies, err := s.rbacEnforcer.GetPolicy()
	if err != nil {
		http.Error(w, fmt.Sprintf("Policy retrieval error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
		"model":    "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// deleteRBACPolicyHandler removes an RBAC policy
func (s *AuthService) deleteRBACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyId := vars["id"]
	
	// Parse policy ID format: "subject:object:action"
	parts := strings.Split(policyId, ":")
	if len(parts) != 3 {
		http.Error(w, "Policy ID must be in format 'subject:object:action'", http.StatusBadRequest)
		return
	}

	removed, err := s.rbacEnforcer.RemovePolicy(parts[0], parts[1], parts[2])
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove policy: %v", err), http.StatusInternalServerError)
		return
	}

	if !removed {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"removed": false,
			"message": "Policy not found",
			"model":   "rbac",
		})
		return
	}

	s.rbacEnforcer.SavePolicy()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"removed": true,
		"message": "Policy removed successfully",
		"model":   "rbac",
	})
}

// addUserRoleHandler handles adding roles to users
func (s *AuthService) addUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	
	var request struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if request.Role == "" {
		http.Error(w, "role is required", http.StatusBadRequest)
		return
	}

	added, err := s.rbacEnforcer.AddRoleForUser(userId, request.Role)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add role: %v", err), http.StatusInternalServerError)
		return
	}

	if !added {
		response := map[string]interface{}{
			"added":   false,
			"message": "User already has this role",
			"user":    userId,
			"role":    request.Role,
			"model":   "rbac",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}

	s.rbacEnforcer.SavePolicy()

	response := map[string]interface{}{
		"added":   true,
		"message": "Role added successfully",
		"user":    userId,
		"role":    request.Role,
		"model":   "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// deleteUserRoleHandler removes a role from a user
func (s *AuthService) deleteUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	roleId := vars["roleId"]

	removed, err := s.rbacEnforcer.DeleteRoleForUser(userId, roleId)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove role: %v", err), http.StatusInternalServerError)
		return
	}

	if !removed {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"removed": false,
			"message": "User does not have this role",
			"user":    userId,
			"role":    roleId,
			"model":   "rbac",
		})
		return
	}

	s.rbacEnforcer.SavePolicy()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"removed": true,
		"message": "Role removed successfully",
		"user":    userId,
		"role":    roleId,
		"model":   "rbac",
	})
}

// deleteUserAttributeHandler removes a user attribute
func (s *AuthService) deleteUserAttributeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId := vars["userId"]
	key := vars["key"]

	// Remove from database
	result := s.db.Where("user_id = ? AND attribute = ?", userId, key).Delete(&UserAttribute{})
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Failed to delete user attribute: %v", result.Error), http.StatusInternalServerError)
		return
	}

	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"removed": false,
			"message": "Attribute not found",
			"user":    userId,
			"key":     key,
			"model":   "abac",
		})
		return
	}

	// Remove from cache
	if s.userAttrs[userId] != nil {
		delete(s.userAttrs[userId], key)
		if len(s.userAttrs[userId]) == 0 {
			delete(s.userAttrs, userId)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"removed": true,
		"message": "Attribute removed successfully",
		"user":    userId,
		"key":     key,
		"model":   "abac",
	})
}

// deleteObjectAttributeHandler removes an object attribute
func (s *AuthService) deleteObjectAttributeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	objectId := vars["objectId"]
	key := vars["key"]

	// Remove from database
	result := s.db.Where("object_id = ? AND attribute = ?", objectId, key).Delete(&ObjectAttribute{})
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Failed to delete object attribute: %v", result.Error), http.StatusInternalServerError)
		return
	}

	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"removed": false,
			"message": "Attribute not found",
			"object":  objectId,
			"key":     key,
			"model":   "abac",
		})
		return
	}

	// Remove from cache
	if s.objectAttrs[objectId] != nil {
		delete(s.objectAttrs[objectId], key)
		if len(s.objectAttrs[objectId]) == 0 {
			delete(s.objectAttrs, objectId)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"removed": true,
		"message": "Attribute removed successfully",
		"object":  objectId,
		"key":     key,
		"model":   "abac",
	})
}

// updateABACPolicyHandler updates an existing ABAC policy
func (s *AuthService) updateABACPolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyId := vars["id"]

	var policy ABACPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	policy.ID = policyId
	policy.UpdatedAt = time.Now()

	// Update policy in database
	result := s.db.Save(&policy)
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Failed to update policy: %v", result.Error), http.StatusInternalServerError)
		return
	}

	// Update conditions
	s.db.Where("policy_id = ?", policyId).Delete(&PolicyCondition{})
	for _, condition := range policy.Conditions {
		condition.PolicyID = policyId
		s.db.Create(&condition)
	}

	// Reload policy engine cache
	s.policyEngine.LoadPolicies()

	response := map[string]interface{}{
		"message": "ABAC policy updated successfully",
		"policy":  policy,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// deleteRelationshipHandler removes a relationship
func (s *AuthService) deleteRelationshipHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	relationshipId := vars["id"]

	// Parse relationship ID format: "subject:relationship:object"
	parts := strings.Split(relationshipId, ":")
	if len(parts) != 3 {
		http.Error(w, "Relationship ID must be in format 'subject:relationship:object'", http.StatusBadRequest)
		return
	}

	subject, relationship, object := parts[0], parts[1], parts[2]

	// Remove from database
	result := s.db.Where("subject = ? AND relationship = ? AND object = ?", subject, relationship, object).Delete(&RelationshipRecord{})
	if result.Error != nil {
		http.Error(w, fmt.Sprintf("Failed to delete relationship: %v", result.Error), http.StatusInternalServerError)
		return
	}

	if result.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"removed": false,
			"message": "Relationship not found",
			"model":   "rebac",
		})
		return
	}

	// Remove from memory
	key := fmt.Sprintf("%s:%s", subject, relationship)
	if objects, exists := s.relationshipGraph.relationships[key]; exists {
		for i, obj := range objects {
			if obj.Object == object {
				s.relationshipGraph.relationships[key] = append(objects[:i], objects[i+1:]...)
				if len(s.relationshipGraph.relationships[key]) == 0 {
					delete(s.relationshipGraph.relationships, key)
				}
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"removed": true,
		"message": "Relationship removed successfully",
		"model":   "rebac",
	})
}

// findRelationshipPathHandler finds relationship paths
func (s *AuthService) findRelationshipPathHandler(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	object := r.URL.Query().Get("object")
	maxDepthStr := r.URL.Query().Get("max_depth")

	if subject == "" || object == "" {
		http.Error(w, "subject and object parameters are required", http.StatusBadRequest)
		return
	}

	maxDepth := 5
	if maxDepthStr != "" {
		if depth, err := strconv.Atoi(maxDepthStr); err == nil && depth > 0 {
			maxDepth = depth
		}
	}

	found, path := s.relationshipGraph.FindRelationshipPath(subject, object, maxDepth)

	response := map[string]interface{}{
		"found":     found,
		"path":      path,
		"subject":   subject,
		"object":    object,
		"max_depth": maxDepth,
		"model":     "rebac",
		"note":      "This endpoint shows relationship connectivity, not authorization. Use /api/v1/authorizations for permission checks.",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getRelationshipPermissionsHandler returns the permissions associated with relationships
func (s *AuthService) getRelationshipPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	relationshipType := r.URL.Query().Get("type")
	
	response := make(map[string]interface{})
	
	if relationshipType != "" {
		// Get permissions for specific relationship type
		permissions := s.relationshipGraph.GetPermissionsForRelationship(relationshipType)
		response["relationship"] = relationshipType
		response["permissions"] = permissions
		response["exists"] = len(permissions) > 0
	} else {
		// Get all relationship-permission mappings
		allMappings := make(map[string][]string)
		for relType, perms := range s.relationshipGraph.permissions {
			allMappings[relType] = perms
		}
		response["mappings"] = allMappings
		response["description"] = "Relationship types and their associated permissions"
	}
	
	response["model"] = "rebac"
	response["note"] = "These mappings define what permissions each relationship type grants"
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// checkRelationshipPermissionHandler checks if a relationship grants a specific permission
func (s *AuthService) checkRelationshipPermissionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Relationship string `json:"relationship"`
		Permission   string `json:"permission"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}
	
	if req.Relationship == "" || req.Permission == "" {
		http.Error(w, "relationship and permission fields are required", http.StatusBadRequest)
		return
	}
	
	hasPermission := s.relationshipGraph.HasPermissionThroughRelationship(req.Relationship, req.Permission)
	permissions := s.relationshipGraph.GetPermissionsForRelationship(req.Relationship)
	
	response := map[string]interface{}{
		"relationship":   req.Relationship,
		"permission":     req.Permission,
		"granted":        hasPermission,
		"all_permissions": permissions,
		"model":          "rebac",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// healthHandler provides a health check endpoint
func (s *AuthService) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":           "healthy",
		"service":          "multi-model-casbin-auth-service",
		"supported_models": []string{"acl", "rbac", "abac", "rebac"},
		"default_model":    "rbac",
		"database":         "sqlite",
		"version":          "2.0.0",
		"rebac_features":   []string{"ownership", "hierarchy", "groups", "social"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// corsMiddleware adds CORS headers to responses
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs incoming HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.RequestURI, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// main initializes and starts the authorization microservice
func main() {
	// Initialize authorization service
	authService, err := NewAuthService()
	if err != nil {
		log.Fatalf("Failed to initialize authorization service: %v", err)
	}

	// Set up initial data
	err = authService.initializeData()
	if err != nil {
		log.Printf("Failed to set up initial data: %v", err)
	}

	// Set up router
	router := mux.NewRouter()

	// Define API endpoints
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/health", authService.healthHandler).Methods("GET")
	api.HandleFunc("/models", authService.getModelsHandler).Methods("GET")
	
	// Authorization endpoint
	api.HandleFunc("/authorizations", authService.authorizationHandler).Methods("POST")

	// ACL Policy endpoints
	api.HandleFunc("/acl/policies", authService.addACLPolicyHandler).Methods("POST")
	api.HandleFunc("/acl/policies", authService.getACLPoliciesHandler).Methods("GET")
	api.HandleFunc("/acl/policies/{id}", authService.deleteACLPolicyHandler).Methods("DELETE")

	// RBAC Policy endpoints
	api.HandleFunc("/rbac/policies", authService.addRBACPolicyHandler).Methods("POST")
	api.HandleFunc("/rbac/policies", authService.getRBACPoliciesHandler).Methods("GET")
	api.HandleFunc("/rbac/policies/{id}", authService.deleteRBACPolicyHandler).Methods("DELETE")

	// User role endpoints
	api.HandleFunc("/users/{userId}/roles", authService.addUserRoleHandler).Methods("POST")
	api.HandleFunc("/users/{userId}/roles", authService.getUserRolesHandler).Methods("GET")
	api.HandleFunc("/users/{userId}/roles/{roleId}", authService.deleteUserRoleHandler).Methods("DELETE")

	// User attributes endpoints
	api.HandleFunc("/users/{userId}/attributes", authService.setUserAttributesHandler).Methods("PUT")
	api.HandleFunc("/users/{userId}/attributes", authService.getUserAttributesHandler).Methods("GET")
	api.HandleFunc("/users/{userId}/attributes/{key}", authService.deleteUserAttributeHandler).Methods("DELETE")

	// Object attributes endpoints
	api.HandleFunc("/objects/{objectId}/attributes", authService.setObjectAttributesHandler).Methods("PUT")
	api.HandleFunc("/objects/{objectId}/attributes", authService.getObjectAttributesHandler).Methods("GET")
	api.HandleFunc("/objects/{objectId}/attributes/{key}", authService.deleteObjectAttributeHandler).Methods("DELETE")

	// ABAC Policy Management endpoints
	api.HandleFunc("/abac/policies", authService.addABACPolicyHandler).Methods("POST")
	api.HandleFunc("/abac/policies", authService.getABACPoliciesHandler).Methods("GET")
	api.HandleFunc("/abac/policies/{id}", authService.getABACPolicyHandler).Methods("GET")
	api.HandleFunc("/abac/policies/{id}", authService.updateABACPolicyHandler).Methods("PUT")
	api.HandleFunc("/abac/policies/{id}", authService.deleteABACPolicyHandler).Methods("DELETE")

	// ReBAC relationship endpoints
	api.HandleFunc("/relationships", authService.addRelationshipHandler).Methods("POST")
	api.HandleFunc("/relationships", authService.getRelationshipsHandler).Methods("GET")
	api.HandleFunc("/relationships/{id}", authService.deleteRelationshipHandler).Methods("DELETE")
	api.HandleFunc("/relationships/paths", authService.findRelationshipPathHandler).Methods("GET")
	
	// ReBAC permission mapping endpoints (following best practices)
	api.HandleFunc("/relationships/permissions", authService.getRelationshipPermissionsHandler).Methods("GET")
	api.HandleFunc("/relationships/permissions/check", authService.checkRelationshipPermissionHandler).Methods("POST")

	// Apply middleware
	router.Use(corsMiddleware)
	router.Use(loggingMiddleware)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("Starting authorization microservice with ACL, RBAC, ABAC, and ReBAC support on port %s", addr)
	log.Printf("Supported models: ACL, RBAC, ABAC, ReBAC")
	log.Printf("API Documentation:")
	log.Printf("  GET  /api/v1/health - Health check")
	log.Printf("  GET  /api/v1/models - List supported models")
	log.Printf("  POST /api/v1/enforce - Authorization check (all models)")
	log.Printf("  POST /api/v1/policies - Add policy (ACL/RBAC/ABAC)")
	log.Printf("  DELETE /api/v1/policies - Remove policy (ACL/RBAC/ABAC)")
	log.Printf("  GET  /api/v1/policies?model=<acl|rbac|abac> - Get policies")
	log.Printf("  POST /api/v1/roles - Add user role (RBAC only)")
	log.Printf("  GET  /api/v1/users/roles?user=alice - Get user roles (RBAC only)")
	log.Printf("  POST /api/v1/users/attributes - Set user attributes (ABAC only)")
	log.Printf("  GET  /api/v1/users/attributes?user=alice - Get user attributes (ABAC only)")
	log.Printf("  POST /api/v1/objects/attributes - Set object attributes (ABAC only)")
	log.Printf("  GET  /api/v1/objects/attributes?object=document1 - Get object attributes (ABAC only)")
	log.Printf("  POST /api/v1/abac/policies - Add ABAC policy (ABAC only)")
	log.Printf("  DELETE /api/v1/abac/policies - Remove ABAC policy (ABAC only)")
	log.Printf("  GET  /api/v1/abac/policies - Get all ABAC policies (ABAC only)")
	log.Printf("  GET  /api/v1/abac/policies/{id} - Get specific ABAC policy (ABAC only)")
	log.Printf("  POST /api/v1/relationships - Add relationship (ReBAC only)")
	log.Printf("  DELETE /api/v1/relationships - Remove relationship (ReBAC only)")
	log.Printf("  GET  /api/v1/relationships?subject=alice - Get relationships (ReBAC only)")
	log.Printf("  GET  /api/v1/relationships/path?subject=alice&object=document1 - Find relationship path (ReBAC only)")

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
