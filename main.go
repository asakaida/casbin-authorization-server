package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	}

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
func (rg *RelationshipGraph) CheckReBACAccess(subject, object, action string) (bool, string) {
	// 1. Check direct ownership
	if rg.HasDirectRelationship(subject, "owner", object) {
		return true, fmt.Sprintf("%s -[owner]-> %s", subject, object)
	}

	// 2. Check editor permissions
	if action == "write" || action == "edit" {
		if rg.HasDirectRelationship(subject, "editor", object) {
			return true, fmt.Sprintf("%s -[editor]-> %s", subject, object)
		}
	}

	// 3. Check read permissions
	if action == "read" {
		if rg.HasDirectRelationship(subject, "viewer", object) {
			return true, fmt.Sprintf("%s -[viewer]-> %s", subject, object)
		}
	}

	// 4. Check access through group membership
	for key, relationships := range rg.relationships {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || parts[0] != subject || parts[1] != "member" {
			continue
		}

		for _, rel := range relationships {
			groupName := rel.Object
			// Check if the group has access to the target object
			if rg.HasDirectRelationship(groupName, "group_access", object) {
				path := fmt.Sprintf("%s -[member]-> %s -[group_access]-> %s", subject, groupName, object)
				return true, path
			}
		}
	}

	// 5. Check hierarchical access (parent-child relationship)
	for key, relationships := range rg.relationships {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || parts[1] != "parent" {
			continue
		}

		parentObject := parts[0]
		for _, rel := range relationships {
			if rel.Object == object {
				// Check if there's access to the parent object
				hasAccess, parentPath := rg.CheckReBACAccess(subject, parentObject, action)
				if hasAccess {
					path := fmt.Sprintf("%s -> %s -[parent]-> %s", parentPath, parentObject, object)
					return true, path
				}
			}
		}
	}

	// 6. Check access through friend relationships (social features)
	if action == "read" {
		found, path := rg.FindRelationshipPath(subject, object, 3)
		if found && strings.Contains(path, "friend") {
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

	// Auto-migrate ABAC attribute tables
	err = db.AutoMigrate(&UserAttribute{}, &ObjectAttribute{})
	if err != nil {
		return nil, fmt.Errorf("failed to migrate ABAC attribute tables: %v", err)
	}

	// Create relationship graph with database persistence
	relationshipGraph, err := NewRelationshipGraph(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create relationship graph: %v", err)
	}

	service := &AuthService{
		aclEnforcer:       aclEnforcer,
		rbacEnforcer:      rbacEnforcer,
		abacEnforcer:      abacEnforcer,
		userAttrs:         make(map[string]map[string]string),
		objectAttrs:       make(map[string]map[string]string),
		relationshipGraph: relationshipGraph,
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

	// Initial data for ABAC (attribute-based)
	// Only add if no user attributes exist in database (first run)
	var userAttrCount int64
	s.db.Model(&UserAttribute{}).Count(&userAttrCount)
	if userAttrCount == 0 {
		// Alice attributes
		s.saveUserAttribute("alice", "department", "hr")
		s.saveUserAttribute("alice", "position", "manager")
		s.saveUserAttribute("alice", "clearance", "high")

		// Bob attributes
		s.saveUserAttribute("bob", "department", "engineering")
		s.saveUserAttribute("bob", "position", "developer")
		s.saveUserAttribute("bob", "clearance", "medium")

		// Charlie attributes
		s.saveUserAttribute("charlie", "department", "sales")
		s.saveUserAttribute("charlie", "position", "representative")
		s.saveUserAttribute("charlie", "clearance", "low")

		// Object attributes
		s.saveObjectAttribute("confidential_data", "classification", "confidential")
		s.saveObjectAttribute("confidential_data", "department", "hr")
		s.saveObjectAttribute("confidential_data", "sensitivity", "high")

		s.saveObjectAttribute("public_data", "classification", "public")
		s.saveObjectAttribute("public_data", "department", "all")
		s.saveObjectAttribute("public_data", "sensitivity", "low")
	}

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

	return nil
}

// matchABACAttributes checks if the subject's attributes match the access requirements
func (s *AuthService) matchABACAttributes(subject, object, action string, reqAttrs map[string]string) bool {
	// Get user attributes
	userAttrs := s.userAttrs[subject]
	if userAttrs == nil {
		userAttrs = make(map[string]string)
	}

	// Merge request attributes
	for k, v := range reqAttrs {
		userAttrs[k] = v
	}

	// Get object attributes
	objectAttrs := s.objectAttrs[object]
	if objectAttrs == nil {
		objectAttrs = make(map[string]string)
	}

	// Environment attributes
	envAttrs := map[string]string{
		"time":     strconv.Itoa(time.Now().Hour()),
		"location": "office",
		"device":   "trusted",
	}

	// Simple rule-based checks
	// 1. High clearance level can access everything
	if userAttrs["clearance"] == "high" {
		return true
	}

	// 2. Same department resources are accessible
	if userAttrs["department"] == objectAttrs["department"] {
		return true
	}

	// 3. Public data is readable by everyone
	if objectAttrs["classification"] == "public" && action == "read" {
		return true
	}

	// 4. Confidential data only accessible during business hours (9-18)
	currentHour, _ := strconv.Atoi(envAttrs["time"])
	if objectAttrs["classification"] == "confidential" {
		return currentHour >= 9 && currentHour <= 18
	}

	return false
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
	var req AttributeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Save each attribute to database and update cache
	for k, v := range req.Attributes {
		err := s.saveUserAttribute(req.Subject, k, v)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to save user attribute: %v", err), http.StatusInternalServerError)
			return
		}
	}

	response := map[string]interface{}{
		"message":    "User attributes set successfully",
		"subject":    req.Subject,
		"attributes": s.userAttrs[req.Subject],
		"model":      "abac",
	}

	w.Header().Set("Content-Type", "application/json")
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
	user := r.URL.Query().Get("user")
	if user == "" {
		http.Error(w, "user parameter is required", http.StatusBadRequest)
		return
	}

	roles, err := s.rbacEnforcer.GetRolesForUser(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Role retrieval error: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user":  user,
		"roles": roles,
		"model": "rbac",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *AuthService) getUserAttributesHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		http.Error(w, "user parameter is required", http.StatusBadRequest)
		return
	}

	// Get attributes from database (ensures consistency)
	attributes, err := s.getUserAttributesFromDB(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve user attributes: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user":       user,
		"attributes": attributes,
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
	api.HandleFunc("/enforce", authService.enforceHandler).Methods("POST")

	// Endpoints for traditional models
	api.HandleFunc("/policies", authService.addPolicyHandler).Methods("POST")
	api.HandleFunc("/policies", authService.removePolicyHandler).Methods("DELETE")
	api.HandleFunc("/policies", authService.getPoliciesHandler).Methods("GET")
	api.HandleFunc("/roles", authService.addRoleHandler).Methods("POST")
	api.HandleFunc("/users/roles", authService.getUserRolesHandler).Methods("GET")
	api.HandleFunc("/users/attributes", authService.setUserAttributesHandler).Methods("POST")
	api.HandleFunc("/users/attributes", authService.getUserAttributesHandler).Methods("GET")

	// ReBAC-specific endpoints
	api.HandleFunc("/relationships", authService.addRelationshipHandler).Methods("POST")
	api.HandleFunc("/relationships", authService.removeRelationshipHandler).Methods("DELETE")
	api.HandleFunc("/relationships", authService.getRelationshipsHandler).Methods("GET")
	api.HandleFunc("/relationships/path", authService.findPathHandler).Methods("GET")

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
	log.Printf("  POST /api/v1/relationships - Add relationship (ReBAC only)")
	log.Printf("  DELETE /api/v1/relationships - Remove relationship (ReBAC only)")
	log.Printf("  GET  /api/v1/relationships?subject=alice - Get relationships (ReBAC only)")
	log.Printf("  GET  /api/v1/relationships/path?subject=alice&object=document1 - Find relationship path (ReBAC only)")

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
