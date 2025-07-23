package services

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"your_project/internal/core/domain"
	"your_project/internal/core/ports/driven"
	"your_project/internal/core/ports/driving"
)

// ReBACEnforcerImpl implements the ReBACEnforcer interface.
type ReBACEnforcerImpl struct {
	repo driven.ReBACRepository
	// In-memory graph for efficient lookups
	relationships map[string][]domain.Relationship // Key: subject:relationshipType
	permissions   map[string][]string             // Relationship type to permissions mapping
	mu            sync.RWMutex
}

// NewReBACEnforcerImpl creates a new ReBACEnforcerImpl.
func NewReBACEnforcerImpl(repo driven.ReBACRepository) driving.ReBACEnforcer {
	e := &ReBACEnforcerImpl{
		repo:          repo,
		relationships: make(map[string][]domain.Relationship),
		permissions:   make(map[string][]string),
	}
	// Initialize default permissions
	e.initializeDefaultPermissions()
	// Load existing relationships from database on startup
	err := e.loadFromDatabase()
	if err != nil {
		fmt.Printf("Failed to load ReBAC relationships on startup: %v\n", err)
	}
	return e
}

// loadFromDatabase loads all relationships from the database into memory
func (e *ReBACEnforcerImpl) loadFromDatabase() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	records, err := e.repo.LoadAllRelationships()
	if err != nil {
		return err
	}

	// Clear existing relationships
	e.relationships = make(map[string][]domain.Relationship)

	// Load relationships into memory
	for _, rel := range records {
		key := fmt.Sprintf("%s:%s", rel.Subject, rel.Relationship)
		e.relationships[key] = append(e.relationships[key], rel)

		// Store reverse relationship for graph traversal
		reverseKey := fmt.Sprintf("%s:reverse_%s", rel.Object, rel.Relationship)
		e.relationships[reverseKey] = append(e.relationships[reverseKey], domain.Relationship{
			Subject:      rel.Object,
			Relationship: "reverse_" + rel.Relationship,
			Object:       rel.Subject,
		})
	}

	return nil
}

// initializeDefaultPermissions sets up the default relationship-to-permission mappings
func (e *ReBACEnforcerImpl) initializeDefaultPermissions() {
	// Owner relationship grants all permissions
	e.permissions["owner"] = []string{"read", "write", "delete", "admin"}

	// Editor relationship grants read and write permissions
	e.permissions["editor"] = []string{"read", "write", "edit"}

	// Viewer relationship grants read-only permission
	e.permissions["viewer"] = []string{"read", "view"}

	// Member relationship inherits permissions from the group
	e.permissions["member"] = []string{"inherit"}

	// Group access relationship defines what groups can access
	e.permissions["group_access"] = []string{"read", "write"}

	// Parent relationship allows inheritance of permissions
	e.permissions["parent"] = []string{"inherit"}

	// Friend relationship grants limited read access
	e.permissions["friend"] = []string{"read_limited"}

	// Manager relationship grants administrative permissions
	e.permissions["manager"] = []string{"read", "write", "delete", "manage"}
}

// GetRelationshipPermissions returns the permissions associated with a relationship type
func (e *ReBACEnforcerImpl) GetRelationshipPermissions() (map[string][]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// Return a copy to prevent external modification
	copyMap := make(map[string][]string)
	for k, v := range e.permissions {
		copyMap[k] = append([]string{}, v...)
	}
	return copyMap, nil
}

// CheckRelationshipPermission checks if a relationship grants a specific permission
func (e *ReBACEnforcerImpl) CheckRelationshipPermission(relationship, permission string) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	perms, exists := e.permissions[relationship]
	if !exists {
		return false, nil
	}
	for _, perm := range perms {
		if perm == permission || perm == "admin" {
			return true, nil
		}
	}
	return false, nil
}

// AddRelationship adds a new relationship to the graph and persists it to database
func (e *ReBACEnforcerImpl) AddRelationship(subject, relationship, object string) error {
	// Save to database first
	err := e.repo.AddRelationship(subject, relationship, object)
	if err != nil {
		return fmt.Errorf("failed to save relationship to repository: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	rel := domain.Relationship{
		Subject:      subject,
		Relationship: relationship,
		Object:       object,
	}

	key := fmt.Sprintf("%s:%s", subject, relationship)
	e.relationships[key] = append(e.relationships[key], rel)

	// Store reverse relationship for graph traversal
	reverseKey := fmt.Sprintf("%s:reverse_%s", object, relationship)
	e.relationships[reverseKey] = append(e.relationships[reverseKey], domain.Relationship{
		Subject:      object,
		Relationship: "reverse_" + relationship,
		Object:       subject,
	})

	return nil
}

// RemoveRelationship removes a relationship from the graph and database
func (e *ReBACEnforcerImpl) RemoveRelationship(subject, relationship, object string) error {
	// Remove from database first
	err := e.repo.RemoveRelationship(subject, relationship, object)
	if err != nil {
		return fmt.Errorf("failed to remove relationship from repository: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	key := fmt.Sprintf("%s:%s", subject, relationship)
	relationships := e.relationships[key]

	for i, rel := range relationships {
		if rel.Object == object {
			e.relationships[key] = append(relationships[:i], relationships[i+1:]...)
			break
		}
	}

	// Remove reverse relationship as well
	reverseKey := fmt.Sprintf("%s:reverse_%s", object, relationship)
	reverseRelationships := e.relationships[reverseKey]

	for i, rel := range reverseRelationships {
		if rel.Object == subject {
			e.relationships[reverseKey] = append(reverseRelationships[:i], reverseRelationships[i+1:]...)
			break
		}
	}

	return nil
}

// GetRelationships retrieves relationships for a given subject (or all if subject is empty)
func (e *ReBACEnforcerImpl) GetRelationships(subject string) ([]domain.Relationship, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []domain.Relationship
	if subject != "" {
		for key, rels := range e.relationships {
			parts := strings.Split(key, ":")
			if len(parts) == 2 && parts[0] == subject && !strings.HasPrefix(parts[1], "reverse_") {
				result = append(result, rels...)
			}
		}
	} else {
		// Get all relationships (excluding reverse ones)
		for key, rels := range e.relationships {
			parts := strings.Split(key, ":")
			if len(parts) == 2 && !strings.HasPrefix(parts[1], "reverse_") {
				result = append(result, rels...)
			}
		}
	}
	return result, nil
}

// FindRelationshipPath searches for a relationship path using breadth-first search
func (e *ReBACEnforcerImpl) FindRelationshipPath(subject, targetObject string, maxDepth int) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

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

		// Check all relationships originating from the current node
		for key, relationships := range e.relationships {
			parts := strings.Split(key, ":")
			if len(parts) != 2 || parts[0] != current.node {
				continue
			}

			relationshipType := parts[1]
			if strings.HasPrefix(relationshipType, "reverse_") {
				continue // Exclude reverse relationships for path finding
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

// Enforce checks access permissions using ReBAC rules
func (e *ReBACEnforcerImpl) Enforce(subject, object, action string) (bool, string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Map common actions to standardized permissions
	permission := e.mapActionToPermission(action)

	// 1. Check all direct relationships and their associated permissions
	directRelationships := e.getDirectRelationships(subject, object)
	for _, rel := range directRelationships {
		if e.hasPermissionThroughRelationship(rel.Relationship, permission) {
			return true, fmt.Sprintf("%s -[%s]-> %s", subject, rel.Relationship, object), nil
		}
	}

	// 2. Check access through group membership (indirect relationships)
	groupAccess, groupPath := e.checkGroupAccess(subject, object, permission)
	if groupAccess {
		return true, groupPath, nil
	}

	// 3. Check hierarchical access (parent-child relationships)
	hierarchicalAccess, hierarchicalPath := e.checkHierarchicalAccess(subject, object, permission)
	if hierarchicalAccess {
		return true, hierarchicalPath, nil
	}

	// 4. Check social relationships for limited access
	if permission == "read" || permission == "read_limited" {
		socialAccess, socialPath := e.checkSocialAccess(subject, object, 3)
		if socialAccess {
			return true, socialPath, nil
		}
	}

	return false, "", nil
}

// mapActionToPermission maps action strings to standardized permissions
func (e *ReBACEnforcerImpl) mapActionToPermission(action string) string {
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

// getDirectRelationships returns all direct relationships between subject and object
func (e *ReBACEnforcerImpl) getDirectRelationships(subject, object string) []domain.Relationship {
	var relationships []domain.Relationship

	for key, rels := range e.relationships {
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

// hasPermissionThroughRelationship checks if a relationship grants a specific permission
func (e *ReBACEnforcerImpl) hasPermissionThroughRelationship(relationship, permission string) bool {
	perms := e.permissions[relationship]
	for _, perm := range perms {
		if perm == permission || perm == "admin" {
			return true
		}
	}
	return false
}

// checkGroupAccess checks if subject has access through group membership
func (e *ReBACEnforcerImpl) checkGroupAccess(subject, object, permission string) (bool, string) {
	// Find all groups the subject is a member of
	memberKey := fmt.Sprintf("%s:member", subject)
	if groups, exists := e.relationships[memberKey]; exists {
		for _, groupRel := range groups {
			groupName := groupRel.Object

			// Check if the group has the required permission on the object
			groupRelationships := e.getDirectRelationships(groupName, object)
			for _, rel := range groupRelationships {
				if e.hasPermissionThroughRelationship(rel.Relationship, permission) {
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
func (e *ReBACEnforcerImpl) checkHierarchicalAccess(subject, object, permission string) (bool, string) {
	// Find parent objects
	for key, relationships := range e.relationships {
		parts := strings.Split(key, ":")
		if len(parts) != 2 || parts[1] != "parent" {
			continue
		}

		parentObject := parts[0]
		for _, rel := range relationships {
			if rel.Object == object {
				// Recursively check if subject has access to parent
				hasAccess, parentPath, _ := e.Enforce(subject, parentObject, permission)
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
func (e *ReBACEnforcerImpl) checkSocialAccess(subject, object string, maxDepth int) (bool, string) {
	found, path := e.FindRelationshipPath(subject, object, maxDepth)
	if found && strings.Contains(path, "friend") {
		// Verify that the friend relationship grants the required permission
		if e.hasPermissionThroughRelationship("friend", "read_limited") {
			return true, path
		}
	}
	return false, ""
}
