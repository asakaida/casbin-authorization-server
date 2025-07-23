package driving

import (
	"your_project/internal/core/domain"
)

// AuthorizationService defines the generic authorization interface.
// This is primarily for the /authorizations endpoint that takes a model type.
type AuthorizationService interface {
	Enforce(model domain.AccessControlModel, subject, object, action string, attributes map[string]string) (bool, error)
}

// ACLEnforcer defines the interface for ACL-specific operations.
type ACLEnforcer interface {
	AddPolicy(subject, object, action string) (bool, error)
	RemovePolicy(subject, object, action string) (bool, error)
	GetPolicy() ([][]string, error)
	Enforce(subject, object, action string) (bool, error)
}

// RBACEnforcer defines the interface for RBAC-specific operations.
type RBACEnforcer interface {
	AddPolicy(subject, object, action string) (bool, error)
	RemovePolicy(subject, object, action string) (bool, error)
	GetPolicy() ([][]string, error)
	AddRoleForUser(user, role string) (bool, error)
	RemoveRoleForUser(user, role string) (bool, error)
	GetRolesForUser(user string) ([]string, error)
	Enforce(subject, object, action string) (bool, error)
}

// ABACEnforcer defines the interface for ABAC-specific operations.
type ABACEnforcer interface {
	AddPolicy(policy *domain.ABACPolicy) error
	RemovePolicy(policyID string) error
	GetPolicyByID(policyID string) (*domain.ABACPolicy, error)
	GetAllPolicies() ([]*domain.ABACPolicy, error)
	UpdatePolicy(policy *domain.ABACPolicy) error
	SetUserAttributes(userID string, attributes map[string]string) error
	GetUserAttributes(userID string) (map[string]string, error)
	RemoveUserAttribute(userID, attributeKey string) error
	SetObjectAttributes(objectID string, attributes map[string]string) error
	GetObjectAttributes(objectID string) (map[string]string, error)
	RemoveObjectAttribute(objectID, attributeKey string) error
	Enforce(subject, object, action string, attributes map[string]string) (bool, error)
}

// ReBACEnforcer defines the interface for ReBAC-specific operations.
type ReBACEnforcer interface {
	AddRelationship(subject, relationship, object string) error
	RemoveRelationship(subject, relationship, object string) error
	GetRelationships(subject string) ([]domain.Relationship, error)
	FindRelationshipPath(subject, targetObject string, maxDepth int) (bool, string) // Returns found, path
	GetRelationshipPermissions() (map[string][]string, error)
	CheckRelationshipPermission(relationship, permission string) (bool, error)
	Enforce(subject, object, action string) (bool, string, error) // Returns allowed, path, error
}
