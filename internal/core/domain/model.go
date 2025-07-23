package domain

import (
	"fmt"
	"time"
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

// EnforceResponse represents the response for an enforcement request
type EnforceResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
	Model   string `json:"model"`
	Path    string `json:"path,omitempty"` // ReBAC: relationship path for access permission
}

// PolicyRequest represents a policy management request (for ACL/RBAC)
type PolicyRequest struct {
	Subject string `json:"subject"`
	Object  string `json:"object"`
	Action  string `json:"action"`
}

// RoleRequest represents a role assignment request (for RBAC)
type RoleRequest struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// AttributeRequest represents an attribute assignment request (for ABAC)
type AttributeRequest struct {
	Subject    string            `json:"subject"`
	Attributes map[string]string `json:"attributes"`
}

// RelationshipRequest represents a relationship request (for ReBAC)
type RelationshipRequest struct {
	Subject      string `json:"subject"`
	Relationship string `json:"relationship"`
	Object       string `json:"object"`
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

// PolicyCondition represents a condition within an ABAC policy
type PolicyCondition struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	PolicyID string `json:"policy_id" gorm:"index"`
	Type     string `json:"type"`     // "user", "object", "environment", "action"
	Field    string `json:"field"`    // attribute name
	Operator string `json:"operator"` // "eq", "ne", "gt", "gte", "lt", "lte", "in", "contains", "startswith", "endswith", "regex"
	Value    string `json:"value"`    // comparison value
	LogicOp  string `json:"logic_op"` // "and", "or" (for combining with next condition)
}

// Relationship represents a relationship in the ReBAC graph
type Relationship struct {
	Subject      string `json:"subject"`
	Relationship string `json:"relationship"`
	Object       string `json:"object"`
}

// ReBACPermissionMapping defines the permissions associated with a relationship type
type ReBACPermissionMapping struct {
	Relationship string   `json:"relationship"`
	Permissions  []string `json:"permissions"`
}

// Validate checks if the ABACPolicy is valid
func (p *ABACPolicy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("policy ID cannot be empty")
	}
	if p.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	if p.Effect != "allow" && p.Effect != "deny" {
		return fmt.Errorf("policy effect must be 'allow' or 'deny'")
	}
	for i, cond := range p.Conditions {
		if cond.Type == "" || cond.Field == "" || cond.Operator == "" || cond.Value == "" {
			return fmt.Errorf("condition %d: type, field, operator, and value cannot be empty", i)
		}
		if cond.LogicOp != "" && cond.LogicOp != "and" && cond.LogicOp != "or" {
			return fmt.Errorf("condition %d: logic_op must be 'and' or 'or' or empty", i)
		}
	}
	return nil
}
