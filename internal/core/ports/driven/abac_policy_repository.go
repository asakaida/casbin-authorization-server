package driven

import (
	"your_project/internal/core/domain"
)

// ABACPolicyRepository defines the interface for ABAC policy persistence.
type ABACPolicyRepository interface {
	AddPolicy(policy *domain.ABACPolicy) error
	RemovePolicy(policyID string) error
	GetPolicyByID(policyID string) (*domain.ABACPolicy, error)
	GetAllPolicies() ([]*domain.ABACPolicy, error)
	UpdatePolicy(policy *domain.ABACPolicy) error
}
