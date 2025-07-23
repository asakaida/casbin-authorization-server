package services

import (
	"your_project/internal/core/ports/driven"
	"your_project/internal/core/ports/driving"
)

// ACLEnforcerImpl implements the ACLEnforcer interface.
type ACLEnforcerImpl struct {
	repo driven.ACLPolicyRepository
}

// NewACLEnforcerImpl creates a new ACLEnforcerImpl.
func NewACLEnforcerImpl(repo driven.ACLPolicyRepository) driving.ACLEnforcer {
	return &ACLEnforcerImpl{repo: repo}
}

func (e *ACLEnforcerImpl) AddPolicy(subject, object, action string) (bool, error) {
	return e.repo.AddPolicy(subject, object, action)
}

func (e *ACLEnforcerImpl) RemovePolicy(subject, object, action string) (bool, error) {
	return e.repo.RemovePolicy(subject, object, action)
}

func (e *ACLEnforcerImpl) GetPolicy() ([][]string, error) {
	return e.repo.GetPolicy()
}

func (e *ACLEnforcerImpl) Enforce(subject, object, action string) (bool, error) {
	// In a real Casbin setup, this would call the Casbin enforcer's Enforce method.
	// For now, we'll simulate it based on existing policies.
	policies, err := e.repo.GetPolicy()
	if err != nil {
		return false, err
	}

	for _, p := range policies {
		if len(p) == 3 && p[0] == subject && p[1] == object && p[2] == action {
			return true, nil
		}
	}
	return false, nil
}
