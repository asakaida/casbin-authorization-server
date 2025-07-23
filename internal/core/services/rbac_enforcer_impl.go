package services

import (
	"your_project/internal/core/ports/driven"
	"your_project/internal/core/ports/driving"
)

// RBACEnforcerImpl implements the RBACEnforcer interface.
type RBACEnforcerImpl struct {
	repo driven.RBACPolicyRepository
}

// NewRBACEnforcerImpl creates a new RBACEnforcerImpl.
func NewRBACEnforcerImpl(repo driven.RBACPolicyRepository) driving.RBACEnforcer {
	return &RBACEnforcerImpl{repo: repo}
}

func (e *RBACEnforcerImpl) AddPolicy(subject, object, action string) (bool, error) {
	return e.repo.AddPolicy(subject, object, action)
}

func (e *RBACEnforcerImpl) RemovePolicy(subject, object, action string) (bool, error) {
	return e.repo.RemovePolicy(subject, object, action)
}

func (e *RBACEnforcerImpl) GetPolicy() ([][]string, error) {
	return e.repo.GetPolicy()
}

func (e *RBACEnforcerImpl) AddRoleForUser(user, role string) (bool, error) {
	return e.repo.AddRoleForUser(user, role)
}

func (e *RBACEnforcerImpl) RemoveRoleForUser(user, role string) (bool, error) {
	return e.repo.RemoveRoleForUser(user, role)
}

func (e *RBACEnforcerImpl) GetRolesForUser(user string) ([]string, error) {
	return e.repo.GetRolesForUser(user)
}

func (e *RBACEnforcerImpl) Enforce(subject, object, action string) (bool, error) {
	// This is a simplified enforcement. In a real Casbin setup, this would involve
	// querying roles and policies. For now, we'll simulate based on direct policies
	// and roles for the subject.

	// Check direct policies
	policies, err := e.repo.GetPolicy()
	if err != nil {
		return false, err
	}
	for _, p := range policies {
		if len(p) == 3 && p[0] == subject && p[1] == object && p[2] == action {
			return true, nil
		}
	}

	// Check roles
	roles, err := e.repo.GetRolesForUser(subject)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		// Check policies for each role
		for _, p := range policies {
			if len(p) == 3 && p[0] == role && p[1] == object && p[2] == action {
				return true, nil
			}
		}
	}

	return false, nil
}
