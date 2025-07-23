package services

import (
	"fmt"
	"your_project/internal/core/domain"
	"your_project/internal/core/ports/driving"
)

// AuthorizationServiceImpl implements the generic AuthorizationService interface.
// It holds references to the *enabled* specific enforcers.
type AuthorizationServiceImpl struct {
	aclEnforcer   driving.ACLEnforcer
	rbacEnforcer  driving.RBACEnforcer
	abacEnforcer  driving.ABACEnforcer
	rebacEnforcer driving.ReBACEnforcer
}

// NewAuthorizationServiceImpl creates a new AuthorizationServiceImpl.
// It takes *optional* enforcers. If an enforcer is nil, that model is considered disabled.
func NewAuthorizationServiceImpl(
	acl driving.ACLEnforcer,
	rbac driving.RBACEnforcer,
	abac driving.ABACEnforcer,
	rebac driving.ReBACEnforcer,
) driving.AuthorizationService {
	return &AuthorizationServiceImpl{
		aclEnforcer:   acl,
		rbacEnforcer:  rbac,
		abacEnforcer:  abac,
		rebacEnforcer: rebac,
	}
}

func (s *AuthorizationServiceImpl) Enforce(model domain.AccessControlModel, subject, object, action string, attributes map[string]string) (bool, error) {
	switch model {
	case domain.ModelACL:
		if s.aclEnforcer == nil {
			return false, domain.ErrServiceUnavailable
		}
		return s.aclEnforcer.Enforce(subject, object, action)
	case domain.ModelRBAC:
		if s.rbacEnforcer == nil {
			return false, domain.ErrServiceUnavailable
		}
		return s.rbacEnforcer.Enforce(subject, object, action)
	case domain.ModelABAC:
		if s.abacEnforcer == nil {
			return false, domain.ErrServiceUnavailable
		}
		return s.abacEnforcer.Enforce(subject, object, action, attributes)
	case domain.ModelReBAC:
		if s.rebacEnforcer == nil {
			return false, domain.ErrServiceUnavailable
		}
		allowed, _, err := s.rebacEnforcer.Enforce(subject, object, action)
		return allowed, err
	default:
		return false, fmt.Errorf("invalid model specified: %s", model)
	}
}

// GetACLEnforcer returns the ACL enforcer. Used by HTTP/gRPC handlers.
func (s *AuthorizationServiceImpl) GetACLEnforcer() driving.ACLEnforcer {
	return s.aclEnforcer
}

// GetRBACEnforcer returns the RBAC enforcer. Used by HTTP/gRPC handlers.
func (s *AuthorizationServiceImpl) GetRBACEnforcer() driving.RBACEnforcer {
	return s.rbacEnforcer
}

// GetABACEnforcer returns the ABAC enforcer. Used by HTTP/gRPC handlers.
func (s *AuthorizationServiceImpl) GetABACEnforcer() driving.ABACEnforcer {
	return s.abacEnforcer
}

// GetReBACEnforcer returns the ReBAC enforcer. Used by HTTP/gRPC handlers.
func (s *AuthorizationServiceImpl) GetReBACEnforcer() driving.ReBACEnforcer {
	return s.rebacEnforcer
}
