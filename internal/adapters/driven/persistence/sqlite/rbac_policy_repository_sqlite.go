package sqlite

import (
	"fmt"
	"your_project/internal/core/ports/driven"

	"gorm.io/gorm"
)

// RBACRule represents a row in the rbac_rules table
type RBACRule struct {
	ID    uint   `gorm:"primaryKey"`
	PType string `gorm:"size:100"` // "p" for policies, "g" for role assignments
	V0    string `gorm:"size:100"`
	V1    string `gorm:"size:100"`
	V2    string `gorm:"size:100"`
	V3    string `gorm:"size:100"`
	V4    string `gorm:"size:100"`
	V5    string `gorm:"size:100"`
}

// RBACPolicyRepositoryImpl implements driven.RBACPolicyRepository for SQLite.
type RBACPolicyRepositoryImpl struct {
	db *gorm.DB
}

// NewRBACPolicyRepository creates a new RBACPolicyRepositoryImpl.
func NewRBACPolicyRepository(db *gorm.DB) driven.RBACPolicyRepository {
	// Auto-migrate the table
	err := db.AutoMigrate(&RBACRule{})
	if err != nil {
		panic(fmt.Sprintf("failed to migrate RBACRule table: %v", err))
	}
	return &RBACPolicyRepositoryImpl{db: db}
}

func (r *RBACPolicyRepositoryImpl) AddPolicy(subject, object, action string) (bool, error) {
	rule := RBACRule{PType: "p", V0: subject, V1: object, V2: action}
	// Check if policy already exists
	var existingRule RBACRule
	res := r.db.Where(&rule).First(&existingRule)
	if res.Error == nil {
		return false, nil // Policy already exists
	}

	result := r.db.Create(&rule)
	if result.Error != nil {
		return false, result.Error
	}
	return true, nil
}

func (r *RBACPolicyRepositoryImpl) RemovePolicy(subject, object, action string) (bool, error) {
	rule := RBACRule{PType: "p", V0: subject, V1: object, V2: action}
	result := r.db.Where(&rule).Delete(&RBACRule{})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

func (r *RBACPolicyRepositoryImpl) GetPolicy() ([][]string, error) {
	var rules []RBACRule
	result := r.db.Where("p_type = ?", "p").Find(&rules)
	if result.Error != nil {
		return nil, result.Error
	}

	var policies [][]string
	for _, rule := range rules {
		policies = append(policies, []string{rule.V0, rule.V1, rule.V2})
	}
	return policies, nil
}

func (r *RBACPolicyRepositoryImpl) AddRoleForUser(user, role string) (bool, error) {
	rule := RBACRule{PType: "g", V0: user, V1: role}
	// Check if role assignment already exists
	var existingRule RBACRule
	res := r.db.Where(&rule).First(&existingRule)
	if res.Error == nil {
		return false, nil // Role assignment already exists
	}

	result := r.db.Create(&rule)
	if result.Error != nil {
		return false, result.Error
	}
	return true, nil
}

func (r *RBACPolicyRepositoryImpl) RemoveRoleForUser(user, role string) (bool, error) {
	rule := RBACRule{PType: "g", V0: user, V1: role}
	result := r.db.Where(&rule).Delete(&RBACRule{})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

func (r *RBACPolicyRepositoryImpl) GetRolesForUser(user string) ([]string, error) {
	var rules []RBACRule
	result := r.db.Where("p_type = ? AND v0 = ?", "g", user).Find(&rules)
	if result.Error != nil {
		return nil, result.Error
	}

	var roles []string
	for _, rule := range rules {
		roles = append(roles, rule.V1)
	}
	return roles, nil
}

func (r *RBACPolicyRepositoryImpl) LoadPolicy() error {
	// For GORM adapter, policies are loaded automatically when enforcer is created
	// or can be reloaded by calling enforcer.LoadPolicy().
	// This method is primarily for Casbin's internal use with adapters.
	return nil
}

func (r *RBACPolicyRepositoryImpl) SavePolicy() error {
	// For GORM adapter, policies are saved automatically with auto-save enabled
	// or can be saved by calling enforcer.SavePolicy().
	// This method is primarily for Casbin's internal use with adapters.
	return nil
}
