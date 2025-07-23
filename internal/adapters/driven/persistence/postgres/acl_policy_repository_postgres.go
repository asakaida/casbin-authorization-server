package postgres

import (
	"fmt"
	"your_project/internal/core/ports/driven"

	"gorm.io/gorm"
)

// ACLRule represents a row in the acl_rules table
type ACLRule struct {
	ID    uint   `gorm:"primaryKey"`
	PType string `gorm:"size:100"`
	V0    string `gorm:"size:100"`
	V1    string `gorm:"size:100"`
	V2    string `gorm:"size:100"`
	V3    string `gorm:"size:100"`
	V4    string `gorm:"size:100"`
	V5    string `gorm:"size:100"`
}

// ACLPolicyRepositoryImpl implements driven.ACLPolicyRepository for PostgreSQL.
type ACLPolicyRepositoryImpl struct {
	db *gorm.DB
}

// NewACLPolicyRepository creates a new ACLPolicyRepositoryImpl.
func NewACLPolicyRepository(db *gorm.DB) driven.ACLPolicyRepository {
	// Auto-migrate the table
	err := db.AutoMigrate(&ACLRule{})
	if err != nil {
		panic(fmt.Sprintf("failed to migrate ACLRule table: %v", err))
	}
	return &ACLPolicyRepositoryImpl{db: db}
}

func (r *ACLPolicyRepositoryImpl) AddPolicy(subject, object, action string) (bool, error) {
	rule := ACLRule{PType: "p", V0: subject, V1: object, V2: action}
	// Check if policy already exists
	var existingRule ACLRule
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

func (r *ACLPolicyRepositoryImpl) RemovePolicy(subject, object, action string) (bool, error) {
	rule := ACLRule{PType: "p", V0: subject, V1: object, V2: action}
	result := r.db.Where(&rule).Delete(&ACLRule{})
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

func (r *ACLPolicyRepositoryImpl) GetPolicy() ([][]string, error) {
	var rules []ACLRule
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

func (r *ACLPolicyRepositoryImpl) LoadPolicy() error {
	// For GORM adapter, policies are loaded automatically when enforcer is created
	// or can be reloaded by calling enforcer.LoadPolicy().
	// This method is primarily for Casbin's internal use with adapters.
	return nil
}

func (r *ACLPolicyRepositoryImpl) SavePolicy() error {
	// For GORM adapter, policies are saved automatically with auto-save enabled
	// or can be saved by calling enforcer.SavePolicy().
	// This method is primarily for Casbin's internal use with adapters.
	return nil
}
