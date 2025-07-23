package sqlite

import (
	"fmt"
	"time"

	"your_project/internal/core/domain"
	"your_project/internal/core/ports/driven"

	"gorm.io/gorm"
)

// ABACPolicyDB represents the abac_policies table
type ABACPolicyDB struct {
	ID          string `gorm:"primaryKey"`
	Name        string
	Description string
	Effect      string
	Priority    int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Conditions  []PolicyConditionDB `gorm:"foreignKey:PolicyID"`
}

// PolicyConditionDB represents the policy_conditions table
type PolicyConditionDB struct {
	ID       uint   `gorm:"primaryKey"`
	PolicyID string `gorm:"index"`
	Type     string
	Field    string
	Operator string
	Value    string
	LogicOp  string
}

// ABACPolicyRepositoryImpl implements driven.ABACPolicyRepository for SQLite.
type ABACPolicyRepositoryImpl struct {
	db *gorm.DB
}

// NewABACPolicyRepository creates a new ABACPolicyRepositoryImpl.
func NewABACPolicyRepository(db *gorm.DB) driven.ABACPolicyRepository {
	// Auto-migrate the tables
	err := db.AutoMigrate(&ABACPolicyDB{}, &PolicyConditionDB{})
	if err != nil {
		panic(fmt.Sprintf("failed to migrate ABAC tables: %v", err))
	}
	return &ABACPolicyRepositoryImpl{db: db}
}

func (r *ABACPolicyRepositoryImpl) AddPolicy(policy *domain.ABACPolicy) error {
	policyDB := toABACPolicyDB(policy)
	result := r.db.Create(policyDB)
	if result.Error != nil {
		return result.Error
	}
	// Update the original policy with generated IDs for conditions if needed
	policy.CreatedAt = policyDB.CreatedAt
	policy.UpdatedAt = policyDB.UpdatedAt
	for i := range policy.Conditions {
		policy.Conditions[i].ID = policyDB.Conditions[i].ID
	}
	return nil
}

func (r *ABACPolicyRepositoryImpl) RemovePolicy(policyID string) error {
	// Delete conditions first
	result := r.db.Where("policy_id = ?", policyID).Delete(&PolicyConditionDB{})
	if result.Error != nil {
		return result.Error
	}
	// Then delete the policy
	result = r.db.Delete(&ABACPolicyDB{}, "id = ?", policyID)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *ABACPolicyRepositoryImpl) GetPolicyByID(policyID string) (*domain.ABACPolicy, error) {
	var policyDB ABACPolicyDB
	result := r.db.Preload("Conditions").First(&policyDB, "id = ?", policyID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, domain.ErrNotFound
		}
		return nil, result.Error
	}
	return toDomainABACPolicy(&policyDB), nil
}

func (r *ABACPolicyRepositoryImpl) GetAllPolicies() ([]*domain.ABACPolicy, error) {
	var policiesDB []ABACPolicyDB
	result := r.db.Preload("Conditions").Find(&policiesDB)
	if result.Error != nil {
		return nil, result.Error
	}

	var policies []*domain.ABACPolicy
	for _, policyDB := range policiesDB {
		policies = append(policies, toDomainABACPolicy(&policyDB))
	}
	return policies, nil
}

func (r *ABACPolicyRepositoryImpl) UpdatePolicy(policy *domain.ABACPolicy) error {
	policyDB := toABACPolicyDB(policy)
	policyDB.UpdatedAt = time.Now()

	// Update policy itself
	result := r.db.Save(policyDB)
	if result.Error != nil {
		return result.Error
	}

	// Delete existing conditions and re-add them
	result = r.db.Where("policy_id = ?", policy.ID).Delete(&PolicyConditionDB{})
	if result.Error != nil {
		return result.Error
	}

	for _, cond := range policyDB.Conditions {
		cond.PolicyID = policy.ID // Ensure PolicyID is set for new conditions
		result = r.db.Create(&cond)
		if result.Error != nil {
			return result.Error
		}
	}

	return nil
}

func toABACPolicyDB(policy *domain.ABACPolicy) *ABACPolicyDB {
	conditionsDB := make([]PolicyConditionDB, len(policy.Conditions))
	for i, cond := range policy.Conditions {
		conditionsDB[i] = PolicyConditionDB{
			ID:       cond.ID,
			PolicyID: cond.PolicyID,
			Type:     cond.Type,
			Field:    cond.Field,
			Operator: cond.Operator,
			Value:    cond.Value,
			LogicOp:  cond.LogicOp,
		}
	}
	return &ABACPolicyDB{
		ID:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Effect:      policy.Effect,
		Priority:    policy.Priority,
		CreatedAt:   policy.CreatedAt,
		UpdatedAt:   policy.UpdatedAt,
		Conditions:  conditionsDB,
	}
}

func toDomainABACPolicy(policyDB *ABACPolicyDB) *domain.ABACPolicy {
	conditions := make([]domain.PolicyCondition, len(policyDB.Conditions))
	for i, condDB := range policyDB.Conditions {
		conditions[i] = domain.PolicyCondition{
			ID:       condDB.ID,
			PolicyID: condDB.PolicyID,
			Type:     condDB.Type,
			Field:    condDB.Field,
			Operator: condDB.Operator,
			Value:    condDB.Value,
			LogicOp:  condDB.LogicOp,
		}
	}
	return &domain.ABACPolicy{
		ID:          policyDB.ID,
		Name:        policyDB.Name,
		Description: policyDB.Description,
		Effect:      policyDB.Effect,
		Priority:    policyDB.Priority,
		CreatedAt:   policyDB.CreatedAt,
		UpdatedAt:   policyDB.UpdatedAt,
		Conditions:  conditions,
	}
}
