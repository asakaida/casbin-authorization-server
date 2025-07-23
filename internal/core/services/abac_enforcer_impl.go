package services

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"your_project/internal/core/domain"
	"your_project/internal/core/ports/driven"
	"your_project/internal/core/ports/driving"
)

// PolicyEvaluationContext holds all data needed for policy evaluation
type PolicyEvaluationContext struct {
	UserAttributes        map[string]string
	ObjectAttributes      map[string]string
	EnvironmentAttributes map[string]string
	ActionAttributes      map[string]string
	Subject               string
	Object                string
	Action                string
}

// ABACHandlerImpl implements the ABACEnforcer interface.
type ABACHandlerImpl struct {
	policyRepo driven.ABACPolicyRepository
	attrRepo   driven.AttributeRepository
	policies   map[string]*domain.ABACPolicy // In-memory cache for policies
	mu         sync.RWMutex
}

// NewABACEnforcerImpl creates a new ABACHandlerImpl.
func NewABACEnforcerImpl(policyRepo driven.ABACPolicyRepository, attrRepo driven.AttributeRepository) driving.ABACEnforcer {
	e := &ABACHandlerImpl{
		policyRepo: policyRepo,
		attrRepo:   attrRepo,
		policies:   make(map[string]*domain.ABACPolicy),
	}
	// Load policies on startup
	err := e.LoadPolicies()
	if err != nil {
		// Log the error, but don't fail startup if policies can't be loaded immediately
		fmt.Printf("Failed to load ABAC policies on startup: %v\n", err)
	}
	return e
}

// LoadPolicies loads all policies from database into memory cache
func (e *ABACHandlerImpl) LoadPolicies() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	policies, err := e.policyRepo.GetAllPolicies()
	if err != nil {
		return fmt.Errorf("failed to load policies from repository: %w", err)
	}

	newPolicies := make(map[string]*domain.ABACPolicy)
	for _, policy := range policies {
		newPolicies[policy.ID] = policy
	}
	e.policies = newPolicies
	return nil
}

// AddPolicy adds a new policy to the engine
func (e *ABACHandlerImpl) AddPolicy(policy *domain.ABACPolicy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid ABAC policy: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if policy already exists
	if _, exists := e.policies[policy.ID]; exists {
		return domain.ErrAlreadyExists
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	if err := e.policyRepo.AddPolicy(policy); err != nil {
		return fmt.Errorf("failed to add policy to repository: %w", err)
	}

	e.policies[policy.ID] = policy
	return nil
}

// RemovePolicy removes a policy from the engine
func (e *ABACHandlerImpl) RemovePolicy(policyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.policies[policyID]; !exists {
		return domain.ErrNotFound
	}

	if err := e.policyRepo.RemovePolicy(policyID); err != nil {
		return fmt.Errorf("failed to remove policy from repository: %w", err)
	}

	delete(e.policies, policyID)
	return nil
}

// GetPolicyByID retrieves a specific ABAC policy by its ID
func (e *ABACHandlerImpl) GetPolicyByID(policyID string) (*domain.ABACPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policy, exists := e.policies[policyID]
	if !exists {
		return nil, domain.ErrNotFound
	}
	return policy, nil
}

// GetAllPolicies retrieves all ABAC policies
func (e *ABACHandlerImpl) GetAllPolicies() ([]*domain.ABACPolicy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := make([]*domain.ABACPolicy, 0, len(e.policies))
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}
	return policies, nil
}

// UpdatePolicy updates an existing ABAC policy
func (e *ABACHandlerImpl) UpdatePolicy(policy *domain.ABACPolicy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid ABAC policy: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.policies[policy.ID]; !exists {
		return domain.ErrNotFound
	}

	policy.UpdatedAt = time.Now()

	if err := e.policyRepo.UpdatePolicy(policy); err != nil {
		return fmt.Errorf("failed to update policy in repository: %w", err)
	}

	e.policies[policy.ID] = policy
	return nil
}

// SetUserAttributes saves user attributes to the repository and updates cache
func (e *ABACHandlerImpl) SetUserAttributes(userID string, attributes map[string]string) error {
	for k, v := range attributes {
		if err := e.attrRepo.SetUserAttribute(userID, k, v); err != nil {
			return fmt.Errorf("failed to set user attribute %s for %s: %w", k, userID, err)
		}
	}
	return nil
}

// GetUserAttributes retrieves user attributes from the repository
func (e *ABACHandlerImpl) GetUserAttributes(userID string) (map[string]string, error) {
	attrs, err := e.attrRepo.GetUserAttributes(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user attributes for %s: %w", userID, err)
	}
	return attrs, nil
}

// RemoveUserAttribute removes a specific user attribute
func (e *ABACHandlerImpl) RemoveUserAttribute(userID, attributeKey string) error {
	if err := e.attrRepo.RemoveUserAttribute(userID, attributeKey); err != nil {
		return fmt.Errorf("failed to remove user attribute %s for %s: %w", attributeKey, userID, err)
	}
	return nil
}

// SetObjectAttributes saves object attributes to the repository and updates cache
func (e *ABACHandlerImpl) SetObjectAttributes(objectID string, attributes map[string]string) error {
	for k, v := range attributes {
		if err := e.attrRepo.SetObjectAttribute(objectID, k, v); err != nil {
			return fmt.Errorf("failed to set object attribute %s for %s: %w", k, objectID, err)
		}
	}
	return nil
}

// GetObjectAttributes retrieves object attributes from the repository
func (e *ABACHandlerImpl) GetObjectAttributes(objectID string) (map[string]string, error) {
	attrs, err := e.attrRepo.GetObjectAttributes(objectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get object attributes for %s: %w", objectID, err)
	}
	return attrs, nil
}

// RemoveObjectAttribute removes a specific object attribute
func (e *ABACHandlerImpl) RemoveObjectAttribute(objectID, attributeKey string) error {
	if err := e.attrRepo.RemoveObjectAttribute(objectID, attributeKey); err != nil {
		return fmt.Errorf("failed to remove object attribute %s for %s: %w", attributeKey, objectID, err)
	}
	return nil
}

// Enforce evaluates all policies against the given context
func (e *ABACHandlerImpl) Enforce(subject, object, action string, reqAttrs map[string]string) (bool, error) {
	// Get user attributes from persistent storage
	userAttrs, err := e.attrRepo.GetUserAttributes(subject)
	if err != nil {
		return false, fmt.Errorf("failed to get user attributes: %w", err)
	}
	if userAttrs == nil {
		userAttrs = make(map[string]string)
	}

	// Get object attributes from persistent storage
	objectAttrs, err := e.attrRepo.GetObjectAttributes(object)
	if err != nil {
		return false, fmt.Errorf("failed to get object attributes: %w", err)
	}
	if objectAttrs == nil {
		objectAttrs = make(map[string]string)
	}

	// Create environment attributes
	envAttrs := map[string]string{
		"time": strconv.Itoa(time.Now().Hour()),
		"date": time.Now().Format("2006-01-02"),
		"day":  time.Now().Format("Monday"),
	}

	// Override with request attributes (including location if provided)
	for k, v := range reqAttrs {
		envAttrs[k] = v
	}

	// Use "hour" attribute from request if provided, otherwise use current time
	if hourStr, exists := reqAttrs["hour"]; exists {
		envAttrs["time"] = hourStr
	}

	// Create evaluation context
	ctx := &PolicyEvaluationContext{
		UserAttributes:        userAttrs,
		ObjectAttributes:      objectAttrs,
		EnvironmentAttributes: envAttrs,
		ActionAttributes:      make(map[string]string),
		Subject:               subject,
		Object:                object,
		Action:                action,
	}

	// Evaluate policies in priority order
	e.mu.RLock()
	defer e.mu.RUnlock()

	var sortedPolicies []*domain.ABACPolicy
	for _, policy := range e.policies {
		sortedPolicies = append(sortedPolicies, policy)
	}

	// Sort policies by priority (higher priority first)
	sort.Slice(sortedPolicies, func(i, j int) bool {
		return sortedPolicies[i].Priority > sortedPolicies[j].Priority
	})

	for _, policy := range sortedPolicies {
		if e.evaluatePolicy(policy, ctx) {
			if policy.Effect == "allow" {
				return true, nil
			} else if policy.Effect == "deny" {
				return false, nil
			}
		}
	}

	// Default deny if no policy matches
	return false, nil
}

// evaluatePolicy evaluates a single policy against the context
func (e *ABACHandlerImpl) evaluatePolicy(policy *domain.ABACPolicy, ctx *PolicyEvaluationContext) bool {
	if len(policy.Conditions) == 0 {
		return false
	}

	result := true
	currentLogicOp := "and" // Start with AND logic

	for i, condition := range policy.Conditions {
		conditionResult := e.evaluateCondition(&condition, ctx)

		if i == 0 {
			result = conditionResult
		} else {
			if currentLogicOp == "and" {
				result = result && conditionResult
			} else { // "or"
				result = result || conditionResult
			}
		}

		// Set logic operator for next iteration
		if condition.LogicOp != "" {
			currentLogicOp = condition.LogicOp
		}
	}

	return result
}

// evaluateCondition evaluates a single condition
func (e *ABACHandlerImpl) evaluateCondition(condition *domain.PolicyCondition, ctx *PolicyEvaluationContext) bool {
	var actualValue string

	// Get the actual value based on condition type
	switch condition.Type {
	case "user":
		actualValue = ctx.UserAttributes[condition.Field]
	case "object":
		actualValue = ctx.ObjectAttributes[condition.Field]
	case "environment":
		actualValue = ctx.EnvironmentAttributes[condition.Field]
	case "action":
		if condition.Field == "action" {
			actualValue = ctx.Action
		} else {
			actualValue = ctx.ActionAttributes[condition.Field]
		}
	case "subject":
		if condition.Field == "subject" {
			actualValue = ctx.Subject
		}
	case "resource":
		if condition.Field == "object" {
			actualValue = ctx.Object
		}
	default:
		return false
	}

	// Evaluate based on operator
	return e.evaluateOperator(actualValue, condition.Operator, condition.Value)
}

// evaluateOperator performs the actual comparison
func (e *ABACHandlerImpl) evaluateOperator(actual, operator, expected string) bool {
	switch operator {
	case "eq":
		return actual == expected
	case "ne":
		return actual != expected
	case "gt":
		return e.compareNumeric(actual, expected) > 0
	case "gte":
		return e.compareNumeric(actual, expected) >= 0
	case "lt":
		return e.compareNumeric(actual, expected) < 0
	case "lte":
		return e.compareNumeric(actual, expected) <= 0
	case "in":
		return e.evaluateIn(actual, expected)
	case "contains":
		return strings.Contains(actual, expected)
	case "startswith":
		return strings.HasPrefix(actual, expected)
	case "endswith":
		return strings.HasSuffix(actual, expected)
	case "regex":
		matched, _ := regexp.MatchString(expected, actual)
		return matched
	default:
		return false
	}
}

// compareNumeric compares two string values as numbers
func (e *ABACHandlerImpl) compareNumeric(actual, expected string) int {
	actualNum, err1 := strconv.ParseFloat(actual, 64)
	expectedNum, err2 := strconv.ParseFloat(expected, 64)

	if err1 != nil || err2 != nil {
		// Fallback to string comparison if not numeric
		return strings.Compare(actual, expected)
	}

	if actualNum > expectedNum {
		return 1
	} else if actualNum < expectedNum {
		return -1
	}
	return 0
}

// evaluateIn checks if actual value is in the comma-separated list
func (e *ABACHandlerImpl) evaluateIn(actual, expectedList string) bool {
	values := strings.Split(expectedList, ",")
	for _, value := range values {
		if strings.TrimSpace(value) == actual {
			return true
		}
	}
	return false
}
