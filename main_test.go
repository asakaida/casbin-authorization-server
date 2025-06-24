// Multi-Model Authorization Microservice - Test Suite
// Copyright (c) 2024 Multi-Model Authorization Microservice
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Test database setup
func setupTestDB() (*gorm.DB, error) {
	// Use in-memory SQLite for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate all tables
	err = db.AutoMigrate(
		&RelationshipRecord{},
		&UserAttribute{},
		&ObjectAttribute{},
		&ABACPolicy{},
		&PolicyCondition{},
	)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// setupTestService creates a test AuthService with in-memory database
func setupTestService(t *testing.T) *AuthService {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	service := &AuthService{
		db:                    db,
		userAttrs:            make(map[string]map[string]string),
		objectAttrs:          make(map[string]map[string]string),
		aclEnforcer:          nil,
		rbacEnforcer:         nil,
		abacEnforcer:         nil,
		relationshipGraph:    nil,
		policyEngine:         nil,
	}

	// Initialize enforcers using embedded logic from NewAuthService
	// Create model strings for test enforcers
	aclModel := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act`

	rbacModel := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`

	abacModel := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = keyMatch(r.sub, p.sub) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)`

	// Create adapters for each model
	aclAdapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "acl_rules")
	if err != nil {
		t.Fatalf("Failed to create ACL adapter: %v", err)
	}

	rbacAdapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "rbac_rules")
	if err != nil {
		t.Fatalf("Failed to create RBAC adapter: %v", err)
	}

	abacAdapter, err := gormadapter.NewAdapterByDBUseTableName(db, "", "abac_rules")
	if err != nil {
		t.Fatalf("Failed to create ABAC adapter: %v", err)
	}

	// Create enforcers
	aclModelObj, err := model.NewModelFromString(aclModel)
	if err != nil {
		t.Fatalf("Failed to create ACL model: %v", err)
	}
	service.aclEnforcer, err = casbin.NewEnforcer(aclModelObj, aclAdapter)
	if err != nil {
		t.Fatalf("Failed to create ACL enforcer: %v", err)
	}

	rbacModelObj, err := model.NewModelFromString(rbacModel)
	if err != nil {
		t.Fatalf("Failed to create RBAC model: %v", err)
	}
	service.rbacEnforcer, err = casbin.NewEnforcer(rbacModelObj, rbacAdapter)
	if err != nil {
		t.Fatalf("Failed to create RBAC enforcer: %v", err)
	}

	abacModelObj, err := model.NewModelFromString(abacModel)
	if err != nil {
		t.Fatalf("Failed to create ABAC model: %v", err)
	}
	service.abacEnforcer, err = casbin.NewEnforcer(abacModelObj, abacAdapter)
	if err != nil {
		t.Fatalf("Failed to create ABAC enforcer: %v", err)
	}

	relationshipGraph, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}
	service.relationshipGraph = relationshipGraph

	policyEngine := NewPolicyEngine(db)
	service.policyEngine = policyEngine

	// Load attributes from database using the correct method name
	err = service.loadABACAttributes()
	if err != nil {
		t.Fatalf("Failed to load attributes: %v", err)
	}

	return service
}

// Unit Tests for RelationshipGraph
func TestRelationshipGraph_InitializeDefaultPermissions(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Test default permissions are initialized
	ownerPerms := rg.GetPermissionsForRelationship("owner")
	expectedOwnerPerms := []string{"read", "write", "delete", "admin"}
	
	if len(ownerPerms) != len(expectedOwnerPerms) {
		t.Errorf("Expected %d owner permissions, got %d", len(expectedOwnerPerms), len(ownerPerms))
	}

	for _, expectedPerm := range expectedOwnerPerms {
		found := false
		for _, perm := range ownerPerms {
			if perm == expectedPerm {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected owner permission '%s' not found", expectedPerm)
		}
	}
}

func TestRelationshipGraph_HasPermissionThroughRelationship(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	testCases := []struct {
		relationship string
		permission   string
		expected     bool
	}{
		{"owner", "read", true},
		{"owner", "write", true},
		{"owner", "admin", true},
		{"editor", "read", true},
		{"editor", "write", true},
		{"editor", "admin", false},
		{"viewer", "read", true},
		{"viewer", "write", false},
		{"nonexistent", "read", false},
	}

	for _, tc := range testCases {
		result := rg.HasPermissionThroughRelationship(tc.relationship, tc.permission)
		if result != tc.expected {
			t.Errorf("HasPermissionThroughRelationship(%s, %s) = %v, expected %v",
				tc.relationship, tc.permission, result, tc.expected)
		}
	}
}

func TestRelationshipGraph_AddAndRemoveRelationship(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Test adding relationship
	err = rg.AddRelationship("alice", "owner", "document1")
	if err != nil {
		t.Errorf("Failed to add relationship: %v", err)
	}

	// Test relationship exists
	if !rg.HasDirectRelationship("alice", "owner", "document1") {
		t.Error("Relationship not found after adding")
	}

	// Test removing relationship
	err = rg.RemoveRelationship("alice", "owner", "document1")
	if err != nil {
		t.Errorf("Failed to remove relationship: %v", err)
	}

	// Test relationship no longer exists
	if rg.HasDirectRelationship("alice", "owner", "document1") {
		t.Error("Relationship still exists after removal")
	}
}

func TestRelationshipGraph_CheckReBACAccess(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup test relationships
	err = rg.AddRelationship("alice", "owner", "document1")
	if err != nil {
		t.Fatalf("Failed to add owner relationship: %v", err)
	}

	err = rg.AddRelationship("bob", "editor", "document1")
	if err != nil {
		t.Fatalf("Failed to add editor relationship: %v", err)
	}

	err = rg.AddRelationship("charlie", "viewer", "document1")
	if err != nil {
		t.Fatalf("Failed to add viewer relationship: %v", err)
	}

	testCases := []struct {
		subject  string
		object   string
		action   string
		expected bool
		desc     string
	}{
		{"alice", "document1", "read", true, "Owner should have read access"},
		{"alice", "document1", "write", true, "Owner should have write access"},
		{"alice", "document1", "delete", true, "Owner should have delete access"},
		{"bob", "document1", "read", true, "Editor should have read access"},
		{"bob", "document1", "write", true, "Editor should have write access"},
		{"bob", "document1", "delete", false, "Editor should not have delete access"},
		{"charlie", "document1", "read", true, "Viewer should have read access"},
		{"charlie", "document1", "write", false, "Viewer should not have write access"},
		{"dave", "document1", "read", false, "Non-member should not have access"},
	}

	for _, tc := range testCases {
		allowed, _ := rg.CheckReBACAccess(tc.subject, tc.object, tc.action)
		if allowed != tc.expected {
			t.Errorf("%s: CheckReBACAccess(%s, %s, %s) = %v, expected %v",
				tc.desc, tc.subject, tc.object, tc.action, allowed, tc.expected)
		}
	}
}

func TestRelationshipGraph_GroupAccess(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup group relationships
	err = rg.AddRelationship("alice", "member", "engineering_team")
	if err != nil {
		t.Fatalf("Failed to add member relationship: %v", err)
	}

	err = rg.AddRelationship("engineering_team", "group_access", "source_code")
	if err != nil {
		t.Fatalf("Failed to add group_access relationship: %v", err)
	}

	// Test group access
	allowed, path := rg.CheckReBACAccess("alice", "source_code", "read")
	if !allowed {
		t.Error("Alice should have read access to source_code through group membership")
	}

	expectedPath := "alice -[member]-> engineering_team -[group_access]-> source_code"
	if path != expectedPath {
		t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
	}
}

// Unit Tests for ABAC Policy Engine
func TestPolicyEngine_AddAndEvaluatePolicy(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	pe := NewPolicyEngine(db)

	// Create test policy
	policy := &ABACPolicy{
		ID:          "test_policy",
		Name:        "Test Policy",
		Description: "Test policy for unit testing",
		Effect:      "allow",
		Priority:    100,
		Conditions: []PolicyCondition{
			{
				Type:     "user",
				Field:    "department",
				Operator: "eq",
				Value:    "engineering",
				LogicOp:  "",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add policy
	err = pe.AddPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Create evaluation context
	ctx := &PolicyEvaluationContext{
		UserAttributes: map[string]string{
			"department": "engineering",
		},
		ObjectAttributes:      make(map[string]string),
		EnvironmentAttributes: make(map[string]string),
		ActionAttributes:      make(map[string]string),
		Subject:               "alice",
		Object:                "document1",
		Action:                "read",
	}

	// Evaluate policy
	allowed, message := pe.Evaluate(ctx)
	if !allowed {
		t.Errorf("Policy evaluation failed: %s", message)
	}

	// Test with different context (should fail)
	ctx.UserAttributes["department"] = "hr"
	allowed, _ = pe.Evaluate(ctx)
	if allowed {
		t.Error("Policy evaluation should have failed for different department")
	}
}

func TestPolicyEngine_RemovePolicy(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	pe := NewPolicyEngine(db)

	// Create and add test policy
	policy := &ABACPolicy{
		ID:          "test_policy",
		Name:        "Test Policy",
		Description: "Test policy for removal",
		Effect:      "allow",
		Priority:    100,
		Conditions:  []PolicyCondition{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = pe.AddPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Remove policy
	err = pe.RemovePolicy("test_policy")
	if err != nil {
		t.Errorf("Failed to remove policy: %v", err)
	}

	// Verify policy is removed
	if _, exists := pe.policies["test_policy"]; exists {
		t.Error("Policy still exists after removal")
	}
}

// Integration Tests
func TestAuthService_Integration(t *testing.T) {
	service := setupTestService(t)

	// Test ACL
	t.Run("ACL Integration", func(t *testing.T) {
		// Add ACL policy
		added, err := service.aclEnforcer.AddPolicy("alice", "document1", "read")
		if err != nil || !added {
			t.Errorf("Failed to add ACL policy: %v", err)
		}

		// Test enforcement
		allowed, err := service.Enforce(ModelACL, "alice", "document1", "read", nil)
		if err != nil || !allowed {
			t.Errorf("ACL enforcement failed: %v", err)
		}

		// Test denial
		allowed, err = service.Enforce(ModelACL, "bob", "document1", "read", nil)
		if err != nil || allowed {
			t.Error("ACL should have denied access for bob")
		}
	})

	// Test RBAC
	t.Run("RBAC Integration", func(t *testing.T) {
		// Add role and policy
		_, err := service.rbacEnforcer.AddRoleForUser("alice", "admin")
		if err != nil {
			t.Fatalf("Failed to add role: %v", err)
		}

		_, err = service.rbacEnforcer.AddPolicy("admin", "document1", "read")
		if err != nil {
			t.Fatalf("Failed to add RBAC policy: %v", err)
		}

		// Test enforcement
		allowed, err := service.Enforce(ModelRBAC, "alice", "document1", "read", nil)
		if err != nil || !allowed {
			t.Errorf("RBAC enforcement failed: %v", err)
		}
	})

	// Test ReBAC
	t.Run("ReBAC Integration", func(t *testing.T) {
		// Add relationship
		err := service.relationshipGraph.AddRelationship("alice", "owner", "document1")
		if err != nil {
			t.Fatalf("Failed to add relationship: %v", err)
		}

		// Test enforcement
		allowed, err := service.Enforce(ModelReBAC, "alice", "document1", "read", nil)
		if err != nil || !allowed {
			t.Errorf("ReBAC enforcement failed: %v", err)
		}
	})

	// Test ABAC
	t.Run("ABAC Integration", func(t *testing.T) {
		// Set user attributes
		err := service.saveUserAttribute("alice", "clearance", "high")
		if err != nil {
			t.Fatalf("Failed to save user attribute: %v", err)
		}

		// Create ABAC policy
		policy := &ABACPolicy{
			ID:          "clearance_policy",
			Name:        "Clearance Policy",
			Description: "High clearance access",
			Effect:      "allow",
			Priority:    100,
			Conditions: []PolicyCondition{
				{
					Type:     "user",
					Field:    "clearance",
					Operator: "eq",
					Value:    "high",
					LogicOp:  "",
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		err = service.policyEngine.AddPolicy(policy)
		if err != nil {
			t.Fatalf("Failed to add ABAC policy: %v", err)
		}

		// Test enforcement
		allowed, err := service.Enforce(ModelABAC, "alice", "document1", "read", nil)
		if err != nil || !allowed {
			t.Errorf("ABAC enforcement failed: %v", err)
		}
	})
}

// HTTP Handler Integration Tests
func TestHTTPHandlers_Integration(t *testing.T) {
	service := setupTestService(t)
	router := mux.NewRouter()
	
	// Setup routes
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/health", service.healthHandler).Methods("GET")
	api.HandleFunc("/authorizations", service.authorizationHandler).Methods("POST")
	api.HandleFunc("/relationships", service.addRelationshipHandler).Methods("POST")
	api.HandleFunc("/relationships/permissions", service.getRelationshipPermissionsHandler).Methods("GET")
	api.HandleFunc("/relationships/permissions/check", service.checkRelationshipPermissionHandler).Methods("POST")

	t.Run("Health Check", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/api/v1/health", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Health check returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		var response map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		if response["status"] != "healthy" {
			t.Errorf("Expected status 'healthy', got %v", response["status"])
		}
	})

	t.Run("Add Relationship", func(t *testing.T) {
		relationshipReq := RelationshipRequest{
			Subject:      "alice",
			Relationship: "owner",
			Object:       "document1",
		}

		reqBody, _ := json.Marshal(relationshipReq)
		req, err := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Add relationship returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		var response map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		if response["message"] != "Relationship added successfully" {
			t.Errorf("Unexpected response message: %v", response["message"])
		}
	})

	t.Run("Authorization Check", func(t *testing.T) {
		// First add a relationship
		service.relationshipGraph.AddRelationship("alice", "owner", "document1")

		authReq := EnforceRequest{
			Model:   ModelReBAC,
			Subject: "alice",
			Object:  "document1",
			Action:  "read",
		}

		reqBody, _ := json.Marshal(authReq)
		req, err := http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Authorization check returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		var response map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		if allowed, ok := response["allowed"].(bool); !ok || !allowed {
			t.Errorf("Expected access to be allowed, got %v", response["allowed"])
		}
	})

	t.Run("Get Relationship Permissions", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/api/v1/relationships/permissions", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Get permissions returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		var response map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		if mappings, ok := response["mappings"].(map[string]interface{}); !ok || len(mappings) == 0 {
			t.Error("Expected permission mappings in response")
		}
	})

	t.Run("Check Relationship Permission", func(t *testing.T) {
		checkReq := map[string]string{
			"relationship": "owner",
			"permission":   "read",
		}

		reqBody, _ := json.Marshal(checkReq)
		req, err := http.NewRequest("POST", "/api/v1/relationships/permissions/check", bytes.NewBuffer(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Check permission returned wrong status code: got %v want %v", status, http.StatusOK)
		}

		var response map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		if granted, ok := response["granted"].(bool); !ok || !granted {
			t.Errorf("Expected permission to be granted, got %v", response["granted"])
		}
	})
}

// Benchmark Tests
func BenchmarkRelationshipGraph_CheckReBACAccess(b *testing.B) {
	db, err := setupTestDB()
	if err != nil {
		b.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		b.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup test data
	for i := 0; i < 100; i++ {
		user := fmt.Sprintf("user%d", i)
		doc := fmt.Sprintf("document%d", i)
		rg.AddRelationship(user, "owner", doc)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		userIndex := i % 100
		user := fmt.Sprintf("user%d", userIndex)
		doc := fmt.Sprintf("document%d", userIndex)
		rg.CheckReBACAccess(user, doc, "read")
	}
}

func BenchmarkPolicyEngine_Evaluate(b *testing.B) {
	db, err := setupTestDB()
	if err != nil {
		b.Fatalf("Failed to setup test database: %v", err)
	}

	pe := NewPolicyEngine(db)

	// Add test policy
	policy := &ABACPolicy{
		ID:          "bench_policy",
		Name:        "Benchmark Policy",
		Description: "Policy for benchmarking",
		Effect:      "allow",
		Priority:    100,
		Conditions: []PolicyCondition{
			{
				Type:     "user",
				Field:    "department",
				Operator: "eq",
				Value:    "engineering",
				LogicOp:  "",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	pe.AddPolicy(policy)

	ctx := &PolicyEvaluationContext{
		UserAttributes: map[string]string{
			"department": "engineering",
		},
		ObjectAttributes:      make(map[string]string),
		EnvironmentAttributes: make(map[string]string),
		ActionAttributes:      make(map[string]string),
		Subject:               "alice",
		Object:                "document1",
		Action:                "read",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pe.Evaluate(ctx)
	}
}

// Test cleanup
func TestMain(m *testing.M) {
	// Run tests
	exitCode := m.Run()

	// Cleanup (if needed)
	os.Exit(exitCode)
}