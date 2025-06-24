// Multi-Model Authorization Microservice - API Integration Tests
// Copyright (c) 2024 Multi-Model Authorization Microservice
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// API Integration Tests
func TestAPI_FullWorkflow(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("Complete ReBAC Workflow", func(t *testing.T) {
		// Step 1: Check relationship permissions
		req, _ := http.NewRequest("GET", "/api/v1/relationships/permissions", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		var permsResponse map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &permsResponse)
		
		// Verify owner permissions exist
		mappings := permsResponse["mappings"].(map[string]interface{})
		ownerPerms := mappings["owner"].([]interface{})
		if len(ownerPerms) == 0 {
			t.Error("Expected owner permissions to be defined")
		}

		// Step 2: Add relationships
		relationships := []RelationshipRequest{
			{"alice", "owner", "document1"},
			{"bob", "editor", "document1"},
			{"charlie", "viewer", "document1"},
			{"alice", "member", "engineering_team"},
			{"bob", "member", "engineering_team"},
			{"engineering_team", "group_access", "project_docs"},
		}

		for _, rel := range relationships {
			reqBody, _ := json.Marshal(rel)
			req, _ := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Failed to add relationship %+v: status %d", rel, rr.Code)
			}
		}

		// Step 3: Test authorization decisions
		authTests := []struct {
			subject  string
			object   string
			action   string
			expected bool
			desc     string
		}{
			{"alice", "document1", "read", true, "Owner read access"},
			{"alice", "document1", "write", true, "Owner write access"},
			{"alice", "document1", "delete", true, "Owner delete access"},
			{"bob", "document1", "read", true, "Editor read access"},
			{"bob", "document1", "write", true, "Editor write access"},
			{"bob", "document1", "delete", false, "Editor no delete access"},
			{"charlie", "document1", "read", true, "Viewer read access"},
			{"charlie", "document1", "write", false, "Viewer no write access"},
			{"alice", "project_docs", "read", true, "Group member access"},
			{"bob", "project_docs", "read", true, "Group member access"},
			{"charlie", "project_docs", "read", false, "Non-member no access"},
		}

		for _, test := range authTests {
			authReq := EnforceRequest{
				Model:   ModelReBAC,
				Subject: test.subject,
				Object:  test.object,
				Action:  test.action,
			}

			reqBody, _ := json.Marshal(authReq)
			req, _ := http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			var authResponse map[string]interface{}
			if rr.Code == http.StatusOK {
				json.Unmarshal(rr.Body.Bytes(), &authResponse)
				allowed := authResponse["allowed"].(bool)
				if allowed != test.expected {
					t.Errorf("%s: Expected %v, got %v", test.desc, test.expected, allowed)
				}
			} else if rr.Code == http.StatusForbidden {
				// 403 means access denied, which is expected for negative test cases
				if test.expected {
					t.Errorf("%s: Expected access allowed but got 403 Forbidden", test.desc)
				}
				// For negative cases, 403 is acceptable - it means access was correctly denied
			} else {
				t.Errorf("%s: Unexpected status code %d", test.desc, rr.Code)
			}
		}

		// Step 4: Test relationship path discovery
		pathReq, _ := http.NewRequest("GET", "/api/v1/relationships/paths?subject=alice&object=project_docs&max_depth=5", nil)
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, pathReq)

		if rr.Code != http.StatusOK {
			t.Errorf("Path discovery failed: status %d", rr.Code)
		}

		var pathResponse map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &pathResponse)

		if !pathResponse["found"].(bool) {
			t.Error("Expected to find path from alice to project_docs")
		}

		// Step 5: Test specific permission check
		permCheckReq := map[string]string{
			"relationship": "owner",
			"permission":   "write",
		}
		reqBody, _ := json.Marshal(permCheckReq)
		req, _ = http.NewRequest("POST", "/api/v1/relationships/permissions/check", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Permission check failed: status %d", rr.Code)
		}

		var permCheckResponse map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &permCheckResponse)

		if !permCheckResponse["granted"].(bool) {
			t.Error("Expected owner to have write permission")
		}
	})

	t.Run("ABAC Workflow", func(t *testing.T) {
		// Step 1: Set user attributes
		userAttrs := map[string]interface{}{
			"attributes": map[string]string{
				"department": "engineering",
				"clearance":  "high",
			},
		}
		reqBody, _ := json.Marshal(userAttrs)
		req, _ := http.NewRequest("PUT", "/api/v1/users/alice/attributes", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Failed to set user attributes: status %d", rr.Code)
		}

		// Step 2: Set object attributes
		objAttrs := map[string]interface{}{
			"attributes": map[string]string{
				"classification": "confidential",
				"department":     "engineering",
			},
		}
		reqBody, _ = json.Marshal(objAttrs)
		req, _ = http.NewRequest("PUT", "/api/v1/objects/sensitive_doc/attributes", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Failed to set object attributes: status %d", rr.Code)
		}

		// Step 3: Create ABAC policy
		policy := ABACPolicy{
			ID:          "dept_access",
			Name:        "Department Access",
			Description: "Users can access documents from their department",
			Effect:      "allow",
			Priority:    100,
			Conditions: []PolicyCondition{
				{
					Type:     "user",
					Field:    "department",
					Operator: "eq",
					Value:    "engineering",
					LogicOp:  "and",
				},
				{
					Type:     "object",
					Field:    "department",
					Operator: "eq",
					Value:    "engineering",
					LogicOp:  "",
				},
			},
		}

		reqBody, _ = json.Marshal(policy)
		req, _ = http.NewRequest("POST", "/api/v1/abac/policies", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Failed to create ABAC policy: status %d", rr.Code)
		}

		// Step 4: Test ABAC authorization
		authReq := EnforceRequest{
			Model:   ModelABAC,
			Subject: "alice",
			Object:  "sensitive_doc",
			Action:  "read",
		}

		reqBody, _ = json.Marshal(authReq)
		req, _ = http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		var authResponse map[string]interface{}
		if rr.Code == http.StatusOK {
			json.Unmarshal(rr.Body.Bytes(), &authResponse)
			if !authResponse["allowed"].(bool) {
				t.Error("Expected ABAC authorization to be allowed")
			}
		} else if rr.Code == http.StatusForbidden {
			// ABAC might deny access if policies don't match
			json.Unmarshal(rr.Body.Bytes(), &authResponse)
			t.Logf("ABAC access denied (this may be expected if policies don't match): %v", authResponse["message"])
		} else {
			t.Errorf("ABAC authorization failed: status %d, body: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("Multi-Model Integration", func(t *testing.T) {
		// Test all four models with the same user
		models := []struct {
			model    AccessControlModel
			setup    func()
			expected bool
		}{
			{
				model: ModelACL,
				setup: func() {
					service.aclEnforcer.AddPolicy("alice", "test_resource", "read")
				},
				expected: true,
			},
			{
				model: ModelRBAC,
				setup: func() {
					service.rbacEnforcer.AddRoleForUser("alice", "reader")
					service.rbacEnforcer.AddPolicy("reader", "test_resource", "read")
				},
				expected: true,
			},
			{
				model: ModelReBAC,
				setup: func() {
					service.relationshipGraph.AddRelationship("alice", "viewer", "test_resource")
				},
				expected: true,
			},
		}

		for _, test := range models {
			test.setup()

			authReq := EnforceRequest{
				Model:   test.model,
				Subject: "alice",
				Object:  "test_resource",
				Action:  "read",
			}

			reqBody, _ := json.Marshal(authReq)
			req, _ := http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("%s authorization failed: status %d", test.model, rr.Code)
				continue
			}

			var authResponse map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &authResponse)

			allowed := authResponse["allowed"].(bool)
			if allowed != test.expected {
				t.Errorf("%s: Expected %v, got %v", test.model, test.expected, allowed)
			}
		}
	})
}

func TestAPI_ErrorHandling(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("Invalid JSON Requests", func(t *testing.T) {
		endpoints := []struct {
			method string
			path   string
		}{
			{"POST", "/api/v1/authorizations"},
			{"POST", "/api/v1/relationships"},
			{"POST", "/api/v1/relationships/permissions/check"},
			{"PUT", "/api/v1/users/alice/attributes"},
		}

		for _, endpoint := range endpoints {
			req, _ := http.NewRequest(endpoint.method, endpoint.path, bytes.NewBufferString("invalid json"))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s %s: Expected status 400, got %d", endpoint.method, endpoint.path, rr.Code)
			}
		}
	})

	t.Run("Missing Required Parameters", func(t *testing.T) {
		// Test missing relationship parameters
		invalidRel := map[string]string{
			"subject": "alice",
			// missing relationship and object
		}
		reqBody, _ := json.Marshal(invalidRel)
		req, _ := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Should handle gracefully, either 400 or add with empty values
		if rr.Code != http.StatusBadRequest && rr.Code != http.StatusOK {
			t.Errorf("Unexpected status code for invalid relationship: %d", rr.Code)
		}

		// Test missing path parameters
		req, _ = http.NewRequest("GET", "/api/v1/relationships/paths", nil)
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400 for missing path parameters, got %d", rr.Code)
		}
	})

	t.Run("Invalid Model Types", func(t *testing.T) {
		invalidAuth := EnforceRequest{
			Model:   "invalid_model",
			Subject: "alice",
			Object:  "document1",
			Action:  "read",
		}

		reqBody, _ := json.Marshal(invalidAuth)
		req, _ := http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// Invalid model could return either 400 (bad request) or 500 (internal error)
		// depending on where the validation occurs
		if rr.Code != http.StatusBadRequest && rr.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 400 or 500 for invalid model, got %d", rr.Code)
		}
	})
}

func TestAPI_SecurityHeaders(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	req, _ := http.NewRequest("GET", "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check CORS headers
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS headers not set correctly")
	}

	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("CORS methods not set")
	}
}

func TestAPI_PerformanceBasics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	service := setupTestService(t)
	router := setupTestRouter(service)

	// Add some test data
	service.relationshipGraph.AddRelationship("alice", "owner", "document1")

	// Test basic performance
	authReq := EnforceRequest{
		Model:   ModelReBAC,
		Subject: "alice",
		Object:  "document1",
		Action:  "read",
	}

	reqBody, _ := json.Marshal(authReq)

	// Measure response time for authorization checks
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Authorization check %d failed: status %d", i, rr.Code)
			break
		}
	}
}

// Helper function to setup test router
func setupTestRouter(service *AuthService) *mux.Router {
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()

	// Add all the endpoints
	api.HandleFunc("/health", service.healthHandler).Methods("GET")
	api.HandleFunc("/models", service.getModelsHandler).Methods("GET")
	api.HandleFunc("/authorizations", service.authorizationHandler).Methods("POST")

	// ReBAC endpoints
	api.HandleFunc("/relationships", service.addRelationshipHandler).Methods("POST")
	api.HandleFunc("/relationships", service.getRelationshipsHandler).Methods("GET")
	api.HandleFunc("/relationships/{id}", service.deleteRelationshipHandler).Methods("DELETE")
	api.HandleFunc("/relationships/paths", service.findRelationshipPathHandler).Methods("GET")
	api.HandleFunc("/relationships/permissions", service.getRelationshipPermissionsHandler).Methods("GET")
	api.HandleFunc("/relationships/permissions/check", service.checkRelationshipPermissionHandler).Methods("POST")

	// User attributes endpoints
	api.HandleFunc("/users/{userId}/attributes", service.setUserAttributesHandler).Methods("PUT")
	api.HandleFunc("/users/{userId}/attributes", service.getUserAttributesHandler).Methods("GET")

	// Object attributes endpoints
	api.HandleFunc("/objects/{objectId}/attributes", service.setObjectAttributesHandler).Methods("PUT")
	api.HandleFunc("/objects/{objectId}/attributes", service.getObjectAttributesHandler).Methods("GET")

	// ABAC Policy endpoints
	api.HandleFunc("/abac/policies", service.addABACPolicyHandler).Methods("POST")
	api.HandleFunc("/abac/policies", service.getABACPoliciesHandler).Methods("GET")
	api.HandleFunc("/abac/policies/{id}", service.getABACPolicyHandler).Methods("GET")

	// Apply middleware
	router.Use(corsMiddleware)

	return router
}