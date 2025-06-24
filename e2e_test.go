package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// End-to-End Tests - Real World Scenarios
func TestE2E_TechCorpScenario(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("TechCorp Complete Authorization Scenario", func(t *testing.T) {
		// Scenario: TechCorp Inc. company from tutorial
		// Setup employees, departments, and documents as described in tutorial

		// Step 1: Setup ReBAC relationships for organizational structure
		relationships := []RelationshipRequest{
			// Document ownership
			{"alice", "owner", "company_strategy.pdf"},
			{"diana", "owner", "employee_records.xlsx"},
			{"bob", "owner", "engineering_docs.md"},

			// Team memberships
			{"bob", "member", "engineering_team"},
			{"charlie", "member", "engineering_team"},
			{"frank", "member", "engineering_team"},

			// Team access rights
			{"engineering_team", "group_access", "source_code.zip"},
			{"engineering_team", "group_access", "engineering_docs.md"},

			// Individual access rights
			{"charlie", "editor", "engineering_docs.md"},

			// Management hierarchy
			{"alice", "manager", "bob"},
			{"bob", "manager", "charlie"},
			{"bob", "manager", "frank"},
		}

		// Add all relationships
		for _, rel := range relationships {
			reqBody, _ := json.Marshal(rel)
			req, _ := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Failed to add relationship %+v: status %d, body: %s", rel, rr.Code, rr.Body.String())
			}
		}

		// Step 2: Test authorization scenarios from tutorial
		authTests := []struct {
			subject  string
			object   string
			action   string
			expected bool
			scenario string
		}{
			// CEO access
			{"alice", "company_strategy.pdf", "read", true, "CEO reads strategy document"},
			{"alice", "company_strategy.pdf", "write", true, "CEO writes strategy document"},

			// HR Manager access
			{"diana", "employee_records.xlsx", "read", true, "HR manager reads employee records"},
			{"diana", "employee_records.xlsx", "write", true, "HR manager updates employee records"},
			{"diana", "company_strategy.pdf", "read", false, "HR manager cannot read strategy"},

			// Engineering Manager access
			{"bob", "engineering_docs.md", "read", true, "Engineering manager reads docs (owner)"},
			{"bob", "engineering_docs.md", "write", true, "Engineering manager writes docs (owner)"},
			{"bob", "source_code.zip", "read", true, "Engineering manager reads code (team access)"},

			// Engineer access
			{"charlie", "engineering_docs.md", "read", true, "Engineer reads docs (editor)"},
			{"charlie", "engineering_docs.md", "write", true, "Engineer writes docs (editor)"},
			{"charlie", "source_code.zip", "read", true, "Engineer reads code (team member)"},
			{"charlie", "employee_records.xlsx", "read", false, "Engineer cannot read HR records"},

			// Junior Developer access
			{"frank", "source_code.zip", "read", true, "Junior developer reads code (team member)"},
			{"frank", "engineering_docs.md", "read", true, "Junior developer reads docs (team access)"},
			{"frank", "engineering_docs.md", "write", false, "Junior developer cannot write docs (no editor role)"},
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
			var allowed bool

			// Handle both 200 (allowed) and 403 (denied) as valid responses
			if rr.Code == http.StatusOK {
				json.Unmarshal(rr.Body.Bytes(), &authResponse)
				allowed = authResponse["allowed"].(bool)
			} else if rr.Code == http.StatusForbidden {
				json.Unmarshal(rr.Body.Bytes(), &authResponse)
				allowed = false // 403 means access denied
			} else {
				t.Errorf("%s: Unexpected HTTP status %d", test.scenario, rr.Code)
				continue
			}

			if allowed != test.expected {
				t.Errorf("%s: Expected %v, got %v", test.scenario, test.expected, allowed)
			} else {
				t.Logf("✓ %s: %v (correct)", test.scenario, allowed)
			}
		}

		// Step 3: Test relationship path discovery for debugging
		pathTests := []struct {
			subject     string
			object      string
			shouldFind  bool
			description string
		}{
			{"charlie", "source_code.zip", true, "Charlie's path to source code"},
			{"frank", "engineering_docs.md", true, "Frank's path to engineering docs"},
			{"alice", "company_strategy.pdf", true, "Alice's direct ownership"},
			{"diana", "source_code.zip", false, "Diana should not have path to source code"},
		}

		for _, test := range pathTests {
			url := fmt.Sprintf("/api/v1/relationships/paths?subject=%s&object=%s&max_depth=5", test.subject, test.object)
			req, _ := http.NewRequest("GET", url, nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("%s: HTTP error %d", test.description, rr.Code)
				continue
			}

			var pathResponse map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &pathResponse)

			found := pathResponse["found"].(bool)
			if found != test.shouldFind {
				t.Errorf("%s: Expected found=%v, got %v", test.description, test.shouldFind, found)
			} else if found {
				path := pathResponse["path"].(string)
				t.Logf("✓ %s: %s", test.description, path)
			}
		}
	})
}

func TestE2E_PermissionManagement(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("Dynamic Permission Management", func(t *testing.T) {
		// Test that permission mappings are working correctly
		req, _ := http.NewRequest("GET", "/api/v1/relationships/permissions", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to get permissions: %d", rr.Code)
		}

		var permsResponse map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &permsResponse)

		mappings := permsResponse["mappings"].(map[string]interface{})

		// Verify key relationship types have expected permissions
		expectedMappings := map[string][]string{
			"owner":  {"read", "write", "delete", "admin"},
			"editor": {"read", "write", "edit"},
			"viewer": {"read", "view"},
		}

		for relType, expectedPerms := range expectedMappings {
			if actualPermsInterface, exists := mappings[relType]; exists {
				actualPerms := make([]string, 0)
				for _, perm := range actualPermsInterface.([]interface{}) {
					actualPerms = append(actualPerms, perm.(string))
				}

				for _, expectedPerm := range expectedPerms {
					found := false
					for _, actualPerm := range actualPerms {
						if actualPerm == expectedPerm {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected permission '%s' not found for relationship '%s'", expectedPerm, relType)
					}
				}
			} else {
				t.Errorf("Relationship type '%s' not found in mappings", relType)
			}
		}

		// Test specific permission checks
		permissionTests := []struct {
			relationship string
			permission   string
			expected     bool
		}{
			{"owner", "read", true},
			{"owner", "write", true},
			{"owner", "delete", true},
			{"owner", "admin", true},
			{"editor", "read", true},
			{"editor", "write", true},
			{"editor", "delete", false},
			{"viewer", "read", true},
			{"viewer", "write", false},
			{"nonexistent", "read", false},
		}

		for _, test := range permissionTests {
			checkReq := map[string]string{
				"relationship": test.relationship,
				"permission":   test.permission,
			}

			reqBody, _ := json.Marshal(checkReq)
			req, _ := http.NewRequest("POST", "/api/v1/relationships/permissions/check", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Permission check failed for %s-%s: %d", test.relationship, test.permission, rr.Code)
				continue
			}

			var checkResponse map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &checkResponse)

			granted := checkResponse["granted"].(bool)
			if granted != test.expected {
				t.Errorf("Permission %s for %s: expected %v, got %v", test.permission, test.relationship, test.expected, granted)
			}
		}
	})
}

func TestE2E_ABACIntegration(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("Complex ABAC Scenario", func(t *testing.T) {
		// Scenario: Time and location-based access with clearance levels

		// Step 1: Set up user attributes
		users := map[string]map[string]string{
			"alice": {
				"department": "executive",
				"clearance":  "top_secret",
				"position":   "ceo",
			},
			"bob": {
				"department": "engineering",
				"clearance":  "secret",
				"position":   "manager",
			},
			"charlie": {
				"department": "engineering",
				"clearance":  "confidential",
				"position":   "engineer",
			},
		}

		for userID, attrs := range users {
			userAttrs := map[string]interface{}{
				"attributes": attrs,
			}
			reqBody, _ := json.Marshal(userAttrs)
			req, _ := http.NewRequest("PUT", fmt.Sprintf("/api/v1/users/%s/attributes", userID), bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Failed to set attributes for %s: %d", userID, rr.Code)
			}
		}

		// Step 2: Set up object attributes
		objects := map[string]map[string]string{
			"classified_doc": {
				"classification": "top_secret",
				"department":     "executive",
			},
			"project_plan": {
				"classification": "secret",
				"department":     "engineering",
			},
			"tech_specs": {
				"classification": "confidential",
				"department":     "engineering",
			},
		}

		for objectID, attrs := range objects {
			objAttrs := map[string]interface{}{
				"attributes": attrs,
			}
			reqBody, _ := json.Marshal(objAttrs)
			req, _ := http.NewRequest("PUT", fmt.Sprintf("/api/v1/objects/%s/attributes", objectID), bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Failed to set attributes for %s: %d", objectID, rr.Code)
			}
		}

		// Step 3: Create ABAC policies
		policies := []ABACPolicy{
			{
				ID:          "executive_access",
				Name:        "Executive Access",
				Description: "Executives can access all documents",
				Effect:      "allow",
				Priority:    100,
				Conditions: []PolicyCondition{
					{
						Type:     "user",
						Field:    "position",
						Operator: "eq",
						Value:    "ceo",
						LogicOp:  "",
					},
				},
			},
			{
				ID:          "clearance_based",
				Name:        "Clearance Based Access",
				Description: "Users can access documents at or below their clearance level",
				Effect:      "allow",
				Priority:    90,
				Conditions: []PolicyCondition{
					{
						Type:     "user",
						Field:    "clearance",
						Operator: "in",
						Value:    "secret,top_secret",
						LogicOp:  "and",
					},
					{
						Type:     "object",
						Field:    "classification",
						Operator: "in",
						Value:    "secret,confidential",
						LogicOp:  "",
					},
				},
			},
			{
				ID:          "department_access",
				Name:        "Department Access",
				Description: "Users can access documents from their department",
				Effect:      "allow",
				Priority:    80,
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
			},
		}

		for _, policy := range policies {
			reqBody, _ := json.Marshal(policy)
			req, _ := http.NewRequest("POST", "/api/v1/abac/policies", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Failed to create policy %s: %d, body: %s", policy.ID, rr.Code, rr.Body.String())
			}
		}

		// Step 4: Test ABAC authorization scenarios
		abacTests := []struct {
			subject  string
			object   string
			action   string
			expected bool
			scenario string
		}{
			{"alice", "classified_doc", "read", true, "CEO reads classified document"},
			{"alice", "project_plan", "read", true, "CEO reads project plan"},
			{"alice", "tech_specs", "read", true, "CEO reads tech specs"},
			{"bob", "project_plan", "read", true, "Manager reads secret project plan (clearance + dept)"},
			{"bob", "tech_specs", "read", true, "Manager reads confidential tech specs (dept)"},
			{"bob", "classified_doc", "read", false, "Manager cannot read top secret document"},
			{"charlie", "tech_specs", "read", true, "Engineer reads confidential tech specs (dept)"},
			{"charlie", "project_plan", "read", false, "Engineer cannot read secret project plan (clearance too low)"},
			{"charlie", "classified_doc", "read", false, "Engineer cannot read classified document"},
		}

		for _, test := range abacTests {
			authReq := EnforceRequest{
				Model:   ModelABAC,
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
			var allowed bool

			// Handle both 200 (allowed) and 403 (denied) as valid responses
			if rr.Code == http.StatusOK {
				json.Unmarshal(rr.Body.Bytes(), &authResponse)
				allowed = authResponse["allowed"].(bool)
			} else if rr.Code == http.StatusForbidden {
				json.Unmarshal(rr.Body.Bytes(), &authResponse)
				allowed = false // 403 means access denied
			} else {
				t.Errorf("%s: Unexpected HTTP status %d, body: %s", test.scenario, rr.Code, rr.Body.String())
				continue
			}

			if allowed != test.expected {
				t.Errorf("%s: Expected %v, got %v", test.scenario, test.expected, allowed)
			} else {
				t.Logf("✓ %s: %v (correct)", test.scenario, allowed)
			}
		}
	})
}

func TestE2E_ScalabilityDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scalability test in short mode")
	}

	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("Large Scale Organization", func(t *testing.T) {
		// Simulate a larger organization with hundreds of users and resources
		numUsers := 100
		numResources := 50
		numTeams := 10

		startTime := time.Now()

		// Create team structure
		for i := 0; i < numTeams; i++ {
			teamName := fmt.Sprintf("team_%d", i)
			
			// Add team members
			for j := 0; j < numUsers/numTeams; j++ {
				userID := fmt.Sprintf("user_%d_%d", i, j)
				
				rel := RelationshipRequest{
					Subject:      userID,
					Relationship: "member",
					Object:       teamName,
				}

				reqBody, _ := json.Marshal(rel)
				req, _ := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Fatalf("Failed to add team membership: %d", rr.Code)
				}
			}

			// Give teams access to resources
			for k := 0; k < numResources/numTeams; k++ {
				resourceID := fmt.Sprintf("resource_%d_%d", i, k)
				
				rel := RelationshipRequest{
					Subject:      teamName,
					Relationship: "group_access",
					Object:       resourceID,
				}

				reqBody, _ := json.Marshal(rel)
				req, _ := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Fatalf("Failed to add team access: %d", rr.Code)
				}
			}
		}

		setupTime := time.Since(startTime)
		t.Logf("Setup %d users, %d teams, %d resources in %v", numUsers, numTeams, numResources, setupTime)

		// Test authorization performance
		startTime = time.Now()
		testCount := 100

		for i := 0; i < testCount; i++ {
			teamIdx := i % numTeams
			userIdx := i % (numUsers / numTeams)
			resourceIdx := i % (numResources / numTeams)

			userID := fmt.Sprintf("user_%d_%d", teamIdx, userIdx)
			resourceID := fmt.Sprintf("resource_%d_%d", teamIdx, resourceIdx)

			authReq := EnforceRequest{
				Model:   ModelReBAC,
				Subject: userID,
				Object:  resourceID,
				Action:  "read",
			}

			reqBody, _ := json.Marshal(authReq)
			req, _ := http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Authorization check %d failed: %d", i, rr.Code)
			}

			var authResponse map[string]interface{}
			json.Unmarshal(rr.Body.Bytes(), &authResponse)

			if !authResponse["allowed"].(bool) {
				t.Errorf("Expected access to be allowed for user %s to resource %s", userID, resourceID)
			}
		}

		authTime := time.Since(startTime)
		avgTime := authTime / time.Duration(testCount)
		t.Logf("Performed %d authorization checks in %v (avg: %v per check)", testCount, authTime, avgTime)

		if avgTime > time.Millisecond*50 {
			t.Errorf("Average authorization time too slow: %v (expected < 50ms)", avgTime)
		}
	})
}

func TestE2E_DataConsistency(t *testing.T) {
	service := setupTestService(t)
	router := setupTestRouter(service)

	t.Run("Database Persistence and Consistency", func(t *testing.T) {
		// Add relationships and verify they persist
		relationships := []RelationshipRequest{
			{"alice", "owner", "document1"},
			{"bob", "editor", "document1"},
			{"alice", "member", "team1"},
		}

		for _, rel := range relationships {
			reqBody, _ := json.Marshal(rel)
			req, _ := http.NewRequest("POST", "/api/v1/relationships", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("Failed to add relationship: %d", rr.Code)
			}
		}

		// Verify relationships exist
		req, _ := http.NewRequest("GET", "/api/v1/relationships?subject=alice", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to get relationships: %d", rr.Code)
		}

		var relResponse map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &relResponse)

		relationships_data := relResponse["relationships"].([]interface{})
		if len(relationships_data) != 2 { // alice has 2 relationships
			t.Errorf("Expected 2 relationships for alice, got %d", len(relationships_data))
		}

		// Test removal
		req, _ = http.NewRequest("DELETE", "/api/v1/relationships/alice:owner:document1", nil)
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to delete relationship: %d", rr.Code)
		}

		// Verify removal
		authReq := EnforceRequest{
			Model:   ModelReBAC,
			Subject: "alice",
			Object:  "document1",
			Action:  "write",
		}

		reqBody, _ := json.Marshal(authReq)
		req, _ = http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		var authResponse map[string]interface{}
		if rr.Code == http.StatusOK {
			json.Unmarshal(rr.Body.Bytes(), &authResponse)
			// Alice should no longer have owner access
			if authResponse["allowed"].(bool) {
				t.Error("Alice should not have access after relationship removal")
			}
		} else if rr.Code == http.StatusForbidden {
			// 403 is expected - Alice should not have access
			json.Unmarshal(rr.Body.Bytes(), &authResponse)
			// This is the expected behavior after removal
		} else {
			t.Fatalf("Authorization check failed: %d", rr.Code)
		}

		// But Bob should still have editor access
		authReq.Subject = "bob"
		authReq.Action = "write"

		reqBody, _ = json.Marshal(authReq)
		req, _ = http.NewRequest("POST", "/api/v1/authorizations", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr = httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK {
			json.Unmarshal(rr.Body.Bytes(), &authResponse)
			if !authResponse["allowed"].(bool) {
				t.Error("Bob should still have editor access")
			}
		} else {
			t.Errorf("Bob's authorization check failed: %d, body: %s", rr.Code, rr.Body.String())
		}
	})
}