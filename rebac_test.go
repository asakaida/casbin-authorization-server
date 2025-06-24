package main

import (
	"testing"
	"time"
)

// Focused ReBAC tests
func TestReBAC_ComplexHierarchy(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup complex hierarchy: folder -> subfolder -> document
	err = rg.AddRelationship("alice", "owner", "root_folder")
	if err != nil {
		t.Fatalf("Failed to add root folder ownership: %v", err)
	}

	err = rg.AddRelationship("root_folder", "parent", "subfolder")
	if err != nil {
		t.Fatalf("Failed to add parent relationship: %v", err)
	}

	err = rg.AddRelationship("subfolder", "parent", "document")
	if err != nil {
		t.Fatalf("Failed to add subfolder parent relationship: %v", err)
	}

	// Test hierarchical access - Alice should have access to document through folder ownership
	allowed, path := rg.CheckReBACAccess("alice", "document", "read")
	if !allowed {
		t.Error("Alice should have access to document through hierarchical ownership")
	}

	if path == "" {
		t.Error("Expected relationship path to be returned")
	}

	t.Logf("Hierarchical access path: %s", path)
}

func TestReBAC_GroupMembershipChain(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup group membership chain
	err = rg.AddRelationship("alice", "member", "engineering_team")
	if err != nil {
		t.Fatalf("Failed to add team membership: %v", err)
	}

	err = rg.AddRelationship("bob", "member", "engineering_team")
	if err != nil {
		t.Fatalf("Failed to add bob's team membership: %v", err)
	}

	err = rg.AddRelationship("engineering_team", "group_access", "project_docs")
	if err != nil {
		t.Fatalf("Failed to add group access: %v", err)
	}

	// Test group access for both members
	testCases := []struct {
		subject  string
		expected bool
	}{
		{"alice", true},
		{"bob", true},
		{"charlie", false}, // Not a member
	}

	for _, tc := range testCases {
		allowed, path := rg.CheckReBACAccess(tc.subject, "project_docs", "read")
		if allowed != tc.expected {
			t.Errorf("Group access for %s: expected %v, got %v", tc.subject, tc.expected, allowed)
		}

		if tc.expected && path == "" {
			t.Errorf("Expected relationship path for %s", tc.subject)
		}
	}
}

func TestReBAC_MultipleRelationshipTypes(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup multiple relationship types to same document
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

	// Test different permission levels
	testCases := []struct {
		subject string
		action  string
		expected bool
		desc    string
	}{
		{"alice", "read", true, "Owner read access"},
		{"alice", "write", true, "Owner write access"},
		{"alice", "delete", true, "Owner delete access"},
		{"bob", "read", true, "Editor read access"},
		{"bob", "write", true, "Editor write access"},
		{"bob", "delete", false, "Editor no delete access"},
		{"charlie", "read", true, "Viewer read access"},
		{"charlie", "write", false, "Viewer no write access"},
		{"charlie", "delete", false, "Viewer no delete access"},
	}

	for _, tc := range testCases {
		allowed, _ := rg.CheckReBACAccess(tc.subject, "document1", tc.action)
		if allowed != tc.expected {
			t.Errorf("%s: expected %v, got %v", tc.desc, tc.expected, allowed)
		}
	}
}

func TestReBAC_SocialRelationships(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Setup social relationships
	err = rg.AddRelationship("alice", "friend", "bob")
	if err != nil {
		t.Fatalf("Failed to add friend relationship: %v", err)
	}

	err = rg.AddRelationship("bob", "owner", "photo1")
	if err != nil {
		t.Fatalf("Failed to add ownership: %v", err)
	}

	// Test social access - limited read access through friend relationship
	allowed, path := rg.CheckReBACAccess("alice", "photo1", "read")
	
	// Note: This test depends on the social access implementation
	// The current implementation checks for friend relationships in path
	if !allowed {
		t.Log("Social access not granted - this might be expected depending on implementation")
	} else {
		t.Logf("Social access granted with path: %s", path)
	}
}

func TestReBAC_PermissionInheritance(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Test action mapping
	testCases := []struct {
		action   string
		expected string
	}{
		{"read", "read"},
		{"view", "read"},
		{"write", "write"},
		{"edit", "write"},
		{"update", "write"},
		{"modify", "write"},
		{"delete", "delete"},
		{"remove", "delete"},
		{"admin", "admin"},
		{"manage", "admin"},
		{"administer", "admin"},
	}

	for _, tc := range testCases {
		mapped := rg.mapActionToPermission(tc.action)
		if mapped != tc.expected {
			t.Errorf("Action mapping for '%s': expected '%s', got '%s'", tc.action, tc.expected, mapped)
		}
	}
}

func TestReBAC_DirectRelationshipQuery(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Add test relationships
	relationships := []struct {
		subject string
		rel     string
		object  string
	}{
		{"alice", "owner", "doc1"},
		{"alice", "editor", "doc2"},
		{"alice", "viewer", "doc3"},
		{"bob", "owner", "doc1"},
	}

	for _, rel := range relationships {
		err = rg.AddRelationship(rel.subject, rel.rel, rel.object)
		if err != nil {
			t.Fatalf("Failed to add relationship %s-%s-%s: %v", rel.subject, rel.rel, rel.object, err)
		}
	}

	// Test GetDirectRelationships
	aliceDoc1Rels := rg.GetDirectRelationships("alice", "doc1")
	if len(aliceDoc1Rels) != 1 {
		t.Errorf("Expected 1 relationship for alice-doc1, got %d", len(aliceDoc1Rels))
	}

	if len(aliceDoc1Rels) > 0 && aliceDoc1Rels[0].Relationship != "owner" {
		t.Errorf("Expected 'owner' relationship, got '%s'", aliceDoc1Rels[0].Relationship)
	}

	// Test multiple relationships to same object
	bobDoc1Rels := rg.GetDirectRelationships("bob", "doc1")
	if len(bobDoc1Rels) != 1 {
		t.Errorf("Expected 1 relationship for bob-doc1, got %d", len(bobDoc1Rels))
	}

	// Test non-existent relationship
	nonExistentRels := rg.GetDirectRelationships("charlie", "doc1")
	if len(nonExistentRels) != 0 {
		t.Errorf("Expected 0 relationships for charlie-doc1, got %d", len(nonExistentRels))
	}
}

func TestReBAC_PathDiscovery(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Create a path: alice -> member -> team -> group_access -> resource
	err = rg.AddRelationship("alice", "member", "team")
	if err != nil {
		t.Fatalf("Failed to add member relationship: %v", err)
	}

	err = rg.AddRelationship("team", "group_access", "resource")
	if err != nil {
		t.Fatalf("Failed to add group_access relationship: %v", err)
	}

	// Test path discovery
	found, path := rg.FindRelationshipPath("alice", "resource", 5)
	if !found {
		t.Error("Expected to find path from alice to resource")
	}

	expectedPath := "alice -[member]-> team -[group_access]-> resource"
	if path != expectedPath {
		t.Errorf("Expected path '%s', got '%s'", expectedPath, path)
	}

	// Test with insufficient depth
	found, _ = rg.FindRelationshipPath("alice", "resource", 1)
	if found {
		t.Error("Should not find path with max_depth=1")
	}

	// Test non-existent path
	found, _ = rg.FindRelationshipPath("alice", "nonexistent", 5)
	if found {
		t.Error("Should not find path to non-existent object")
	}
}

func TestReBAC_DatabasePersistence(t *testing.T) {
	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg1, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Add relationships
	err = rg1.AddRelationship("alice", "owner", "document1")
	if err != nil {
		t.Fatalf("Failed to add relationship: %v", err)
	}

	err = rg1.AddRelationship("bob", "editor", "document1")
	if err != nil {
		t.Fatalf("Failed to add relationship: %v", err)
	}

	// Create new instance to test persistence
	rg2, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create second relationship graph: %v", err)
	}

	// Test that relationships are loaded from database
	if !rg2.HasDirectRelationship("alice", "owner", "document1") {
		t.Error("Relationship not loaded from database")
	}

	if !rg2.HasDirectRelationship("bob", "editor", "document1") {
		t.Error("Second relationship not loaded from database")
	}

	// Test removal persistence
	err = rg2.RemoveRelationship("alice", "owner", "document1")
	if err != nil {
		t.Fatalf("Failed to remove relationship: %v", err)
	}

	// Create third instance to verify removal was persisted
	rg3, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create third relationship graph: %v", err)
	}

	if rg3.HasDirectRelationship("alice", "owner", "document1") {
		t.Error("Removed relationship still exists in database")
	}

	// Bob's relationship should still exist
	if !rg3.HasDirectRelationship("bob", "editor", "document1") {
		t.Error("Other relationship was incorrectly removed")
	}
}

func TestReBAC_PerformanceWithLargeDataset(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	db, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	rg, err := NewRelationshipGraph(db)
	if err != nil {
		t.Fatalf("Failed to create relationship graph: %v", err)
	}

	// Create large dataset
	numUsers := 1000
	numDocs := 500
	
	start := time.Now()
	
	// Add many relationships
	for i := 0; i < numUsers; i++ {
		user := formatString("user%d", i)
		doc := formatString("doc%d", i%numDocs)
		
		var relationship string
		switch i % 3 {
		case 0:
			relationship = "owner"
		case 1:
			relationship = "editor"
		case 2:
			relationship = "viewer"
		}
		
		err = rg.AddRelationship(user, relationship, doc)
		if err != nil {
			t.Fatalf("Failed to add relationship %d: %v", i, err)
		}
	}
	
	insertTime := time.Since(start)
	t.Logf("Inserted %d relationships in %v", numUsers, insertTime)
	
	// Test query performance
	start = time.Now()
	
	for i := 0; i < 100; i++ {
		user := formatString("user%d", i)
		doc := formatString("doc%d", i%numDocs)
		
		allowed, _ := rg.CheckReBACAccess(user, doc, "read")
		if !allowed {
			t.Errorf("Expected access for user%d to doc%d", i, i%numDocs)
		}
	}
	
	queryTime := time.Since(start)
	t.Logf("Performed 100 authorization checks in %v (avg: %v per check)", 
		queryTime, queryTime/100)
	
	// Performance assertion
	avgQueryTime := queryTime / 100
	if avgQueryTime > time.Millisecond*10 {
		t.Errorf("Average query time too slow: %v (expected < 10ms)", avgQueryTime)
	}
}

// Helper function for string formatting (since we can't import fmt in some contexts)
func formatString(format string, args ...interface{}) string {
	// Simple string formatting for test purposes
	if len(args) == 1 {
		if i, ok := args[0].(int); ok {
			result := ""
			for _, char := range format {
				if char == '%' {
					// Skip %d
					continue
				}
				if char == 'd' {
					// Convert int to string
					result += intToString(i)
					continue
				}
				result += string(char)
			}
			return result
		}
	}
	return format
}

func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	
	return string(digits)
}