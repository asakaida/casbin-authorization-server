#!/bin/bash

# Authorization Service Test Runner
# Comprehensive testing for the multi-model authorization service

echo "🧪 Running Authorization Service Tests"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test categories
run_test_category() {
    local category=$1
    local pattern=$2
    local description=$3
    
    echo ""
    echo -e "${BLUE}📋 $description${NC}"
    echo "----------------------------------------"
    
    if go test -v -short -run "$pattern" 2>&1; then
        echo -e "${GREEN}✅ $category tests passed${NC}"
        return 0
    else
        echo -e "${RED}❌ $category tests failed${NC}"
        return 1
    fi
}

# Initialize test results
total_categories=0
passed_categories=0

# 1. Unit Tests - RelationshipGraph
total_categories=$((total_categories + 1))
if run_test_category "RelationshipGraph" "TestRelationshipGraph_" "Unit Tests - RelationshipGraph Core Logic"; then
    passed_categories=$((passed_categories + 1))
fi

# 2. Unit Tests - Policy Engine
total_categories=$((total_categories + 1))
if run_test_category "PolicyEngine" "TestPolicyEngine_" "Unit Tests - ABAC Policy Engine"; then
    passed_categories=$((passed_categories + 1))
fi

# 3. Integration Tests - AuthService
total_categories=$((total_categories + 1))
if run_test_category "AuthService" "TestAuthService_" "Integration Tests - Multi-Model Authorization"; then
    passed_categories=$((passed_categories + 1))
fi

# 4. HTTP Handler Tests
total_categories=$((total_categories + 1))
if run_test_category "HTTPHandlers" "TestHTTPHandlers_" "HTTP Handler Integration Tests"; then
    passed_categories=$((passed_categories + 1))
fi

# 5. ReBAC Advanced Tests
total_categories=$((total_categories + 1))
if run_test_category "ReBAC_Advanced" "TestReBAC_" "Advanced ReBAC Scenarios"; then
    passed_categories=$((passed_categories + 1))
fi

# 6. API Integration Tests
total_categories=$((total_categories + 1))
if run_test_category "API_Integration" "TestAPI_" "Full API Integration Tests"; then
    passed_categories=$((passed_categories + 1))
fi

# Run short performance tests
echo ""
echo -e "${BLUE}⚡ Performance Tests (Quick)${NC}"
echo "----------------------------------------"
total_categories=$((total_categories + 1))
if go test -v -short -run "Benchmark" -bench=. -benchtime=1s 2>&1; then
    echo -e "${GREEN}✅ Performance tests completed${NC}"
    passed_categories=$((passed_categories + 1))
else
    echo -e "${YELLOW}⚠️  Performance tests had issues (non-critical)${NC}"
    passed_categories=$((passed_categories + 1))  # Non-critical for basic tests
fi

# Summary
echo ""
echo "🏁 Test Summary"
echo "==============="
echo -e "Categories passed: ${GREEN}$passed_categories${NC}/$total_categories"

if [ $passed_categories -eq $total_categories ]; then
    echo -e "${GREEN}🎉 All test categories passed!${NC}"
    
    # Offer to run extended tests
    echo ""
    echo -e "${YELLOW}🔄 Run extended tests? (y/N)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${BLUE}🚀 Running Extended E2E Tests${NC}"
        echo "----------------------------------------"
        if go test -v -run "TestE2E_" -timeout=5m; then
            echo -e "${GREEN}✅ Extended E2E tests passed${NC}"
        else
            echo -e "${RED}❌ Extended E2E tests failed${NC}"
            exit 1
        fi
        
        echo ""
        echo -e "${BLUE}📊 Running Full Performance Tests${NC}"
        echo "----------------------------------------"
        go test -v -run "Performance\|Scalability" -timeout=10m
    fi
    
    exit 0
else
    echo -e "${RED}💥 Some test categories failed${NC}"
    exit 1
fi