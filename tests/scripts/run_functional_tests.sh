#!/bin/bash
# Run functional tests for Corvid
# Usage: ./tests/scripts/run_functional_tests.sh [URL]

set -e

URL="${1:-http://localhost:8000}"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Corvid Functional Test Suite"
echo "=========================================="
echo "Testing against: $URL"
echo ""

# Check if URL is provided
if [ -z "$URL" ]; then
    echo -e "${RED}Error: Please provide URL as argument or set CORVID_TEST_URL${NC}"
    exit 1
fi

# Function to run a test and report
run_test() {
    local name="$1"
    local command="$2"
    
    echo -n "Testing: $name ... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi
}

# Counters
PASSED=0
FAILED=0

# Health Check
echo "----------------------------------------"
echo "1. Health Check"
echo "----------------------------------------"
if run_test "Health endpoint" "curl -s -o /dev/null -w '%{http_code}' $URL/health | grep -q '200'"; then
    ((PASSED++))
else
    ((FAILED++))
fi
echo ""

# IOC Creation Tests
echo "----------------------------------------"
echo "2. IOC Creation"
echo "----------------------------------------"

# Test valid IP
IOC_IP_RESPONSE=$(curl -s -X POST "$URL/api/v1/iocs/" \
    -H "Content-Type: application/json" \
    -d '{"type": "ip", "value": "8.8.8.8", "tags": ["functional-test"]}')
if echo "$IOC_IP_RESPONSE" | grep -q '"id"'; then
    echo -e "Create valid IP ... ${GREEN}PASS${NC}"
    ((PASSED++))
    IOC_IP_ID=$(echo "$IOC_IP_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
else
    echo -e "Create valid IP ... ${RED}FAIL${NC}"
    ((FAILED++))
fi

# Test invalid type
if curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/api/v1/iocs/" \
    -H "Content-Type: application/json" \
    -d '{"type": "invalid_type", "value": "test"}' | grep -q '422'; then
    echo -e "Reject invalid type ... ${GREEN}PASS${NC}"
    ((PASSED++))
else
    echo -e "Reject invalid type ... ${RED}FAIL${NC}"
    ((FAILED++))
fi

# Test empty value
if curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/api/v1/iocs/" \
    -H "Content-Type: application/json" \
    -d '{"type": "ip", "value": ""}' | grep -q '422'; then
    echo -e "Reject empty value ... ${GREEN}PASS${NC}"
    ((PASSED++))
else
    echo -e "Reject empty value ... ${RED}FAIL${NC}"
    ((FAILED++))
fi

# Test type/value mismatch
if curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/api/v1/iocs/" \
    -H "Content-Type: application/json" \
    -d '{"type": "ip", "value": "not.an.ip"}' | grep -q '422'; then
    echo -e "Reject type/value mismatch ... ${GREEN}PASS${NC}"
    ((PASSED++))
else
    echo -e "Reject type/value mismatch ... ${RED}FAIL${NC}"
    ((FAILED++))
fi

echo ""

# IOC Retrieval Tests
echo "----------------------------------------"
echo "3. IOC Retrieval"
echo "----------------------------------------"

if [ -n "$IOC_IP_ID" ]; then
    if curl -s "$URL/api/v1/iocs/$IOC_IP_ID" | grep -q "8.8.8.8"; then
        echo -e "Retrieve IOC by ID ... ${GREEN}PASS${NC}"
        ((PASSED++))
    else
        echo -e "Retrieve IOC by ID ... ${RED}FAIL${NC}"
        ((FAILED++))
    fi
else
    echo -e "Retrieve IOC by ID ... ${YELLOW}SKIP (no ID)${NC}"
fi

# List all IOCs
if curl -s "$URL/api/v1/iocs" | grep -q "items"; then
    echo -e "List IOCs ... ${GREEN}PASS${NC}"
    ((PASSED++))
else
    echo -e "List IOCs ... ${RED}FAIL${NC}"
    ((FAILED++))
fi

echo ""

# Analysis Tests
echo "----------------------------------------"
echo "4. Analysis"
echo "----------------------------------------"

# Test analysis endpoint exists
if curl -s -o /dev/null -w '%{http_code}' -X POST "$URL/api/v1/iocs/analyze" \
    -H "Content-Type: application/json" \
    -d '{"iocs": [{"type": "ip", "value": "8.8.8.8"}], "context": "test", "priority": "low"}' | grep -q '200\|201'; then
    echo -e "Submit analysis ... ${GREEN}PASS${NC}"
    ((PASSED++))
else
    echo -e "Submit analysis ... ${RED}FAIL${NC}"
    ((FAILED++))
fi

echo ""

# Cleanup
echo "----------------------------------------"
echo "5. Cleanup"
echo "----------------------------------------"

if [ -n "$IOC_IP_ID" ]; then
    if curl -s -o /dev/null -w '%{http_code}' -X DELETE "$URL/api/v1/iocs/$IOC_IP_ID" | grep -q '200\|204'; then
        echo -e "Delete IOC ... ${GREEN}PASS${NC}"
        ((PASSED++))
    else
        echo -e "Delete IOC ... ${RED}FAIL${NC}"
        ((FAILED++))
    fi
else
    echo -e "Delete IOC ... ${YELLOW}SKIP (no ID)${NC}"
fi

echo ""
echo "=========================================="
echo "Test Results"
echo "=========================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
