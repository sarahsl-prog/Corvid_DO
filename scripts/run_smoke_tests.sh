#!/usr/bin/env bash
# run_smoke_tests.sh - Run smoke tests against a deployed Corvid instance
#
# Usage: ./scripts/run_smoke_tests.sh [URL]
#
# Arguments:
#   URL    Base URL of the Corvid instance (default: http://localhost:8000)
#
# Environment:
#   CORVID_TEST_URL    Alternative way to set the target URL

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get target URL
TARGET_URL="${1:-${CORVID_TEST_URL:-http://localhost:8000}}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Corvid Smoke Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Target: ${YELLOW}$TARGET_URL${NC}"
echo ""

PASSED=0
FAILED=0

# Test function
run_test() {
    local name="$1"
    local endpoint="$2"
    local method="${3:-GET}"
    local data="${4:-}"
    local expected_status="${5:-200}"

    echo -n "Testing $name... "

    if [[ "$method" == "GET" ]]; then
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint")
    else
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$TARGET_URL$endpoint")
    fi

    if [[ "$STATUS" == "$expected_status" ]]; then
        echo -e "${GREEN}PASSED${NC} (HTTP $STATUS)"
        ((PASSED++))
    else
        echo -e "${RED}FAILED${NC} (Expected $expected_status, got $STATUS)"
        ((FAILED++))
    fi
}

# Test health endpoint
run_test "Health check" "/health" "GET" "" "200"

# Test health response structure
echo -n "Testing health response structure... "
HEALTH_RESP=$(curl -s "$TARGET_URL/health")
if echo "$HEALTH_RESP" | grep -q '"status"' && echo "$HEALTH_RESP" | grep -q '"checks"'; then
    echo -e "${GREEN}PASSED${NC}"
    ((PASSED++))
else
    echo -e "${RED}FAILED${NC} (Invalid response structure)"
    ((FAILED++))
fi

# Test IOC list endpoint
run_test "List IOCs" "/api/v1/iocs/" "GET" "" "200"

# Test IOC creation
IOC_DATA='{"type": "ip", "value": "203.0.113.1", "tags": ["smoke-test"]}'
run_test "Create IOC" "/api/v1/iocs/" "POST" "$IOC_DATA" "201"

# Get created IOC ID for further tests
IOC_RESP=$(curl -s -X POST -H "Content-Type: application/json" -d "$IOC_DATA" "$TARGET_URL/api/v1/iocs/")
IOC_ID=$(echo "$IOC_RESP" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

if [[ -n "$IOC_ID" ]]; then
    # Test get specific IOC
    run_test "Get IOC by ID" "/api/v1/iocs/$IOC_ID" "GET" "" "200"

    # Test delete IOC
    run_test "Delete IOC" "/api/v1/iocs/$IOC_ID" "DELETE" "" "204"

    # Verify deletion
    run_test "Verify IOC deleted" "/api/v1/iocs/$IOC_ID" "GET" "" "404"
fi

# Test 404 for non-existent IOC
run_test "Non-existent IOC" "/api/v1/iocs/00000000-0000-0000-0000-000000000000" "GET" "" "404"

# Test invalid IOC type
INVALID_IOC='{"type": "invalid", "value": "test"}'
run_test "Invalid IOC type (422)" "/api/v1/iocs/" "POST" "$INVALID_IOC" "422"

# Test analysis list endpoint
run_test "List analyses" "/api/v1/analyses/" "GET" "" "200"

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "   Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo -e "${BLUE}========================================${NC}"

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All smoke tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some smoke tests failed${NC}"
    exit 1
fi
