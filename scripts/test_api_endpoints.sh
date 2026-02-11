#!/usr/bin/env bash
# test_api_endpoints.sh - Detailed API endpoint testing with verbose output
#
# Usage: ./scripts/test_api_endpoints.sh [URL]
#
# This script tests all API endpoints with detailed output showing
# request/response data for debugging and verification.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get target URL
TARGET_URL="${1:-${CORVID_TEST_URL:-http://localhost:8000}}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Corvid API Endpoint Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Target: ${YELLOW}$TARGET_URL${NC}"
echo ""

# Helper function for pretty JSON
pretty_json() {
    python3 -m json.tool 2>/dev/null || cat
}

# Test with full output
test_endpoint() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local data="${4:-}"

    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Test: $name${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}Request:${NC}"
    echo "  $method $TARGET_URL$endpoint"

    if [[ -n "$data" ]]; then
        echo -e "${YELLOW}Body:${NC}"
        echo "$data" | pretty_json | sed 's/^/  /'
    fi

    echo ""
    echo -e "${YELLOW}Response:${NC}"

    if [[ "$method" == "GET" ]]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$endpoint")
    elif [[ "$method" == "DELETE" ]]; then
        RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$TARGET_URL$endpoint")
    else
        RESPONSE=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$TARGET_URL$endpoint")
    fi

    # Split response body and status code
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    echo "  Status: $HTTP_CODE"
    if [[ -n "$BODY" ]]; then
        echo "  Body:"
        echo "$BODY" | pretty_json | sed 's/^/    /'
    fi
    echo ""
}

# ============================================
# Health Check Tests
# ============================================
echo -e "${GREEN}▶ Health Check Tests${NC}"
echo ""

test_endpoint "Health endpoint" "GET" "/health"

# ============================================
# IOC CRUD Tests
# ============================================
echo -e "${GREEN}▶ IOC CRUD Tests${NC}"
echo ""

# Create test IOCs
test_endpoint "Create IP IOC" "POST" "/api/v1/iocs/" \
    '{"type": "ip", "value": "198.51.100.1", "tags": ["test", "api-test"]}'

test_endpoint "Create domain IOC" "POST" "/api/v1/iocs/" \
    '{"type": "domain", "value": "test.example.com", "tags": ["test"]}'

test_endpoint "Create hash IOC" "POST" "/api/v1/iocs/" \
    '{"type": "hash_sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "tags": ["test", "empty-file"]}'

test_endpoint "Create URL IOC" "POST" "/api/v1/iocs/" \
    '{"type": "url", "value": "https://test.example.com/path", "tags": ["test"]}'

# List IOCs
test_endpoint "List all IOCs" "GET" "/api/v1/iocs/"
test_endpoint "List with filter (type=ip)" "GET" "/api/v1/iocs/?type=ip"
test_endpoint "List with pagination" "GET" "/api/v1/iocs/?limit=2&offset=0"

# Get specific IOC (use first one from list)
echo -e "${YELLOW}Getting IOC ID from list...${NC}"
IOC_ID=$(curl -s "$TARGET_URL/api/v1/iocs/" | python3 -c "import sys, json; items=json.load(sys.stdin).get('items',[]); print(items[0]['id'] if items else '')" 2>/dev/null || echo "")

if [[ -n "$IOC_ID" ]]; then
    test_endpoint "Get IOC by ID" "GET" "/api/v1/iocs/$IOC_ID"

    # Duplicate creation (should update last_seen)
    test_endpoint "Create duplicate IOC" "POST" "/api/v1/iocs/" \
        '{"type": "ip", "value": "198.51.100.1", "tags": ["duplicate-test"]}'

    # Delete IOC
    test_endpoint "Delete IOC" "DELETE" "/api/v1/iocs/$IOC_ID"
    test_endpoint "Verify deletion (expect 404)" "GET" "/api/v1/iocs/$IOC_ID"
else
    echo -e "${RED}Could not get IOC ID for detailed tests${NC}"
fi

# ============================================
# Validation Tests
# ============================================
echo -e "${GREEN}▶ Validation Tests${NC}"
echo ""

test_endpoint "Invalid IOC type" "POST" "/api/v1/iocs/" \
    '{"type": "invalid_type", "value": "test"}'

test_endpoint "Empty value" "POST" "/api/v1/iocs/" \
    '{"type": "ip", "value": ""}'

test_endpoint "Missing required field" "POST" "/api/v1/iocs/" \
    '{"type": "ip"}'

# ============================================
# Analysis Tests
# ============================================
echo -e "${GREEN}▶ Analysis Tests${NC}"
echo ""

test_endpoint "List analyses" "GET" "/api/v1/analyses/"

# Test analyze endpoint if it exists
test_endpoint "Analyze IOC" "POST" "/api/v1/analyses/analyze" \
    '{"iocs": [{"type": "ip", "value": "8.8.8.8"}], "context": "API test", "priority": "low"}'

# ============================================
# Error Handling Tests
# ============================================
echo -e "${GREEN}▶ Error Handling Tests${NC}"
echo ""

test_endpoint "Non-existent IOC" "GET" "/api/v1/iocs/00000000-0000-0000-0000-000000000000"
test_endpoint "Non-existent analysis" "GET" "/api/v1/analyses/00000000-0000-0000-0000-000000000000"
test_endpoint "Invalid UUID format" "GET" "/api/v1/iocs/not-a-uuid"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   API Testing Complete${NC}"
echo -e "${BLUE}========================================${NC}"
