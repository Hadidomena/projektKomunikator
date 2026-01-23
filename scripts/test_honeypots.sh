#!/bin/bash
#
# Honeypot Testing Script for Komunikator (Linux/macOS version)
# This script tests the honeypot protection on registration and login endpoints.
#
# Usage:
#   ./test_honeypots.sh [BASE_URL]
#
# Examples:
#   ./test_honeypots.sh                          # Uses default http://localhost:8000
#   ./test_honeypots.sh http://localhost:8000    # Custom URL
#   VERBOSE=1 ./test_honeypots.sh                # Verbose output
#   LONG_DELAY=1 ./test_honeypots.sh             # Use 15s delays to avoid nginx rate limits
#

set -e

BASE_URL="${1:-http://localhost:8000}"
VERBOSE="${VERBOSE:-0}"
LONG_DELAY="${LONG_DELAY:-0}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
ERRORS=0

echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}  Honeypot Testing Script${NC}"
echo -e "${CYAN}  Testing: ${BASE_URL}${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""

# Check if curl is available
if ! command -v curl &> /dev/null; then
    echo -e "${RED}ERROR: curl is required but not installed.${NC}"
    exit 1
fi

# Check if jq is available (optional, for JSON parsing)
HAS_JQ=0
if command -v jq &> /dev/null; then
    HAS_JQ=1
fi

# Test connection first
echo -e "${YELLOW}Testing connection to server...${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}' \
    --connect-timeout 5 2>/dev/null || echo "000")

if [ "$HTTP_CODE" == "000" ]; then
    echo -e "${RED}  ERROR: Cannot connect to server at ${BASE_URL}${NC}"
    echo -e "${YELLOW}  Make sure the server is running (docker-compose up)${NC}"
    echo ""
    echo -e "${YELLOW}  Tip: Check if correct port is used:${NC}"
    echo -e "${GRAY}    - nginx proxy: port 8000 (default)${NC}"
    echo -e "${GRAY}    - direct backend: port 8080 (inside docker network)${NC}"
    exit 1
else
    echo -e "${GREEN}  Server is responding (got HTTP ${HTTP_CODE})${NC}"
fi
echo ""

# Test function
test_endpoint() {
    local name="$1"
    local url="$2"
    local body="$3"
    local expected_status="$4"
    local success_msg="$5"

    echo -e "${YELLOW}Testing: ${name}${NC}"

    if [ "$VERBOSE" == "1" ]; then
        echo -e "${GRAY}  Request Body: ${body}${NC}"
    fi

    # Make the request
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${url}" \
        -H "Content-Type: application/json" \
        -d "${body}" \
        --connect-timeout 10 2>&1)

    # Extract status code (last line) and body (everything else)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$VERBOSE" == "1" ]; then
        echo -e "${GRAY}  Status Code: ${HTTP_CODE}${NC}"
        echo -e "${GRAY}  Response: ${BODY}${NC}"
    fi

    # Check if it matches expected status
    if [ "$HTTP_CODE" == "$expected_status" ]; then
        echo -e "${GREEN}  PASSED: ${success_msg} (status: ${HTTP_CODE})${NC}"
        ((PASSED++))
    else
        echo -e "${RED}  FAILED: Expected status ${expected_status}, got: ${HTTP_CODE}${NC}"
        ((FAILED++))
    fi
    echo ""
}

# ============================================
# Registration Honeypot Tests
# ============================================

echo -e "${MAGENTA}=== Registration Honeypot Tests ===${NC}"
echo ""

# Test 1: Normal registration (no honeypot triggered)
RANDOM_NUM=$RANDOM
test_endpoint \
    "Registration - Normal (no honeypot)" \
    "${BASE_URL}/api/register" \
    "{\"username\":\"testuser_${RANDOM_NUM}\",\"email\":\"test${RANDOM_NUM}@example.com\",\"password\":\"SecureP@ss123!\",\"website\":\"\"}" \
    "201" \
    "Normal registration handled correctly"

# Note: Test might return 400 if password policy is different, or 201 if successful
# Adjust validator as needed

# Test 2: Registration with honeypot field filled (bot behavior)
RANDOM_NUM=$RANDOM
test_endpoint \
    "Registration - Honeypot filled (bot detected)" \
    "${BASE_URL}/api/register" \
    "{\"username\":\"bot_user_${RANDOM_NUM}\",\"email\":\"bot${RANDOM_NUM}@example.com\",\"password\":\"BotP@ss123!\",\"website\":\"http://spam-site.com\"}" \
    "201" \
    "Bot trapped - fake success returned"

# ============================================
# Login Honeypot Tests  
# ============================================

echo -e "${MAGENTA}=== Login Honeypot Tests ===${NC}"
echo ""

# Delay between tests to avoid rate limiting (in seconds)
# nginx has 5r/m limit on /api/login, so we need 12-15 seconds between requests
# when using LONG_DELAY=1 for production-like testing
if [ "$LONG_DELAY" == "1" ]; then
    TEST_DELAY=15
    echo -e "${YELLOW}Using long delays (${TEST_DELAY}s) to respect nginx rate limits${NC}"
    echo ""
else
    TEST_DELAY=1
    echo -e "${GRAY}NOTE: nginx rate limits may cause 503 errors. Use LONG_DELAY=1 for reliable testing.${NC}"
    echo ""
fi

# Test 3: Normal login (no honeypot triggered)
RANDOM_EMAIL3="test_normal_${RANDOM}@example.com"
test_endpoint \
    "Login - Normal (no honeypot)" \
    "${BASE_URL}/api/login" \
    "{\"email\":\"${RANDOM_EMAIL3}\",\"password\":\"wrongpassword\",\"website\":\"\",\"phone\":\"\",\"middle_name\":\"\"}" \
    "401" \
    "Normal login failure handled correctly"

sleep $TEST_DELAY

# Test 4: Login with website honeypot filled
RANDOM_EMAIL4="bot_web_${RANDOM}@example.com"
test_endpoint \
    "Login - Website honeypot filled (bot detected)" \
    "${BASE_URL}/api/login" \
    "{\"email\":\"${RANDOM_EMAIL4}\",\"password\":\"password123\",\"website\":\"http://malicious-site.com\",\"phone\":\"\",\"middle_name\":\"\"}" \
    "401" \
    "Bot trapped via website field"

sleep $TEST_DELAY

# Test 5: Login with phone honeypot filled
RANDOM_EMAIL5="bot_phone_${RANDOM}@example.com"
test_endpoint \
    "Login - Phone honeypot filled (bot detected)" \
    "${BASE_URL}/api/login" \
    "{\"email\":\"${RANDOM_EMAIL5}\",\"password\":\"password123\",\"website\":\"\",\"phone\":\"+1234567890\",\"middle_name\":\"\"}" \
    "401" \
    "Bot trapped via phone field"

sleep $TEST_DELAY

# Test 6: Login with middle_name honeypot filled
RANDOM_EMAIL6="bot_middle_${RANDOM}@example.com"
test_endpoint \
    "Login - Middle name honeypot filled (bot detected)" \
    "${BASE_URL}/api/login" \
    "{\"email\":\"${RANDOM_EMAIL6}\",\"password\":\"password123\",\"website\":\"\",\"phone\":\"\",\"middle_name\":\"Bot\"}" \
    "401" \
    "Bot trapped via middle_name field"

sleep $TEST_DELAY

# Test 7: Login with ALL honeypot fields filled (aggressive bot)
RANDOM_EMAIL7="bot_aggressive_${RANDOM}@example.com"
test_endpoint \
    "Login - All honeypots filled (aggressive bot)" \
    "${BASE_URL}/api/login" \
    "{\"email\":\"${RANDOM_EMAIL7}\",\"password\":\"password123\",\"website\":\"http://spam.com\",\"phone\":\"+9999999999\",\"middle_name\":\"Spammer\"}" \
    "401" \
    "Aggressive bot trapped"

# ============================================
# Summary
# ============================================

echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}  Test Summary${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""

TOTAL=$((PASSED + FAILED + ERRORS))
echo -e "Total Tests: ${TOTAL}"
echo -e "${GREEN}Passed: ${PASSED}${NC}"

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: ${FAILED}${NC}"
else
    echo -e "${GREEN}Failed: ${FAILED}${NC}"
fi

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}Errors: ${ERRORS}${NC}"
else
    echo -e "${GREEN}Errors: ${ERRORS}${NC}"
fi
echo ""

if [ $FAILED -eq 0 ] && [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All honeypot tests passed!${NC}"
    exit 0
else
    exit 1
fi
