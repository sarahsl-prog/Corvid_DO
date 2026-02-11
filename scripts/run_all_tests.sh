#!/usr/bin/env bash
# run_all_tests.sh - Run the complete Corvid test suite
#
# Usage: ./scripts/run_all_tests.sh [--coverage] [--verbose]
#
# Options:
#   --coverage    Generate HTML coverage report
#   --verbose     Show verbose test output
#   --phase N     Run only phase N tests (1-4)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
COVERAGE=false
VERBOSE=""
PHASE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            COVERAGE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE="-v"
            shift
            ;;
        --phase)
            PHASE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Corvid Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Ensure we're in project root
cd "$(dirname "$0")/.."

# Check if virtual environment is active
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    echo -e "${YELLOW}Warning: No virtual environment detected${NC}"
    echo "Run: source .venv/bin/activate"
fi

# Build pytest command
PYTEST_CMD="pytest"

if [[ "$COVERAGE" == "true" ]]; then
    PYTEST_CMD="$PYTEST_CMD --cov=corvid --cov-report=html --cov-report=term-missing"
fi

if [[ -n "$VERBOSE" ]]; then
    PYTEST_CMD="$PYTEST_CMD $VERBOSE"
fi

if [[ -n "$PHASE" ]]; then
    PYTEST_CMD="$PYTEST_CMD -m phase${PHASE}"
    echo -e "${BLUE}Running Phase $PHASE tests only${NC}"
fi

echo -e "${BLUE}Running: $PYTEST_CMD${NC}"
echo ""

# Run tests
if $PYTEST_CMD; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   All tests passed!${NC}"
    echo -e "${GREEN}========================================${NC}"

    if [[ "$COVERAGE" == "true" ]]; then
        echo ""
        echo -e "${BLUE}Coverage report: htmlcov/index.html${NC}"
    fi

    exit 0
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}   Some tests failed${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
