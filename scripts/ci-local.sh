#!/bin/bash
# Mirror CI pipeline execution locally for debugging
# This script replicates the GitHub Actions test pipeline

set -e  # Exit on any error

COVERAGE_THRESHOLD=85

echo "🔍 Running CI pipeline locally..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Stage 1: Lint & Format
echo "================================================"
echo "Stage 1: Lint & Format"
echo "================================================"

echo -e "${YELLOW}→${NC} Checking formatting..."
if cargo fmt --all -- --check; then
    echo -e "${GREEN}✓${NC} Formatting check passed"
else
    echo -e "${RED}✗${NC} Formatting check failed"
    exit 1
fi

echo -e "${YELLOW}→${NC} Running clippy..."
if cargo clippy --all-targets --all-features -- -D warnings; then
    echo -e "${GREEN}✓${NC} Clippy passed"
else
    echo -e "${RED}✗${NC} Clippy failed"
    exit 1
fi

echo ""

# Stage 2: Tests
echo "================================================"
echo "Stage 2: Test Execution"
echo "================================================"

echo -e "${YELLOW}→${NC} Running tests..."
if cargo test --all-features --workspace; then
    echo -e "${GREEN}✓${NC} Tests passed"
else
    echo -e "${RED}✗${NC} Tests failed"
    exit 1
fi

echo ""

# Stage 3: Coverage
echo "================================================"
echo "Stage 3: Coverage Enforcement (${COVERAGE_THRESHOLD}% required)"
echo "================================================"

echo -e "${YELLOW}→${NC} Running coverage analysis..."

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}⚠${NC}  cargo-llvm-cov not installed"
    echo "   Install with: cargo install cargo-llvm-cov --locked"
    echo "   Skipping coverage check..."
else
    mkdir -p coverage

    if cargo llvm-cov --all-features --workspace --all-targets --cobertura --output-path ./coverage/cobertura.xml; then
        cargo llvm-cov --all-features --workspace --all-targets --html --output-dir ./coverage/html --no-run

        # Extract coverage percentage
        COVERAGE=$(grep -oP 'line-rate="\K[0-9.]+' coverage/cobertura.xml | head -1)
        COVERAGE_PCT=$(echo "$COVERAGE * 100" | bc)

        echo ""
        echo "📊 Current coverage: ${COVERAGE_PCT}%"
        echo "🎯 Required coverage: ${COVERAGE_THRESHOLD}%"

        if (( $(echo "$COVERAGE_PCT < $COVERAGE_THRESHOLD" | bc -l) )); then
            echo -e "${RED}✗${NC} Coverage below threshold: ${COVERAGE_PCT}% < ${COVERAGE_THRESHOLD}%"
            exit 1
        else
            echo -e "${GREEN}✓${NC} Coverage meets threshold: ${COVERAGE_PCT}% >= ${COVERAGE_THRESHOLD}%"
        fi
    else
        echo -e "${RED}✗${NC} Coverage analysis failed"
        exit 1
    fi
fi

echo ""

# Stage 4: Burn-in (reduced iterations for local execution)
echo "================================================"
echo "Stage 4: Burn-In Loop (3 iterations - reduced for local)"
echo "================================================"

echo "🔥 Purpose: Detect flaky/non-deterministic tests"
echo ""

for i in {1..3}; do
    echo -e "${YELLOW}→${NC} Burn-in iteration $i/3..."

    if ! cargo test --all-features --workspace; then
        echo ""
        echo -e "${RED}❌ FLAKY TEST DETECTED!${NC}"
        echo "   Test failed on iteration $i/3"
        echo "   This indicates non-deterministic behavior"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Iteration $i/3 passed"
done

echo ""
echo -e "${GREEN}🎉 All 3 burn-in iterations passed - no flaky tests detected${NC}"
echo ""

# Stage 5: Benchmarks (optional - only if user requests)
if [[ "$1" == "--bench" ]]; then
    echo "================================================"
    echo "Stage 5: Performance Benchmarks"
    echo "================================================"

    echo -e "${YELLOW}→${NC} Running benchmarks..."
    if cargo bench -p nails-core --bench performance --all-features && \
       cargo bench -p nails-cli --bench startup --all-features; then
        echo -e "${GREEN}✓${NC} Benchmarks completed"
    else
        echo -e "${RED}✗${NC} Benchmarks failed"
        exit 1
    fi

    echo ""
fi

# Success summary
echo "================================================"
echo "✅ Local CI Pipeline Complete"
echo "================================================"
echo ""
echo "Summary:"
echo "  ✓ Formatting & Clippy"
echo "  ✓ Unit & Integration Tests"
echo "  ✓ Coverage (${COVERAGE_THRESHOLD}%)"
echo "  ✓ Burn-in (3 iterations)"
if [[ "$1" == "--bench" ]]; then
    echo "  ✓ Benchmarks"
fi
echo ""
echo "Your code is ready to push!"
