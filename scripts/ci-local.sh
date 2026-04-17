#!/bin/bash
# Local CI Mirror Script
# =====================
# This script runs a reduced subset of the full CI pipeline locally.
#
# Full CI stages (see .github/workflows/ci.yml):
#   1. Lint & format (cargo fmt, clippy, 500-line check)
#   2. Security audit (cargo audit, cargo deny)
#   3. Test execution (cargo nextest, sharded 4-way in CI)
#   4. Coverage enforcement (cargo llvm-cov, 85% threshold)
#   5. SBOM generation (cargo sbom + CycloneDX validation)
#   6. Unsafe code audit (cargo geiger)
#   7. Burn-in loop (10 iterations in CI, flaky test detection)
#   8. Performance benchmarks (Criterion)
#
# This script runs:
#   1. Lint & format (including 500-line check)
#   2. Security audit (cargo audit + cargo deny)
#   3. Tests (cargo test, single process — no nextest sharding)
#   4. Coverage (cargo llvm-cov, 85% threshold)
#   5. Burn-in (3 iterations — reduced from CI's 10)
#   6. Benchmarks (optional, pass --bench)
#
# CI-only stages (skipped locally):
#   - SBOM generation (requires CycloneDX CLI)
#   - cargo geiger (slow, informational only)
#   - nextest sharding (unnecessary locally)
#   - Artifact uploads / PR comments

set -e  # Exit on any error

COVERAGE_THRESHOLD=85

echo "Running CI pipeline locally..."
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

echo -e "${YELLOW}>${NC} Checking formatting..."
if cargo fmt --all -- --check; then
    echo -e "${GREEN}ok${NC} Formatting check passed"
else
    echo -e "${RED}FAIL${NC} Formatting check failed"
    exit 1
fi

echo -e "${YELLOW}>${NC} Running clippy..."
if cargo clippy --all-targets --all-features -- -D warnings; then
    echo -e "${GREEN}ok${NC} Clippy passed"
else
    echo -e "${RED}FAIL${NC} Clippy failed"
    exit 1
fi

echo -e "${YELLOW}>${NC} Checking 500-line limit..."
if ./scripts/check-line-count.sh; then
    echo -e "${GREEN}ok${NC} Line count check passed"
else
    echo -e "${RED}FAIL${NC} Files exceed 500-line limit"
    exit 1
fi

echo ""

# Stage 2: Security Audit
echo "================================================"
echo "Stage 2: Security Audit"
echo "================================================"

echo -e "${YELLOW}>${NC} Running cargo audit..."
if command -v cargo-audit &> /dev/null; then
    if cargo audit; then
        echo -e "${GREEN}ok${NC} Security audit passed"
    else
        echo -e "${RED}FAIL${NC} Security audit found vulnerabilities"
        exit 1
    fi
else
    echo -e "${YELLOW}SKIP${NC} cargo-audit not installed (cargo install cargo-audit --locked)"
fi

echo -e "${YELLOW}>${NC} Running cargo deny..."
if command -v cargo-deny &> /dev/null; then
    if cargo deny check advisories && cargo deny check licenses && cargo deny check bans && cargo deny check sources; then
        echo -e "${GREEN}ok${NC} Dependency policy check passed"
    else
        echo -e "${RED}FAIL${NC} Dependency policy check failed"
        exit 1
    fi
else
    echo -e "${YELLOW}SKIP${NC} cargo-deny not installed (cargo install cargo-deny --locked)"
fi

echo ""

# Stage 3: Tests
echo "================================================"
echo "Stage 3: Test Execution"
echo "================================================"

echo -e "${YELLOW}>${NC} Running tests..."
if cargo test --all-features --workspace; then
    echo -e "${GREEN}ok${NC} Tests passed"
else
    echo -e "${RED}FAIL${NC} Tests failed"
    exit 1
fi

echo ""

# Stage 4: Coverage
echo "================================================"
echo "Stage 4: Coverage Enforcement (${COVERAGE_THRESHOLD}% required)"
echo "================================================"

echo -e "${YELLOW}>${NC} Running coverage analysis..."

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}SKIP${NC} cargo-llvm-cov not installed"
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
        echo "Current coverage: ${COVERAGE_PCT}%"
        echo "Required coverage: ${COVERAGE_THRESHOLD}%"

        if (( $(echo "$COVERAGE_PCT < $COVERAGE_THRESHOLD" | bc -l) )); then
            echo -e "${RED}FAIL${NC} Coverage below threshold: ${COVERAGE_PCT}% < ${COVERAGE_THRESHOLD}%"
            exit 1
        else
            echo -e "${GREEN}ok${NC} Coverage meets threshold: ${COVERAGE_PCT}% >= ${COVERAGE_THRESHOLD}%"
        fi
    else
        echo -e "${RED}FAIL${NC} Coverage analysis failed"
        exit 1
    fi
fi

echo ""

# Stage 5: Burn-in (reduced iterations for local execution)
echo "================================================"
echo "Stage 5: Burn-In Loop (3 iterations - reduced from CI's 10)"
echo "================================================"

echo "Purpose: Detect flaky/non-deterministic tests"
echo ""

for i in {1..3}; do
    echo -e "${YELLOW}>${NC} Burn-in iteration $i/3..."

    if ! cargo test --all-features --workspace; then
        echo ""
        echo -e "${RED}FLAKY TEST DETECTED!${NC}"
        echo "   Test failed on iteration $i/3"
        echo "   This indicates non-deterministic behavior"
        exit 1
    fi

    echo -e "${GREEN}ok${NC} Iteration $i/3 passed"
done

echo ""
echo -e "${GREEN}All 3 burn-in iterations passed - no flaky tests detected${NC}"
echo ""

# Stage 6: Benchmarks (optional - only if user requests)
if [[ "$1" == "--bench" ]]; then
    echo "================================================"
    echo "Stage 6: Performance Benchmarks"
    echo "================================================"

    echo -e "${YELLOW}>${NC} Running benchmarks..."
    if cargo bench -p nails-core --bench performance --all-features && \
       cargo bench -p nails-cli --bench startup --all-features; then
        echo -e "${GREEN}ok${NC} Benchmarks completed"
    else
        echo -e "${RED}FAIL${NC} Benchmarks failed"
        exit 1
    fi

    echo ""
fi

# Success summary
echo "================================================"
echo "Local CI Pipeline Complete"
echo "================================================"
echo ""
echo "Summary:"
echo "  ok  Formatting & Clippy & Line Count"
echo "  ok  Security Audit (cargo audit + cargo deny)"
echo "  ok  Unit & Integration Tests"
echo "  ok  Coverage (${COVERAGE_THRESHOLD}%)"
echo "  ok  Burn-in (3 iterations)"
if [[ "$1" == "--bench" ]]; then
    echo "  ok  Benchmarks"
fi
echo ""
echo "Your code is ready to push!"
