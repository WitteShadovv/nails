#!/bin/bash
# Standalone burn-in loop for detecting flaky tests
# Runs tests multiple times to catch non-deterministic failures

set -e

# Default iterations
ITERATIONS=${1:-10}

echo "🔥 Burn-in Loop: $ITERATIONS iterations"
echo "Purpose: Detect flaky/non-deterministic tests"
echo ""

FAILED=0
FAILED_ITERATION=0

for i in $(seq 1 $ITERATIONS); do
    echo "================================================"
    echo "🔥 Iteration $i/$ITERATIONS"
    echo "================================================"
    
    if ! cargo test --all-features --workspace; then
        FAILED=1
        FAILED_ITERATION=$i
        break
    fi
    
    echo "✅ Iteration $i/$ITERATIONS passed"
    echo ""
done

if [ $FAILED -eq 1 ]; then
    echo ""
    echo "❌ FLAKY TEST DETECTED!"
    echo "   Test failed on iteration $FAILED_ITERATION/$ITERATIONS"
    echo "   This indicates non-deterministic behavior"
    echo ""
    echo "Action required:"
    echo "  1. Review test output above"
    echo "  2. Identify which test failed"
    echo "  3. Fix the flaky test"
    echo "  4. Common causes:"
    echo "     - Race conditions"
    echo "     - Timing dependencies"
    echo "     - External state pollution"
    echo "     - Non-isolated test setup/teardown"
    exit 1
else
    echo "🎉 All $ITERATIONS iterations passed - no flaky tests detected"
    exit 0
fi
