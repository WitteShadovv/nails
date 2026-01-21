# NAILS Test Suite

**Project:** NAILS (NixOS Anti-forensics Isolation & Layering System)  
**Test Framework:** Rust native + Criterion + Tarpaulin  
**Coverage Target:** 100% (enforced via pre-commit hooks)  
**TDD Methodology:** Red → Green → Refactor from Day 1

---

## Test Architecture Overview

### Test Pyramid Distribution

```
        /\
       /  \
      /Sys  \      10% - System Tests (20 tests) - Optional
     /------\      - Forensic validation (RQ1)
    /        \     - Performance benchmarks (RQ2)
   /  Integ   \    
  /------------\   20% - Integration Tests (40 tests)
 /              \  - Full command flows
/     Unit       \ - Rollback scenarios
-----------------  
       70%         70% - Unit Tests (140 tests)
                   - State machine logic
                   - Trait implementations
                   - Pre-flight validation
```

**Total:** ~200 tests for Phase 1 (4 core commands: activate, deactivate, emergency, status)

### Test Levels

#### Unit Tests (70% - ~140 tests)

**Location:** `nails/src/` (inline with modules) + `tests/unit/`

**Target Areas:**
- State machine transitions (30 tests)
- Filesystem trait mocking (25 tests)
- Pre-flight validation (20 tests)
- Artifact cleanup (15 tests)
- Error handling (15 tests)
- Configuration management (10 tests)
- State persistence (10 tests)
- NixOS integration (10 tests)
- Logging (5 tests)

**Run Command:**
```bash
cargo test --lib
```

#### Integration Tests (20% - ~40 tests)

**Location:** `tests/integration/`

**Target Areas:**
- Full command flows (12 tests)
- Rollback scenarios (10 tests)
- Error handling (8 tests)
- Idempotency (5 tests)
- State transitions (5 tests)

**Run Command:**
```bash
cargo test --test '*'
```

#### System Tests (10% - ~20 tests) - Optional

**Location:** `tests/system/` (Phase 2)

**Target Areas:**
- Forensic validation (8 tests - RQ1 thesis validation)
- Performance benchmarks (8 tests - RQ2 thesis validation)
- Cold boot attack resistance (4 tests - optional)

**Run Command:**
```bash
# Performance benchmarks
cargo bench

# Forensic validation (requires privileged container)
./tests/system/forensic-validation.sh
```

---

## Setup Instructions

### Prerequisites

- **Rust 1.70+** (specified in Cargo.toml)
- **Cargo** (included with Rust)
- **Git** (for pre-commit hooks)

### 1. Install Development Tools

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install coverage tooling
cargo install cargo-tarpaulin

# Install pre-commit hooks (Python required)
pip install pre-commit
pre-commit install

# Install additional test dependencies (optional)
cargo install cargo-watch  # Live test reloading
cargo install cargo-nextest  # Faster test runner
```

### 2. Verify Installation

```bash
# Check Rust version
rustc --version  # Should be 1.70+

# Check cargo-tarpaulin
cargo tarpaulin --version

# Check pre-commit
pre-commit --version
```

### 3. Environment Setup

No environment variables required for unit/integration tests. Tests use `MockFilesystem` trait (no root privileges needed).

For system tests (optional Phase 2):
```bash
# Optional: Forensic validation
export NAILS_FORENSIC_VM_IMAGE="/path/to/test-vm.qcow2"
```

---

## Running Tests

### Quick Start

```bash
# Run all tests (unit + integration)
cargo test

# Run with output display (no capture)
cargo test -- --nocapture

# Run specific test
cargo test test_activation_blocks_without_hidden_volume

# Run tests matching pattern
cargo test activation
```

### Development Workflow

```bash
# Watch mode (auto-rerun on file change)
cargo watch -x test

# Run tests with coverage
cargo tarpaulin --out Html --output-dir coverage/

# Open coverage report
open coverage/index.html  # macOS
xdg-open coverage/index.html  # Linux
```

### Test Coverage Enforcement

```bash
# Verify 100% coverage (required for commits)
cargo tarpaulin --fail-under 100

# Pre-commit hook runs this automatically
# If coverage < 100%, commit will be blocked
```

### CI/CD Pipeline

Tests run automatically on:
- **Every commit:** Unit tests + coverage check (100% required)
- **Pull requests:** Unit + integration tests
- **Nightly:** Performance benchmarks (regression detection)

---

## Test Architecture Details

### Trait-Based Mocking

**Key Design:** 99% of tests run **without root privileges** via trait abstraction.

```rust
// Production: Requires root
pub trait Filesystem {
    fn mount_overlay(&self, lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<()>;
    fn unmount(&self, target: &Path, force: bool) -> Result<()>;
    fn is_mounted(&self, target: &Path) -> Result<bool>;
}

pub struct RealFilesystem;  // Actual system calls

// Testing: No root required
pub struct MockFilesystem {
    mounted: Arc<Mutex<HashSet<PathBuf>>>,
    // ... controllable mock state
}
```

**Benefits:**
- Fast test execution (no actual mounts)
- Parallelizable (isolated state per test)
- CI-compatible (no privileged containers)
- Deterministic (no external dependencies)

### Property-Based Testing

**Strategy:** Use `proptest` for state machine validation.

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn state_transitions_always_valid(
        initial_state in any::<SystemState>(),
        next_state in any::<SystemState>()
    ) {
        // Property: Invalid transitions always rejected
        if !initial_state.can_transition_to(next_state) {
            let result = manager.transition(next_state);
            assert!(result.is_err());
        }
    }
}
```

### Fixture Pattern (Auto-Cleanup)

**Strategy:** RAII pattern ensures cleanup even on panic.

```rust
pub struct OverlayGuard {
    mount_point: PathBuf,
}

impl Drop for OverlayGuard {
    fn drop(&mut self) {
        // Automatic cleanup even if test panics
        let _ = unmount_overlay(&self.mount_point);
    }
}

#[test]
fn test_with_auto_cleanup() {
    let _guard = OverlayGuard::new("/tmp/test-mount");
    // Test code here
    // Cleanup happens automatically when _guard drops
}
```

---

## Test Organization

### Directory Structure

```
nails/
├── src/
│   ├── lib.rs                 # Unit tests inline with modules
│   ├── state.rs               # #[cfg(test)] mod tests { ... }
│   ├── filesystem.rs          # Unit tests for Filesystem trait
│   └── ...
├── tests/
│   ├── integration/           # Integration tests
│   │   ├── activation_flow.rs
│   │   ├── rollback_scenarios.rs
│   │   └── error_handling.rs
│   ├── system/                # System tests (Phase 2 optional)
│   │   ├── forensic/
│   │   └── benchmarks/
│   └── README.md              # This file
├── benches/
│   └── performance.rs         # Criterion benchmarks
└── Cargo.toml                 # Test dependencies
```

### Test Naming Convention

```rust
// Unit tests: test_<function>_<scenario>_<expected_result>
#[test]
fn test_activate_without_hidden_volume_returns_error() { }

// Integration tests: test_<feature>_<scenario>
#[test]
fn test_full_activation_deactivation_cycle() { }

// Property tests: prop_<property_being_tested>
proptest! {
    #[test]
    fn prop_state_transitions_never_invalid(state in any::<SystemState>()) { }
}
```

---

## Test Quality Standards

### Definition of Done (Test Requirements)

✅ **All tests must:**
1. Be **deterministic** (no flaky tests)
2. Be **isolated** (no shared state between tests)
3. Include **explicit assertions** (no silent passes)
4. Run **fast** (<1s per unit test, <10s per integration test)
5. Have **clear names** describing scenario and expectation
6. **Clean up** after themselves (no leaked state)
7. Use **MockFilesystem** (no actual filesystem operations in unit tests)

### Test Structure (Given-When-Then)

```rust
#[test]
fn test_activation_with_pre_flight_failure() {
    // GIVEN: Hidden volume is not mounted
    let config = test_config();
    let fs = MockFilesystem::new();  // No volume mounted
    let mut manager = NailsManager::new(config, fs).unwrap();

    // WHEN: Attempting activation
    let result = manager.activate();

    // THEN: Activation blocked with clear error
    assert!(matches!(result, Err(NailsError::HiddenVolumeNotMounted)));
    // AND: System remains in INACTIVE state
    assert_eq!(manager.state(), SystemState::Inactive);
}
```

---

## Benchmarking (Performance Tests)

### Criterion Benchmarks

**Location:** `benches/performance.rs`

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench activation

# Compare against baseline
cargo bench --save-baseline main
git checkout feature-branch
cargo bench --baseline main
```

### Performance Targets (RQ2 Validation)

| Operation | Target (p95) | Median | Notes |
|-----------|--------------|--------|-------|
| Activation (after build) | <5.0s | <3.0s | Subsequent activations |
| First activation (with build) | <60s | <45s | Initial NixOS profile build |
| Emergency deactivation | <3.0s | <2.5s | Critical for threat response |
| Status query | <500ms | <200ms | Lightweight operation |

### Example Benchmark

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_activation(c: &mut Criterion) {
    let config = test_config();
    let fs = MockFilesystem::new_with_profile_built();
    
    c.bench_function("activate_after_build", |b| {
        b.iter(|| {
            let mut manager = NailsManager::new(config.clone(), fs.clone()).unwrap();
            black_box(manager.activate())
        });
    });
}

criterion_group!(benches, benchmark_activation);
criterion_main!(benches);
```

---

## Pre-Commit Hooks

### Enforcement Strategy

**Pre-commit hooks prevent commits unless:**
1. ✅ All tests pass (`cargo test`)
2. ✅ Coverage ≥100% (`cargo tarpaulin --fail-under 100`)
3. ✅ Code formatted (`cargo fmt --check`)
4. ✅ No linter warnings (`cargo clippy -- -D warnings`)

### Hook Configuration

`.git/hooks/pre-commit` (installed via `pre-commit install`):

```bash
#!/bin/bash
set -e

echo "🔍 Running pre-commit checks..."

# Format check
echo "  • Checking code formatting..."
cargo fmt -- --check

# Lint check
echo "  • Running clippy lints..."
cargo clippy -- -D warnings

# Test execution
echo "  • Running tests..."
cargo test

# Coverage check (BLOCKS COMMIT IF <100%)
echo "  • Checking test coverage..."
cargo tarpaulin --fail-under 100 --quiet

echo "✅ All pre-commit checks passed!"
```

### Bypassing Hooks (NOT Recommended)

```bash
# Emergency bypass (use sparingly)
git commit --no-verify -m "WIP: Emergency commit"

# Better approach: Fix coverage gaps before committing
cargo tarpaulin  # Identify untested code
# Write missing tests
cargo tarpaulin --fail-under 100  # Verify
git commit  # Now passes hooks
```

---

## Continuous Integration (GitHub Actions)

### CI Pipeline Stages

**On Push:**
```yaml
- Run cargo test --lib (unit tests)
- Run cargo clippy
- Run cargo fmt --check
```

**On Pull Request:**
```yaml
- Run cargo test (all tests)
- Run cargo tarpaulin --fail-under 100
- Upload coverage to Codecov
```

**Nightly:**
```yaml
- Run cargo bench
- Compare against baseline
- Alert on regressions >10%
```

### CI Configuration

See `.github/workflows/ci.yml` for complete pipeline definition.

---

## Forensic Validation (System Tests - Phase 2)

### RQ1: Forensic Undetectability Testing

**Objective:** Validate that hidden environment artifacts are undetectable by forensic tools.

**Strategy:**

1. **Setup:** VM snapshot (clean NixOS state)
2. **Action:** Activate → perform operations → deactivate
3. **Validation:** Run forensic tools (Autopsy, Sleuth Kit, Volatility)
4. **Assert:** 0% detection rate of hidden environment traces

**Location:** `tests/system/forensic/validation.sh`

**Execution:** Requires privileged Docker/Podman container

```bash
# Run forensic validation suite
./tests/system/forensic/validation.sh

# Expected output:
# ✅ Autopsy: 0 traces detected
# ✅ Sleuth Kit: 0 traces detected
# ✅ Volatility: Minimal RAM traces (acceptable)
```

**Pass Criteria:** 0% detection rate across 3 forensic tools

---

## Common Testing Patterns

### Pattern 1: Testing State Transitions

```rust
#[test]
fn test_invalid_state_transition_rejected() {
    let mut manager = create_test_manager();
    manager.set_state(SystemState::Inactive);
    
    // Invalid: Cannot go from Inactive directly to Deactivating
    let result = manager.transition_to(SystemState::Deactivating);
    
    assert!(result.is_err());
    assert_eq!(manager.state(), SystemState::Inactive);  // State unchanged
}
```

### Pattern 2: Testing Rollback Scenarios

```rust
#[test]
fn test_partial_mount_triggers_rollback() {
    let config = test_config();
    let mut fs = MockFilesystem::new();
    
    // Mock: First mount succeeds, second fails
    fs.set_mount_behavior(|path| {
        if path.ends_with("/home") { Ok(()) }
        else { Err(FilesystemError::NoSpace) }
    });
    
    let mut manager = NailsManager::new(config, fs).unwrap();
    let result = manager.activate();
    
    // Assert: Activation failed
    assert!(matches!(result, Err(NailsError::MountFailed(_))));
    
    // Assert: Automatic rollback - first mount unmounted
    assert!(!manager.filesystem.is_mounted("/home"));
    
    // Assert: System back to INACTIVE state
    assert_eq!(manager.state(), SystemState::Inactive);
}
```

### Pattern 3: Testing Error Messages

```rust
#[test]
fn test_error_message_includes_fix_guidance() {
    let mut manager = create_test_manager();
    
    // Trigger error: swap enabled
    let result = manager.activate();
    
    match result {
        Err(NailsError::SwapEnabled(msg)) => {
            // Assert: Error message includes problem description
            assert!(msg.contains("Swap is enabled"));
            
            // Assert: Error message includes fix guidance
            assert!(msg.contains("sudo swapoff -a"));
        }
        _ => panic!("Expected SwapEnabled error"),
    }
}
```

---

## Troubleshooting

### Common Issues

#### Issue: Tests fail with "permission denied"

**Cause:** Test is attempting actual filesystem operations instead of using mock.

**Solution:**
```rust
// ❌ Wrong: Uses real filesystem
let manager = NailsManager::new(config, RealFilesystem);

// ✅ Correct: Uses mock filesystem
let manager = NailsManager::new(config, MockFilesystem::new());
```

#### Issue: Coverage <100% but all tests pass

**Cause:** Some code paths not exercised by tests.

**Solution:**
```bash
# Generate coverage report
cargo tarpaulin --out Html

# Open report to identify untested code
open tarpaulin-report.html

# Write tests for highlighted untested code
```

#### Issue: Tests are flaky (pass sometimes, fail other times)

**Cause:** Non-deterministic behavior (timing, shared state, external dependencies).

**Solution:**
- Remove `thread::sleep()` calls (use deterministic waits)
- Ensure test isolation (no shared state between tests)
- Use `MockFilesystem` (no actual system calls)

#### Issue: Benchmarks show regressions

**Cause:** Performance degradation in recent changes.

**Solution:**
```bash
# Compare against baseline
cargo bench --baseline main

# Profile to identify bottleneck
cargo flamegraph --bench performance

# Optimize hot path identified in flamegraph
```

---

## Knowledge Base References

### TEA Knowledge Fragments (Referenced from Test Design)

- **test-levels-framework.md** - Test level selection (Unit vs Integration vs System)
- **fixture-architecture.md** - RAII pattern for auto-cleanup
- **test-priorities-matrix.md** - P0-P3 prioritization (thesis scope)
- **risk-governance.md** - Risk-based test prioritization

### Related Documentation

- **Test Design:** `docs/test-design-system.md` (1,508 lines - comprehensive strategy)
- **Architecture:** `docs/architecture.md` (4,035 lines - TDD integration)
- **Development Guide:** `docs/development-guide.md` (TDD workflow)
- **PRD:** `docs/prd.md` (security requirements)

---

## Next Steps

### For Developers Starting TDD

1. ✅ **Read this README** (you are here!)
2. 🔲 **Set up development environment** (install cargo-tarpaulin, pre-commit)
3. 🔲 **Review test design document** (`docs/test-design-system.md`)
4. 🔲 **Start with first failing test** (Red phase)
   ```bash
   # Example: tests/unit/state_machine.rs
   cargo test test_activation_blocks_without_hidden_volume -- --nocapture
   # Expected: Test fails (not implemented yet)
   ```
5. 🔲 **Implement minimal code to pass** (Green phase)
6. 🔲 **Refactor and improve** (Refactor phase)
7. 🔲 **Verify coverage remains 100%** (`cargo tarpaulin --fail-under 100`)
8. 🔲 **Commit** (pre-commit hooks enforce quality)

### Recommended Workflow Sequence

```
✅ testarch/test-design   (COMPLETE - strategy defined)
✅ testarch/framework     (COMPLETE - this infrastructure)
🔲 testarch/ci            (Set up GitHub Actions pipeline)
🔲 testarch/atdd          (Generate failing tests for P0 scenarios)
🔲 Implementation         (TDD: Red → Green → Refactor)
🔲 testarch/automate      (Expand P1-P3 coverage)
```

---

## Contributing

### Test Development Guidelines

**Before writing tests:**
1. Review test design document for prioritization
2. Check existing tests for patterns
3. Use `MockFilesystem` for unit tests (no actual mounts)
4. Follow Given-When-Then structure

**Test quality checklist:**
- [ ] Test is deterministic (no flaky behavior)
- [ ] Test is isolated (no shared state)
- [ ] Test has clear name describing scenario
- [ ] Test includes explicit assertions
- [ ] Test runs fast (<1s for unit, <10s for integration)
- [ ] Test cleans up after itself

**Coverage enforcement:**
- Every commit must maintain 100% coverage
- Pre-commit hooks will block commits below 100%
- Coverage reports available in `coverage/` directory

---

## Support

### Resources

- **Test Design Document:** `docs/test-design-system.md`
- **Architecture Document:** `docs/architecture.md` (Section: Testing Strategy)
- **Rust Testing Guide:** https://doc.rust-lang.org/book/ch11-00-testing.html
- **Criterion Documentation:** https://bheisler.github.io/criterion.rs/book/

### Getting Help

- **Check existing tests** for patterns and examples
- **Review test design** for strategy and prioritization
- **Read architecture docs** for trait abstractions and design decisions

---

**Test Infrastructure Setup Complete!** 🎉

You're ready to begin TDD implementation. Start with the first failing test and work through the Red-Green-Refactor cycle.

**Next Command:**
```bash
# Generate first failing tests from test design
# (Run testarch/atdd workflow for P0 scenario generation)
```
