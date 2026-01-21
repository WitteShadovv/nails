# Integration Tests

This directory contains integration tests that verify full command flows and system behavior.

## Test Organization

- `activation_flow.rs` - Full activation/deactivation cycles
- `rollback_scenarios.rs` - Automatic rollback on failures
- `error_handling.rs` - Error propagation and messaging
- `idempotency.rs` - Command idempotency validation
- `state_transitions.rs` - State machine integration

## Running Integration Tests

```bash
# Run all integration tests
cargo test --test '*'

# Run specific integration test file
cargo test --test activation_flow

# Run with output
cargo test --test activation_flow -- --nocapture
```

## Test Pattern

All integration tests follow this structure:

```rust
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_full_activation_cycle() {
    // GIVEN: Test environment setup
    let temp_dir = tempfile::tempdir().unwrap();

    // WHEN: Running command
    let mut cmd = Command::cargo_bin("nails").unwrap();
    cmd.arg("activate");

    // THEN: Assert behavior
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("activated"));
}
```

## Dependencies

Integration tests use:
- `assert_cmd` - CLI testing
- `predicates` - Assertion helpers
- `tempfile` - Temporary directories
