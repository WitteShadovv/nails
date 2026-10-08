# Pre-flight Checks

This directory contains the pre-flight checks that live in `nails-core`. Each check validates a specific aspect of the system before NAILS activation. The checks of other areas live with their area: the swap check with the framework in `nails-base`, the NixOS configuration checks in `nails-platform`, the session's checks in `nails-session` and the residue-catalog check in `nails-forensics` ([ADR 0010](../../../../docs/adr/0010-library-crate-split.md)). `nails_core::preflight::checks` re-exports all of them.

## Overview

Pre-flight checks are trait-based validators that run before system activation to ensure:
- System safety (e.g., swap disabled, state valid)
- Resource availability (e.g., disk space, hidden volume mounted)
- Configuration validity (e.g., NixOS config structure, overlay directories)

All checks implement the `PreFlightCheck<F: Filesystem>` trait defined in `nails_base::preflight`.

## Available Checks

The set of checks changes often, and which ones run depends on the host and the
requested operation (for example the NixOS config and build-target checks run
only on a NixOS host with a selected hidden flake). Rather than keep a hand-written
list in step with the code, read the rustdoc, which is generated from the check
implementations themselves:

```bash
cargo doc --no-deps --open -p nails-core
```

Then open the `nails_core::preflight::checks` module: every check type carries a
doc comment explaining what it validates and why. `manager::preflight_runner`
shows the exact registration order and the host conditions under which each check
is added.

Notable details worth calling out here:

- **`space/`** - `SpaceCheck` enforces a single hard floor (no warn band). The
  default minimum is **500 MB**, matching the `default_minimum_space_mb` config
  default; it is the base floor for an overlay-only activation, while a full NixOS
  rebuild's much larger store delta is enforced separately during activation. The
  module also defines the `OverlayDirs` struct used to describe overlay layouts.
- **`storage_readiness/`** - `StorageReadinessCheck` is the unified storage
  validator: it checks the required directory structure, auto-creates missing
  directories with `0o700` permissions, and validates overlay lower/upper/work
  accessibility, replacing the separate structure and overlay checks.

## Adding a New Check

To add a new pre-flight check:

### 1. Create the check file

Create a new file in this directory: `checks/my_check.rs`

```rust
//! Brief description of what this check validates

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::path::PathBuf;

/// Documentation for MyCheck
///
/// Explain what conditions are validated and why they matter.
#[derive(Debug, Clone)]
pub struct MyCheck {
    // Check-specific fields
    config_value: String,
}

impl MyCheck {
    /// Create a new MyCheck
    pub fn new(config_value: String) -> Self {
        Self { config_value }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for MyCheck {
    fn name(&self) -> &'static str {
        "my-check"  // Kebab-case identifier
    }

    fn description(&self) -> &'static str {
        "Brief description for CLI output"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Validation logic here

        if validation_passes {
            Ok(CheckResult::Pass("Success message".to_string()))
        } else if needs_warning {
            Ok(CheckResult::Warn("Warning message".to_string()))
        } else {
            Ok(CheckResult::Fail("Failure message with guidance".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn test_my_check_passes() {
        let fs = MockFilesystem::new();
        let check = MyCheck::new("test".to_string());
        // Setup mock filesystem state
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
    }

    // Add more tests for failure cases, edge cases, etc.
}
```

### 2. Register the check module

Add to `checks/mod.rs`:

```rust
pub mod my_check;  // Add module declaration

// Add re-export
pub use my_check::MyCheck;
```

### 3. Write comprehensive tests

Every check should have tests covering:
- Success case (all conditions pass)
- Failure cases (each validation that can fail)
- Edge cases (boundary conditions, error handling)
- Integration with `PreFlightRegistry`

Cover every branch a check can take. CI enforces a single production-code
line-coverage floor (defined in `.config/coverage.toml`), not a per-check 100%
target; test infrastructure such as `MockFilesystem` is excluded from the
figure.

### 4. Register with the CLI

In `nails-cli/src/lib.rs`, add the check to the appropriate registry:

```rust
use nails_core::preflight::checks::MyCheck;

// In build_preflight_registry() or similar:
registry.add_check(Box::new(MyCheck::new(config.my_value.clone())));
```

## Check Result Types

Pre-flight checks return `CheckResult` with three variants:

- **`Pass(String)`**: Validation succeeded, system is ready
  - Example: "Swap disabled: memory security maintained"

- **`Warn(String)`**: Non-critical issue detected, can proceed with caution
  - Example: "Backend mapping has discard enabled; consider disabling it."

- **`Fail(String)`**: Critical issue blocks activation
  - Example: "Swap is enabled. Run: sudo swapoff -a"
  - Should include actionable guidance when possible

## Design Principles

### 1. Single Responsibility
Each check validates ONE specific aspect of the system. Keep checks focused and composable.

### 2. Fail Fast with Context
Return early with clear error messages. Include:
- What failed
- Why it matters
- How to fix it (when applicable)

### 3. Actionable Error Messages
Provide fix guidance in failure messages.

Bad: "Storage not ready"
Good: "Storage not ready: Missing /etc/ directory. Create with: sudo mkdir -p /mnt/data/etc"

### 4. Idempotent Checks
Checks should be safe to run multiple times without side effects (except auto-creation features).

### 5. Test Coverage
All checks require comprehensive unit tests exercising every branch. Use `MockFilesystem` for deterministic testing; it is test-only infrastructure and does not count toward the coverage figure.

## Auto-creation Pattern

Checks can auto-create missing resources:

```rust
if !fs.path_exists(&required_dir)? {
    match fs.create_directory(&required_dir) {
        Ok(()) => {
            fs.set_permissions(&required_dir, 0o700)?;
            tracing::info!(directory = %required_dir, "Auto-created");
            // Continue validation
        }
        Err(e) => {
            return Ok(CheckResult::Fail(format!(
                "Missing: {}. Auto-create failed: {}",
                required_dir, e
            )));
        }
    }
}
```

Auto-creation should:
- Only create resources that are safe and expected
- Set appropriate permissions (0o700 for sensitive directories)
- Log creation events
- Fail gracefully if creation is not possible

## Common Patterns

### Checking Paths
```rust
if !fs.path_exists(&path)? {
    return Ok(CheckResult::Fail(format!("Missing: {}", path.display())));
}
```

### Checking Permissions
```rust
if !fs.is_writable(&path)? {
    return Ok(CheckResult::Fail(format!("Not writable: {}", path.display())));
}
```

### Reading Configuration
```rust
let content = fs.read_file_content(&config_path)?;
if !content.contains(expected_value) {
    return Ok(CheckResult::Fail("Config missing required value".into()));
}
```

### Collecting Multiple Issues
```rust
let mut issues = Vec::new();

if condition1_fails {
    issues.push("Issue 1 description".to_string());
}
if condition2_fails {
    issues.push("Issue 2 description".to_string());
}

if issues.is_empty() {
    Ok(CheckResult::Pass("All checks passed".to_string()))
} else {
    Ok(CheckResult::Fail(format!(
        "Validation failed: {}",
        issues.join(". ")
    )))
}
```

## Testing Strategy

### Unit Tests
Test each check in isolation using `MockFilesystem`:

```rust
#[test]
fn test_check_handles_missing_file() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/required/file", false);

    let check = MyCheck::new();
    let result = check.run(&fs).unwrap();

    assert!(result.is_fail());
    assert!(result.message().contains("Missing"));
}
```

### Integration Tests
Test checks work correctly with `PreFlightRegistry`:

```rust
#[test]
fn test_check_integration_with_registry() {
    let fs = MockFilesystem::new();
    // Setup valid state

    let mut registry = PreFlightRegistry::new();
    registry.add_check(Box::new(MyCheck::new()));

    let result = registry.run_all(&fs);
    assert!(result.is_ok());
}
```

### Edge Case Tests
Test boundary conditions, error handling, race conditions, etc.

## Anti-patterns to Avoid

### ❌ Vague Error Messages
```rust
Ok(CheckResult::Fail("Check failed".to_string()))
```

### ✅ Specific, Actionable Messages
```rust
Ok(CheckResult::Fail(format!(
    "Config file missing at {}. Create with: nails config init",
    path.display()
)))
```

---

### ❌ Silent Failures
```rust
if let Err(_) = fs.create_directory(&path) {
    // Silently continue
}
```

### ✅ Explicit Error Handling
```rust
if let Err(e) = fs.create_directory(&path) {
    return Ok(CheckResult::Fail(format!(
        "Failed to create directory {}: {}",
        path.display(), e
    )));
}
```

---

### ❌ Mixing Concerns
```rust
// Check that validates both storage AND state in one check
```

### ✅ Single Responsibility
```rust
// Separate StorageCheck and StateCheck
```

## Resources

- Parent module: `../mod.rs` (re-exports the framework from `nails_base::preflight`: trait definitions, registry)
- Filesystem abstraction: `../../filesystem/mod.rs`
- Error types: `../../error.rs`
- Architecture decisions: [`docs/adr/`](../../../../docs/adr)
- Threat model: [`docs/threat-model.md`](../../../../docs/threat-model.md)
