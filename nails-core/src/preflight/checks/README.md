# Pre-flight Checks

This directory contains all concrete pre-flight check implementations. Each check validates a specific aspect of the system before NAILS activation.

## Overview

Pre-flight checks are trait-based validators that run before system activation to ensure:
- System safety (e.g., swap disabled, state valid)
- Resource availability (e.g., disk space, hidden volume mounted)
- Configuration validity (e.g., NixOS config structure, overlay directories)

All checks implement the `PreFlightCheck<F: Filesystem>` trait defined in `../mod.rs`.

## Available Checks

### Security & State

- **`state.rs`** - `StateCheck`: Validates system state is appropriate for activation
  - Ensures system is not already active or in emergency state
  - Verifies transition validity according to state machine rules

- **`swap.rs`** - `SwapCheck`: Ensures swap is disabled for memory security
  - Prevents sensitive data (keys, credentials) from being written to persistent storage
  - Critical for plausible deniability guarantee

### Storage & Resources

- **`hidden_volume.rs`** - `HiddenVolumeCheck`: Validates hidden volume is mounted and accessible
  - Checks mount point exists and is writable
  - Ensures hidden storage root directory is available

- **`space.rs`** - `SpaceCheck`: Validates sufficient disk space for activation
  - Uses graduated response system (Pass/Warn/Fail thresholds)
  - Default minimum: 1024 MB (1 GB)
  - Also defines `OverlayDirs` struct for overlay configuration

- **`storage_readiness.rs`** - `StorageReadinessCheck`: Unified storage validation (Story 14.5)
  - Validates required directory structure on hidden volume
  - Auto-creates missing directories with proper permissions
  - Validates overlay directory accessibility (lower/upper/work)
  - Replaces separate structure and overlay checks

### Configuration

- **`nixos_config.rs`** - `NixOSConfigCheck`: Validates NixOS configuration overlay structure
  - Ensures base NixOS config exists
  - Validates hidden storage NixOS configuration structure
  - Checks modified hardware-configuration.nix has correct imports
  - Verifies symlink staging for hidden config

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

Aim for 100% code coverage (enforced by CI).

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
  - Example: "800 MB available (below 1.0 GB recommended). Monitor space."

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
Follow UXR19: Provide fix guidance in failure messages.

Bad: "Storage not ready"
Good: "Storage not ready: Missing /etc/ directory. Create with: sudo mkdir -p /mnt/hidden-volume/etc"

### 4. Idempotent Checks
Checks should be safe to run multiple times without side effects (except auto-creation features like Story 14.4).

### 5. Test Coverage
All checks require comprehensive unit tests with 100% coverage. Use `MockFilesystem` for deterministic testing.

## Story 14.4: Auto-creation Pattern

Starting with Story 14.4, checks can auto-create missing resources:

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

- Parent module: `../mod.rs` (trait definitions, registry)
- Filesystem abstraction: `../../filesystem/mod.rs`
- Error types: `../../error.rs`
- Design documentation: `docs/design.tex` (Section 4.3.5 - Pre-flight Checks)
