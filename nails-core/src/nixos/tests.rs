//! Tests for NixOS builder
//!
//! Unit tests using a mock command executor so no real NixOS system is needed.

use super::*;
use crate::error::Result;
use std::path::PathBuf;

/// Mock command executor for testing
struct MockCommandExecutor {
    /// Whether command should succeed
    should_succeed: bool,
    /// Stdout to return
    stdout: String,
    /// Stderr to return
    stderr: String,
}

impl MockCommandExecutor {
    fn success() -> Self {
        Self {
            should_succeed: true,
            stdout: String::from("nixos-rebuild output here"),
            stderr: String::new(),
        }
    }

    #[allow(dead_code)]
    fn failure(stderr: String) -> Self {
        Self {
            should_succeed: false,
            stdout: String::new(),
            stderr,
        }
    }
}

impl CommandExecutorTrait for MockCommandExecutor {
    fn execute_nixos_rebuild(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        Ok((
            self.should_succeed,
            self.stdout.clone(),
            self.stderr.clone(),
        ))
    }

    fn execute_switch_to_configuration(
        &self,
        _script_path: &std::path::Path,
        _args: &[&str],
    ) -> Result<(bool, String, String)> {
        // For build tests, we don't actually call switch-to-configuration
        // Return success by default
        Ok((true, String::new(), String::new()))
    }
}

#[test]
fn test_nixos_builder_construction() {
    let config_path = PathBuf::from("/mnt/hidden/nixos");
    let profile_path = PathBuf::from("/nix/var/nix/profiles/nails-system");

    let builder = NixOSBuilder::new(config_path.clone(), profile_path.clone());

    // Verify struct is constructed with correct values
    assert_eq!(builder.config_path, config_path);
    assert_eq!(builder.profile_path, profile_path);
}

#[test]
fn test_extract_generation_id_valid_paths() {
    // Test standard system profile format
    let path = PathBuf::from("/nix/var/nix/profiles/system-123-link");
    let generation = NixOSBuilder::extract_generation_id(&path).unwrap();
    assert_eq!(generation, "123");

    // Test custom profile format
    let path = PathBuf::from("/nix/var/nix/profiles/nails-system-456-link");
    let generation = NixOSBuilder::extract_generation_id(&path).unwrap();
    assert_eq!(generation, "456");

    // Test profile with multiple hyphens in name
    let path = PathBuf::from("/nix/var/nix/profiles/my-custom-profile-789-link");
    let generation = NixOSBuilder::extract_generation_id(&path).unwrap();
    assert_eq!(generation, "789");
}

#[test]
fn test_extract_generation_id_invalid_paths() {
    // Test path without generation number
    let path = PathBuf::from("/nix/var/nix/profiles/invalid");
    assert!(NixOSBuilder::extract_generation_id(&path).is_err());

    // Test path with non-numeric generation
    let path = PathBuf::from("/nix/var/nix/profiles/system-abc-link");
    assert!(NixOSBuilder::extract_generation_id(&path).is_err());

    // Test empty path
    let path = PathBuf::from("");
    assert!(NixOSBuilder::extract_generation_id(&path).is_err());
}

#[test]
fn test_get_cached_generation_no_profile() {
    // Create builder with non-existent profile path
    let config_path = PathBuf::from("/mnt/hidden/nixos");
    let profile_path = PathBuf::from("/tmp/nonexistent-profile-12345");

    let builder = NixOSBuilder::new(config_path, profile_path);

    // Should return Ok(None) when profile doesn't exist
    let result = builder.get_cached_generation().unwrap();
    assert_eq!(result, None);
}

#[test]
#[cfg(unix)] // Symlink operations are Unix-specific
fn test_get_cached_generation_with_profile() {
    use tempfile::TempDir;

    // Create temporary directory for test
    let temp_dir = TempDir::new().unwrap();
    let profile_path = temp_dir.path().join("test-profile");

    // Create a symlink to simulate NixOS profile
    // Symlink target format: /nix/store/hash-nixos-system-123-link
    let target = temp_dir.path().join("system-123-link");
    std::fs::write(&target, "dummy").unwrap();

    std::os::unix::fs::symlink(&target, &profile_path).unwrap();

    let builder = NixOSBuilder::new(PathBuf::from("/mnt/hidden/nixos"), profile_path);

    // Should extract generation ID from symlink target
    let result = builder.get_cached_generation().unwrap();
    assert_eq!(result, Some("123".to_string()));
}

#[test]
#[cfg(unix)] // Symlink operations are Unix-specific
fn test_build_profile_uses_cached_generation() {
    use tempfile::TempDir;

    // Create temporary directory with cached profile
    let temp_dir = TempDir::new().unwrap();
    let profile_path = temp_dir.path().join("test-profile");
    let target = temp_dir.path().join("system-456-link");
    std::fs::write(&target, "dummy").unwrap();

    std::os::unix::fs::symlink(&target, &profile_path).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/mnt/hidden/nixos"),
        profile_path,
        Box::new(MockCommandExecutor::success()),
    );

    // Should use cached generation without building
    let generation = builder.build_profile().unwrap();
    assert_eq!(generation, "456");
}

// ========================================================================
// Flake ref tests (--flake /path#attr support)
// ========================================================================

#[test]
fn test_nixos_builder_new_with_flake_ref() {
    let builder = NixOSBuilder::new_with_flake_ref(
        "/etc/nixos#amnesia-virtualbox".to_string(),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // config_path should be the directory part (before #)
    assert_eq!(builder.config_path, PathBuf::from("/etc/nixos"));
    // flake_ref should hold the full ref
    assert_eq!(
        builder.flake_ref,
        Some("/etc/nixos#amnesia-virtualbox".to_string())
    );
}

#[test]
fn test_nixos_builder_new_with_flake_ref_no_fragment() {
    let builder = NixOSBuilder::new_with_flake_ref(
        "/etc/nixos".to_string(),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // config_path should be the full path (no # to split on)
    assert_eq!(builder.config_path, PathBuf::from("/etc/nixos"));
    // flake_ref should be None when there's no fragment (no need to override)
    assert_eq!(builder.flake_ref, None);
}

#[test]
fn test_nixos_builder_flake_arg_with_fragment() {
    let builder = NixOSBuilder::new_with_flake_ref(
        "/etc/nixos#amnesia-virtualbox".to_string(),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert_eq!(
        builder.effective_flake_arg(),
        "/etc/nixos#amnesia-virtualbox"
    );
}

#[test]
fn test_nixos_builder_flake_arg_without_fragment() {
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // Without flake_ref, should fall back to config_path
    assert_eq!(builder.effective_flake_arg(), "/mnt/hidden/nixos");
}

#[test]
fn test_nixos_builder_new_preserves_no_flake_ref() {
    // Existing new() constructor should have flake_ref = None
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert_eq!(builder.flake_ref, None);
}
