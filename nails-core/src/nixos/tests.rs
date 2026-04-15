//! Tests for NixOS builder
//!
//! Unit tests using a mock command executor so no real NixOS system is needed.

use super::*;
use crate::error::Result;
use serial_test::serial;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordedCall {
    NixosRebuild {
        args: Vec<String>,
    },
    SwitchToConfiguration {
        script_path: PathBuf,
        args: Vec<String>,
    },
}

struct RecordingCommandExecutor {
    rebuild_results: Mutex<VecDeque<Result<(bool, String, String)>>>,
    switch_results: Mutex<VecDeque<Result<(bool, String, String)>>>,
    calls: Arc<Mutex<Vec<RecordedCall>>>,
}

impl RecordingCommandExecutor {
    fn new(
        rebuild_results: Vec<Result<(bool, String, String)>>,
        switch_results: Vec<Result<(bool, String, String)>>,
    ) -> Self {
        Self {
            rebuild_results: Mutex::new(rebuild_results.into()),
            switch_results: Mutex::new(switch_results.into()),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn with_call_log(
        rebuild_results: Vec<Result<(bool, String, String)>>,
        switch_results: Vec<Result<(bool, String, String)>>,
    ) -> (Self, Arc<Mutex<Vec<RecordedCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                rebuild_results: Mutex::new(rebuild_results.into()),
                switch_results: Mutex::new(switch_results.into()),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl CommandExecutorTrait for RecordingCommandExecutor {
    fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)> {
        self.calls.lock().unwrap().push(RecordedCall::NixosRebuild {
            args: args.iter().map(|arg| arg.to_string()).collect(),
        });
        self.rebuild_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing mocked nixos-rebuild result")
    }

    fn execute_switch_to_configuration(
        &self,
        script_path: &std::path::Path,
        args: &[&str],
    ) -> Result<(bool, String, String)> {
        self.calls
            .lock()
            .unwrap()
            .push(RecordedCall::SwitchToConfiguration {
                script_path: script_path.to_path_buf(),
                args: args.iter().map(|arg| arg.to_string()).collect(),
            });
        self.switch_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing mocked switch-to-configuration result")
    }
}

fn make_store_target(temp_dir: &tempfile::TempDir, name: &str) -> PathBuf {
    let target = temp_dir.path().join(name);
    std::fs::create_dir_all(&target).unwrap();
    target
}

#[cfg(unix)]
fn make_profile_generation_dir(profile_path: &Path, generation: &str) -> PathBuf {
    let path = PathBuf::from(format!("{}-{}-link", profile_path.display(), generation));
    std::fs::create_dir_all(path.join("bin")).unwrap();
    path
}

#[cfg(unix)]
fn make_system_generation_dir(profiles_dir: &Path, generation: &str) -> PathBuf {
    let path = profiles_dir.join(format!("system-{}-link", generation));
    std::fs::create_dir_all(path.join("bin")).unwrap();
    path
}

#[cfg(unix)]
fn make_system_profile_symlink(system_profile: &Path, target: &Path) {
    if system_profile.exists() {
        std::fs::remove_file(system_profile).unwrap();
    }
    std::os::unix::fs::symlink(target, system_profile).unwrap();
}

fn clear_system_profile_env() {
    unsafe {
        std::env::remove_var("NAILS_SYSTEM_PROFILE_PATH");
    }
}

fn write_executable_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
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

#[test]
fn test_nixos_builder_new_legacy_creates_legacy_builder() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // Legacy builder uses the parent dir as config_path
    assert_eq!(builder.config_path, PathBuf::from("/etc/nixos"));
    assert!(!builder.is_flake());
    assert_eq!(builder.flake_ref, None);
}

#[test]
fn test_nixos_builder_new_legacy_config_at_root_uses_etc_nixos_fallback() {
    // When configuration.nix has no parent, falls back to /etc/nixos
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("configuration.nix"), // relative path with no parent
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // Falls back to /etc/nixos when no parent directory
    assert!(!builder.is_flake());
}

#[test]
fn test_nixos_builder_flake_dir_returns_none_for_legacy_builder() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert!(builder.flake_dir().is_none());
}

#[test]
fn test_nixos_builder_flake_dir_returns_some_for_flake_builder() {
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    assert_eq!(
        builder.flake_dir(),
        Some(PathBuf::from("/mnt/hidden/nixos").as_path())
    );
}

#[test]
fn test_nixos_builder_is_flake_for_new() {
    let builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );
    assert!(builder.is_flake());
}

#[test]
fn test_nixos_builder_is_not_flake_for_legacy() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );
    assert!(!builder.is_flake());
}

#[test]
fn test_nixos_builder_effective_flake_arg_for_legacy_uses_config_dir() {
    let builder = NixOSBuilder::new_legacy(
        PathBuf::from("/etc/nixos/configuration.nix"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );

    // effective_flake_arg returns config_path (parent dir) for legacy
    assert_eq!(builder.effective_flake_arg(), "/etc/nixos");
}

#[test]
#[cfg(unix)]
fn test_get_cached_generation_invalid_symlink_target_returns_err() {
    let temp_dir = tempfile::tempdir().unwrap();
    let profile_path = temp_dir.path().join("test-profile");
    let target = temp_dir.path().join("invalid");
    std::fs::write(&target, "dummy").unwrap();
    std::os::unix::fs::symlink(&target, &profile_path).unwrap();

    let builder = NixOSBuilder::new(temp_dir.path().join("config"), profile_path);

    assert!(builder.get_cached_generation().is_err());
}

#[test]
#[cfg(unix)]
fn test_build_profile_builds_when_no_cache_and_result_symlink_exists() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let profile_path = temp_dir.path().join("test-profile");
    let target = make_store_target(&temp_dir, "12345678-nixos-system-host");
    std::os::unix::fs::symlink(&target, config_path.join("result")).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        profile_path,
        Box::new(MockCommandExecutor::success()),
    );

    assert_eq!(builder.build_profile().unwrap(), "12345678");
}

#[test]
fn test_build_profile_returns_error_when_nixos_rebuild_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let profile_path = temp_dir.path().join("test-profile");

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        profile_path,
        Box::new(MockCommandExecutor::failure("boom".to_string())),
    );

    let err = builder.build_profile().unwrap_err();
    assert!(err.to_string().contains("Build failed: boom"));
}

#[test]
#[cfg(unix)]
fn test_get_result_store_path_returns_some_for_live_result_symlink() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let target = make_store_target(&temp_dir, "12345678-nixos-system-host");
    std::os::unix::fs::symlink(&target, config_path.join("result")).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::success()),
    );

    assert_eq!(builder.get_result_store_path().unwrap(), Some(target));
}

#[test]
#[cfg(unix)]
fn test_get_result_store_path_returns_none_for_broken_symlink() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let missing_target = temp_dir.path().join("missing-store-path");
    std::os::unix::fs::symlink(&missing_target, config_path.join("result")).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::success()),
    );

    assert_eq!(builder.get_result_store_path().unwrap(), None);
}

#[test]
fn test_get_result_store_path_returns_none_for_plain_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    std::fs::write(config_path.join("result"), "not a symlink").unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::success()),
    );

    assert_eq!(builder.get_result_store_path().unwrap(), None);
}

#[test]
#[cfg(unix)]
fn test_build_profile_missing_only_reuses_existing_result_store_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let target = make_store_target(&temp_dir, "12345678-nixos-system-host");
    std::os::unix::fs::symlink(&target, config_path.join("result")).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::failure("should not build".to_string())),
    );

    assert_eq!(
        builder.build_profile_missing_only().unwrap(),
        ("12345678".to_string(), true)
    );
}

#[test]
fn test_build_profile_missing_only_rejects_legacy_mode() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("configuration.nix");
    std::fs::write(&config_path, "{}").unwrap();

    let builder = NixOSBuilder::new_legacy_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::success()),
    );

    let err = builder.build_profile_missing_only().unwrap_err();
    assert!(
        err.to_string()
            .contains("Legacy NixOS builds are not supported in the missing-only path")
    );
}

#[test]
#[cfg(unix)]
fn test_build_profile_with_fingerprint_uses_fast_path_when_cache_exists() {
    let temp_dir = tempfile::tempdir().unwrap();
    let profile_path = temp_dir.path().join("test-profile");
    let target = temp_dir.path().join("system-456-link");
    std::fs::write(&target, "dummy").unwrap();
    std::os::unix::fs::symlink(&target, &profile_path).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        profile_path,
        Box::new(MockCommandExecutor::failure("should not build".to_string())),
    );

    let result = builder
        .build_profile_with_fingerprint("fp1", Some("fp1"))
        .unwrap();

    assert_eq!(result, ("456".to_string(), "fp1".to_string(), true));
}

#[test]
#[cfg(unix)]
fn test_build_profile_with_fingerprint_falls_back_when_cache_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let target = make_store_target(&temp_dir, "12345678-nixos-system-host");
    std::os::unix::fs::symlink(&target, config_path.join("result")).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::failure("should not build".to_string())),
    );

    let result = builder
        .build_profile_with_fingerprint("fp1", Some("fp1"))
        .unwrap();

    assert_eq!(result, ("12345678".to_string(), "fp1".to_string(), false));
}

#[test]
#[cfg(unix)]
fn test_build_profile_with_fingerprint_falls_back_without_stored_fingerprint() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("config");
    std::fs::create_dir_all(&config_path).unwrap();
    let target = make_store_target(&temp_dir, "12345678-nixos-system-host");
    std::os::unix::fs::symlink(&target, config_path.join("result")).unwrap();

    let builder = NixOSBuilder::new_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::failure("should not build".to_string())),
    );

    let result = builder.build_profile_with_fingerprint("fp1", None).unwrap();

    assert_eq!(result, ("12345678".to_string(), "fp1".to_string(), false));
}

#[test]
fn test_build_and_switch_succeeds_in_legacy_mode() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join("configuration.nix");
    std::fs::write(&config_path, "{}").unwrap();

    let builder = NixOSBuilder::new_legacy_with_executor(
        config_path,
        temp_dir.path().join("profile"),
        Box::new(MockCommandExecutor::success()),
    );

    assert!(builder.build_and_switch().is_ok());
}

#[test]
fn test_build_and_switch_uses_flake_args_and_succeeds() {
    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![Ok((true, String::new(), String::new()))],
        vec![],
    );
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/etc/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(executor),
    );

    assert!(builder.build_and_switch().is_ok());

    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![RecordedCall::NixosRebuild {
            args: vec![
                "test".to_string(),
                "--flake".to_string(),
                "/etc/nixos".to_string(),
                "--no-update-lock-file".to_string(),
                "--impure".to_string(),
            ],
        }]
    );
}

#[test]
fn test_build_and_switch_returns_error_when_flake_test_fails() {
    let builder = NixOSBuilder::new_with_executor(
        PathBuf::from("/etc/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
        Box::new(RecordingCommandExecutor::new(
            vec![Ok((false, String::new(), "flake boom".to_string()))],
            vec![],
        )),
    );

    let err = builder.build_and_switch().unwrap_err();
    assert!(
        err.to_string()
            .contains("nixos-rebuild test failed: flake boom")
    );
}

#[test]
#[cfg(unix)]
fn test_switch_profile_returns_error_when_profile_generation_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let profile_path = temp_dir.path().join("nails-system");
    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        profile_path,
        Box::new(RecordingCommandExecutor::new(vec![], vec![])),
    );

    let err = builder.switch_profile("123", "switch").unwrap_err();
    assert!(
        err.to_string()
            .contains("Profile not found: 123. Run 'nails activate' to rebuild.")
    );
}

#[test]
#[cfg(unix)]
fn test_switch_profile_uses_generation_specific_switch_script_on_success() {
    let temp_dir = tempfile::tempdir().unwrap();
    let profile_path = temp_dir.path().join("nails-system");
    let generation_dir = make_profile_generation_dir(&profile_path, "123");
    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![],
        vec![Ok((true, String::new(), String::new()))],
    );
    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        profile_path,
        Box::new(executor),
    );

    assert!(builder.switch_profile("123", "boot").is_ok());

    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![RecordedCall::SwitchToConfiguration {
            script_path: generation_dir.join("bin/switch-to-configuration"),
            args: vec!["boot".to_string()],
        }]
    );
}

#[test]
#[cfg(unix)]
#[serial]
fn test_switch_profile_rolls_back_to_current_system_generation_when_switch_fails() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let profiles_dir = temp_dir.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let system_profile = profiles_dir.join("system");
    let current_generation = make_system_generation_dir(&profiles_dir, "41");
    make_system_profile_symlink(&system_profile, &current_generation);
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let profile_path = temp_dir.path().join("nails-system");
    make_profile_generation_dir(&profile_path, "123");
    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![],
        vec![
            Ok((false, String::new(), "primary failed".to_string())),
            Ok((true, String::new(), String::new())),
        ],
    );
    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        profile_path,
        Box::new(executor),
    );

    let err = builder.switch_profile("123", "switch").unwrap_err();
    assert!(err.to_string().contains("Switch failed: primary failed"));
    assert_eq!(calls.lock().unwrap().len(), 2);

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_switch_profile_returns_original_error_when_rollback_fails() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let profiles_dir = temp_dir.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let system_profile = profiles_dir.join("system");
    let current_generation = make_system_generation_dir(&profiles_dir, "41");
    make_system_profile_symlink(&system_profile, &current_generation);
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let profile_path = temp_dir.path().join("nails-system");
    make_profile_generation_dir(&profile_path, "123");
    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![],
        vec![
            Ok((false, String::new(), "primary failed".to_string())),
            Ok((false, String::new(), "rollback failed".to_string())),
        ],
    );
    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        profile_path,
        Box::new(executor),
    );

    let err = builder.switch_profile("123", "switch").unwrap_err();
    assert!(err.to_string().contains("Switch failed: primary failed"));
    assert_eq!(calls.lock().unwrap().len(), 2);

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_switch_profile_skips_rollback_when_current_system_generation_unavailable() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let missing_system_profile = temp_dir.path().join("profiles/system");
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &missing_system_profile);
    }

    let profile_path = temp_dir.path().join("nails-system");
    make_profile_generation_dir(&profile_path, "123");
    let (executor, calls) = RecordingCommandExecutor::with_call_log(
        vec![],
        vec![Ok((false, String::new(), "primary failed".to_string()))],
    );
    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        profile_path,
        Box::new(executor),
    );

    let err = builder.switch_profile("123", "switch").unwrap_err();
    assert!(err.to_string().contains("Switch failed: primary failed"));
    assert_eq!(calls.lock().unwrap().len(), 1);

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_switch_system_generation_returns_error_when_generation_missing() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let system_profile = temp_dir.path().join("profiles/system");
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        temp_dir.path().join("nails-system"),
        Box::new(RecordingCommandExecutor::new(vec![], vec![])),
    );

    let err = builder
        .switch_system_generation("99", "switch")
        .unwrap_err();
    assert!(err.to_string().contains("System generation not found: 99"));

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_current_system_generation_reads_generation_from_overridden_system_profile() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let profiles_dir = temp_dir.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let system_profile = profiles_dir.join("system");
    let current_generation = make_system_generation_dir(&profiles_dir, "42");
    make_system_profile_symlink(&system_profile, &current_generation);
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        temp_dir.path().join("nails-system"),
        Box::new(RecordingCommandExecutor::new(vec![], vec![])),
    );

    assert_eq!(
        builder.current_system_generation().unwrap(),
        Some("42".to_string())
    );

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_current_system_generation_returns_none_for_unparseable_system_target() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let profiles_dir = temp_dir.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let system_profile = profiles_dir.join("system");
    let invalid_target = profiles_dir.join("not-a-generation");
    std::fs::create_dir_all(&invalid_target).unwrap();
    make_system_profile_symlink(&system_profile, &invalid_target);
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        temp_dir.path().join("nails-system"),
        Box::new(RecordingCommandExecutor::new(vec![], vec![])),
    );

    assert_eq!(builder.current_system_generation().unwrap(), None);

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_switch_to_system_profile_returns_ok_when_system_profile_missing() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let system_profile = temp_dir.path().join("profiles/system");
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        temp_dir.path().join("nails-system"),
        Box::new(RecordingCommandExecutor::new(vec![], vec![])),
    );

    assert!(builder.switch_to_system_profile().is_ok());

    clear_system_profile_env();
}

#[test]
#[cfg(unix)]
#[serial]
fn test_switch_to_system_profile_returns_stderr_when_switch_fails() {
    clear_system_profile_env();
    let temp_dir = tempfile::tempdir().unwrap();
    let profiles_dir = temp_dir.path().join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let system_profile = profiles_dir.join("system");
    std::fs::create_dir_all(system_profile.join("bin")).unwrap();
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    }

    let builder = NixOSBuilder::new_with_executor(
        temp_dir.path().join("config"),
        temp_dir.path().join("nails-system"),
        Box::new(RecordingCommandExecutor::new(
            vec![],
            vec![Ok((false, String::new(), "denied".to_string()))],
        )),
    );

    let err = builder.switch_to_system_profile().unwrap_err();
    assert!(
        err.to_string()
            .contains("System profile switch failed: denied")
    );

    clear_system_profile_env();
}

#[test]
#[serial]
fn test_real_command_executor_execute_nixos_rebuild_uses_path_and_captures_output() {
    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("nixos-rebuild");
    write_executable_script(
        &script,
        "#!/bin/sh\nprintf 'rebuilt ok\\n'\nprintf 'warn\\n' 1>&2\nexit 0\n",
    );

    let old_path = std::env::var_os("PATH");
    unsafe {
        std::env::set_var("PATH", temp_dir.path());
    }

    let result = RealCommandExecutor
        .execute_nixos_rebuild(&["test"])
        .unwrap();

    if let Some(old_path) = old_path {
        unsafe {
            std::env::set_var("PATH", old_path);
        }
    } else {
        unsafe {
            std::env::remove_var("PATH");
        }
    }

    assert_eq!(
        result,
        (true, "rebuilt ok\n".to_string(), "warn\n".to_string())
    );
}

#[test]
#[serial]
fn test_real_command_executor_execute_nixos_rebuild_returns_false_on_nonzero_exit() {
    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("nixos-rebuild");
    write_executable_script(
        &script,
        "#!/bin/sh\nprintf 'partial out\\n'\nprintf 'build failed\\n' 1>&2\nexit 17\n",
    );

    let old_path = std::env::var_os("PATH");
    unsafe {
        std::env::set_var("PATH", temp_dir.path());
    }

    let result = RealCommandExecutor.execute_nixos_rebuild(&[]).unwrap();

    if let Some(old_path) = old_path {
        unsafe {
            std::env::set_var("PATH", old_path);
        }
    } else {
        unsafe {
            std::env::remove_var("PATH");
        }
    }

    assert_eq!(
        result,
        (
            false,
            "partial out\n".to_string(),
            "build failed\n".to_string(),
        )
    );
}

#[test]
#[serial]
fn test_real_command_executor_execute_nixos_rebuild_returns_not_found_when_missing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let old_path = std::env::var_os("PATH");
    unsafe {
        std::env::set_var("PATH", temp_dir.path());
    }

    let err = RealCommandExecutor.execute_nixos_rebuild(&[]).unwrap_err();

    if let Some(old_path) = old_path {
        unsafe {
            std::env::set_var("PATH", old_path);
        }
    } else {
        unsafe {
            std::env::remove_var("PATH");
        }
    }

    match err {
        crate::NailsError::IoError(io) => assert_eq!(io.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected IoError(NotFound), got {other:?}"),
    }
}

#[test]
#[serial]
fn test_real_command_executor_execute_switch_to_configuration_runs_exact_script_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("switch-to-configuration");
    write_executable_script(
        &script,
        "#!/bin/sh\nprintf 'mode=%s\\n' \"$1\"\nprintf 'note\\n' 1>&2\nexit 0\n",
    );

    let result = RealCommandExecutor
        .execute_switch_to_configuration(&script, &["switch"])
        .unwrap();

    assert_eq!(
        result,
        (true, "mode=switch\n".to_string(), "note\n".to_string())
    );
}
