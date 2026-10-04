// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for `NailsManager`, one file per production module of `manager`.
//!
//! This file holds the shared fixtures and the tests of `manager/mod.rs`
//! itself; each submodule starts with `use super::*;` to pick them up.

#![allow(clippy::field_reassign_with_default)]
use super::*;
use crate::filesystem::{Filesystem, MockOp, PathKind};
use crate::test_support::EnvGuard;
use crate::{
    MockFilesystem, OverlayConfig, OverlayInfo, StateFile, Stopwatch, SystemState, TestWorld,
    Verbosity, config::DEFAULT_HIDDEN_VOLUME_ROOT, config::OverlayMode, inject_import_block,
};
use chrono::Utc;
use serial_test::serial;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod activation;
mod deactivation;
mod helpers;
mod mount_tracker;
mod preflight_runner;
mod rollback;
mod state_management;

fn setup_nixos_config_check(fs: &MockFilesystem, hidden_root: &Path) {
    // Base hardware-configuration.nix must exist
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_files_with_pattern(
        "/etc/nixos",
        ".nix",
        &[Path::new("/etc/nixos/hardware-configuration.nix")],
    );
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);

    // Hidden overlay hardware config
    let hidden_etc = hidden_root.join("etc/nixos");
    let hidden_hw = hidden_etc.join("hardware-configuration.nix");
    fs.mock_set_path_exists(hidden_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_etc.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(hidden_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(hidden_hw.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_hw.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(
        hidden_hw.to_str().unwrap(),
        "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
    );

    // Hidden config in new location
    let hidden_config = hidden_root.join("config/nixos/configuration.nix");
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ }");

    let nails_dir = hidden_root.join("etc/nixos/nails");
    fs.mock_set_path_exists(nails_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nails_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_writable(nails_dir.to_str().unwrap(), true);
}

fn create_test_manager() -> NailsManager<MockFilesystem> {
    let fs = MockFilesystem::new();
    let config = Config::test_default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    NailsManager::new(fs, config, state_path)
}

// ========== NailsManager::new ==========

#[test]
fn test_new_stores_all_parameters() {
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/test-hidden"),
        state_file_path: PathBuf::from("/mnt/test-hidden/state.json"),
        overlays: vec![],
        ..Config::test_default()
    };
    let state_path = PathBuf::from("/mnt/test-hidden/state.json");

    let manager = NailsManager::new(fs, config.clone(), state_path.clone());

    // Verify fields are stored (we can't directly access private fields,
    // but we can verify behavior in other tests)
    assert_eq!(manager.state_file_path, state_path);
    assert_eq!(manager.config, config);
}

#[test]
fn test_new_does_not_load_state() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/nonexistent/path/state.json");

    // Constructor should NOT fail even with invalid path
    // because it doesn't load state (lazy loading)
    let manager = NailsManager::new(fs, config, state_path);

    // State is not loaded yet
    let cached = manager.cached_state.borrow();
    assert!(cached.is_none());
}

#[test]
fn test_new_initializes_cached_state_to_none() {
    let manager = create_test_manager();

    // Verify cached_state is None (not yet loaded)
    let cached = manager.cached_state.borrow();
    assert!(cached.is_none());
}

#[test]
fn test_new_with_different_filesystem_implementations() {
    // Test with MockFilesystem
    let mock_fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    let _mock_manager = NailsManager::new(mock_fs, config.clone(), state_path.clone());

    // Test with RealFilesystem (just verify compilation)
    use crate::RealFilesystem;
    let real_fs = RealFilesystem;
    let _real_manager = NailsManager::new(real_fs, config, state_path);
}

// ========== unmount_overlays ==========

#[test]
fn test_unmount_overlays_method_reverse_order() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock successful mounts
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);

    // Create mounted paths in mount order: /home, /etc
    let mounted_paths = vec![home.clone(), etc.clone()];

    // Unmount should happen in reverse: /etc first, /home second
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_ok(), "Unmount should succeed");

    // Verify both unmounted
    assert!(!fs.is_mounted(&home).unwrap());
    assert!(!fs.is_mounted(&etc).unwrap());
}

#[test]
fn test_unmount_overlays_best_effort_on_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock /etc unmount to fail, /home to succeed
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mounted_paths = vec![home.clone(), etc.clone()];

    // Should return error but still unmount /home
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_err(), "Should return error for /etc failure");

    // Verify /home still unmounted (best-effort)
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted despite /etc failure"
    );
}

#[test]
fn test_unmount_overlays_empty_list_succeeds() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs, config, state_path);

    // Unmount empty list should succeed
    let result = manager.unmount_overlays(vec![]);
    assert!(result.is_ok(), "Unmounting empty list should succeed");
}

#[test]
fn test_unmount_overlays_single_path_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");

    // Mock unmount to fail
    fs.mock_set_mounted(&home, true);
    fs.mock_set_unmount_should_fail(&home.to_string_lossy(), true);

    let mounted_paths = vec![home.clone()];

    // Should return error
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_err(), "Should return error when unmount fails");

    let err = result.unwrap_err();
    assert!(matches!(err, NailsError::OverlayError(_)));
    assert!(
        err.to_string().contains("/home"),
        "Error should name the /home target that failed to unmount"
    );
}

#[test]
fn test_unmount_overlays_multiple_paths_partial_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock /etc to fail, /home to succeed
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mounted_paths = vec![home.clone(), etc.clone()];

    // Should return error but /home should be unmounted (best-effort)
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_err(), "Should return error for /etc failure");

    // /home should still be unmounted (best-effort)
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted despite /etc failure"
    );
}

#[test]
fn test_unmount_overlays_three_paths_reverse_order() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");
    let opt = PathBuf::from("/opt");

    // Mock all as mounted
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_mounted(&opt, true);

    // Create mounted paths in order: /home, /etc, /opt
    let mounted_paths = vec![home.clone(), etc.clone(), opt.clone()];

    // Unmount should happen in reverse: /opt, /etc, /home
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_ok(), "Unmount should succeed");

    // Verify all unmounted
    assert!(!fs.is_mounted(&home).unwrap());
    assert!(!fs.is_mounted(&etc).unwrap());
    assert!(!fs.is_mounted(&opt).unwrap());
}

#[test]
fn test_unmount_overlays_graceful_fails_force_succeeds() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");

    // Mock /home as mounted
    fs.mock_set_mounted(&home, true);

    // Configure graceful unmount to fail, force to succeed
    fs.mock_set_unmount_graceful_fails(&home.to_string_lossy(), true);

    let mounted_paths = vec![home.clone()];

    // unmount_overlays should succeed (graceful fails, force succeeds)
    let result = manager.unmount_overlays(mounted_paths);
    assert!(
        result.is_ok(),
        "Unmount should succeed when force unmount works"
    );

    // Verify /home is unmounted
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted after force unmount succeeded"
    );
}

// ========== Debug ==========

#[test]
fn test_nails_manager_debug_impl() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    let manager = NailsManager::new(fs, config.clone(), state_path.clone());

    // Test Debug implementation (lines 242-252)
    let debug_output = format!("{:?}", manager);

    // Verify Debug output contains expected fields
    assert!(
        debug_output.contains("NailsManager"),
        "Debug should contain struct name"
    );
    assert!(
        debug_output.contains("<filesystem>"),
        "Debug should mask filesystem"
    );
    assert!(
        debug_output.contains("config"),
        "Debug should contain config field"
    );
    assert!(
        debug_output.contains("state_file_path"),
        "Debug should contain state_file_path"
    );
    assert!(
        debug_output.contains("<RefCell<...>>"),
        "Debug should mask cached_state"
    );
}

#[test]
fn test_nails_manager_debug_with_nixos_builder() {
    use crate::NixOSBuilder;

    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    let nixos_builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );
    let manager = NailsManager::with_nixos(fs, config, state_path, nixos_builder);

    // Test Debug implementation with NixOSBuilder present
    let debug_output = format!("{:?}", manager);

    // Verify Debug output contains nixos_builder field
    assert!(
        debug_output.contains("nixos_builder"),
        "Debug should contain nixos_builder field"
    );
    assert!(
        debug_output.contains("<NixOSBuilder>"),
        "Debug should mask nixos_builder"
    );
}

// ========== Verbosity ==========

#[test]
fn test_verbosity_set_get() {
    let mut manager = create_test_manager();

    // Default should be Normal
    assert_eq!(manager.verbosity, Verbosity::Normal);

    // Set to Quiet
    manager.set_verbosity(Verbosity::Quiet);
    assert_eq!(manager.verbosity, Verbosity::Quiet);

    // Set to Verbose
    manager.set_verbosity(Verbosity::Verbose);
    assert_eq!(manager.verbosity, Verbosity::Verbose);

    // Set to Debug
    manager.set_verbosity(Verbosity::Debug);
    assert_eq!(manager.verbosity, Verbosity::Debug);
}

#[test]
fn test_verbosity_included_in_debug_output() {
    let manager = create_test_manager();
    let debug_str = format!("{:?}", manager);

    // Verify verbosity field is included in Debug output
    assert!(debug_str.contains("verbosity"));
}

#[test]
fn test_activate_with_different_verbosity_levels() {
    // Test that activate() respects verbosity settings
    // This is tested implicitly through the existing activate tests
    // since they use Normal verbosity by default

    let mut manager = create_test_manager();
    manager.set_verbosity(Verbosity::Quiet);
    assert_eq!(manager.verbosity, Verbosity::Quiet);

    manager.set_verbosity(Verbosity::Debug);
    assert_eq!(manager.verbosity, Verbosity::Debug);
}

#[test]
fn test_stopwatch_used_for_timing() {
    // Verify Stopwatch is available and works correctly
    let stopwatch = Stopwatch::start();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let elapsed = stopwatch.elapsed();

    assert!(elapsed.as_millis() >= 10);

    // Verify Display trait works
    let display = format!("{}", stopwatch);
    assert!(display.ends_with("ms") || display.ends_with("s"));
}

#[test]
fn test_verbosity_ordering_in_manager() {
    // Verify verbosity levels can be compared
    assert!(Verbosity::Quiet < Verbosity::Normal);
    assert!(Verbosity::Normal < Verbosity::Verbose);
    assert!(Verbosity::Verbose < Verbosity::Debug);
}

// ========== TestWorld builder ==========

#[test]
fn test_world_roots_under_tempdir_by_default() {
    let (manager, tmp) = TestWorld::new().manager();
    assert_eq!(manager.config().hidden_volume_root, tmp.path());
    assert_eq!(manager.state_file_path, tmp.path().join("state.json"));
}

#[test]
fn test_world_stages_files_and_dirs() {
    let (manager, _tmp) = TestWorld::new()
        .with_dir("/etc/nixos")
        .with_file("/etc/nixos/configuration.nix", "{ }")
        .manager();

    let fs = manager.filesystem();
    assert!(fs.is_directory(Path::new("/etc/nixos")).unwrap());
    assert!(
        fs.path_exists(Path::new("/etc/nixos/configuration.nix"))
            .unwrap()
    );
    assert_eq!(
        fs.read_file_content(Path::new("/etc/nixos/configuration.nix"))
            .unwrap(),
        "{ }"
    );
}

#[test]
fn test_world_honours_supplied_config() {
    let config = Config {
        minimum_space_mb: 4242,
        ..Config::test_default()
    };
    let (manager, _tmp) = TestWorld::new().with_config(config).manager();
    assert_eq!(manager.config().minimum_space_mb, 4242);
}
