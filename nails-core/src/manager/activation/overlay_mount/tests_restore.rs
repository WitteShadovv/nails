use crate::filesystem::PathKind;
use crate::manager::activation::guards::NixDaemonGuard;
use crate::{Config, Filesystem, MockFilesystem, NailsManager, OverlayConfig};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[test]
fn test_restore_nix_security_model_self_binds_nix_store_in_test_runtime() {
    let hidden_root = tempfile::tempdir().unwrap();
    let state_path = hidden_root.path().join("state.json");
    let fs = MockFilesystem::new();

    // The overlaid /nix/store is self-bound read-only; no decoy source is used.
    fs.mock_set_path_exists("/nix/store", true);
    fs.mock_set_path_type("/nix/store", PathKind::Dir);

    let manager = NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.path().to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![OverlayConfig {
                name: "nix".to_string(),
                lower: PathBuf::from("/nix"),
                upper: hidden_root.path().join("nix-upper"),
                work: hidden_root.path().join("nix-work"),
                target: PathBuf::from("/nix"),
            }],
            ..Config::test_default()
        },
        state_path,
    );
    let mut guard = NixDaemonGuard::new(false);

    manager.restore_nix_security_model(&mut guard).unwrap();

    // Exactly one bind on /nix/store is made and the test-runtime path never
    // forks into the init namespace.
    assert!(
        fs.is_mounted(Path::new("/nix/store")).unwrap(),
        "expected /nix/store self-bind to be restored"
    );
    assert_eq!(
        fs.mock_get_symlink_target(Path::new("/run/current-system")),
        None,
        "without cached system profile no symlink should be restored"
    );
}

#[test]
fn test_restore_nix_security_model_clears_stale_init_namespace_flag_in_test_runtime() {
    let hidden_root = tempfile::tempdir().unwrap();
    let state_path = hidden_root.path().join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/nix/store", true);
    fs.mock_set_path_type("/nix/store", PathKind::Dir);

    let manager = NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.path().to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![OverlayConfig {
                name: "nix".to_string(),
                lower: PathBuf::from("/nix"),
                upper: hidden_root.path().join("nix-upper"),
                work: hidden_root.path().join("nix-work"),
                target: PathBuf::from("/nix"),
            }],
            ..Config::test_default()
        },
        state_path,
    );

    // Pre-seed a cached state carrying a stale "bound in the init namespace" flag
    // from an earlier, differing-namespace activation.
    *manager.cached_state.borrow_mut() = Some(crate::StateFile {
        nix_store_init_namespace_bound: true,
        ..crate::StateFile::default()
    });

    let mut guard = NixDaemonGuard::new(false);
    manager.restore_nix_security_model(&mut guard).unwrap();

    // The test runtime never forks into the init namespace, so restore records no
    // init-namespace bind and clears the stale flag: a later teardown must not try
    // to undo a bind that does not exist.
    assert!(
        !manager
            .cached_state
            .borrow()
            .as_ref()
            .unwrap()
            .nix_store_init_namespace_bound,
        "test-runtime restore must record no init-namespace /nix/store bind"
    );
}

#[test]
fn test_restore_nix_security_model_self_binds_without_any_submount_sources() {
    let hidden_root = tempfile::tempdir().unwrap();
    let state_path = hidden_root.path().join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/nix/store", true);
    fs.mock_set_path_type("/nix/store", PathKind::Dir);

    let manager = NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.path().to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![OverlayConfig {
                name: "nix".to_string(),
                lower: PathBuf::from("/nix"),
                upper: hidden_root.path().join("nix-upper"),
                work: hidden_root.path().join("nix-work"),
                target: PathBuf::from("/nix"),
            }],
            ..Config::test_default()
        },
        state_path,
    );
    let mut guard = NixDaemonGuard::new(false);

    manager.restore_nix_security_model(&mut guard).unwrap();

    assert!(fs.is_mounted(Path::new("/nix/store")).unwrap());
}

#[test]
fn test_replace_symlink_creates_new_symlink() {
    let temp_dir = tempfile::tempdir().unwrap();
    let link = temp_dir.path().join("run-current-system");
    let target = temp_dir.path().join("system-1-link");

    std::fs::create_dir_all(&target).unwrap();

    NailsManager::<MockFilesystem>::replace_symlink(&link, &target).unwrap();

    assert_eq!(std::fs::read_link(&link).unwrap(), target);
}

#[test]
fn test_replace_symlink_replaces_existing_symlink_target() {
    let temp_dir = tempfile::tempdir().unwrap();
    let link = temp_dir.path().join("run-current-system");
    let original_target = temp_dir.path().join("system-old-link");
    let new_target = temp_dir.path().join("system-new-link");

    std::fs::create_dir_all(&original_target).unwrap();
    std::fs::create_dir_all(&new_target).unwrap();
    std::os::unix::fs::symlink(&original_target, &link).unwrap();

    NailsManager::<MockFilesystem>::replace_symlink(&link, &new_target).unwrap();

    assert_eq!(std::fs::read_link(&link).unwrap(), new_target);
}

#[test]
fn test_replace_symlink_rejects_existing_non_symlink() {
    let temp_dir = tempfile::tempdir().unwrap();
    let link = temp_dir.path().join("run-current-system");
    let target = temp_dir.path().join("system-1-link");

    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(&link, "not a symlink").unwrap();

    let err = NailsManager::<MockFilesystem>::replace_symlink(&link, &target).unwrap_err();
    assert!(err.to_string().contains("exists but is not a symlink"));
}

#[test]
fn test_replace_symlink_reports_inspect_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let blocked_dir = temp_dir.path().join("blocked");
    let link = blocked_dir.join("run-current-system");
    let target = temp_dir.path().join("system-1-link");

    std::fs::create_dir_all(&blocked_dir).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::set_permissions(&blocked_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

    let err = NailsManager::<MockFilesystem>::replace_symlink(&link, &target).unwrap_err();

    std::fs::set_permissions(&blocked_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(err.to_string().contains("Failed to inspect"));
}

#[test]
fn test_replace_symlink_reports_remove_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let blocked_dir = temp_dir.path().join("blocked");
    let link = blocked_dir.join("run-current-system");
    let original_target = temp_dir.path().join("system-old-link");
    let new_target = temp_dir.path().join("system-new-link");

    std::fs::create_dir_all(&blocked_dir).unwrap();
    std::fs::create_dir_all(&original_target).unwrap();
    std::fs::create_dir_all(&new_target).unwrap();
    std::os::unix::fs::symlink(&original_target, &link).unwrap();
    std::fs::set_permissions(&blocked_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let err = NailsManager::<MockFilesystem>::replace_symlink(&link, &new_target).unwrap_err();

    std::fs::set_permissions(&blocked_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        err.to_string()
            .contains("Failed to remove existing symlink")
    );
}

#[test]
fn test_replace_symlink_reports_create_error() {
    let temp_dir = tempfile::tempdir().unwrap();
    let link = temp_dir.path().join("missing").join("run-current-system");
    let target = temp_dir.path().join("system-1-link");

    std::fs::create_dir_all(&target).unwrap();

    let err = NailsManager::<MockFilesystem>::replace_symlink(&link, &target).unwrap_err();

    assert!(err.to_string().contains("Failed to create symlink"));
}

#[test]
fn test_replace_symlink_rejects_dangling_target_after_creation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let link = temp_dir.path().join("run-current-system");
    let missing_target = temp_dir.path().join("missing-system-link");

    let err = NailsManager::<MockFilesystem>::replace_symlink(&link, &missing_target).unwrap_err();

    assert!(
        err.to_string()
            .contains("is still not reachable after restoration")
    );
}
