// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::{MockFilesystem, PathKind};
use std::path::Path;

/// Helper: create StorageReadinessCheck with no overlays
fn make_check_no_overlays() -> StorageReadinessCheck {
    StorageReadinessCheck::new(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT), vec![])
}

/// Helper: create StorageReadinessCheck with home+etc overlays
fn make_check_with_overlays() -> StorageReadinessCheck {
    StorageReadinessCheck::new(
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        vec![
            OverlayDirs::new(
                "home".to_string(),
                PathBuf::from("/home"),
                PathBuf::from("/mnt/data/home"),
                PathBuf::from("/mnt/data/.work/home"),
            ),
            OverlayDirs::new(
                "etc".to_string(),
                PathBuf::from("/etc"),
                PathBuf::from("/mnt/data/etc"),
                PathBuf::from("/mnt/data/.work/etc"),
            ),
        ],
    )
}

/// Helper: set up all required directories on hidden volume
fn setup_all_required_dirs(fs: &MockFilesystem) {
    for dir in &[
        "root",
        "root/upper",
        "root/work",
        "home",
        ".work",
        ".work/home",
        "etc",
        ".work/etc",
    ] {
        let path = format!("/mnt/data/{}", dir);
        fs.mock_set_path_exists(&path, true);
        fs.mock_set_path_type(&path, PathKind::Dir);
        fs.mock_set_writable(&path, true);
    }
}

/// Helper: set up overlay lower directories
fn setup_overlay_lower_dirs(fs: &MockFilesystem) {
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_readable("/home", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_readable("/etc", true);
}

#[test]
fn test_storage_readiness_trait_metadata() {
    let check = make_check_no_overlays();
    assert_eq!(
        <StorageReadinessCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "storage-readiness"
    );
    assert!(
        <StorageReadinessCheck as PreFlightCheck<MockFilesystem>>::description(&check)
            .contains("directories exist and are accessible")
    );
}

#[test]
fn test_storage_readiness_all_dirs_exist_no_overlays_pass() {
    // All dirs exist -> Pass
    let fs = MockFilesystem::new();
    let check = make_check_no_overlays();
    setup_all_required_dirs(&fs);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
}

#[test]
fn test_storage_readiness_all_dirs_and_overlays_pass() {
    // All dirs exist + overlays accessible -> single Pass
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);
    setup_overlay_lower_dirs(&fs);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());
}

#[test]
fn test_storage_readiness_sets_upper_permissions_from_lower() {
    // Upper permissions should mirror lower directory permissions
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);
    setup_overlay_lower_dirs(&fs);

    fs.set_permissions(Path::new("/home"), 0o750).unwrap();
    fs.set_permissions(Path::new("/etc"), 0o755).unwrap();

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());

    let home_upper = fs.mock_get_permissions(Path::new("/mnt/data/home"));
    let etc_upper = fs.mock_get_permissions(Path::new("/mnt/data/etc"));
    assert_eq!(home_upper, Some(0o750));
    assert_eq!(etc_upper, Some(0o755));
}

#[test]
fn test_storage_readiness_missing_dir_autocreate_success() {
    // Auto-create missing dirs (integration from 14.4)
    let fs = MockFilesystem::new();
    let check = make_check_no_overlays();

    // The work directory exists
    for dir in &["root", "root/work"] {
        let path = format!("/mnt/data/{}", dir);
        fs.mock_set_path_exists(&path, true);
        fs.mock_set_path_type(&path, PathKind::Dir);
    }

    // root/upper is missing but creatable
    fs.mock_set_path_exists("/mnt/data/root/upper", false);
    fs.mock_set_directory_creatable("/mnt/data/root/upper", true);

    let result = check.run(&fs).unwrap();
    assert!(result.is_pass());

    // Verify permissions set
    let perms = fs.mock_get_permissions(Path::new("/mnt/data/root/upper"));
    assert_eq!(perms, Some(0o700));
}

#[test]
fn test_storage_readiness_missing_dir_autocreate_fails() {
    // Creation failure -> single Fail message
    let fs = MockFilesystem::new();
    let check = make_check_no_overlays();

    for dir in &["root", "root/work"] {
        let path = format!("/mnt/data/{}", dir);
        fs.mock_set_path_exists(&path, true);
        fs.mock_set_path_type(&path, PathKind::Dir);
    }

    fs.mock_set_path_exists("/mnt/data/root/upper", false);
    fs.mock_set_directory_creatable("/mnt/data/root/upper", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("root/upper/"));
}

#[test]
fn test_storage_readiness_overlay_lower_missing_fail() {
    // Overlay lower missing -> Fail
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);

    // /home exists, /etc does NOT
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_readable("/home", true);
    fs.mock_set_path_exists("/etc", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("etc lower directory not found"));
}

#[test]
fn test_storage_readiness_overlay_upper_not_writable_fail() {
    // Upper not writable -> single Fail
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);
    setup_overlay_lower_dirs(&fs);

    // Override: home upper is not writable
    fs.mock_set_writable("/mnt/data/home", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Not writable: home upper"));
}

#[test]
fn test_storage_readiness_overlay_work_not_writable_fail() {
    // Work not writable -> Fail
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);
    setup_overlay_lower_dirs(&fs);

    // Override: etc work is not writable
    fs.mock_set_writable("/mnt/data/.work/etc", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("Not writable: etc work"));
}

#[test]
fn test_storage_readiness_mixed_issues_single_fail() {
    // Mixed issues -> single Fail message listing ALL problems
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();

    // root/upper and root/work missing and not creatable
    for dir in &["root", "etc", "home", ".work", ".work/etc", ".work/home"] {
        let path = format!("/mnt/data/{}", dir);
        fs.mock_set_path_exists(&path, true);
        fs.mock_set_path_type(&path, PathKind::Dir);
        fs.mock_set_writable(&path, true);
    }
    fs.mock_set_path_exists("/mnt/data/root/upper", false);
    fs.mock_set_directory_creatable("/mnt/data/root/upper", false);
    fs.mock_set_path_exists("/mnt/data/root/work", false);
    fs.mock_set_directory_creatable("/mnt/data/root/work", false);

    // Lower dirs: /etc not readable
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_readable("/home", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_readable("/etc", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    let msg = result.message();
    assert!(msg.contains("root/upper/"), "missing root/upper/: {}", msg);
    assert!(msg.contains("root/work/"), "missing root/work/: {}", msg);
    assert!(
        msg.contains("etc lower directory not readable"),
        "etc not readable: {}",
        msg
    );
}

#[test]
fn test_storage_readiness_directory_is_file_triggers_autocreate() {
    // Directory exists but is a file -> treated as missing, auto-create attempted
    let fs = MockFilesystem::new();
    let check = make_check_no_overlays();

    for dir in &["root", "root/work"] {
        let path = format!("/mnt/data/{}", dir);
        fs.mock_set_path_exists(&path, true);
        fs.mock_set_path_type(&path, PathKind::Dir);
        fs.mock_set_writable(&path, true);
    }

    // root/upper exists but is a file, not a directory
    fs.mock_set_path_exists("/mnt/data/root/upper", true);
    fs.mock_set_path_type("/mnt/data/root/upper", PathKind::File);
    fs.mock_set_directory_creatable("/mnt/data/root/upper", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("root/upper/"));
}

#[test]
fn test_storage_readiness_overlay_lower_not_readable_fail() {
    // Lower exists but not readable -> Fail
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);

    fs.mock_set_path_exists("/home", true);
    fs.mock_set_readable("/home", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_readable("/etc", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(
        result
            .message()
            .contains("etc lower directory not readable")
    );
}

#[test]
fn test_storage_readiness_overlay_upper_missing_fail() {
    // Upper directory missing -> Fail (when not auto-creatable)
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);
    setup_overlay_lower_dirs(&fs);

    // Override: home upper does not exist and is NOT creatable
    fs.mock_set_path_exists("/mnt/data/home", false);
    fs.mock_set_directory_creatable("/mnt/data/home", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("home upper directory not found"));
}

#[test]
fn test_storage_readiness_overlay_work_missing_fail() {
    // Work directory missing -> Fail (when not auto-creatable)
    let fs = MockFilesystem::new();
    let check = make_check_with_overlays();
    setup_all_required_dirs(&fs);
    setup_overlay_lower_dirs(&fs);

    // Override: etc work does not exist and is NOT creatable
    fs.mock_set_path_exists("/mnt/data/.work/etc", false);
    fs.mock_set_directory_creatable("/mnt/data/.work/etc", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("etc work directory not found"));
}

#[test]
fn test_storage_readiness_collect_all_overlay_errors() {
    // All overlay dirs missing -> single Fail with all issues listed (when not creatable)
    let fs = MockFilesystem::new();
    let check = StorageReadinessCheck::new(
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        vec![OverlayDirs::new(
            "home".to_string(),
            PathBuf::from("/home"),
            PathBuf::from("/mnt/data/home"),
            PathBuf::from("/mnt/data/.work/home"),
        )],
    );
    setup_all_required_dirs(&fs);

    // All overlay dirs missing and NOT creatable
    fs.mock_set_path_exists("/home", false);
    fs.mock_set_path_exists("/mnt/data/home", false);
    fs.mock_set_directory_creatable("/mnt/data/home", false);
    fs.mock_set_path_exists("/mnt/data/.work/home", false);
    fs.mock_set_directory_creatable("/mnt/data/.work/home", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("lower directory not found"));
    assert!(result.message().contains("upper directory not found"));
    assert!(result.message().contains("work directory not found"));
}

#[test]
fn test_storage_readiness_multiple_missing_dirs_autocreate_partial() {
    // Multiple dirs missing: one creatable, one not -> Fail with only the uncreatable
    let fs = MockFilesystem::new();
    let check = make_check_no_overlays();

    fs.mock_set_path_exists("/mnt/data/root", true);
    fs.mock_set_path_type("/mnt/data/root", PathKind::Dir);
    // root/upper missing but creatable
    fs.mock_set_path_exists("/mnt/data/root/upper", false);
    fs.mock_set_directory_creatable("/mnt/data/root/upper", true);
    // root/work missing and NOT creatable
    fs.mock_set_path_exists("/mnt/data/root/work", false);
    fs.mock_set_directory_creatable("/mnt/data/root/work", false);

    let result = check.run(&fs).unwrap();
    assert!(result.is_fail());
    assert!(result.message().contains("root/work/"));
    // root/upper was auto-created; only root/work is reported missing
}

#[test]
fn test_storage_readiness_clone() {
    let check = make_check_with_overlays();
    let cloned = check.clone();
    assert_eq!(format!("{:?}", check), format!("{:?}", cloned));
}

#[test]
fn test_storage_readiness_debug() {
    let check = make_check_no_overlays();
    let debug = format!("{:?}", check);
    assert!(debug.contains("StorageReadinessCheck"));
}
