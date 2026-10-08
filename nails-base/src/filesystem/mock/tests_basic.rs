// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::MockFilesystem;
use super::PathKind;
use crate::filesystem::Filesystem;
use std::path::Path;

#[test]
fn test_mock_filesystem_new_starts_empty() {
    let fs = MockFilesystem::new();
    assert!(fs.get_mounted_paths().is_empty());
}

#[test]
fn test_mock_filesystem_reset_clears_state() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.reset();
    assert!(fs.get_mounted_paths().is_empty());
}

#[test]
fn test_mock_filesystem_clone_shares_state() {
    let fs1 = MockFilesystem::new();
    fs1.mock_set_mounted(Path::new("/home"), true);

    let fs2 = fs1.clone();
    assert!(fs2.is_mounted(Path::new("/home")).unwrap());

    fs2.mock_set_mounted(Path::new("/tmp"), true);
    assert!(fs1.is_mounted(Path::new("/tmp")).unwrap());
}

#[test]
fn test_mock_set_mounted_can_unmount() {
    let fs = MockFilesystem::new();
    let path = Path::new("/test/mount");

    fs.mock_set_mounted(path, true);
    assert!(fs.is_mounted(path).unwrap());

    fs.mock_set_mounted(path, false);
    assert!(!fs.is_mounted(path).unwrap());
}

#[test]
fn test_mock_set_swap_enabled_drives_classifier() {
    use crate::preflight::{SwapSeverity, classify_swap};

    let fs = MockFilesystem::new();
    // No /proc/swaps seeded: nothing is active.
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Pass);

    fs.mock_set_swap_enabled(true);
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Fail);

    fs.mock_set_swap_enabled(false);
    assert_eq!(classify_swap(&fs).severity, SwapSeverity::Pass);
}

#[test]
fn test_mock_filesystem_directory_operations() {
    let fs = MockFilesystem::new();
    let path = Path::new("/test/dir");

    fs.mock_set_path_exists("/test/dir", true);
    fs.mock_set_path_type("/test/dir", PathKind::Dir);

    assert!(fs.path_exists(path).unwrap());
    assert!(fs.is_directory(path).unwrap());
}

#[test]
fn test_mock_filesystem_file_permissions() {
    let fs = MockFilesystem::new();
    let path = Path::new("/test/file");

    fs.mock_set_path_exists("/test/file", true);
    fs.mock_set_readable("/test/file", true);
    fs.mock_set_writable("/test/file", true);

    assert!(fs.is_readable(path).unwrap());
    assert!(fs.is_writable(path).unwrap());
}

#[test]
fn test_write_user_file_new_file_gets_target_owner_and_mode() {
    let fs = MockFilesystem::new();
    let user = crate::TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash");
    let path = Path::new("/home/operator/.bashrc");

    fs.write_user_file(path, "export X=1", &user, 0o644)
        .unwrap();

    assert_eq!(fs.get_written_content(path).as_deref(), Some("export X=1"));
    assert_eq!(fs.mock_get_owner(path), Some((1000, 100)));
    assert_eq!(fs.mock_get_permissions(path), Some(0o644));
}

#[test]
fn test_write_user_file_existing_file_keeps_owner_and_mode() {
    let fs = MockFilesystem::new();
    let first = crate::TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash");
    let path = Path::new("/home/operator/.bashrc");

    // First write establishes owner 1000:100 and mode 0644.
    fs.write_user_file(path, "first", &first, 0o644).unwrap();

    // A later write by a different user with a different default must not change
    // the recorded owner or mode of the now-existing file.
    let second = crate::TargetUser::for_test(2000, 2000, "intruder", "/home/intruder", "/bin/sh");
    fs.write_user_file(path, "second", &second, 0o600).unwrap();

    assert_eq!(fs.get_written_content(path).as_deref(), Some("second"));
    assert_eq!(fs.mock_get_owner(path), Some((1000, 100)));
    assert_eq!(fs.mock_get_permissions(path), Some(0o644));
}

#[test]
fn test_write_user_file_creates_user_owned_parents() {
    let fs = MockFilesystem::new();
    let user = crate::TargetUser::for_test(1000, 100, "operator", "/home/operator", "/bin/bash");
    // /home/operator exists already; the autostart chain below it does not.
    fs.mock_set_path_exists("/home/operator", true);
    let path = Path::new("/home/operator/.config/autostart/nails-notify.desktop");

    fs.write_user_file(path, "[Desktop Entry]\n", &user, 0o644)
        .unwrap();

    // The directories NAILS created are owned by the operator, 0700.
    assert_eq!(
        fs.mock_get_owner(Path::new("/home/operator/.config")),
        Some((1000, 100))
    );
    assert_eq!(
        fs.mock_get_owner(Path::new("/home/operator/.config/autostart")),
        Some((1000, 100))
    );
    assert_eq!(
        fs.mock_get_permissions(Path::new("/home/operator/.config/autostart")),
        Some(0o700)
    );
    // The pre-existing home is left untouched.
    assert_eq!(fs.mock_get_owner(Path::new("/home/operator")), None);
    // The file itself is operator-owned with the requested mode.
    assert_eq!(fs.mock_get_owner(path), Some((1000, 100)));
    assert_eq!(fs.mock_get_permissions(path), Some(0o644));
}

#[test]
fn canonicalize_without_links_returns_the_path() {
    let fs = MockFilesystem::new();
    assert_eq!(
        fs.canonicalize(Path::new("/mnt/hv/state.json")).unwrap(),
        Path::new("/mnt/hv/state.json")
    );
}

#[test]
fn canonicalize_follows_recorded_links_in_any_component() {
    let fs = MockFilesystem::new();
    fs.create_symlink(Path::new("/media/veracrypt1"), Path::new("/mnt/hv"))
        .unwrap();
    fs.create_symlink(Path::new("/mnt/hv"), Path::new("/srv/link"))
        .unwrap();

    assert_eq!(
        fs.canonicalize(Path::new("/mnt/hv/logs")).unwrap(),
        Path::new("/media/veracrypt1/logs")
    );
    // A chain of links resolves to the final target.
    assert_eq!(
        fs.canonicalize(Path::new("/srv/link")).unwrap(),
        Path::new("/media/veracrypt1")
    );
}

#[test]
fn canonicalize_resolves_relative_link_targets_against_the_link_directory() {
    let fs = MockFilesystem::new();
    fs.create_symlink(Path::new("real"), Path::new("/media/alias"))
        .unwrap();

    assert_eq!(
        fs.canonicalize(Path::new("/media/alias/state.json"))
            .unwrap(),
        Path::new("/media/real/state.json")
    );
}

#[test]
fn canonicalize_refuses_a_link_loop() {
    let fs = MockFilesystem::new();
    fs.create_symlink(Path::new("/b"), Path::new("/a")).unwrap();
    fs.create_symlink(Path::new("/a"), Path::new("/b")).unwrap();

    assert!(fs.canonicalize(Path::new("/a/x")).is_err());
}

#[test]
fn mock_filesystem_default_matches_new() {
    let fs = MockFilesystem::default();
    assert!(fs.get_mounted_paths().is_empty());
}

#[test]
fn mock_filesystem_is_shared_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MockFilesystem>();

    let fs = MockFilesystem::new();
    let other = fs.clone();
    std::thread::spawn(move || other.mock_set_mounted(Path::new("/home"), true))
        .join()
        .unwrap();
    assert!(fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn mock_disk_usage_reports_the_seeded_sizes() {
    let fs = MockFilesystem::new();
    let path = Path::new("/mnt/hidden-volume");
    fs.mock_set_disk_usage(path, 4 << 30, 1 << 30);

    let usage = fs.disk_usage(path).unwrap();
    assert_eq!((usage.total, usage.available), (4 << 30, 1 << 30));
    assert_eq!(usage.used(), 3 << 30);
}

#[test]
fn mock_writable_and_readable_follow_the_seeds() {
    let fs = MockFilesystem::new();
    assert!(!fs.is_readable(Path::new("/untracked")).unwrap());
    fs.mock_set_writable("/mnt/hidden-volume", true);
    assert!(fs.is_writable(Path::new("/mnt/hidden-volume")).unwrap());
    fs.mock_set_writable("/mnt/hidden-volume", false);
    assert!(!fs.is_writable(Path::new("/mnt/hidden-volume")).unwrap());
}
