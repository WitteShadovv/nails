// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::MockFilesystem;
use crate::{
    NailsError,
    filesystem::{Filesystem, verify_mount_preconditions},
};
use std::path::{Path, PathBuf};

#[test]
fn test_mount_overlay_success_tracks_mount_info() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_ok());
    assert!(fs.is_mounted(Path::new("/home")).unwrap());

    let mount_info = fs.mock_get_mount_info(Path::new("/home"));
    assert!(mount_info.is_some());

    let info = mount_info.unwrap();
    assert_eq!(info.lowers, vec![Path::new("/").to_path_buf()]);
    assert_eq!(info.upper, Path::new("/mnt/hidden/upper"));
    assert_eq!(info.work, Path::new("/mnt/hidden/work"));
    assert_eq!(info.target, Path::new("/home"));
    let elapsed = chrono::Utc::now() - info.mounted_at;
    assert!(elapsed.num_seconds() < 2);
}

#[test]
fn test_mount_overlay_fails_on_missing_lower() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = fs.mount_overlay(
        &[Path::new("/nonexistent/lower")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Lower directory not found"));
            assert!(msg.contains("/nonexistent/lower"));
        }
        _ => panic!("Expected OverlayError for missing lower directory"),
    }
}

#[test]
fn test_mount_overlay_fails_on_missing_upper() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/nonexistent/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Upper directory not found"));
            assert!(msg.contains("/nonexistent/upper"));
        }
        _ => panic!("Expected OverlayError for missing upper directory"),
    }
}

#[test]
fn test_mount_overlay_fails_on_missing_work() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/nonexistent/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Work directory not found"));
            assert!(msg.contains("/nonexistent/work"));
        }
        _ => panic!("Expected OverlayError for missing work directory"),
    }
}

#[test]
fn test_mount_overlay_fails_on_already_mounted() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );
    assert!(result.is_ok());

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::AlreadyMounted { path } => {
            assert_eq!(path, Path::new("/home"));
        }
        _ => panic!("Expected AlreadyMounted error"),
    }
}

#[test]
fn test_mock_filesystem_can_simulate_mount_failure() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);
    fs.mock_set_mount_should_fail("/home", true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::Mount { target, errno } => {
            assert_eq!(target, Path::new("/home"), "Error should carry the target");
            assert_eq!(
                errno,
                nix::errno::Errno::EIO,
                "Default simulated mount errno should be the fatal EIO"
            );
        }
        other => panic!("Expected Mount error for simulated failure, got {other:?}"),
    }
}

#[test]
fn test_mount_overlay_target_contains_merged_view() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );
    assert!(result.is_ok());

    let mount_info = fs.mock_get_mount_info(Path::new("/home")).unwrap();
    assert_eq!(
        mount_info.lowers,
        vec![Path::new("/").to_path_buf()],
        "Lower directories should be tracked"
    );
    assert_eq!(
        mount_info.upper,
        Path::new("/mnt/hidden/upper"),
        "Upper directory should be tracked"
    );
    assert_eq!(
        mount_info.work,
        Path::new("/mnt/hidden/work"),
        "Work directory should be tracked"
    );
    assert_eq!(
        mount_info.target,
        Path::new("/home"),
        "Target mount point should be tracked"
    );
}

#[test]
fn test_unmount_removes_mount_info() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    )
    .unwrap();

    assert!(fs.is_mounted(Path::new("/home")).unwrap());
    assert!(fs.mock_get_mount_info(Path::new("/home")).is_some());

    fs.unmount(Path::new("/home"), false).unwrap();

    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
    assert!(fs.mock_get_mount_info(Path::new("/home")).is_none());
}

#[test]
fn test_unmount_refuses_unmanaged_mount() {
    let fs = MockFilesystem::new();

    // A real ext4 /home that NAILS never mounted.
    fs.mock_set_mount_unmanaged(Path::new("/home"));
    assert!(fs.is_mounted(Path::new("/home")).unwrap());

    // Both graceful and forced unmount must be refused, never detaching it.
    for force in [false, true] {
        let err = fs
            .unmount(Path::new("/home"), force)
            .expect_err("unmanaged unmount must be refused");
        assert!(
            matches!(err, NailsError::RefusedUnmanagedUnmount { .. }),
            "expected RefusedUnmanagedUnmount, got {err:?}"
        );
    }

    // Still mounted — the refusal did not touch it.
    assert!(fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_unmount_allows_nails_owned_mount() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);
    fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    )
    .unwrap();

    // A NAILS-owned overlay unmounts normally.
    fs.unmount(Path::new("/home"), false).unwrap();
    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_verify_mount_preconditions_succeeds_when_all_valid() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_ok());
}

#[test]
fn test_verify_mount_preconditions_fails_on_missing_lower() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/nonexistent"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Lower directory not found"));
        }
        _ => panic!("Expected OverlayError"),
    }
}

#[test]
fn test_verify_mount_preconditions_fails_on_missing_upper() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/nonexistent/subdir/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Upper directory not found and parent doesn't exist"));
        }
        _ => panic!("Expected OverlayError"),
    }
}

#[test]
fn test_verify_mount_preconditions_fails_on_missing_work() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/nonexistent/subdir/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Work directory not found and parent doesn't exist"));
        }
        _ => panic!("Expected OverlayError"),
    }
}

#[test]
fn test_verify_mount_preconditions_fails_on_already_mounted() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);

    fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    )
    .unwrap();

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::AlreadyMounted { path } => {
            assert_eq!(path, Path::new("/home"));
        }
        _ => panic!("Expected AlreadyMounted error"),
    }
}

#[test]
fn test_verify_mount_preconditions_succeeds_when_upper_creatable() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);
    fs.mock_set_directory_creatable("/mnt/hidden/upper", true);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_ok());
}

#[test]
fn test_verify_mount_preconditions_succeeds_when_work_creatable() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_directory_creatable("/mnt/hidden/work", true);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_ok());
}

#[test]
fn test_verify_mount_preconditions_fails_when_upper_not_creatable() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/work", true);
    fs.mock_set_directory_creatable("/mnt/hidden/upper", false);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::PermissionDenied(msg) => {
            assert!(msg.contains("Upper directory not found and parent not writable"));
        }
        _ => panic!("Expected PermissionDenied error"),
    }
}

#[test]
fn test_verify_mount_preconditions_fails_when_work_not_creatable() {
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/upper", true);
    fs.mock_set_directory_creatable("/mnt/hidden/work", false);

    let result = verify_mount_preconditions(
        &fs,
        Path::new("/"),
        Path::new("/mnt/hidden/upper"),
        Path::new("/mnt/hidden/work"),
        Path::new("/home"),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        NailsError::PermissionDenied(msg) => {
            assert!(msg.contains("Work directory not found and parent not writable"));
        }
        _ => panic!("Expected PermissionDenied error"),
    }
}

#[test]
fn discover_nails_mounts_reports_overlays_and_binds_owned_but_not_foreign() {
    // A persistent overlay, a pivot staging bind and the /nix/store restore bind
    // over an overlaid /nix are all NAILS-owned; a plain mounted-but-unmanaged
    // path is not — the mock must classify the same way the real parser does.
    let fs = MockFilesystem::new();
    let hidden = Path::new("/mnt/hidden");

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/mnt/hidden/home/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/home/work", true);
    fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/mnt/hidden/home/upper"),
        Path::new("/mnt/hidden/home/work"),
        Path::new("/home"),
    )
    .unwrap();

    fs.mock_set_path_exists("/nix", true);
    fs.mock_set_path_exists("/mnt/hidden/nix/upper", true);
    fs.mock_set_path_exists("/mnt/hidden/nix/work", true);
    fs.mount_overlay(
        &[Path::new("/nix")],
        Path::new("/mnt/hidden/nix/upper"),
        Path::new("/mnt/hidden/nix/work"),
        Path::new("/nix"),
    )
    .unwrap();

    // The per-activation runtime scaffolding root (a random-named tmpfs under
    // /run), a pivot staging bind inside it, and the /nix/store restore bind over
    // an overlaid /nix. The root is discovered structurally via the staging bind.
    let runtime_root = "/run/0123456789abcdef";
    fs.mount_tmpfs(Path::new(runtime_root), "16M").unwrap();
    fs.mock_set_path_exists("/nix/store", true);
    fs.bind_mount(
        Path::new("/nix/store"),
        &PathBuf::from(format!("{runtime_root}/etc")),
    )
    .unwrap();
    fs.mock_set_path_exists("/nix-real/store", true);
    fs.bind_mount(Path::new("/nix-real/store"), Path::new("/nix/store"))
        .unwrap();

    // A plain host mount stale state might wrongly point at.
    fs.mock_set_mount_unmanaged(Path::new("/data"));

    let mounts = fs.discover_nails_mounts(Some(hidden)).unwrap();

    assert_eq!(mounts.runtime_tmpfs, Some(PathBuf::from(runtime_root)));
    assert!(mounts.is_owned(Path::new("/home")));
    assert!(mounts.is_owned(Path::new("/nix")));
    assert!(mounts.is_owned(&PathBuf::from(format!("{runtime_root}/etc"))));
    assert!(mounts.is_owned(Path::new(runtime_root)));
    // /nix/store is ours because /nix is overlaid.
    assert!(mounts.nix_overlay_present);
    assert!(mounts.is_owned(Path::new("/nix/store")));
    // The foreign mount is never owned.
    assert!(!mounts.is_owned(Path::new("/data")));
}
