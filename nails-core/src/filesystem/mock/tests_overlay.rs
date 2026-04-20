use super::MockFilesystem;
use crate::{
    NailsError,
    filesystem::{Filesystem, verify_mount_preconditions},
};
use std::path::Path;

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
    assert_eq!(info.lower, Path::new("/"));
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
        NailsError::OverlayError(msg) => {
            assert!(msg.contains("Mock mount failure for testing"));
            assert!(msg.contains("/home"), "Error should include target path");
        }
        _ => panic!("Expected OverlayError for simulated failure"),
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
        mount_info.lower,
        Path::new("/"),
        "Lower directory should be tracked"
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
