//! Tests for ephemeral overlay configuration

use crate::config::EphemeralOverlayDir;
use std::path::PathBuf;

#[test]
fn test_ephemeral_overlay_dir_creation() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    assert_eq!(dir.path, PathBuf::from("/var"));
    assert_eq!(dir.tmpfs_upper_size, "1G");
    assert_eq!(dir.tmpfs_work_size, "512M");
}

#[test]
fn test_parse_size_megabytes() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "512M".to_string(),
        tmpfs_work_size: "256MB".to_string(),
    };

    assert_eq!(dir.parse_upper_size().unwrap(), 512 * 1024 * 1024);
    assert_eq!(dir.parse_work_size().unwrap(), 256 * 1024 * 1024);
}

#[test]
fn test_parse_size_gigabytes() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "2GB".to_string(),
    };

    assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
    assert_eq!(dir.parse_work_size().unwrap(), 2 * 1024 * 1024 * 1024);
}

#[test]
fn test_parse_size_lowercase() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1g".to_string(),
        tmpfs_work_size: "512m".to_string(),
    };

    assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
    assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
}

#[test]
fn test_parse_size_bytes() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1048576".to_string(), // 1 MB in bytes
        tmpfs_work_size: "524288".to_string(),   // 512 KB in bytes
    };

    assert_eq!(dir.parse_upper_size().unwrap(), 1048576);
    assert_eq!(dir.parse_work_size().unwrap(), 524288);
}

#[test]
fn test_parse_size_with_whitespace() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "  1G  ".to_string(),
        tmpfs_work_size: " 512M ".to_string(),
    };

    assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
    assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
}

#[test]
fn test_parse_size_invalid_format() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "invalid".to_string(),
        tmpfs_work_size: "1X".to_string(),
    };

    assert!(dir.parse_upper_size().is_err());
    assert!(dir.parse_work_size().is_err());
}

#[test]
fn test_parse_size_invalid_number() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "abcM".to_string(),
        tmpfs_work_size: "G".to_string(),
    };

    assert!(dir.parse_upper_size().is_err());
    assert!(dir.parse_work_size().is_err());
}

#[test]
fn test_ephemeral_overlay_dir_serialization() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&dir).expect("Should serialize");
    assert!(json.contains("\"path\""));
    assert!(json.contains("\"/var\""));
    assert!(json.contains("\"tmpfs_upper_size\""));
    assert!(json.contains("\"1G\""));

    // Deserialize back
    let deserialized: EphemeralOverlayDir =
        serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, dir);
}
