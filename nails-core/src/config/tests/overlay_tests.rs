//! Tests for overlay configuration

use crate::config::{
    DEFAULT_HIDDEN_VOLUME_ROOT, EphemeralOverlayDir, ExtendedOverlayConfig, OverlayConfig,
};
use std::path::PathBuf;

// ========== OverlayConfig Tests ==========

#[test]
fn test_overlay_config_creation() {
    let overlay = OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
        work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
        target: PathBuf::from("/home"),
    };

    assert_eq!(overlay.name, "home");
    assert_eq!(overlay.lower, PathBuf::from("/home"));
    assert_eq!(
        overlay.upper,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper")
    );
    assert_eq!(
        overlay.work,
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work")
    );
    assert_eq!(overlay.target, PathBuf::from("/home"));
}

#[test]
fn test_overlay_config_default() {
    let overlay = OverlayConfig::default();
    assert_eq!(overlay.name, String::new());
    assert_eq!(overlay.lower, PathBuf::new());
    assert_eq!(overlay.upper, PathBuf::new());
    assert_eq!(overlay.work, PathBuf::new());
    assert_eq!(overlay.target, PathBuf::new());
}

#[test]
fn test_overlay_config_clone() {
    let overlay1 = OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
        work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
        target: PathBuf::from("/home"),
    };

    let overlay2 = overlay1.clone();
    assert_eq!(overlay1, overlay2);
}

#[test]
fn test_overlay_config_serialization() {
    let overlay = OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from("/home"),
        upper: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/upper"),
        work: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("overlays/home/work"),
        target: PathBuf::from("/home"),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&overlay).expect("Should serialize");
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"home\""));
    assert!(json.contains("\"lower\""));
    assert!(json.contains("\"upper\""));
    assert!(json.contains("\"work\""));
    assert!(json.contains("\"target\""));

    // Deserialize back
    let deserialized: OverlayConfig = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, overlay);
}

// ========== ExtendedOverlayConfig Tests ==========

#[test]
fn test_extended_overlay_config_default() {
    let config = ExtendedOverlayConfig::default();
    assert!(!config.enabled);
    assert!(config.directories.is_empty());
}

#[test]
fn test_extended_overlay_config_creation() {
    let dir1 = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    let dir2 = EphemeralOverlayDir {
        path: PathBuf::from("/tmp"),
        tmpfs_upper_size: "512M".to_string(),
        tmpfs_work_size: "256M".to_string(),
    };

    let config = ExtendedOverlayConfig {
        enabled: true,
        directories: vec![dir1.clone(), dir2.clone()],
    };

    assert!(config.enabled);
    assert_eq!(config.directories.len(), 2);
    assert_eq!(config.directories[0], dir1);
    assert_eq!(config.directories[1], dir2);
}

#[test]
fn test_extended_overlay_config_serialization() {
    let dir = EphemeralOverlayDir {
        path: PathBuf::from("/var"),
        tmpfs_upper_size: "1G".to_string(),
        tmpfs_work_size: "512M".to_string(),
    };

    let config = ExtendedOverlayConfig {
        enabled: true,
        directories: vec![dir],
    };

    // Serialize to JSON
    let json = serde_json::to_string(&config).expect("Should serialize");
    assert!(json.contains("\"enabled\""));
    assert!(json.contains("true"));
    assert!(json.contains("\"directories\""));

    // Deserialize back
    let deserialized: ExtendedOverlayConfig =
        serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, config);
}
