//! Configuration management for NAILS
//!
//! This module provides configuration structures for the NAILS system.
//! Full implementation will be completed in Epic 10.
//!
//! # Placeholder Design
//!
//! This is a minimal placeholder implementation for Story 2.3 (NailsManager).
//! It provides the necessary types for NailsManager to compile and be tested,
//! but does not yet implement:
//! - Configuration file parsing
//! - Validation logic
//! - Builder pattern
//! - Environment variable overrides
//!
//! Those features will be added in Epic 10.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Overlay filesystem configuration
///
/// Defines the paths for a single overlay mount point. OverlayFS combines
/// multiple directories into a single view:
/// - **lower**: Read-only base layer (from decoy system)
/// - **upper**: Writable layer (on hidden volume)
/// - **work**: Work directory for overlay metadata
/// - **target**: Where the overlay is mounted
///
/// # Security Consideration
///
/// All writable layers (upper, work) MUST be on the hidden volume to prevent
/// forensic evidence from leaking to the decoy system.
///
/// # Example
///
/// ```rust
/// use nails_core::config::OverlayConfig;
/// use std::path::PathBuf;
///
/// let overlay = OverlayConfig {
///     name: "home".to_string(),
///     lower: PathBuf::from("/home"),
///     upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
///     work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
///     target: PathBuf::from("/home"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayConfig {
    /// Human-readable name for this overlay (e.g., "home", "etc")
    pub name: String,

    /// Lower directory (read-only base layer)
    pub lower: PathBuf,

    /// Upper directory (writable, on hidden volume)
    pub upper: PathBuf,

    /// Work directory (overlay metadata)
    pub work: PathBuf,

    /// Target mount point
    pub target: PathBuf,
}

impl Default for OverlayConfig {
    /// Create an empty overlay configuration for testing
    fn default() -> Self {
        Self {
            name: String::new(),
            lower: PathBuf::new(),
            upper: PathBuf::new(),
            work: PathBuf::new(),
            target: PathBuf::new(),
        }
    }
}

/// Application configuration (placeholder for Epic 10)
///
/// This is a minimal placeholder implementation. Full configuration management
/// including file loading, validation, and builder pattern will be implemented
/// in Epic 10.
///
/// # Example
///
/// ```rust
/// use nails_core::config::Config;
/// use std::path::PathBuf;
///
/// // Use default for tests
/// let config = Config::default();
///
/// // Or create custom config
/// let config = Config {
///     hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
///     state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
///     overlays: vec![],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Root of hidden volume
    pub hidden_volume_root: PathBuf,

    /// Path to state file (on hidden volume)
    pub state_file_path: PathBuf,

    /// Overlay configurations
    pub overlays: Vec<OverlayConfig>,
}

impl Default for Config {
    /// Create default configuration with sensible test defaults
    ///
    /// Uses standard paths that work for testing with MockFilesystem.
    fn default() -> Self {
        Self {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![],
        }
    }
}

impl Config {
    /// Create test configuration with sensible defaults
    ///
    /// Alias for Default::default() with clearer intent for test code.
    pub fn test_default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== OverlayConfig Tests ==========

    #[test]
    fn test_overlay_config_creation() {
        let overlay = OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            target: PathBuf::from("/home"),
        };

        assert_eq!(overlay.name, "home");
        assert_eq!(overlay.lower, PathBuf::from("/home"));
        assert_eq!(
            overlay.upper,
            PathBuf::from("/mnt/hidden-volume/overlays/home/upper")
        );
        assert_eq!(
            overlay.work,
            PathBuf::from("/mnt/hidden-volume/overlays/home/work")
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
            upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
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
            upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
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

    // ========== Config Tests ==========

    #[test]
    fn test_config_default() {
        let config = Config::default();

        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/mnt/hidden-volume")
        );
        assert_eq!(
            config.state_file_path,
            PathBuf::from("/mnt/hidden-volume/.nails/state.json")
        );
        assert!(config.overlays.is_empty());
    }

    #[test]
    fn test_config_test_default() {
        let config = Config::test_default();

        // test_default() should be identical to default()
        let default_config = Config::default();
        assert_eq!(config, default_config);
    }

    #[test]
    fn test_config_with_overlays() {
        let overlay = OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            target: PathBuf::from("/home"),
        };

        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![overlay.clone()],
        };

        assert_eq!(config.overlays.len(), 1);
        assert_eq!(config.overlays[0], overlay);
    }

    #[test]
    fn test_config_clone() {
        let config1 = Config {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![],
        };

        let config2 = config1.clone();
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/home"),
                upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                target: PathBuf::from("/home"),
            }],
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&config).expect("Should serialize");
        assert!(json.contains("\"hidden_volume_root\""));
        assert!(json.contains("\"state_file_path\""));
        assert!(json.contains("\"overlays\""));

        // Deserialize back
        let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, config);
    }

    #[test]
    fn test_config_multiple_overlays() {
        let overlay1 = OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            target: PathBuf::from("/home"),
        };

        let overlay2 = OverlayConfig {
            name: "etc".to_string(),
            lower: PathBuf::from("/etc"),
            upper: PathBuf::from("/mnt/hidden-volume/overlays/etc/upper"),
            work: PathBuf::from("/mnt/hidden-volume/overlays/etc/work"),
            target: PathBuf::from("/etc"),
        };

        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![overlay1.clone(), overlay2.clone()],
        };

        assert_eq!(config.overlays.len(), 2);
        assert_eq!(config.overlays[0], overlay1);
        assert_eq!(config.overlays[1], overlay2);
    }
}
