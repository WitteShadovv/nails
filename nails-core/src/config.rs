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
///     ..Config::default()
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

    /// Minimum disk space required for activation (in MB)
    pub minimum_space_mb: u64,

    /// Extended overlay configuration for ephemeral (tmpfs-backed) overlays (Story 4.11)
    #[serde(default)]
    pub extended_overlays: ExtendedOverlayConfig,
}

impl Default for Config {
    /// Create default configuration with sensible test defaults
    ///
    /// Uses standard paths that work for testing with MockFilesystem.
    /// Includes default overlays for /home and /etc for VM testing.
    fn default() -> Self {
        let hidden_root = PathBuf::from("/mnt/hidden-volume");

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join(".nails/state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/home"),
                    upper: hidden_root.join("home"),
                    work: hidden_root.join(".work/home"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/etc"),
                    upper: hidden_root.join("etc"),
                    work: hidden_root.join(".work/etc"),
                    target: PathBuf::from("/etc"),
                },
            ],
            minimum_space_mb: 500, // Default minimum: 500 MB
            // Ephemeral overlays enabled with pivot mount strategy (Story 4.11)
            // Uses staging + bind mount to overlay active directories like /var
            extended_overlays: ExtendedOverlayConfig {
                enabled: true,
                directories: vec![EphemeralOverlayDir {
                    path: PathBuf::from("/var"),
                    tmpfs_upper_size: "512M".to_string(),
                    tmpfs_work_size: "128M".to_string(),
                }],
            },
        }
    }
}

impl Config {
    /// Create test configuration with disabled extended overlays
    ///
    /// This provides a minimal config for unit tests that don't need
    /// ephemeral overlay functionality. Extended overlays are disabled
    /// to avoid tests needing to set up pivot mount staging directories.
    ///
    /// For tests that specifically need extended overlays, configure
    /// them explicitly in the test setup.
    pub fn test_default() -> Self {
        let hidden_root = PathBuf::from("/mnt/hidden-volume");

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join(".nails/state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/home"),
                    upper: hidden_root.join("home"),
                    work: hidden_root.join(".work/home"),
                    target: PathBuf::from("/home"),
                },
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/etc"),
                    upper: hidden_root.join("etc"),
                    work: hidden_root.join(".work/etc"),
                    target: PathBuf::from("/etc"),
                },
            ],
            minimum_space_mb: 500,
            // Disabled for tests - avoids needing to set up pivot mount paths
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
        }
    }
}

/// Extended overlay configuration for ephemeral (tmpfs-backed) overlays
///
/// Enables optional extended overlay mounting for high-activity directories
/// (/var, /tmp, /srv, /opt) with tmpfs-backed upper layers.
///
/// This strategy provides defense-in-depth against forensic analysis by:
/// - Storing runtime artifacts in RAM only (tmpfs)
/// - Destroying data immediately on unmount
/// - Preventing hidden storage capacity waste on transient files
///
/// # Forensic Rationale (Thesis Section 4.3.6)
///
/// - Persistent overlays (home/etc): Data on hidden encrypted storage
/// - Ephemeral overlays (var/tmp): Data in RAM, destroyed on unmount
/// - Different threat models for different data types
///
/// # Example
///
/// ```rust
/// use nails_core::config::ExtendedOverlayConfig;
///
/// let config = ExtendedOverlayConfig::default();
/// assert!(!config.enabled); // Disabled by default for safety
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedOverlayConfig {
    /// Whether extended overlays are enabled
    pub enabled: bool,

    /// List of ephemeral overlay directories
    #[serde(default)]
    pub directories: Vec<EphemeralOverlayDir>,
}

impl Default for ExtendedOverlayConfig {
    /// Extended overlays disabled by default for safety
    ///
    /// User must explicitly opt-in via configuration.
    fn default() -> Self {
        Self {
            enabled: false,
            directories: vec![],
        }
    }
}

/// Ephemeral overlay directory configuration
///
/// Defines a single ephemeral overlay with tmpfs-backed upper and work layers.
///
/// # Example
///
/// ```rust
/// use nails_core::config::EphemeralOverlayDir;
/// use std::path::PathBuf;
///
/// let dir = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralOverlayDir {
    /// Target directory path to overlay (e.g., "/var", "/tmp")
    pub path: PathBuf,

    /// Tmpfs size for upper layer (e.g., "1G", "512M")
    pub tmpfs_upper_size: String,

    /// Tmpfs size for work layer (e.g., "512M", "256M")
    pub tmpfs_work_size: String,
}

impl EphemeralOverlayDir {
    /// Parse tmpfs size string to bytes
    ///
    /// Supports standard size suffixes:
    /// - "M" or "MB" for megabytes
    /// - "G" or "GB" for gigabytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::EphemeralOverlayDir;
    /// use std::path::PathBuf;
    ///
    /// let dir = EphemeralOverlayDir {
    ///     path: PathBuf::from("/var"),
    ///     tmpfs_upper_size: "1G".to_string(),
    ///     tmpfs_work_size: "512M".to_string(),
    /// };
    ///
    /// assert_eq!(dir.parse_upper_size().unwrap(), 1024 * 1024 * 1024);
    /// assert_eq!(dir.parse_work_size().unwrap(), 512 * 1024 * 1024);
    /// ```
    pub fn parse_upper_size(&self) -> Result<u64, String> {
        parse_size(&self.tmpfs_upper_size)
    }

    /// Parse work directory tmpfs size to bytes
    pub fn parse_work_size(&self) -> Result<u64, String> {
        parse_size(&self.tmpfs_work_size)
    }
}

/// Parse size string to bytes
///
/// Internal helper for parsing tmpfs size specifications.
///
/// # Supported Formats
///
/// - "512M", "512MB" → 512 megabytes
/// - "1G", "1GB" → 1 gigabyte
/// - Numbers only → bytes
///
/// # Errors
///
/// Returns error string if format is invalid.
fn parse_size(size_str: &str) -> Result<u64, String> {
    let trimmed = size_str.trim().to_uppercase();

    // Check for gigabyte suffix
    if let Some(num_str) = trimmed.strip_suffix("GB") {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = trimmed.strip_suffix('G') {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    // Check for megabyte suffix
    if let Some(num_str) = trimmed.strip_suffix("MB") {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = trimmed.strip_suffix('M') {
        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number in size: {}", size_str))?;
        return Ok(num * 1024 * 1024);
    }

    // No suffix, parse as bytes
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("Invalid size format: {}", size_str))
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
        // Default config includes /home and /etc overlays for VM testing
        assert_eq!(config.overlays.len(), 2);
        assert_eq!(config.overlays[0].name, "home");
        assert_eq!(config.overlays[1].name, "etc");
        // Extended overlays enabled with /var using pivot mount strategy
        assert!(config.extended_overlays.enabled);
        assert_eq!(config.extended_overlays.directories.len(), 1);
        assert_eq!(
            config.extended_overlays.directories[0].path,
            PathBuf::from("/var")
        );
    }

    #[test]
    fn test_config_test_default() {
        let config = Config::test_default();

        // test_default() should have overlays but extended_overlays disabled
        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/mnt/hidden-volume")
        );
        assert_eq!(config.overlays.len(), 2);
        assert_eq!(config.overlays[0].name, "home");
        assert_eq!(config.overlays[1].name, "etc");
        // Extended overlays disabled in test_default for simpler testing
        assert!(!config.extended_overlays.enabled);
        assert!(config.extended_overlays.directories.is_empty());
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
            ..Config::default()
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
            ..Config::default()
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
            ..Config::default()
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
            ..Config::default()
        };

        assert_eq!(config.overlays.len(), 2);
        assert_eq!(config.overlays[0], overlay1);
        assert_eq!(config.overlays[1], overlay2);
    }

    #[test]
    fn test_config_with_extended_overlays() {
        let extended = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![],
            extended_overlays: extended.clone(),
            ..Config::default()
        };

        assert_eq!(config.extended_overlays, extended);
        assert!(config.extended_overlays.enabled);
        assert_eq!(config.extended_overlays.directories.len(), 1);
    }

    #[test]
    fn test_config_default_has_enabled_extended_overlays() {
        let config = Config::default();
        // Extended overlays enabled by default with pivot mount strategy
        assert!(config.extended_overlays.enabled);
        assert_eq!(config.extended_overlays.directories.len(), 1);
        assert_eq!(
            config.extended_overlays.directories[0].path,
            PathBuf::from("/var")
        );
    }

    #[test]
    fn test_config_serialization_with_extended_overlays() {
        let extended = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
            state_file_path: PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
            overlays: vec![],
            extended_overlays: extended,
            ..Config::default()
        };

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Should serialize");
        assert!(json.contains("\"extended_overlays\""));
        assert!(json.contains("\"enabled\""));

        // Deserialize back
        let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, config);
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

    // ========== EphemeralOverlayDir Tests ==========

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
}
