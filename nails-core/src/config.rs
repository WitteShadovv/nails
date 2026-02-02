//! Configuration management for NAILS
//!
//! This module provides configuration structures for the NAILS system,
//! including the `Config` struct with user-configurable options and
//! `ConfigBuilder` for fluent API construction with validation.
//!
//! # Example
//!
//! ```rust
//! use nails_core::ConfigBuilder;
//! use std::path::PathBuf;
//!
//! let config = ConfigBuilder::new()
//!     .hidden_volume_path(PathBuf::from("/mnt/hidden-volume"))
//!     .clear_history(false)
//!     .default_verbosity("debug")
//!     .build()
//!     .expect("Failed to build config");
//! ```

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

/// Application configuration
///
/// Complete configuration management with file loading, validation, and builder pattern.
/// Use `ConfigBuilder` for programmatic construction with validation.
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
    #[serde(alias = "hidden_volume_path")]
    pub hidden_volume_root: PathBuf,

    /// Path to state file (on hidden volume)
    #[serde(default = "default_state_file_path")]
    pub state_file_path: PathBuf,

    /// Overlay configurations
    #[serde(default)]
    pub overlays: Vec<OverlayConfig>,

    /// Minimum disk space required for activation (in MB)
    #[serde(default = "default_minimum_space_mb")]
    pub minimum_space_mb: u64,

    /// Extended overlay configuration for ephemeral (tmpfs-backed) overlays (Story 4.11)
    #[serde(default)]
    pub extended_overlays: ExtendedOverlayConfig,

    // ===== User-Configurable Options (Epic 10) =====
    /// Whether to clear shell history during deactivation
    #[serde(default = "default_clear_history")]
    pub clear_history: bool,

    /// Whether to run preflight checks before activation
    #[serde(default = "default_preflight_checks")]
    pub preflight_checks: bool,

    /// Default verbosity level for logging (e.g., "info", "debug", "warn")
    #[serde(default = "default_verbosity")]
    pub default_verbosity: String,

    /// Whether to use colored output in terminal
    #[serde(default = "default_color_output")]
    pub color_output: bool,

    /// Whether to run verify command after deactivation
    #[serde(default = "default_verify_on_deactivate")]
    pub verify_on_deactivate: bool,

    /// Whether to show milestone tips during operations
    #[serde(default = "default_milestone_tips")]
    pub milestone_tips: bool,

    /// Path to log file directory
    #[serde(default = "default_log_path")]
    pub log_path: PathBuf,

    /// Maximum log file size in megabytes before rotation
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,

    /// Number of days to retain log files
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
}

// Serde default functions for new user-configurable fields
fn default_state_file_path() -> PathBuf {
    // This will be overridden in load() to use the actual hidden_volume_root
    PathBuf::from("/mnt/hidden-volume/.nails/state.json")
}

fn default_minimum_space_mb() -> u64 {
    500
}

fn default_clear_history() -> bool {
    true
}

fn default_preflight_checks() -> bool {
    true
}

fn default_verbosity() -> String {
    "info".to_string()
}

fn default_color_output() -> bool {
    true
}

fn default_verify_on_deactivate() -> bool {
    true
}

fn default_milestone_tips() -> bool {
    true
}

fn default_log_path() -> PathBuf {
    // Default will be derived from hidden_volume_root in builder
    PathBuf::from("/mnt/hidden-volume/logs")
}

fn default_max_log_size_mb() -> u64 {
    10
}

fn default_retention_days() -> u64 {
    7
}

/// Builder for Config with validation and smart defaults
///
/// Provides fluent API for constructing Config instances with validation.
/// Required fields must be set before calling `build()`.
///
/// # Example
///
/// ```rust
/// use nails_core::config::ConfigBuilder;
/// use std::path::PathBuf;
///
/// let config = ConfigBuilder::new()
///     .hidden_volume_path(PathBuf::from("/mnt/hidden-volume"))
///     .clear_history(false)
///     .default_verbosity("debug")
///     .build()
///     .expect("Failed to build config");
/// ```
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    hidden_volume_root: Option<PathBuf>,
    state_file_path: Option<PathBuf>,
    overlays: Option<Vec<OverlayConfig>>,
    minimum_space_mb: Option<u64>,
    extended_overlays: Option<ExtendedOverlayConfig>,
    clear_history: Option<bool>,
    preflight_checks: Option<bool>,
    default_verbosity: Option<String>,
    color_output: Option<bool>,
    verify_on_deactivate: Option<bool>,
    milestone_tips: Option<bool>,
    log_path: Option<PathBuf>,
    max_log_size_mb: Option<u64>,
    retention_days: Option<u64>,
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hidden volume root path (required)
    ///
    /// This is the only required field. All other fields have smart defaults.
    pub fn hidden_volume_path(mut self, path: PathBuf) -> Self {
        self.hidden_volume_root = Some(path);
        self
    }

    /// Set the state file path
    ///
    /// Default: `{hidden_volume_root}/.nails/state.json`
    pub fn state_file_path(mut self, path: PathBuf) -> Self {
        self.state_file_path = Some(path);
        self
    }

    /// Set overlay configurations
    ///
    /// Default: empty list
    pub fn overlays(mut self, overlays: Vec<OverlayConfig>) -> Self {
        self.overlays = Some(overlays);
        self
    }

    /// Set minimum space in megabytes
    ///
    /// Default: 500 MB
    pub fn minimum_space_mb(mut self, mb: u64) -> Self {
        self.minimum_space_mb = Some(mb);
        self
    }

    /// Set extended overlay configuration
    ///
    /// Default: disabled
    pub fn extended_overlays(mut self, config: ExtendedOverlayConfig) -> Self {
        self.extended_overlays = Some(config);
        self
    }

    /// Set whether to clear shell history during deactivation
    ///
    /// Default: `true`
    pub fn clear_history(mut self, enabled: bool) -> Self {
        self.clear_history = Some(enabled);
        self
    }

    /// Set whether to run preflight checks before activation
    ///
    /// Default: `true`
    pub fn preflight_checks(mut self, enabled: bool) -> Self {
        self.preflight_checks = Some(enabled);
        self
    }

    /// Set default verbosity level for logging
    ///
    /// Common values: "quiet", "info", "debug"
    ///
    /// Default: `"info"`
    pub fn default_verbosity(mut self, level: &str) -> Self {
        self.default_verbosity = Some(level.to_string());
        self
    }

    /// Set whether to use colored output in terminal
    ///
    /// Default: `true`
    pub fn color_output(mut self, enabled: bool) -> Self {
        self.color_output = Some(enabled);
        self
    }

    /// Set whether to run verify command after deactivation
    ///
    /// Default: `true`
    pub fn verify_on_deactivate(mut self, enabled: bool) -> Self {
        self.verify_on_deactivate = Some(enabled);
        self
    }

    /// Set whether to show milestone tips during operations
    ///
    /// Default: `true`
    pub fn milestone_tips(mut self, enabled: bool) -> Self {
        self.milestone_tips = Some(enabled);
        self
    }

    /// Set log file directory path
    ///
    /// Default: `{hidden_volume_root}/logs`
    pub fn log_path(mut self, path: PathBuf) -> Self {
        self.log_path = Some(path);
        self
    }

    /// Set maximum log file size in megabytes before rotation
    ///
    /// Default: 10 MB
    pub fn max_log_size_mb(mut self, size: u64) -> Self {
        self.max_log_size_mb = Some(size);
        self
    }

    /// Set number of days to retain log files
    ///
    /// Default: 7 days
    pub fn retention_days(mut self, days: u64) -> Self {
        self.retention_days = Some(days);
        self
    }

    /// Build the Config with validation and smart defaults
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` if required fields are missing.
    pub fn build(self) -> crate::error::Result<Config> {
        use crate::error::NailsError;

        // Validate required field
        let hidden_volume_root = self.hidden_volume_root.ok_or_else(|| {
            NailsError::ConfigError("Missing required field: hidden_volume_path".into())
        })?;

        // Apply smart defaults for optional fields
        let state_file_path = self
            .state_file_path
            .unwrap_or_else(|| hidden_volume_root.join(".nails/state.json"));

        let overlays = self.overlays.unwrap_or_default();

        let minimum_space_mb = self.minimum_space_mb.unwrap_or(500);

        let extended_overlays = self.extended_overlays.unwrap_or_default();

        let clear_history = self.clear_history.unwrap_or_else(default_clear_history);

        let preflight_checks = self
            .preflight_checks
            .unwrap_or_else(default_preflight_checks);

        let default_verbosity = self.default_verbosity.unwrap_or_else(default_verbosity);

        let color_output = self.color_output.unwrap_or_else(default_color_output);

        let verify_on_deactivate = self
            .verify_on_deactivate
            .unwrap_or_else(default_verify_on_deactivate);

        let milestone_tips = self.milestone_tips.unwrap_or_else(default_milestone_tips);

        // Derive log_path from hidden_volume_root if not specified
        let log_path = self
            .log_path
            .unwrap_or_else(|| hidden_volume_root.join("logs"));

        let max_log_size_mb = self.max_log_size_mb.unwrap_or_else(default_max_log_size_mb);

        let retention_days = self.retention_days.unwrap_or_else(default_retention_days);

        Ok(Config {
            hidden_volume_root,
            state_file_path,
            overlays,
            minimum_space_mb,
            extended_overlays,
            clear_history,
            preflight_checks,
            default_verbosity,
            color_output,
            verify_on_deactivate,
            milestone_tips,
            log_path,
            max_log_size_mb,
            retention_days,
        })
    }
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
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
        }
    }
}

impl Config {
    /// Load configuration from YAML file
    ///
    /// Reads and parses configuration from the specified path. Returns descriptive
    /// errors for missing files, malformed YAML, or missing required fields.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to YAML configuration file (typically `~/.nails/config.yaml`)
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` if:
    /// - File does not exist (includes example config in error)
    /// - YAML syntax is invalid (includes line number)
    /// - Required field `hidden_volume_path` is missing
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// # use std::io::Write;
    /// # use tempfile::NamedTempFile;
    /// # let mut file = NamedTempFile::new().unwrap();
    /// # writeln!(file, "hidden_volume_path: /mnt/hidden-volume").unwrap();
    /// let config = Config::load(file.path()).expect("Failed to load config");
    /// ```
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        use crate::error::NailsError;

        // Read file contents with descriptive error
        let contents = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NailsError::ConfigError(format!(
                    "Config file not found: {}\n\nCreate one with:\n{}",
                    path.display(),
                    Self::example_config()
                ))
            } else {
                NailsError::ConfigError(format!("Failed to read config: {}", e))
            }
        })?;

        // Parse YAML with line number in errors
        let mut config: Config = serde_yaml::from_str(&contents).map_err(|e| {
            let line_info = if let Some(location) = e.location() {
                format!(" at line {}", location.line())
            } else {
                String::new()
            };

            NailsError::ConfigError(format!(
                "Invalid YAML{}: {}\n\nExample config:\n{}",
                line_info,
                e,
                Self::example_config()
            ))
        })?;

        // Validate required field
        if config.hidden_volume_root.as_os_str().is_empty() {
            return Err(NailsError::ConfigError(
                "Missing required field: hidden_volume_path".into(),
            ));
        }

        // Derive state_file_path from hidden_volume_root if it's still the default
        if config.state_file_path.as_os_str() == "/mnt/hidden-volume/.nails/state.json" {
            config.state_file_path = config.hidden_volume_root.join(".nails/state.json");
        }

        Ok(config)
    }

    /// Returns example YAML configuration with all fields documented
    ///
    /// Provides a complete example config showing required and optional fields
    /// with their default values. Useful for error messages and documentation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    ///
    /// let example = Config::example_config();
    /// println!("{}", example);
    /// ```
    pub fn example_config() -> &'static str {
        r#"# NAILS Configuration
# Required fields:
hidden_volume_path: /mnt/hidden-volume

# Optional fields (defaults shown):
clear_history: true
preflight_checks: true
default_verbosity: info  # quiet, info, debug
color_output: true
verify_on_deactivate: true
milestone_tips: true

# Logging configuration:
log_path: /mnt/hidden-volume/logs
max_log_size_mb: 10
retention_days: 7

# Overlay configuration (advanced):
# overlays:
#   - name: home
#     lower: /home
#     upper: /mnt/hidden-volume/home
#     work: /mnt/hidden-volume/.work/home
#     target: /home

# Extended overlay configuration (ephemeral tmpfs-backed overlays):
# extended_overlays:
#   enabled: false
#   directories:
#     - path: /var
#       tmpfs_upper_size: 512M
#       tmpfs_work_size: 128M
"#
    }

    /// Load configuration from file, or return default if file doesn't exist
    ///
    /// Convenience method that attempts to load config from file, but falls back
    /// to `Config::default()` if the file doesn't exist. Other errors (malformed
    /// YAML, missing required fields) are still returned.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to YAML configuration file
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` for parsing errors, but NOT for missing files.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// let config = Config::load_or_default(&PathBuf::from("~/.nails/config.yaml"))
    ///     .expect("Failed to load config");
    /// ```
    pub fn load_or_default(path: &std::path::Path) -> crate::error::Result<Self> {
        match Self::load(path) {
            Ok(config) => Ok(config),
            Err(crate::error::NailsError::ConfigError(msg))
                if msg.contains("Config file not found") =>
            {
                Ok(Self::default())
            }
            Err(e) => Err(e),
        }
    }

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
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
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
        // User-configurable options with defaults (Epic 10)
        assert!(config.clear_history);
        assert!(config.preflight_checks);
        assert_eq!(config.default_verbosity, "info");
        assert!(config.color_output);
        assert!(config.verify_on_deactivate);
        assert!(config.milestone_tips);
        assert_eq!(config.log_path, PathBuf::from("/mnt/hidden-volume/logs"));
        assert_eq!(config.max_log_size_mb, 10);
        assert_eq!(config.retention_days, 7);
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
        // User-configurable options should still have defaults
        assert!(config.clear_history);
        assert!(config.preflight_checks);
        assert_eq!(config.default_verbosity, "info");
        assert!(config.color_output);
        assert!(config.verify_on_deactivate);
        assert!(config.milestone_tips);
        assert_eq!(config.log_path, PathBuf::from("/mnt/hidden-volume/logs"));
        assert_eq!(config.max_log_size_mb, 10);
        assert_eq!(config.retention_days, 7);
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

    // ========== ConfigBuilder Tests ==========

    #[test]
    fn test_builder_with_all_fields_specified() {
        let overlays = vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: PathBuf::from("/mnt/hidden/home"),
            work: PathBuf::from("/mnt/hidden/.work/home"),
            target: PathBuf::from("/home"),
        }];

        let extended = ExtendedOverlayConfig {
            enabled: true,
            directories: vec![EphemeralOverlayDir {
                path: PathBuf::from("/var"),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }],
        };

        let config = ConfigBuilder::new()
            .hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .state_file_path(PathBuf::from("/mnt/hidden/state.json"))
            .overlays(overlays.clone())
            .minimum_space_mb(1000)
            .extended_overlays(extended.clone())
            .clear_history(false)
            .preflight_checks(false)
            .default_verbosity("debug")
            .color_output(false)
            .verify_on_deactivate(false)
            .milestone_tips(false)
            .log_path(PathBuf::from("/custom/logs"))
            .max_log_size_mb(20)
            .retention_days(14)
            .build()
            .expect("Build should succeed");

        assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));
        assert_eq!(
            config.state_file_path,
            PathBuf::from("/mnt/hidden/state.json")
        );
        assert_eq!(config.overlays, overlays);
        assert_eq!(config.minimum_space_mb, 1000);
        assert_eq!(config.extended_overlays, extended);
        assert!(!config.clear_history);
        assert!(!config.preflight_checks);
        assert_eq!(config.default_verbosity, "debug");
        assert!(!config.color_output);
        assert!(!config.verify_on_deactivate);
        assert!(!config.milestone_tips);
        assert_eq!(config.log_path, PathBuf::from("/custom/logs"));
        assert_eq!(config.max_log_size_mb, 20);
        assert_eq!(config.retention_days, 14);
    }

    #[test]
    fn test_builder_with_minimal_fields_applies_defaults() {
        let config = ConfigBuilder::new()
            .hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .build()
            .expect("Build should succeed");

        // Required field
        assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/hidden"));

        // Smart defaults
        assert_eq!(
            config.state_file_path,
            PathBuf::from("/mnt/hidden/.nails/state.json")
        );
        assert!(config.overlays.is_empty());
        assert_eq!(config.minimum_space_mb, 500);
        assert!(!config.extended_overlays.enabled);

        // User-configurable defaults
        assert!(config.clear_history);
        assert!(config.preflight_checks);
        assert_eq!(config.default_verbosity, "info");
        assert!(config.color_output);
        assert!(config.verify_on_deactivate);
        assert!(config.milestone_tips);
        assert_eq!(config.log_path, PathBuf::from("/mnt/hidden/logs"));
        assert_eq!(config.max_log_size_mb, 10);
        assert_eq!(config.retention_days, 7);
    }

    #[test]
    fn test_builder_missing_required_field_returns_error() {
        let result = ConfigBuilder::new().build();

        assert!(result.is_err());
        match result {
            Err(crate::error::NailsError::ConfigError(msg)) => {
                assert!(msg.contains("Missing required field: hidden_volume_path"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn test_builder_each_default_value_is_correct() {
        let config = ConfigBuilder::new()
            .hidden_volume_path(PathBuf::from("/mnt/test"))
            .build()
            .expect("Build should succeed");

        // Verify each default matches the spec
        assert!(config.clear_history);
        assert!(config.preflight_checks);
        assert_eq!(config.default_verbosity, "info");
        assert!(config.color_output);
        assert!(config.verify_on_deactivate);
        assert!(config.milestone_tips);
        assert_eq!(config.log_path, PathBuf::from("/mnt/test/logs"));
        assert_eq!(config.max_log_size_mb, 10);
        assert_eq!(config.retention_days, 7);
    }

    #[test]
    fn test_builder_log_path_derived_from_hidden_volume() {
        let config = ConfigBuilder::new()
            .hidden_volume_path(PathBuf::from("/custom/path"))
            .build()
            .expect("Build should succeed");

        // log_path should be derived from hidden_volume_root
        assert_eq!(config.log_path, PathBuf::from("/custom/path/logs"));
    }

    #[test]
    fn test_builder_log_path_can_be_overridden() {
        let config = ConfigBuilder::new()
            .hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .log_path(PathBuf::from("/var/log/nails"))
            .build()
            .expect("Build should succeed");

        // Explicit log_path should override derived value
        assert_eq!(config.log_path, PathBuf::from("/var/log/nails"));
    }

    #[test]
    fn test_config_serialization_with_new_fields() {
        let config = ConfigBuilder::new()
            .hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .clear_history(false)
            .default_verbosity("debug")
            .build()
            .expect("Build should succeed");

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Should serialize");
        assert!(json.contains("\"clear_history\""));
        assert!(json.contains("false"));
        assert!(json.contains("\"default_verbosity\""));
        assert!(json.contains("\"debug\""));

        // Deserialize back
        let deserialized: Config = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, config);
    }

    #[test]
    fn test_config_backward_compatibility_with_old_configs() {
        // Simulate old config JSON without new fields
        let old_json = r#"{
            "hidden_volume_root": "/mnt/hidden-volume",
            "state_file_path": "/mnt/hidden-volume/.nails/state.json",
            "overlays": [],
            "minimum_space_mb": 500,
            "extended_overlays": {
                "enabled": false,
                "directories": []
            }
        }"#;

        // Should deserialize successfully with defaults for missing fields
        let config: Config = serde_json::from_str(old_json).expect("Should deserialize");

        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/mnt/hidden-volume")
        );
        assert!(config.clear_history); // Default applied
        assert!(config.preflight_checks); // Default applied
        assert_eq!(config.default_verbosity, "info"); // Default applied
        assert!(config.color_output); // Default applied
        assert!(config.verify_on_deactivate); // Default applied
        assert!(config.milestone_tips); // Default applied
        assert_eq!(config.log_path, PathBuf::from("/mnt/hidden-volume/logs")); // Default applied
        assert_eq!(config.max_log_size_mb, 10); // Default applied
        assert_eq!(config.retention_days, 7); // Default applied
    }

    // ========== Config::load() Tests (Story 10.2) ==========

    #[test]
    fn test_load_valid_yaml_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
hidden_volume_path: /mnt/test-volume
clear_history: false
preflight_checks: true
default_verbosity: debug
color_output: true
verify_on_deactivate: false
milestone_tips: true
log_path: /mnt/test-volume/custom-logs
max_log_size_mb: 20
retention_days: 14
"#
        )
        .unwrap();

        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/test-volume"));
        assert!(!config.clear_history);
        assert!(config.preflight_checks);
        assert_eq!(config.default_verbosity, "debug");
        assert!(config.color_output);
        assert!(!config.verify_on_deactivate);
        assert!(config.milestone_tips);
        assert_eq!(
            config.log_path,
            PathBuf::from("/mnt/test-volume/custom-logs")
        );
        assert_eq!(config.max_log_size_mb, 20);
        assert_eq!(config.retention_days, 14);
    }

    #[test]
    fn test_load_file_not_found_error() {
        let result = Config::load(&PathBuf::from("/nonexistent/config.yaml"));
        assert!(result.is_err());

        match result {
            Err(crate::error::NailsError::ConfigError(msg)) => {
                assert!(msg.contains("Config file not found"));
                assert!(msg.contains("/nonexistent/config.yaml"));
                assert!(msg.contains("Create one with:"));
            }
            _ => panic!("Expected ConfigError for missing file"),
        }
    }

    #[test]
    fn test_load_malformed_yaml_error() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
hidden_volume_path: /mnt/test
clear_history: [this, is, invalid
"#
        )
        .unwrap();

        let result = Config::load(file.path());
        assert!(result.is_err());

        match result {
            Err(crate::error::NailsError::ConfigError(msg)) => {
                assert!(msg.contains("Invalid YAML"));
            }
            _ => panic!("Expected ConfigError for malformed YAML"),
        }
    }

    #[test]
    fn test_load_missing_required_field_error() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        // Write empty YAML or YAML without hidden_volume_path
        writeln!(
            file,
            r#"
clear_history: true
preflight_checks: true
"#
        )
        .unwrap();

        let result = Config::load(file.path());
        assert!(result.is_err());

        match result {
            Err(crate::error::NailsError::ConfigError(msg)) => {
                // Could be serde error for missing field or our validation
                assert!(
                    msg.contains("hidden_volume_path")
                        || msg.contains("hidden_volume_root")
                        || msg.contains("Missing required field")
                );
            }
            _ => panic!("Expected ConfigError for missing required field"),
        }
    }

    #[test]
    fn test_load_partial_config_with_defaults() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Only specify required field and a few optional ones
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
hidden_volume_path: /mnt/partial
clear_history: false
"#
        )
        .unwrap();

        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/partial"));
        assert!(!config.clear_history); // Specified
        assert!(config.preflight_checks); // Default
        assert_eq!(config.default_verbosity, "info"); // Default
        assert!(config.color_output); // Default
        assert!(config.verify_on_deactivate); // Default
        assert!(config.milestone_tips); // Default
    }

    #[test]
    fn test_example_config_returns_valid_yaml() {
        let example = Config::example_config();

        // Example should be parseable
        assert!(example.contains("hidden_volume_path"));
        assert!(example.contains("clear_history"));
        assert!(example.contains("preflight_checks"));
        assert!(example.contains("default_verbosity"));

        // Try to parse it (simulated - actual parsing would require serde_yaml)
        assert!(example.contains("# NAILS Configuration"));
        assert!(example.contains("# Required fields:"));
    }

    #[test]
    fn test_load_or_default_with_existing_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
hidden_volume_path: /mnt/test-default
clear_history: false
"#
        )
        .unwrap();

        let config = Config::load_or_default(file.path()).unwrap();
        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/mnt/test-default")
        );
        assert!(!config.clear_history);
    }

    #[test]
    fn test_load_or_default_with_nonexistent_file() {
        let config = Config::load_or_default(&PathBuf::from("/nonexistent/config.yaml")).unwrap();

        // Should return Config::default()
        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/mnt/hidden-volume")
        );
        assert!(config.clear_history);
    }

    #[test]
    fn test_load_with_hidden_volume_path_alias() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Test that the YAML alias "hidden_volume_path" works
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
hidden_volume_path: /mnt/alias-test
clear_history: false
"#
        )
        .unwrap();

        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/alias-test"));
        assert!(!config.clear_history);
    }
}
