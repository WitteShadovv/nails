//! Configuration management for NAILS
//!
//! This module provides configuration structures for the NAILS system,
//! including the `Config` struct with user-configurable options and
//! `ConfigBuilder` for fluent API construction with validation.
//!
//! # Example
//!
//! ```rust
//! use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
//! use nails_core::ConfigBuilder;
//! use std::path::PathBuf;
//!
//! let config = ConfigBuilder::new()
//!     .hidden_volume_path(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT))
//!     .clear_history(false)
//!     .default_verbosity("debug")
//!     .build()
//!     .expect("Failed to build config");
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Sub-modules
pub mod colors;
pub mod ephemeral;
pub mod overlay;

// Re-exports for public API
pub use colors::{ColorProfile, ColorSchemeConfig, DecoyProfile};
pub use ephemeral::EphemeralOverlayDir;
pub use overlay::{ExtendedOverlayConfig, OverlayConfig, OverlayMode};

// Tests module
#[cfg(test)]
mod tests;

/// CLI argument overrides for configuration
///
/// All fields are Option to distinguish "not specified" from "explicitly set".
/// Only Some values override the loaded config.
///
/// # Priority Order (UXR26)
///
/// Configuration values are resolved in this priority order:
/// 1. CLI flags (highest priority)
/// 2. Config file values
/// 3. Default values (lowest priority)
///
/// # Example
///
/// ```rust
/// use nails_core::CliOverrides;
///
/// let overrides = CliOverrides {
///     preflight_checks: Some(false), // --no-preflight flag
///     verbosity: Some("debug".to_string()), // -vv flag
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// Override preflight_checks (--no-preflight sets to false)
    pub preflight_checks: Option<bool>,

    /// Override clear_history (--no-clear-history sets to false)
    pub clear_history: Option<bool>,

    /// Override default_verbosity (from -q, -v, -vv flags)
    pub verbosity: Option<String>,

    /// Override color_output (--no-color sets to false)
    pub color_output: Option<bool>,

    /// Override verify_on_deactivate (--no-verify sets to false)
    pub verify_on_deactivate: Option<bool>,
}

/// Application configuration
///
/// Complete configuration management with file loading, validation, and builder pattern.
/// Use `ConfigBuilder` for programmatic construction with validation.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::config::Config;
/// use std::path::PathBuf;
///
/// // Use default for tests
/// let config = Config::default();
///
/// // Or create custom config
/// let config = Config {
///     hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
///     state_file_path: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json"),
///     overlays: vec![],
///     ..Config::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Root of hidden volume
    ///
    /// Auto-derived from binary location if not specified in config file (Story 14.9).
    /// Priority: config file value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
    #[serde(alias = "hidden_volume_path", default = "default_hidden_volume_root")]
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

    // ===== Dynamic Overlay Configuration (Story 14.10) =====
    /// Overlay mode: determines how overlay targets are selected
    ///
    /// - **Auto** (default, recommended): Dynamically enumerate ALL directories under `/`
    ///   and overlay them (except those in the exclusion list). Provides maximum forensic
    ///   protection by ensuring no directory on the base system can leak artifacts.
    ///
    /// - **Explicit**: Only overlay directories explicitly listed in `overlays` field.
    ///   Preserves legacy behavior for users who want fine-grained control.
    ///
    /// **Default**: `OverlayMode::Auto`
    ///
    /// **Example**:
    /// ```yaml
    /// overlay_mode: auto  # Use dynamic enumeration (default)
    /// # OR
    /// overlay_mode: explicit  # Use explicit overlay list
    /// ```
    #[serde(default)]
    pub overlay_mode: OverlayMode,

    /// User-specified additional exclusions (merged with defaults)
    ///
    /// Directories to exclude from overlay in Auto mode, in addition to the defaults.
    /// These paths are merged with the default exclusion list.
    ///
    /// **Default exclusions**: `/proc`, `/sys`, `/dev`, `/run`, `/mnt`, `/boot`, `/bin`, `/usr`, `/lib`, `/lib64`, `/sbin`, `/lost+found`, `/Downloads`
    ///
    /// **Use case**: Exclude additional directories you don't want overlaid
    /// (e.g., `/boot` for boot partition, `/nix` for Nix store performance).
    ///
    /// **Example**:
    /// ```yaml
    /// overlay_exclusions:
    ///   - /boot
    ///   - /nix
    /// ```
    #[serde(default)]
    pub overlay_exclusions: Vec<PathBuf>,

    /// User-specified exclusions to REMOVE from defaults
    ///
    /// Directories to remove from the default exclusion list. Provides full user control
    /// over what gets overlaid - no mandatory exclusions.
    ///
    /// **Warning**: Removing default exclusions like `/proc`, `/sys`, `/dev` will likely
    /// cause mount failures (they are pseudo-filesystems that cannot be overlaid).
    /// Only remove if you understand the implications.
    ///
    /// **Use case**: Advanced users who want to overlay `/mnt` or other default exclusions.
    ///
    /// **Example**:
    /// ```yaml
    /// overlay_exclusions_remove:
    ///   - /mnt  # I want /mnt overlaid (not excluded)
    /// ```
    #[serde(default)]
    pub overlay_exclusions_remove: Vec<PathBuf>,

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

    /// Whether to show OpSec reminders based on uptime thresholds
    #[serde(default = "default_show_opsec_reminders")]
    pub show_opsec_reminders: bool,

    /// Path to log file directory
    #[serde(default = "default_log_path")]
    pub log_path: PathBuf,

    /// Maximum log file size in megabytes before rotation
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,

    /// Number of days to retain log files
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,

    /// Terminal color scheme configuration
    #[serde(default)]
    pub color_scheme: ColorSchemeConfig,
}

/// Default hidden volume root path (single source of truth)
///
/// # Note
///
/// This constant is public for use in documentation examples and tests.
/// Production code should use `Config::hidden_volume_root` field instead of
/// hardcoding this value.
pub const DEFAULT_HIDDEN_VOLUME_ROOT: &str = "/mnt/hidden-volume";

/// Derive hidden volume root from binary location
///
/// Automatically determines the hidden volume root by extracting the parent
/// directory of the nails binary (after symlink resolution). This enables
/// zero-config operation where users can simply place the binary on the
/// hidden volume and everything "just works" without explicit configuration.
///
/// # Returns
///
/// The parent directory of the nails binary (after symlink resolution).
/// Falls back to `DEFAULT_HIDDEN_VOLUME_ROOT` if binary path cannot be determined.
///
/// # Algorithm
///
/// 1. Call `std::env::current_exe()` to get binary path
/// 2. Call `.canonicalize()` to resolve all symlinks
/// 3. Extract parent directory with `.parent()`
/// 4. Return parent, or fallback to `DEFAULT_HIDDEN_VOLUME_ROOT` on any error
///
/// # Logging
///
/// - DEBUG: Logs detected binary path and canonical path
/// - INFO: Logs successfully derived path when successful
/// - WARN: Logs fallback when `current_exe()` fails
/// - WARN: Logs fallback when `canonicalize()` fails (uses original path)
/// - WARN: Logs fallback when `parent()` returns None (binary at root)
///
/// # Example
///
/// Binary at `/mnt/hidden-volume/nails` → returns `/mnt/hidden-volume`
/// Binary at `/custom/nails` → returns `/custom`
/// Symlink at `/usr/local/bin/nails` → `/mnt/hidden-volume/nails` → returns `/mnt/hidden-volume`
///
/// # Errors
///
/// Does not return `Result`. All errors handled internally with fallback.
/// This design ensures config loading never fails due to binary path resolution.
///
/// # Priority Order
///
/// This function provides the middle-priority default:
/// 1. Config file value (explicit user intent - highest priority)
/// 2. **Binary-derived default (smart inference - this function)**
/// 3. `DEFAULT_HIDDEN_VOLUME_ROOT` constant (hardcoded fallback - lowest priority)
pub fn derive_hidden_volume_root() -> PathBuf {
    match std::env::current_exe() {
        Ok(exe_path) => {
            tracing::debug!("Binary path detected: {}", exe_path.display());

            // Resolve symlinks
            let canonical_path = exe_path.canonicalize().unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to canonicalize binary path {:?}: {}. Using original path.",
                    exe_path,
                    e
                );
                exe_path.clone()
            });

            tracing::debug!("Canonical binary path: {}", canonical_path.display());

            // Extract parent directory
            match canonical_path.parent() {
                Some(parent) => {
                    let parent_path = parent.to_path_buf();

                    // TEST SAFETY GUARD (Layer 4): Detect build directories
                    // Prevents tests from treating target/debug/ as a valid hidden volume
                    // This is a defense-in-depth measure to protect against accidental
                    // system operations during test execution.
                    let path_str = parent_path.to_string_lossy();
                    if path_str.contains("/target/debug")
                        || path_str.contains("/target/release")
                        || path_str.contains("/target/llvm-cov-target")
                        || path_str.starts_with("/nix/store")
                    {
                        tracing::warn!(
                            "Binary path not suitable for deriving hidden volume (build/store location): {}. \
                             Refusing to derive hidden volume root from build artifacts. \
                             Falling back to {}",
                            parent_path.display(),
                            DEFAULT_HIDDEN_VOLUME_ROOT
                        );
                        return PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
                    }

                    tracing::debug!(
                        "Derived hidden volume root from binary location: {}",
                        parent_path.display()
                    );
                    parent_path
                }
                None => {
                    tracing::warn!(
                        "Binary at root directory (no parent): {}. Falling back to {}",
                        canonical_path.display(),
                        DEFAULT_HIDDEN_VOLUME_ROOT
                    );
                    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "Failed to determine binary location: {}. Falling back to {}",
                e,
                DEFAULT_HIDDEN_VOLUME_ROOT
            );
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        }
    }
}

// Serde default functions for new user-configurable fields
fn default_hidden_volume_root() -> PathBuf {
    derive_hidden_volume_root()
}

fn default_state_file_path() -> PathBuf {
    // This will be overridden in load() to use the actual hidden_volume_root
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json")
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

fn default_show_opsec_reminders() -> bool {
    true
}

fn default_log_path() -> PathBuf {
    // Default will be derived from hidden_volume_root in builder
    PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
}

fn default_max_log_size_mb() -> u64 {
    10
}

fn default_retention_days() -> u64 {
    7
}

/// Discover configuration file path using binary-relative resolution
///
/// Priority order (Story 14.1):
/// 1. --config CLI flag override (highest priority)
/// 2. Binary-relative path: `{binary_dir}/config/nails.yaml` (symlinks resolved)
/// 3. CWD fallback: `{current_dir}/config/nails.yaml` (if current_exe() fails)
///
/// # Symlink Handling
///
/// This function uses `canonicalize()` on the binary path to resolve symlinks.
/// For example, if `/usr/local/bin/nails` is a symlink to `/mnt/hidden-volume/bin/nails`,
/// the config will be resolved to `/mnt/hidden-volume/config/nails.yaml`.
///
/// # Fallback Behavior
///
/// If `current_exe()` fails (rare cases like proc not mounted on Linux),
/// a warning is logged via `tracing::warn!` and the current working directory
/// is used as fallback. If CWD also cannot be determined, `./config/nails.yaml` is returned.
///
/// # Arguments
///
/// * `config_override` - Optional path from `--config` CLI flag
///
/// # Returns
///
/// Resolved config path (always returns a path, never fails)
///
/// # Example
///
/// ```rust
/// use nails_core::config::discover_config_path;
/// use std::path::PathBuf;
///
/// // With CLI override
/// let path = discover_config_path(Some(&PathBuf::from("/custom/config.yaml")));
/// assert_eq!(path, PathBuf::from("/custom/config.yaml"));
///
/// // Binary-relative (most common case)
/// let path = discover_config_path(None);
/// // Returns {binary_dir}/config/nails.yaml
/// ```
pub fn discover_config_path(config_override: Option<&std::path::Path>) -> PathBuf {
    // Priority 1: Explicit --config override
    if let Some(override_path) = config_override {
        return override_path.to_path_buf();
    }

    // Priority 2: Binary-relative path (preferred)
    // Use canonicalize() to resolve symlinks before getting parent directory
    // This handles the case where /usr/local/bin/nails is a symlink to
    // /mnt/hidden-volume/bin/nails - we want config at the actual binary location
    if let Ok(exe_path) = std::env::current_exe()
        && let Ok(resolved_path) = exe_path.canonicalize()
        && let Some(exe_dir) = resolved_path.parent()
    {
        return exe_dir.join("config/nails.yaml");
    }

    // Priority 3: CWD fallback (when current_exe() or canonicalize() fails)
    tracing::warn!(
        "Failed to determine binary location for config discovery, trying current working directory"
    );

    let cwd = std::env::current_dir();
    match cwd {
        Ok(dir) => dir.join("config/nails.yaml"),
        Err(e) => {
            // Both current_exe() and current_dir() failed - this is very unusual
            // Log error and return relative path as last resort
            tracing::error!(
                "Failed to determine current directory for config discovery: {}. Using fallback ./config/nails.yaml",
                e
            );
            PathBuf::from("./config/nails.yaml")
        }
    }
}

/// Default exclusion list for dynamic overlay enumeration (Story 14.10)
///
/// These directories are excluded by default because they are:
/// - Kernel-managed virtual filesystems (/proc, /sys, /dev)
/// - Runtime state directories (/run)
/// - Mount point directories (/mnt)
/// - Bootloader directory (/boot)
/// - System library symlinks common in NixOS (/lib, /lib64, /sbin)
/// - Filesystem recovery directory (/lost+found)
/// - Non-standard user directories (/Downloads)
///
/// Directories like /etc, /home, /nix, /var, /tmp, /srv, /root, /opt, /media
/// ARE included by default for maximum forensic protection.
///
/// Users can add more exclusions via `overlay_exclusions` or remove
/// defaults via `overlay_exclusions_remove` in config YAML.
pub const DEFAULT_OVERLAY_EXCLUSIONS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/mnt",
    "/bin",
    "/usr",
    "/lib",
    "/lib64",
    "/sbin",
    "/lost+found",
    "/Downloads",
];

impl Config {
    /// Compute effective exclusion list for dynamic overlay enumeration
    ///
    /// Combines default exclusions with user additions and removals:
    /// 1. Start with DEFAULT_OVERLAY_EXCLUSIONS
    /// 2. Add user-specified overlay_exclusions
    /// 3. Remove user-specified overlay_exclusions_remove
    /// 4. Deduplicate results
    ///
    /// # Returns
    ///
    /// Vec of PathBuf containing all effective exclusions (deduplicated)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::config::Config;
    /// use std::path::PathBuf;
    ///
    /// let mut config = Config::default();
    /// config.overlay_exclusions = vec![PathBuf::from("/tmp")];
    /// config.overlay_exclusions_remove = vec![PathBuf::from("/mnt")];
    ///
    /// let exclusions = config.compute_effective_exclusions();
    /// assert!(exclusions.contains(&PathBuf::from("/proc")));  // default
    /// assert!(exclusions.contains(&PathBuf::from("/tmp")));   // user addition
    /// assert!(!exclusions.contains(&PathBuf::from("/mnt")));  // user removal
    /// ```
    pub fn compute_effective_exclusions(&self) -> Vec<PathBuf> {
        use std::collections::HashSet;

        // Start with defaults converted to PathBuf
        let mut exclusions: HashSet<PathBuf> = DEFAULT_OVERLAY_EXCLUSIONS
            .iter()
            .map(PathBuf::from)
            .collect();

        // Warn if user is removing dangerous exclusions (pseudo-filesystems that cannot be overlaid)
        let dangerous_exclusions = ["/proc", "/sys", "/dev", "/run"];
        for dangerous in &dangerous_exclusions {
            if self
                .overlay_exclusions_remove
                .contains(&PathBuf::from(dangerous))
            {
                tracing::warn!(
                    exclusion = %dangerous,
                    "Removing {} from exclusion list - mount will likely FAIL (pseudo-filesystem cannot be overlaid)",
                    dangerous
                );
            }
        }

        // Add user-specified additions
        for path in &self.overlay_exclusions {
            exclusions.insert(path.clone());
        }

        // Remove user-specified removals
        for path in &self.overlay_exclusions_remove {
            exclusions.remove(path);
        }

        // Convert to Vec and sort for deterministic output
        let mut result: Vec<PathBuf> = exclusions.into_iter().collect();
        result.sort();
        result
    }
}

/// Builder for Config with validation and smart defaults
///
/// Provides fluent API for constructing Config instances with validation.
/// Required fields must be set before calling `build()`.
///
/// # Example
///
/// ```rust
/// use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
/// use nails_core::config::ConfigBuilder;
/// use std::path::PathBuf;
///
/// let config = ConfigBuilder::new()
///     .hidden_volume_path(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT))
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
    overlay_mode: Option<OverlayMode>,
    overlay_exclusions: Option<Vec<PathBuf>>,
    overlay_exclusions_remove: Option<Vec<PathBuf>>,
    clear_history: Option<bool>,
    preflight_checks: Option<bool>,
    default_verbosity: Option<String>,
    color_output: Option<bool>,
    verify_on_deactivate: Option<bool>,
    milestone_tips: Option<bool>,
    show_opsec_reminders: Option<bool>,
    log_path: Option<PathBuf>,
    max_log_size_mb: Option<u64>,
    retention_days: Option<u64>,
    color_scheme: Option<ColorSchemeConfig>,
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
    /// Default: `{hidden_volume_root}/state.json`
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

    /// Set whether to show OpSec reminders based on uptime thresholds
    ///
    /// Default: `true`
    pub fn show_opsec_reminders(mut self, enabled: bool) -> Self {
        self.show_opsec_reminders = Some(enabled);
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

    /// Set terminal color scheme configuration
    ///
    /// Default: enabled with dark navy background
    pub fn color_scheme(mut self, config: ColorSchemeConfig) -> Self {
        self.color_scheme = Some(config);
        self
    }

    /// Build the Config with validation and smart defaults
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` if required fields are missing.
    pub fn build(self) -> crate::error::Result<Config> {
        // Use explicit value if set, otherwise derive from binary (Story 14.9)
        // Priority order: explicit value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        let hidden_volume_root = self
            .hidden_volume_root
            .unwrap_or_else(derive_hidden_volume_root);

        // Apply smart defaults for optional fields
        let state_file_path = self
            .state_file_path
            .unwrap_or_else(|| hidden_volume_root.join("state.json"));

        let overlays = self.overlays.unwrap_or_default();

        let minimum_space_mb = self.minimum_space_mb.unwrap_or(500);

        let extended_overlays = self.extended_overlays.unwrap_or_default();

        let overlay_mode = self.overlay_mode.unwrap_or_default();

        let overlay_exclusions = self.overlay_exclusions.unwrap_or_default();

        let overlay_exclusions_remove = self.overlay_exclusions_remove.unwrap_or_default();

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

        let show_opsec_reminders = self
            .show_opsec_reminders
            .unwrap_or_else(default_show_opsec_reminders);

        // Derive log_path from hidden_volume_root if not specified
        let log_path = self
            .log_path
            .unwrap_or_else(|| hidden_volume_root.join("logs"));

        let max_log_size_mb = self.max_log_size_mb.unwrap_or_else(default_max_log_size_mb);

        let retention_days = self.retention_days.unwrap_or_else(default_retention_days);

        let color_scheme = self.color_scheme.unwrap_or_default();

        Ok(Config {
            hidden_volume_root,
            state_file_path,
            overlays,
            minimum_space_mb,
            extended_overlays,
            overlay_mode,
            overlay_exclusions,
            overlay_exclusions_remove,
            clear_history,
            preflight_checks,
            default_verbosity,
            color_output,
            verify_on_deactivate,
            milestone_tips,
            show_opsec_reminders,
            log_path,
            max_log_size_mb,
            retention_days,
            color_scheme,
        })
    }
}

impl Default for Config {
    /// Create default configuration with sensible test defaults
    ///
    /// Uses binary-derived hidden volume root for zero-config operation.
    /// Includes default overlays for /home, /etc, and /var for VM testing.
    fn default() -> Self {
        // Auto-derive hidden volume root from binary location (Story 14.9)
        let hidden_root = derive_hidden_volume_root();

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join("state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "boot".to_string(),
                    lower: PathBuf::from("/boot"),
                    upper: hidden_root.join("boot"),
                    work: hidden_root.join(".work/boot"),
                    target: PathBuf::from("/boot"),
                },
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
                OverlayConfig {
                    name: "var".to_string(),
                    lower: PathBuf::from("/var"),
                    upper: hidden_root.join("var"),
                    work: hidden_root.join(".work/var"),
                    target: PathBuf::from("/var"),
                },
            ],
            minimum_space_mb: 500, // Default minimum: 500 MB
            // Ephemeral overlays DISABLED - using regular overlays instead (Story 4.11)
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
            // Dynamic overlay configuration (Story 14.10)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
            color_scheme: ColorSchemeConfig::default(),
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

        // If hidden_volume_root not specified in YAML, derive from binary (Story 14.9)
        // Priority order: config file value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
        if config.hidden_volume_root.as_os_str().is_empty() {
            tracing::info!("Config file missing hidden_volume_root, deriving from binary location");
            config.hidden_volume_root = derive_hidden_volume_root();
        }

        // Derive state_file_path from hidden_volume_root if it's still the default
        let default_state_path = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("state.json");
        if config.state_file_path == default_state_path {
            config.state_file_path = config.hidden_volume_root.join("state.json");
        }

        // Derive log_path from hidden_volume_root if it's still the default
        // When hidden_volume_root is auto-derived, log_path still gets the constant default
        // via serde default function. This ensures log_path matches the derived root.
        let default_log_path = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs");
        if config.log_path == default_log_path {
            config.log_path = config.hidden_volume_root.join("logs");
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
        r##"# NAILS Configuration
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

# Terminal color scheme configuration:
color_scheme:
  enabled: true
  hidden:
    background: "#1a1a2e"
    foreground: "#e0e0e0"
  decoy:
    reset: true

# Overlay mode configuration (Story 14.10):
# overlay_mode: auto  # auto (default) or explicit
#
# Auto mode (recommended): Dynamically overlay ALL directories under /
# except those in the exclusion list. Provides maximum forensic protection.
#
# Explicit mode: Only overlay directories listed in 'overlays' section below.
# Use this for fine-grained control over what gets overlaid.

# Overlay exclusion configuration (Auto mode only):
# overlay_exclusions:
#   - /boot        # Add custom exclusions (merged with defaults)
#   - /nix
#
# overlay_exclusions_remove:
#   - /mnt         # Remove from default exclusions if needed
#
# Default exclusions: /proc, /sys, /dev, /run, /mnt
# (pseudo-filesystems that cannot/should not be overlaid)

# Overlay configuration (Explicit mode only):
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
"##
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
                tracing::info!("No config file found at {}, using defaults", path.display());
                Ok(Self::default())
            }
            Err(e) => Err(e),
        }
    }

    /// Apply CLI flag overrides to this config
    ///
    /// Priority order: CLI flags > Config file > Defaults (UXR26)
    /// Only overrides values that are explicitly set (Some).
    ///
    /// # Arguments
    ///
    /// * `overrides` - CLI overrides to apply
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{Config, CliOverrides};
    ///
    /// let mut config = Config::default();
    /// let overrides = CliOverrides {
    ///     preflight_checks: Some(false),
    ///     verbosity: Some("debug".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// config.apply_cli_overrides(&overrides);
    /// assert!(!config.preflight_checks);
    /// assert_eq!(config.default_verbosity, "debug");
    /// ```
    pub fn apply_cli_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(v) = overrides.preflight_checks {
            self.preflight_checks = v;
        }
        if let Some(v) = overrides.clear_history {
            self.clear_history = v;
        }
        if let Some(v) = &overrides.verbosity {
            self.default_verbosity = v.clone();
        }
        if let Some(v) = overrides.color_output {
            self.color_output = v;
        }
        if let Some(v) = overrides.verify_on_deactivate {
            self.verify_on_deactivate = v;
        }
    }

    /// Load config from file and apply CLI overrides
    ///
    /// This is the primary entry point for CLI applications.
    ///
    /// # Priority Order (UXR26)
    /// 1. CLI flags (highest priority)
    /// 2. Config file values
    /// 3. Default values (lowest priority)
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to YAML config file (uses defaults if missing)
    /// * `overrides` - CLI argument overrides
    ///
    /// # Errors
    ///
    /// Returns `NailsError::ConfigError` for malformed YAML or missing required fields.
    /// Missing config file is not an error (uses defaults).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{Config, CliOverrides};
    /// use std::path::PathBuf;
    ///
    /// let overrides = CliOverrides {
    ///     preflight_checks: Some(false),
    ///     ..Default::default()
    /// };
    ///
    /// let config = Config::from_file_and_cli(
    ///     &PathBuf::from("~/.nails/config.yaml"),
    ///     &overrides,
    /// ).expect("Failed to load config");
    /// ```
    pub fn from_file_and_cli(
        config_path: &std::path::Path,
        overrides: &CliOverrides,
    ) -> crate::error::Result<Self> {
        let mut config = Self::load_or_default(config_path)?;
        config.apply_cli_overrides(overrides);
        Ok(config)
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
        let hidden_root = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);

        Self {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join("state.json"),
            overlays: vec![
                OverlayConfig {
                    name: "boot".to_string(),
                    lower: PathBuf::from("/boot"),
                    upper: hidden_root.join("boot"),
                    work: hidden_root.join(".work/boot"),
                    target: PathBuf::from("/boot"),
                },
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
                OverlayConfig {
                    name: "var".to_string(),
                    lower: PathBuf::from("/var"),
                    upper: hidden_root.join("var"),
                    work: hidden_root.join(".work/var"),
                    target: PathBuf::from("/var"),
                },
            ],
            minimum_space_mb: 500,
            // Disabled for tests - avoids needing to set up pivot mount paths
            extended_overlays: ExtendedOverlayConfig {
                enabled: false,
                directories: vec![],
            },
            // Dynamic overlay configuration (Story 14.10)
            // Use Auto mode by default (test actual default behavior)
            overlay_mode: OverlayMode::Auto,
            overlay_exclusions: vec![],
            overlay_exclusions_remove: vec![],
            // User-configurable options with smart defaults (Epic 10)
            clear_history: default_clear_history(),
            preflight_checks: default_preflight_checks(),
            default_verbosity: default_verbosity(),
            color_output: default_color_output(),
            verify_on_deactivate: default_verify_on_deactivate(),
            milestone_tips: default_milestone_tips(),
            show_opsec_reminders: default_show_opsec_reminders(),
            log_path: hidden_root.join("logs"), // Derived from hidden_volume_root
            max_log_size_mb: default_max_log_size_mb(),
            retention_days: default_retention_days(),
            color_scheme: ColorSchemeConfig::default(),
        }
    }
}
