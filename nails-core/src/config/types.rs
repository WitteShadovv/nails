//! Core configuration type definitions

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::overlay::{ExtendedOverlayConfig, OverlayConfig, OverlayMode};

/// Default hidden volume root path (single source of truth)
///
/// # Note
///
/// This constant is public for use in documentation examples and tests.
/// Production code should use `Config::hidden_volume_root` field instead of
/// hardcoding this value.
pub const DEFAULT_HIDDEN_VOLUME_ROOT: &str = "/mnt/hidden-volume";

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
    #[serde(
        alias = "hidden_volume_path",
        default = "super::defaults::default_hidden_volume_root"
    )]
    pub hidden_volume_root: PathBuf,

    /// Path to state file (on hidden volume)
    #[serde(default = "super::defaults::default_state_file_path")]
    pub state_file_path: PathBuf,

    /// Overlay configurations
    #[serde(default)]
    pub overlays: Vec<OverlayConfig>,

    /// Minimum disk space required for activation (in MB)
    #[serde(default = "super::defaults::default_minimum_space_mb")]
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
    #[serde(default = "super::defaults::default_clear_history")]
    pub clear_history: bool,

    /// Whether to run preflight checks before activation
    #[serde(default = "super::defaults::default_preflight_checks")]
    pub preflight_checks: bool,

    /// Default verbosity level for logging (e.g., "info", "debug", "warn")
    #[serde(default = "super::defaults::default_verbosity")]
    pub default_verbosity: String,

    /// Whether to use colored output in terminal
    #[serde(default = "super::defaults::default_color_output")]
    pub color_output: bool,

    /// Whether to run verify command after deactivation
    #[serde(default = "super::defaults::default_verify_on_deactivate")]
    pub verify_on_deactivate: bool,

    /// Whether to show milestone tips during operations
    #[serde(default = "super::defaults::default_milestone_tips")]
    pub milestone_tips: bool,

    /// Whether to show OpSec reminders based on uptime thresholds
    #[serde(default = "super::defaults::default_show_opsec_reminders")]
    pub show_opsec_reminders: bool,

    /// Path to log file directory
    #[serde(default = "super::defaults::default_log_path")]
    pub log_path: PathBuf,

    /// Maximum log file size in megabytes before rotation
    #[serde(default = "super::defaults::default_max_log_size_mb")]
    pub max_log_size_mb: u64,

    /// Number of days to retain log files
    #[serde(default = "super::defaults::default_retention_days")]
    pub retention_days: u64,

    /// Terminal color scheme configuration
    #[serde(default)]
    pub color_scheme: ColorSchemeConfig,
}
