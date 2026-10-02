//! Core configuration type definitions

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::overlay::{OverlayConfig, OverlayMode};
use crate::process::RiskyServicePolicy;

/// Default hidden volume root path (single source of truth).
///
/// Production code should use the `Config::hidden_volume_root` field, which is
/// auto-derived from the binary location; this constant is the final fallback
/// used when no path can be derived or configured.
pub const DEFAULT_HIDDEN_VOLUME_ROOT: &str = "/mnt/hidden-volume";

/// Default hidden volume root path as an owned `String`.
#[allow(dead_code)]
pub fn default_hidden_volume_root() -> String {
    DEFAULT_HIDDEN_VOLUME_ROOT.to_string()
}

/// Get the default hidden volume root path.
pub fn get_default_hidden_volume_root() -> String {
    DEFAULT_HIDDEN_VOLUME_ROOT.to_string()
}

/// Default exclusion list for dynamic overlay enumeration
///
/// These directories are excluded by default because they are:
/// - Kernel-managed virtual filesystems (/proc, /sys, /dev)
/// - Runtime state directories (/run)
/// - Mount point directories (/mnt)
/// - Note: /boot is NOT excluded — it is overlayed via snapshot pivot on vfat partitions
///   (contents copied to tmpfs in RAM, then overlayed)
/// - System library symlinks common in NixOS (/lib, /lib64, /sbin)
/// - Filesystem recovery directory (/lost+found)
///
/// Directories like /etc, /home, /nix, /var, /tmp, /srv, /root, /opt, /media
/// ARE included by default for maximum forensic protection.
///
/// Users can add more exclusions via `overlay_exclusions` or remove
/// defaults via `overlay_exclusions_remove` in `nails.toml`.
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
];

/// CLI argument overrides for configuration
///
/// All fields are Option to distinguish "not specified" from "explicitly set".
/// Only Some values override the loaded config.
///
/// # Priority Order
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
///     clear_history: Some(false), // --no-clear-history flag
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// Override clear_history (--no-clear-history sets to false)
    pub clear_history: Option<bool>,

    /// Override nixos_flake (--flake sets to the given flake reference)
    pub nixos_flake: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_hidden_volume_root_returns_nonempty_string() {
        let root = default_hidden_volume_root();
        assert!(!root.is_empty());
    }

    #[test]
    fn test_get_default_hidden_volume_root_returns_same_as_default() {
        let root1 = default_hidden_volume_root();
        let root2 = get_default_hidden_volume_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_default_overlay_exclusions_contains_proc() {
        assert!(DEFAULT_OVERLAY_EXCLUSIONS.contains(&"/proc"));
        assert!(DEFAULT_OVERLAY_EXCLUSIONS.contains(&"/sys"));
        assert!(DEFAULT_OVERLAY_EXCLUSIONS.contains(&"/dev"));
    }
}

/// Application configuration
///
/// Loaded from `nails.toml` (see [`Config::load`]). Every key is optional and
/// unknown keys are rejected, so a misspelt key fails loudly instead of being
/// silently replaced by a default. Use `ConfigBuilder` for programmatic
/// construction.
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
///     state_file_path: PathBuf::from("/mnt/hidden-volume").join("state.json"),
///     overlays: vec![],
///     ..Config::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Root of hidden volume
    ///
    /// Derived from the binary location when the config file does not set it.
    /// Priority: config file value > binary-derived > DEFAULT_HIDDEN_VOLUME_ROOT
    #[serde(default = "super::defaults::default_hidden_volume_root")]
    pub hidden_volume_root: PathBuf,

    /// Path to state file (on hidden volume)
    ///
    /// Derived as `{hidden_volume_root}/state.json` when the config file does
    /// not set it.
    #[serde(default = "super::defaults::default_state_file_path")]
    pub state_file_path: PathBuf,

    /// Overlay configurations
    #[serde(default)]
    pub overlays: Vec<OverlayConfig>,

    /// Minimum disk space required for activation (in MB)
    #[serde(default = "super::defaults::default_minimum_space_mb")]
    pub minimum_space_mb: u64,

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
    /// ```toml
    /// overlay_mode = "auto"      # Use dynamic enumeration (default)
    /// # or
    /// overlay_mode = "explicit"  # Use explicit overlay list
    /// ```
    #[serde(default)]
    pub overlay_mode: OverlayMode,

    /// User-specified additional exclusions (merged with defaults)
    ///
    /// Directories to exclude from overlay in Auto mode, in addition to the defaults.
    /// These paths are merged with the default exclusion list.
    ///
    /// **Default exclusions**: `/proc`, `/sys`, `/dev`, `/run`, `/mnt`, `/bin`, `/usr`, `/lib`, `/lib64`, `/sbin`, `/lost+found`
    ///
    /// **Use case**: Exclude additional directories you don't want overlaid
    /// (e.g., `/nix` for Nix store performance). Note: `/boot` is NOT excluded
    /// by default — vfat partitions are handled via snapshot pivot automatically.
    ///
    /// **Example**:
    /// ```toml
    /// overlay_exclusions = ["/boot", "/nix"]
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
    /// ```toml
    /// overlay_exclusions_remove = ["/mnt"]  # overlay /mnt instead of excluding it
    /// ```
    #[serde(default)]
    pub overlay_exclusions_remove: Vec<PathBuf>,

    /// Whether to clear shell history during deactivation
    #[serde(default = "super::defaults::default_clear_history")]
    pub clear_history: bool,

    /// Whether to show OpSec reminders based on uptime thresholds
    #[serde(default = "super::defaults::default_show_opsec_reminders")]
    pub show_opsec_reminders: bool,

    /// Path to log file directory
    ///
    /// Derived as `{hidden_volume_root}/logs` when the config file does not
    /// set it.
    #[serde(default = "super::defaults::default_log_path")]
    pub log_path: PathBuf,

    /// Resolved config file path currently backing this config, if any.
    ///
    /// Runtime-only metadata: this is never read from or written to user config.
    #[serde(skip, default)]
    pub loaded_config_path: Option<PathBuf>,

    /// Terminal color scheme configuration
    #[serde(default)]
    pub color_scheme: ColorSchemeConfig,

    /// Neutral active-state indicator prepended to the shell prompt while the
    /// hidden environment is active.
    ///
    /// Empty (the default) shows no indicator. Any on-screen indicator is a
    /// shoulder-surfing and screenshot liability, so it is opt-in: set it only
    /// if you accept that the hidden session becomes visible on screen and in
    /// screen recordings.
    #[serde(default)]
    pub prompt_label: String,

    /// NixOS flake reference (optional, auto-detected if not set)
    ///
    /// When set, this value is passed directly to `nixos-rebuild --flake <value>`
    /// instead of auto-detecting the flake path. Supports full flake references
    /// with attribute selection (e.g., `/mnt/hidden-volume/nixos#my-host`).
    ///
    /// **Precedence**: CLI `--flake` flag > config `nixos_flake` > auto-discovery
    ///
    /// **Example**:
    /// ```toml
    /// nixos_flake = "/mnt/hidden-volume/nixos#my-host"
    /// ```
    #[serde(default)]
    pub nixos_flake: Option<String>,

    /// What to do with risky services (NetworkManager, dbus-daemon, the audio
    /// server) that still reference an overlay target at activation.
    ///
    /// Leaving one running keeps it writing to the decoy, so this is a security
    /// trade-off. Unset (the default) defers the decision to activation: restart
    /// when the session is killed, prompt on a terminal otherwise. The
    /// `--risky-services` flag overrides this key.
    ///
    /// **Values**: `"restart"` or `"skip"`
    ///
    /// **Example**:
    /// ```toml
    /// risky_services = "restart"
    /// ```
    #[serde(default)]
    pub risky_services: Option<RiskyServicePolicy>,
}

/// Every top-level key `nails.toml` accepts, in the order they are documented
/// and displayed.
///
/// Kept in sync with the fields of [`Config`] by a unit test.
pub const CONFIG_KEYS: &[&str] = &[
    "hidden_volume_root",
    "state_file_path",
    "log_path",
    "overlay_mode",
    "overlay_exclusions",
    "overlay_exclusions_remove",
    "overlays",
    "minimum_space_mb",
    "clear_history",
    "show_opsec_reminders",
    "prompt_label",
    "nixos_flake",
    "risky_services",
    "color_scheme",
];
