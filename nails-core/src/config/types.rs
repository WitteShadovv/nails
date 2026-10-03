//! Core configuration type definitions

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::colors::ColorSchemeConfig;
use super::overlay::{OverlayConfig, OverlayMode};
use super::persona::PersonaConfig;
use crate::process::RiskyServicePolicy;

/// Neutral placeholder hidden volume root path (single source of truth).
///
/// Production code should use the `Config::hidden_volume_root` field, which is
/// auto-derived from the binary location or set in `nails.toml`; this constant
/// is only the last-resort default and the value tests build paths from.
///
/// The value is deliberately neutral: a default that read as "hidden" would end
/// up in the leftover mount-point directory, in generated mount unit names and in
/// journal lines, so it must reveal nothing. `HiddenVolumeCheck` warns when a
/// configured root, mapper name or label hints at hidden storage; the default
/// must never trip that warning.
pub const DEFAULT_HIDDEN_VOLUME_ROOT: &str = "/mnt/data";

/// Get the default hidden volume root path.
pub fn get_default_hidden_volume_root() -> String {
    DEFAULT_HIDDEN_VOLUME_ROOT.to_string()
}

/// Default exclusion list for dynamic overlay enumeration
///
/// These are the host-independent defaults only. They are excluded because they
/// are:
/// - Kernel-managed virtual filesystems (/proc, /sys, /dev)
/// - Runtime state directories (/run)
/// - Mount point directories (/mnt)
/// - Filesystem recovery directory (/lost+found)
/// - Note: /boot is NOT excluded — it is overlayed via snapshot pivot on vfat
///   partitions (contents copied to tmpfs in RAM, then overlayed)
///
/// The base-OS trees that must not be overlaid (`/usr`, `/bin`, `/sbin`, `/lib*`)
/// are *not* listed here: they are platform data now, carried by
/// [`Platform::overlay_policy`](crate::platform::Platform::overlay_policy), so a
/// NixOS-specific exclusion never leaks onto Debian and vice versa. The overlay
/// enumeration in [`build_overlay_targets`](crate::build_overlay_targets) folds
/// the active platform's policy in on top of these defaults.
///
/// Directories like /etc, /home, /nix, /var, /tmp, /srv, /root, /opt, /media
/// ARE included by default for maximum forensic protection.
///
/// Users can add more exclusions via `overlay_exclusions` or remove
/// defaults via `overlay_exclusions_remove` in `nails.toml`.
pub const DEFAULT_OVERLAY_EXCLUSIONS: &[&str] =
    &["/proc", "/sys", "/dev", "/run", "/mnt", "/lost+found"];

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

    /// Override nixos_flake (--nixos-flake sets to the given flake reference)
    pub nixos_flake: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_hidden_volume_root_returns_nonempty_string() {
        let root = get_default_hidden_volume_root();
        assert!(!root.is_empty());
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
///     hidden_volume_root: PathBuf::from("/mnt/data"),
///     state_file_path: PathBuf::from("/mnt/data").join("state.json"),
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
    /// Priority: config file value > binary-derived > `DEFAULT_HIDDEN_VOLUME_ROOT`
    /// (a neutral placeholder; a real deployment should set or derive a name
    /// that does not hint at hidden storage)
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

    /// Base free-space floor for activation, in MB.
    ///
    /// The space pre-flight check fails below this value with no warn band;
    /// `activate --no-preflight` skips the check. This floor covers an
    /// overlay-only activation that writes no NixOS store delta.
    #[serde(default = "super::defaults::default_minimum_space_mb")]
    pub minimum_space_mb: u64,

    /// Free-space floor applied when a hidden NixOS build is expected, in MB.
    ///
    /// A full rebuild (no cached hidden toplevel, or the fingerprint changed)
    /// writes the store delta into the overlaid `/nix` upper, often several GB.
    /// After the overlays are mounted and before the build runs, free space is
    /// re-checked against this floor and activation is rolled back if short.
    #[serde(default = "super::defaults::default_rebuild_space_mb")]
    pub rebuild_space_mb: u64,

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
    /// Everything the hidden session writes under an excluded directory goes
    /// straight to the decoy disk, so only exclude directories the session
    /// never writes to. Excluding a directory a normal session writes to
    /// (see [`LOAD_BEARING_DIRECTORIES`](super::LOAD_BEARING_DIRECTORIES))
    /// is refused unless it is also listed in `allow_leaky_exclusions`.
    /// `/boot` is NOT excluded by default — vfat partitions are handled via
    /// snapshot pivot automatically.
    ///
    /// **Example**:
    /// ```toml
    /// overlay_exclusions = ["/media"]
    /// ```
    #[serde(default)]
    pub overlay_exclusions: Vec<PathBuf>,

    /// Load-bearing directories the user accepts excluding in Auto mode
    ///
    /// Excluding `/home`, `/root`, `/etc`, `/var`, `/nix`, `/srv`, `/opt` or a
    /// `/tmp` that is not a tmpfs sends the hidden session's writes there to
    /// the decoy disk, so `overlay_exclusions` naming one of them is refused.
    /// Listing the directory here records that the leak is intended.
    ///
    /// **Example**:
    /// ```toml
    /// overlay_exclusions = ["/srv"]
    /// allow_leaky_exclusions = ["/srv"]
    /// ```
    #[serde(default)]
    pub allow_leaky_exclusions: Vec<PathBuf>,

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

    /// How the hidden session relates to the decoy account.
    ///
    /// Defaults to the legacy shared-home model (the decoy home, merged
    /// read-write). `fresh-home` bind-mounts a clean hidden home over the
    /// operator's home so the decoy home contents are not visible. See
    /// [`PersonaConfig`](super::persona::PersonaConfig).
    #[serde(default)]
    pub persona: PersonaConfig,

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
    /// with attribute selection (e.g., `/mnt/data/nixos#my-host`).
    ///
    /// **Precedence**: CLI `--nixos-flake` flag > config `nixos_flake` > auto-discovery
    ///
    /// **Example**:
    /// ```toml
    /// nixos_flake = "/mnt/data/nixos#my-host"
    /// ```
    #[serde(default)]
    pub nixos_flake: Option<String>,

    /// Whether a failed hidden NixOS build or switch fails the whole activation.
    ///
    /// The hidden configuration is switched into place *before* the session is
    /// restarted. When this is `true` (the default, fail closed) a build or switch
    /// failure rolls the overlays back and restores the decoy session instead of
    /// bringing the session up on a half-applied or decoy configuration. Set it to
    /// `false` to keep the overlays and session and only warn when the hidden
    /// configuration could not be applied.
    ///
    /// **Example**:
    /// ```toml
    /// nixos_switch_required = true
    /// ```
    #[serde(default = "super::defaults::default_nixos_switch_required")]
    pub nixos_switch_required: bool,

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

    /// Accept a persistent decoy posture instead of refusing activation.
    ///
    /// By default activation fails closed when the decoy keeps forensic traces:
    /// a persistent systemd-journald journal on the decoy disk, or an active
    /// rsyslog/syslog-ng/auditd. Records those sinks write before the overlays
    /// are mounted survive on the decoy disk across deactivation and reboot. Set
    /// this to `true` (or pass `--accept-persistent-decoy`) to accept that risk;
    /// the decoy-persistence check then warns instead of failing. Lower-severity
    /// findings (root filesystem type, atime policy, crash-dump channels,
    /// maintenance timers) are always warnings regardless of this setting.
    ///
    /// **Example**:
    /// ```toml
    /// accept_persistent_decoy = true
    /// ```
    #[serde(default = "super::defaults::default_accept_persistent_decoy")]
    pub accept_persistent_decoy: bool,
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
    "allow_leaky_exclusions",
    "overlays",
    "minimum_space_mb",
    "rebuild_space_mb",
    "clear_history",
    "show_opsec_reminders",
    "prompt_label",
    "nixos_flake",
    "nixos_switch_required",
    "risky_services",
    "accept_persistent_decoy",
    "color_scheme",
    "persona",
];
