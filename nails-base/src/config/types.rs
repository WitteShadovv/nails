// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Core configuration type definitions

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::backend_watch::BackendWatchConfig;
use super::persona::PersonaConfig;
use super::session_mounts::SessionMountsConfig;

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
/// use nails_base::CliOverrides;
///
/// let overrides = CliOverrides {
///     nixos_flake: Some("/etc/nixos#host".to_string()), // --nixos-flake
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
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
    fn sleep_policy_defaults_to_warn_and_runs_no_guard() {
        let config = SleepPolicyConfig::default();
        assert_eq!(config.mode, SleepPolicyMode::Warn);
        assert!(!SleepPolicyMode::Warn.runs_guard());
        assert!(SleepPolicyMode::Block.runs_guard());
        assert!(SleepPolicyMode::Teardown.runs_guard());
    }

    #[test]
    fn sleep_policy_empty_table_fills_default() {
        let config: SleepPolicyConfig = toml::from_str("").unwrap();
        assert_eq!(config, SleepPolicyConfig::default());
    }

    #[test]
    fn sleep_policy_parses_every_mode() {
        for (text, mode) in [
            ("mode = \"warn\"", SleepPolicyMode::Warn),
            ("mode = \"block\"", SleepPolicyMode::Block),
            ("mode = \"teardown\"", SleepPolicyMode::Teardown),
        ] {
            let config: SleepPolicyConfig = toml::from_str(text).unwrap();
            assert_eq!(config.mode, mode);
        }
    }

    #[test]
    fn sleep_policy_rejects_unknown_key_and_bad_mode() {
        assert!(toml::from_str::<SleepPolicyConfig>("bogus = true").is_err());
        assert!(toml::from_str::<SleepPolicyConfig>("mode = \"nap\"").is_err());
    }

    #[test]
    fn sleep_policy_round_trips_through_toml() {
        let config = SleepPolicyConfig {
            mode: SleepPolicyMode::Teardown,
        };
        let serialized = toml::to_string(&config).unwrap();
        let parsed: SleepPolicyConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed, config);
    }
}

/// What NAILS does about system sleep (suspend/hibernate) while a hidden
/// session is active.
///
/// Closing the lid or an idle auto-suspend leaves the whole hidden session
/// resident in RAM behind the decoy lock screen: on resume the decoy login
/// unlocks a session whose overlays, mapper and master key are all still live.
/// Each mode trades that exposure against a practical cost, so the safe default
/// only warns rather than silently changing the machine's power behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SleepPolicyMode {
    /// Pre-flight warns when the host would suspend an active session; nothing
    /// runs at runtime. The default: a permanent sleep inhibitor has real costs
    /// (a suspend blocked with the lid shut can overheat a laptop), so taking one
    /// is opt-in.
    #[default]
    Warn,
    /// Hold a sleep/idle *block* inhibitor for the life of the session so the
    /// host cannot suspend or idle-sleep while the hidden environment is up. The
    /// inhibitor is released at deactivation.
    Block,
    /// Hold a sleep *delay* inhibitor and, when the host is about to sleep, run
    /// the emergency (a power-off) inside logind's delay window before
    /// releasing the inhibitor and letting the sleep proceed. Bounded by
    /// `InhibitDelayMaxSec` (logind default 5s), so it reuses the fast emergency
    /// path rather than a full deactivation.
    Teardown,
}

impl SleepPolicyMode {
    /// Whether this mode runs a long-lived sleep guard at activation.
    ///
    /// [`Warn`](Self::Warn) only reports at pre-flight and starts nothing;
    /// [`Block`](Self::Block) and [`Teardown`](Self::Teardown) both start the
    /// guard that holds a logind inhibitor for the session.
    pub fn runs_guard(self) -> bool {
        matches!(self, SleepPolicyMode::Block | SleepPolicyMode::Teardown)
    }
}

/// `[sleep_policy]` configuration table.
///
/// Mirrors the other nested tables: every key is optional and unknown keys are
/// rejected, so a typo fails loudly instead of silently selecting a default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SleepPolicyConfig {
    /// How to handle suspend/hibernate while active. Defaults to
    /// [`SleepPolicyMode::Warn`].
    #[serde(default)]
    pub mode: SleepPolicyMode,
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
/// use nails_base::config::Config;
/// use std::path::PathBuf;
///
/// // Use default for tests
/// let config = Config::default();
///
/// // Or create custom config
/// let config = Config {
///     hidden_volume_root: PathBuf::from("/mnt/data"),
///     state_file_path: PathBuf::from("/mnt/data").join("state.json"),
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

    /// Base free-space floor for activation, in MB.
    ///
    /// The space pre-flight check fails below this value with no warn band;
    /// `activate --no-preflight` skips the check. This floor covers an
    /// overlay-only activation that writes no NixOS store delta.
    #[serde(default = "super::defaults::default_minimum_space_mb")]
    pub minimum_space_mb: u64,

    /// Free-space floor applied when a hidden NixOS build is expected, in MB.
    ///
    /// A hidden NixOS build writes its store delta into the root upper on the
    /// hidden volume, often several GB. Right before the build runs, the entry
    /// checks the hidden volume's free space against this floor and is rolled
    /// back if it is short.
    #[serde(default = "super::defaults::default_rebuild_space_mb")]
    pub rebuild_space_mb: u64,

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

    /// How the hidden session relates to the decoy account.
    ///
    /// Defaults to the legacy shared-home model (the decoy home, merged
    /// read-write). `fresh-home` bind-mounts a clean hidden home over the
    /// operator's home so the decoy home contents are not visible. See
    /// [`PersonaConfig`](super::persona::PersonaConfig).
    #[serde(default)]
    pub persona: PersonaConfig,

    /// In-session watcher over the hidden root.
    ///
    /// Controls the long-running component started at activation that alerts the
    /// operator (and, opt-in, tears the session down) when the hidden backend
    /// fails mid-session. Alert-only by default. See
    /// [`BackendWatchConfig`](super::backend_watch::BackendWatchConfig).
    #[serde(default)]
    pub backend_watch: BackendWatchConfig,

    /// Disks mounted during the hidden session.
    ///
    /// The session watcher alerts on a read-write mount of a disk outside the
    /// hidden volume (on by default); `read_only` opts into making every disk
    /// the session does not use read-only for the session. See
    /// [`SessionMountsConfig`].
    #[serde(default)]
    pub session_mounts: SessionMountsConfig,

    /// What to do about system sleep (suspend/hibernate) while active.
    ///
    /// Suspending an active session leaves the hidden environment resident in RAM
    /// behind the decoy lock screen. Warn-only by default; `block` holds a sleep
    /// inhibitor for the session and `teardown` runs the bounded emergency
    /// teardown when the host is about to sleep. See [`SleepPolicyConfig`].
    #[serde(default)]
    pub sleep_policy: SleepPolicyConfig,

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
    "minimum_space_mb",
    "rebuild_space_mb",
    "show_opsec_reminders",
    "nixos_flake",
    "accept_persistent_decoy",
    "persona",
    "backend_watch",
    "session_mounts",
    "sleep_policy",
];
