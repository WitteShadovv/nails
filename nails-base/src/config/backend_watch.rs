// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `[backend_watch]` configuration: the in-session watcher over the hidden root.
//!
//! The hidden volume can fail mid-session — a udisks/VeraCrypt automount is
//! lazily torn down when the device is pulled, the backing device drops off the
//! bus, or the filesystem goes read-only after an I/O error. When that happens
//! the overlays keep serving stale pages and the operator sees unexplained
//! application errors with nothing to connect them to.
//!
//! The watcher is the long-running component that closes that gap: started from
//! the runtime copy under `/run` at activation, it polls the mount table and
//! probes the hidden root every few seconds and alerts the operator the moment a
//! probe fails. It is **alert-only by default**: a transient I/O stall must never
//! be allowed to tear the session down on its own. Automatic emergency teardown
//! is strictly opt-in ([`BackendWatchConfig::auto_emergency`]) and only fires
//! once a failure has outlasted the debounce window, so a brief hiccup that
//! recovers is reported but never acted on.

use serde::{Deserialize, Serialize};

/// Default poll interval between probes, in seconds.
///
/// A few seconds is responsive enough that the operator hears about a failed
/// backend before most applications surface their own confusing errors, without
/// the wakeups themselves becoming a visible, periodic footprint.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Default debounce window a failure must outlast before an opted-in automatic
/// emergency teardown fires, in seconds.
///
/// Fifteen seconds is long enough to ride out a transient I/O stall or a device
/// that re-settles on the bus, and short enough that a genuinely gone backend is
/// torn down promptly rather than leaking writes for minutes.
pub const DEFAULT_DEBOUNCE_SECS: u64 = 15;

fn default_enabled() -> bool {
    true
}

fn default_poll_interval_secs() -> u64 {
    DEFAULT_POLL_INTERVAL_SECS
}

fn default_debounce_secs() -> u64 {
    DEFAULT_DEBOUNCE_SECS
}

/// `[backend_watch]` configuration table.
///
/// Mirrors the other nested config tables: every key is optional and unknown keys
/// are rejected, so a typo fails loudly instead of silently selecting a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendWatchConfig {
    /// Whether to start the in-session watcher at activation. Defaults to `true`:
    /// the watcher is alert-only unless [`auto_emergency`](Self::auto_emergency)
    /// is also set, so leaving it on costs nothing but a desktop notification if
    /// the backend fails. Set to `false` to run no long-lived component at all.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Whether a persistent backend failure triggers an automatic emergency
    /// teardown. Defaults to `false` (alert-only): a transient I/O stall must not
    /// be able to kill a live session. When `true`, teardown fires only after the
    /// failure has outlasted [`debounce_secs`](Self::debounce_secs).
    #[serde(default)]
    pub auto_emergency: bool,

    /// Seconds between probes of the hidden root. Defaults to
    /// [`DEFAULT_POLL_INTERVAL_SECS`].
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Seconds a failure must persist before an opted-in automatic emergency
    /// teardown fires. Defaults to [`DEFAULT_DEBOUNCE_SECS`]. Ignored unless
    /// [`auto_emergency`](Self::auto_emergency) is `true`.
    #[serde(default = "default_debounce_secs")]
    pub debounce_secs: u64,
}

impl Default for BackendWatchConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            auto_emergency: false,
            poll_interval_secs: default_poll_interval_secs(),
            debounce_secs: default_debounce_secs(),
        }
    }
}

impl BackendWatchConfig {
    /// The poll interval as a [`std::time::Duration`].
    pub fn poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.poll_interval_secs)
    }

    /// The debounce window as a [`std::time::Duration`].
    pub fn debounce(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.debounce_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled_and_alert_only() {
        let config = BackendWatchConfig::default();
        assert!(config.enabled);
        assert!(!config.auto_emergency);
        assert_eq!(config.poll_interval_secs, DEFAULT_POLL_INTERVAL_SECS);
        assert_eq!(config.debounce_secs, DEFAULT_DEBOUNCE_SECS);
    }

    #[test]
    fn empty_table_fills_defaults() {
        let config: BackendWatchConfig = toml::from_str("").unwrap();
        assert_eq!(config, BackendWatchConfig::default());
    }

    #[test]
    fn parses_all_keys() {
        let config: BackendWatchConfig = toml::from_str(
            "enabled = false\nauto_emergency = true\npoll_interval_secs = 2\ndebounce_secs = 30",
        )
        .unwrap();
        assert!(!config.enabled);
        assert!(config.auto_emergency);
        assert_eq!(config.poll_interval_secs, 2);
        assert_eq!(config.debounce_secs, 30);
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(toml::from_str::<BackendWatchConfig>("auto-emergency = true").is_err());
        assert!(toml::from_str::<BackendWatchConfig>("bogus = 1").is_err());
    }

    #[test]
    fn round_trips_through_toml() {
        let config = BackendWatchConfig {
            enabled: true,
            auto_emergency: true,
            poll_interval_secs: 3,
            debounce_secs: 20,
        };
        let serialized = toml::to_string(&config).unwrap();
        let parsed: BackendWatchConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn durations_derive_from_seconds() {
        let config = BackendWatchConfig {
            poll_interval_secs: 4,
            debounce_secs: 12,
            ..BackendWatchConfig::default()
        };
        assert_eq!(config.poll_interval(), std::time::Duration::from_secs(4));
        assert_eq!(config.debounce(), std::time::Duration::from_secs(12));
    }
}
