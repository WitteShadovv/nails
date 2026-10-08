// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `[session_mounts]` configuration: disks mounted during the hidden session.
//!
//! The fstab policy at entry covers every filesystem the decoy knows about.
//! A disk the hidden session itself mounts — a USB drive automounted by
//! udisks, a manual `mount` of a decoy partition the policy masked, a Windows
//! partition — is a real disk, and a read-write mount of it takes hidden
//! writes. Two answers, both in the hidden session:
//!
//! - **alert** (default on): the session watcher raises a neutral desktop alert
//!   for every read-write mount of a block device outside the hidden volume;
//! - **read-only** (opt-in): every disk the session does not itself use is
//!   made read-only at the block layer for the session, the ones present at
//!   entry and every one attached later, so a mount comes up read-only and a
//!   write fails; the way back makes them writable again.
//!
//! Neither stops a root user who sets a disk writable again on purpose.

use serde::{Deserialize, Serialize};

fn default_alert() -> bool {
    true
}

/// `[session_mounts]` configuration table.
///
/// Every key is optional and unknown keys are rejected, like the other tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMountsConfig {
    /// Alert when a block device outside the hidden volume is mounted
    /// read-write during the session. Defaults to `true`. The alert comes from
    /// the session watcher, which then runs even with `backend_watch.enabled =
    /// false`.
    #[serde(default = "default_alert")]
    pub alert: bool,

    /// Make every disk the hidden session does not use read-only at the block
    /// layer for the session, including disks attached during it. Defaults to
    /// `false`.
    #[serde(default)]
    pub read_only: bool,
}

impl Default for SessionMountsConfig {
    fn default() -> Self {
        Self {
            alert: default_alert(),
            read_only: false,
        }
    }
}

impl SessionMountsConfig {
    /// Whether the session watcher has anything to do for these settings.
    pub fn needs_watcher(&self) -> bool {
        self.alert || self.read_only
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_alerts_and_leaves_disks_writable() {
        let config = SessionMountsConfig::default();
        assert!(config.alert);
        assert!(!config.read_only);
        assert!(config.needs_watcher());
    }

    #[test]
    fn an_empty_table_fills_the_defaults_and_unknown_keys_are_refused() {
        let config: SessionMountsConfig = toml::from_str("").unwrap();
        assert_eq!(config, SessionMountsConfig::default());
        let config: SessionMountsConfig =
            toml::from_str("read_only = true\nalert = false\n").unwrap();
        assert!(config.read_only && !config.alert);
        assert!(toml::from_str::<SessionMountsConfig>("readonly = true\n").is_err());
        let off: SessionMountsConfig = toml::from_str("alert = false\n").unwrap();
        assert!(!off.needs_watcher());
    }
}
