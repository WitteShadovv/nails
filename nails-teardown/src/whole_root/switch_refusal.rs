// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Why the last switch was refused, kept on the hidden volume.
//!
//! The [`transition`](crate::whole_root::transition) step runs with no output
//! and no log: a soft-reboot that cannot switch root
//! ([`Disarmed`](crate::whole_root::transition::Outcome::Disarmed)) leaves PID 1
//! on the root it is already on, and until now the reason went nowhere. An
//! operator back on the decoy, or a window that looks next time, had no way to
//! learn why the switch did not happen.
//!
//! This module keeps that one reason on the hidden volume, so `status` can read
//! it back. It is written only when the hidden volume is genuinely mounted at
//! its recorded path on its recorded device — the same device identity the
//! attach gate checks — so the record never lands on the decoy disk: a plain
//! reboot that meets a leftover tree, whose volume the shutdown already
//! unmounted, writes nothing. The transition is still the one step that never
//! touches the decoy disk; this writes to the encrypted hidden volume beside the
//! state file, not to the decoy.
//!
//! The record is the most recent switch's outcome only. A new activation clears
//! it when it commits (the session flow one layer up), so a stale reason never
//! outlives the switch it describes.

use crate::mountinfo::{MountEntry, top_mount_at};
use crate::whole_root::plan::{self, Plan};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The record's file name on the hidden volume, beside the state file.
pub const REFUSAL_NAME: &str = "last-switch.json";

/// Why the last switch was refused, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchRefusal {
    /// The reason the transition gave (a failed init check, failed unit masks,
    /// or an arming that did not run in time).
    pub reason: String,
    /// When it was refused, in seconds since the epoch.
    pub at: u64,
}

/// The record's path under `hidden_root`.
#[must_use]
pub fn refusal_path(hidden_root: &Path) -> PathBuf {
    hidden_root.join(REFUSAL_NAME)
}

/// Whether the hidden volume is live at the plan's recorded root: a filesystem
/// is mounted there now, on the device the entry recorded. This is what keeps a
/// write on the hidden volume and off the decoy disk — when the volume is not
/// mounted (a plain reboot unmounted it), the top mount at the path is the
/// decoy's own, its device differs, and nothing is written. A plan written
/// before the device was recorded (no `hidden_dev`) is treated as not live.
fn hidden_root_is_live(mounts: &[MountEntry], plan: &Plan) -> bool {
    let Some(dev) = plan.hidden_dev.as_deref() else {
        return false;
    };
    let root =
        std::fs::canonicalize(&plan.hidden_root).unwrap_or_else(|_| plan.hidden_root.clone());
    top_mount_at(mounts, &root).is_some_and(|mount| mount.dev == dev)
}

/// Record on the hidden volume that the switch the `plan` armed was refused,
/// with `reason`. A no-op unless the plan armed a switch (so a plain reboot that
/// meets a leftover tree records nothing) and the hidden volume is live at its
/// recorded path and device (so nothing is written to the decoy disk).
/// Best-effort: a write failure is swallowed, because the transition must finish
/// whatever happens to this record.
pub fn record(mounts: &[MountEntry], plan: &Plan, reason: &str, now: u64) {
    if plan.armed.is_none() || !hidden_root_is_live(mounts, plan) {
        return;
    }
    let record = SwitchRefusal {
        reason: reason.to_string(),
        at: now,
    };
    if let Ok(bytes) = serde_json::to_vec(&record) {
        let _ = plan::write_private_atomic(&refusal_path(&plan.hidden_root), &bytes);
    }
}

/// The last refused switch recorded under `hidden_root`, or `None` when the
/// volume is not mounted there, no switch was refused, or the record cannot be
/// read.
#[must_use]
pub fn read(hidden_root: &Path) -> Option<SwitchRefusal> {
    let text = std::fs::read(refusal_path(hidden_root)).ok()?;
    serde_json::from_slice(&text).ok()
}

/// Forget the recorded refusal under `hidden_root`. Best-effort: a missing
/// record is success. Called when a new switch supersedes the last one.
pub fn clear(hidden_root: &Path) {
    let _ = std::fs::remove_file(refusal_path(hidden_root));
}

#[cfg(test)]
#[path = "switch_refusal_tests.rs"]
mod tests;
