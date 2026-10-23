// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Why the last switch was refused, kept where `status` can read it back and
//! never on the decoy disk.
//!
//! The [`transition`](crate::whole_root::transition) step runs with no output
//! and no log: a soft-reboot that cannot switch root
//! ([`Disarmed`](crate::whole_root::transition::Outcome::Disarmed)) leaves PID 1
//! on the root it is already on, and the reason would go nowhere. This module
//! keeps that one reason, and when it was given:
//!
//! - **A refused entry** keeps it on the hidden volume, beside the state file,
//!   where `status` reads it once the volume is open again. The transition
//!   runs after `umount.target`, so the decoy's shutdown has already unmounted
//!   the volume at its own path; what is left of it is its bind in the next
//!   root, below `/run/nextroot`, which no shutdown unmounts. The record is
//!   written through that bind, before the next root is detached, and only
//!   while the mount there is on the device the entry recorded, the identity
//!   the attach gate checks: anything else at that path (the root overlay
//!   itself, were the bind missing) receives nothing.
//! - **A refused way back** keeps it in the runtime directory, in RAM. The
//!   hidden session's shutdown has unmounted the volume too, and no path
//!   reaches it any more. PID 1 stays in the hidden root and keeps `/run`, so
//!   the next `status` there reads the record, and every way back to the decoy
//!   removes the runtime directory with it.
//!
//! A soft-reboot that meets a tree nothing armed (an activation that died
//! before arming it, then a plain reboot) records nothing. The record is the
//! most recent switch's outcome only: a new activation or deactivation clears
//! it when it arms its own switch (the session flow one layer up).

use crate::mountinfo::{MountEntry, top_mount_at};
use crate::whole_root::nextroot;
use crate::whole_root::plan::{self, Plan};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The record's file name, beside the state file on the hidden volume and in
/// the runtime directory.
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

/// The record's path in `dir`: the hidden volume root or the runtime directory.
#[must_use]
pub fn refusal_path(dir: &Path) -> PathBuf {
    dir.join(REFUSAL_NAME)
}

/// The hidden volume as the next root `nextroot` holds it: the directory the
/// plan's hidden root resolves to inside the next root, as the hidden session
/// would resolve it, when the mount there is the volume's own bind (on the
/// device the entry recorded). `None` when the plan recorded no device, the
/// path does not resolve, or anything else is mounted there.
#[must_use]
pub fn volume_in_next_root(mounts: &[MountEntry], plan: &Plan, nextroot: &Path) -> Option<PathBuf> {
    let dev = plan.hidden_dev.as_deref()?;
    let dir = nextroot::open_dir_in_root(nextroot, &plan.hidden_root)
        .and_then(|fd| nextroot::real_path(&fd))
        .ok()?;
    top_mount_at(mounts, &dir)
        .is_some_and(|mount| mount.dev == dev)
        .then_some(dir)
}

/// Record on the hidden volume that the entry the `plan` armed was refused,
/// with `reason`, through the volume's bind in the next root `nextroot` (see
/// the module docs). A no-op unless the plan armed a switch and that bind is
/// the volume's. Best-effort: a write failure is swallowed, because the
/// transition must finish whatever happens to this record.
pub fn record_on_volume(
    mounts: &[MountEntry],
    plan: &Plan,
    nextroot: &Path,
    reason: &str,
    now: u64,
) {
    if plan.armed.is_none() {
        return;
    }
    if let Some(volume) = volume_in_next_root(mounts, plan, nextroot) {
        write(&volume, reason, now);
    }
}

/// Record in the runtime directory `runtime_dir`, in RAM, that the way back
/// the `plan` armed was refused, with `reason` (see the module docs). A no-op
/// unless the plan armed a switch. Best-effort, as [`record_on_volume`].
pub fn record_in_runtime(plan: &Plan, runtime_dir: &Path, reason: &str, now: u64) {
    if plan.armed.is_some() {
        write(runtime_dir, reason, now);
    }
}

fn write(dir: &Path, reason: &str, now: u64) {
    let record = SwitchRefusal {
        reason: reason.to_string(),
        at: now,
    };
    if let Ok(bytes) = serde_json::to_vec(&record) {
        let _ = plan::write_private_atomic(&refusal_path(dir), &bytes);
    }
}

/// The last refused switch recorded in `dir`, or `None` when no switch was
/// refused, the record cannot be read or it gives no reason. Status reads the
/// hidden volume root (an entry refused) and the runtime directory (a way back
/// refused).
#[must_use]
pub fn read(dir: &Path) -> Option<SwitchRefusal> {
    let text = std::fs::read(refusal_path(dir)).ok()?;
    serde_json::from_slice::<SwitchRefusal>(&text)
        .ok()
        .filter(|record| !record.reason.trim().is_empty())
}

/// Forget the refusal recorded in `dir`. Best-effort: a missing record is
/// success. Called when a new switch supersedes the last one.
pub fn clear(dir: &Path) {
    let _ = std::fs::remove_file(refusal_path(dir));
}

#[cfg(test)]
#[path = "switch_refusal_tests.rs"]
mod tests;
