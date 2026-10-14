// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! In-session watcher over the hidden backend.
//!
//! After activation the hidden volume can fail silently: a udisks/VeraCrypt
//! automount is lazily detached when its device disappears, the backing device
//! drops off the bus, or the filesystem flips read-only after an I/O error. The
//! overlays keep serving stale pages and the operator sees unexplained
//! application errors with nothing connecting them to the real cause.
//!
//! The watcher is the long-running component that closes that gap. It is launched
//! from the RAM-backed runtime copy ([`crate::runtime_copy`]) as a transient
//! systemd unit with a neutral name, keeps all of its state in `/run`, and every
//! few seconds probes the mount table and the hidden root. The moment a probe
//! fails it alerts the operator; it tears the session down on its own **only**
//! when the operator opted in (`[backend_watch] auto_emergency = true`) and the
//! failure has outlasted the debounce window, so a transient I/O stall that
//! recovers is reported but never allowed to kill a live session.
//!
//! [`BackendWatch`] is the debounce/alert decision, kept free of clocks and I/O
//! so it can be exercised deterministically; [`probe_backend`] is the health
//! check; [`CoverWatch`] reports a mount stacked on the hidden root; [`run_loop`]
//! ties them together around a real sleep for the CLI's hidden `watch`
//! subcommand.

mod cover;

pub use cover::{CoverWatch, shadowing_mount};

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::BackendWatchConfig;
use crate::filesystem::Filesystem;
use crate::runtime_copy::RuntimeManifest;
use nails_base::hidden_root::{covered_mount, holds_the_session_volume};
use nails_teardown::mountinfo::{MountEntry, top_mount_at};

/// What the watcher should do in response to one probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchAction {
    /// The backend is healthy, or a failure that has already been handled
    /// persists: nothing to do.
    Nothing,
    /// A failure was observed for the first time: alert the operator.
    Alert,
    /// A failure has outlasted the debounce window and automatic emergency is
    /// enabled: tear the session down.
    Emergency,
}

/// The watcher's debounce and alert decision, decoupled from clocks and I/O.
///
/// One alert fires on the first failure; an automatic emergency fires at most
/// once, and only when `auto_emergency` is set and the failure has persisted for
/// at least the debounce window. A healthy probe resets the machine so a later,
/// unrelated failure alerts afresh.
#[derive(Debug)]
pub struct BackendWatch {
    auto_emergency: bool,
    debounce: Duration,
    first_failure_at: Option<Instant>,
    alerted: bool,
    emergency_fired: bool,
}

impl BackendWatch {
    /// Build a watcher decision from the `[backend_watch]` configuration.
    pub fn new(config: &BackendWatchConfig) -> Self {
        Self {
            auto_emergency: config.auto_emergency,
            debounce: config.debounce(),
            first_failure_at: None,
            alerted: false,
            emergency_fired: false,
        }
    }

    /// Feed one probe result, observed at `now`, and return the action to take.
    pub fn observe(&mut self, healthy: bool, now: Instant) -> WatchAction {
        if healthy {
            // Recovery clears the failure so a later failure alerts again and the
            // debounce clock restarts from the new failure.
            self.first_failure_at = None;
            self.alerted = false;
            self.emergency_fired = false;
            return WatchAction::Nothing;
        }

        let first = *self.first_failure_at.get_or_insert(now);

        if !self.alerted {
            self.alerted = true;
            return WatchAction::Alert;
        }

        if self.auto_emergency
            && !self.emergency_fired
            && now.saturating_duration_since(first) >= self.debounce
        {
            self.emergency_fired = true;
            return WatchAction::Emergency;
        }

        WatchAction::Nothing
    }
}

/// The result of one [`probe_backend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendProbe {
    /// The hidden root answers and takes writes; every target is mounted.
    Healthy,
    /// The backend has failed, or is no longer mounted at the hidden root.
    Failed,
    /// Another filesystem is mounted over the hidden volume. Nothing was
    /// written: a write would land on that filesystem, not the hidden volume.
    Covered,
}

impl BackendProbe {
    /// Whether the backend failed. A covered root is not a failure of the
    /// backend, so it raises no backend alert and never an emergency.
    pub fn is_failure(self) -> bool {
        self == BackendProbe::Failed
    }
}

/// Probe the hidden backend's health from the recorded manifest.
///
/// Returns [`BackendProbe::Failed`] when the hidden root has become unreachable
/// or unreadable, is no longer a mount point, or when any overlay target the
/// manifest recorded is no longer mounted — the ways a lazily detached or
/// failed backend shows up. A probe error is treated as a failure: the whole
/// point is to react to a backend that can no longer answer.
///
/// Before anything is written, the mount at the hidden root must be the volume
/// the session entered with (the attach gate's session rule, see
/// [`nails_base::hidden_root::holds_the_session_volume`]); when another
/// filesystem covers it the probe stops at [`BackendProbe::Covered`].
///
/// The health check reads the hidden root's *directory contents* rather than
/// merely opening it. When the backing device fails in place — a yanked disk, a
/// dm error target swapped under the mount — the mount point and its inode stay
/// in the kernel's caches, so `path_exists` and even `File::open` still succeed
/// while every real access returns `EIO` and the filesystem shuts down. A
/// `readdir` touches the backing store, so it surfaces exactly that failure;
/// anything other than a successful listing is unhealthy.
pub fn probe_backend<F: Filesystem>(filesystem: &F, manifest: &RuntimeManifest) -> BackendProbe {
    let root = &manifest.hidden_root;
    match filesystem.path_exists(root) {
        Ok(true) => {}
        _ => return BackendProbe::Failed,
    }
    if filesystem.list_directory(root).is_err() {
        return BackendProbe::Failed;
    }
    let Ok(table) = filesystem.mount_table() else {
        return BackendProbe::Failed;
    };
    let canonical = filesystem
        .canonicalize(root)
        .unwrap_or_else(|_| root.clone());
    let Some(visible) = top_mount_at(&table, &canonical) else {
        return BackendProbe::Failed;
    };
    if covered_mount(&table, visible).is_some()
        || !holds_the_session_volume(
            filesystem,
            &canonical,
            visible,
            manifest.hidden_dev.as_deref(),
        )
    {
        return BackendProbe::Covered;
    }
    // A device that fails in place keeps its dentry cache, so the directory read
    // above still succeeds; the kernel's response to the I/O error is to remount
    // the filesystem read-only. NAILS keeps the hidden volume writable, so the
    // surest sign the backend has failed is that the hidden root can no longer be
    // written: an actual create-and-remove probe returns EROFS on a read-only
    // remount or EIO on a dead device, without depending on how the mount table
    // reports the flags. (The cheaper mount-table check is kept as a fast path.)
    if filesystem.is_mount_read_only(root).unwrap_or(false) {
        return BackendProbe::Failed;
    }
    if !filesystem.is_writable(root).unwrap_or(false) {
        return BackendProbe::Failed;
    }
    let mounted = manifest
        .overlay_targets
        .iter()
        .all(|target| filesystem.is_mounted(target).unwrap_or(false));
    if mounted {
        BackendProbe::Healthy
    } else {
        BackendProbe::Failed
    }
}

/// Whether a mount is a read-write mount of a disk that the session does not
/// own: read-write, backed by a block device (`is_block` judges its source),
/// and neither inside the hidden volume nor the decoy root mounted at
/// `/run/nextroot` on the way back. The session's own mounts never qualify:
/// the root and the decoy filesystems are overlays, the boot filesystems are
/// read-only binds, and the carried decoy filesystems are inside the hidden
/// volume.
pub fn is_unguarded_mount(
    mount: &MountEntry,
    hidden_root: &Path,
    is_block: &dyn Fn(&MountEntry) -> bool,
) -> bool {
    !mount.read_only()
        && !mount.mount_point.starts_with(hidden_root)
        && !mount
            .mount_point
            .starts_with(nails_teardown::whole_root::nextroot::NEXTROOT)
        && is_block(mount)
}

/// The watcher's view of disk mounts made during the session (T-143): each
/// unguarded read-write mount is reported once, by mount id.
#[derive(Debug, Default)]
pub struct MountWatch {
    hidden_root: PathBuf,
    seen: BTreeSet<i32>,
}

impl MountWatch {
    /// Watch for mounts outside `hidden_root`.
    pub fn new(hidden_root: &Path) -> Self {
        Self {
            hidden_root: hidden_root.to_path_buf(),
            seen: BTreeSet::new(),
        }
    }

    /// The unguarded mounts in `mounts` not reported before. A mount that is
    /// gone is forgotten, so its id can alert again when it is reused.
    pub fn observe(
        &mut self,
        mounts: &[MountEntry],
        is_block: &dyn Fn(&MountEntry) -> bool,
    ) -> Vec<MountEntry> {
        let current: BTreeSet<i32> = mounts.iter().map(|m| m.mount_id).collect();
        self.seen.retain(|id| current.contains(id));
        mounts
            .iter()
            .filter(|m| is_unguarded_mount(m, &self.hidden_root, is_block))
            .filter(|m| self.seen.insert(m.mount_id))
            .cloned()
            .collect()
    }
}

/// Run the watch loop around a real sleep until an automatic emergency fires.
///
/// The probe, alert and emergency effects are injected so the loop itself stays
/// free of the host: the CLI's hidden `watch` subcommand supplies a real
/// backend probe, a desktop notification, and an in-process emergency teardown.
/// `tick` runs at the start of every round, before the sleep (the mount watch
/// and the read-only sweep). The loop returns once an automatic emergency has
/// run; with alert-only configuration it runs until the process is stopped
/// (deactivation and emergency stop the transient unit).
pub fn run_loop<P, A, E, T>(
    config: &BackendWatchConfig,
    mut probe: P,
    mut alert: A,
    mut emergency: E,
    mut tick: T,
) where
    P: FnMut() -> bool,
    A: FnMut(),
    E: FnMut(),
    T: FnMut(),
{
    let mut watch = BackendWatch::new(config);
    loop {
        tick();
        std::thread::sleep(config.poll_interval());
        let healthy = probe();
        match watch.observe(healthy, Instant::now()) {
            WatchAction::Nothing => {}
            WatchAction::Alert => alert(),
            WatchAction::Emergency => {
                emergency();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests;
