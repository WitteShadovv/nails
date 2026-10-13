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
//! check; [`run_loop`] ties them together around a real sleep for the CLI's
//! hidden `watch` subcommand.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::BackendWatchConfig;
use crate::filesystem::Filesystem;
use crate::runtime_copy::RuntimeManifest;
use nails_teardown::mountinfo::MountEntry;

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

/// Probe the hidden backend's health from the recorded manifest.
///
/// Returns `false` (unhealthy) when the hidden root has become unreachable or
/// unreadable, or when any overlay target the manifest recorded is no longer
/// mounted — the ways a lazily detached or failed backend shows up. A probe error
/// is treated as unhealthy: the whole point is to react to a backend that can no
/// longer answer.
///
/// The health check reads the hidden root's *directory contents* rather than
/// merely opening it. When the backing device fails in place — a yanked disk, a
/// dm error target swapped under the mount — the mount point and its inode stay
/// in the kernel's caches, so `path_exists` and even `File::open` still succeed
/// while every real access returns `EIO` and the filesystem shuts down. A
/// `readdir` touches the backing store, so it surfaces exactly that failure;
/// anything other than a successful listing is unhealthy.
pub fn probe_backend<F: Filesystem>(filesystem: &F, manifest: &RuntimeManifest) -> bool {
    match filesystem.path_exists(&manifest.hidden_root) {
        Ok(true) => {}
        _ => return false,
    }
    if filesystem.list_directory(&manifest.hidden_root).is_err() {
        return false;
    }
    // A device that fails in place keeps its dentry cache, so the directory read
    // above still succeeds; the kernel's response to the I/O error is to remount
    // the filesystem read-only. NAILS keeps the hidden volume writable, so the
    // surest sign the backend has failed is that the hidden root can no longer be
    // written: an actual create-and-remove probe returns EROFS on a read-only
    // remount or EIO on a dead device, without depending on how the mount table
    // reports the flags. (The cheaper mount-table check is kept as a fast path.)
    if filesystem
        .is_mount_read_only(&manifest.hidden_root)
        .unwrap_or(false)
    {
        return false;
    }
    if !filesystem
        .is_writable(&manifest.hidden_root)
        .unwrap_or(false)
    {
        return false;
    }
    manifest
        .overlay_targets
        .iter()
        .all(|target| filesystem.is_mounted(target).unwrap_or(false))
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
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::{Path, PathBuf};

    fn mounted(fs: &MockFilesystem, target: &str, yes: bool) {
        fs.mock_set_mounted(Path::new(target), yes);
    }

    fn alert_only() -> BackendWatchConfig {
        BackendWatchConfig {
            auto_emergency: false,
            debounce_secs: 15,
            ..BackendWatchConfig::default()
        }
    }

    fn auto_emergency() -> BackendWatchConfig {
        BackendWatchConfig {
            auto_emergency: true,
            debounce_secs: 15,
            ..BackendWatchConfig::default()
        }
    }

    #[test]
    fn healthy_probe_does_nothing() {
        let mut watch = BackendWatch::new(&alert_only());
        assert_eq!(watch.observe(true, Instant::now()), WatchAction::Nothing);
    }

    #[test]
    fn first_failure_alerts() {
        let mut watch = BackendWatch::new(&alert_only());
        assert_eq!(watch.observe(false, Instant::now()), WatchAction::Alert);
    }

    #[test]
    fn alert_only_never_triggers_emergency_however_long_it_persists() {
        let mut watch = BackendWatch::new(&alert_only());
        let t0 = Instant::now();
        assert_eq!(watch.observe(false, t0), WatchAction::Alert);
        // Well past the debounce window, still only alert-only: no emergency.
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(60)),
            WatchAction::Nothing
        );
    }

    #[test]
    fn auto_emergency_fires_only_after_the_debounce() {
        let mut watch = BackendWatch::new(&auto_emergency());
        let t0 = Instant::now();
        assert_eq!(watch.observe(false, t0), WatchAction::Alert);
        // Still inside the debounce: no teardown yet.
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(5)),
            WatchAction::Nothing
        );
        // Past the debounce: teardown.
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(15)),
            WatchAction::Emergency
        );
        // It fires only once.
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(30)),
            WatchAction::Nothing
        );
    }

    #[test]
    fn a_transient_failure_that_recovers_never_triggers_emergency() {
        let mut watch = BackendWatch::new(&auto_emergency());
        let t0 = Instant::now();
        assert_eq!(watch.observe(false, t0), WatchAction::Alert);
        // Recovers before the debounce elapses.
        assert_eq!(
            watch.observe(true, t0 + Duration::from_secs(5)),
            WatchAction::Nothing
        );
        // A fresh failure alerts again rather than counting the old one.
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(6)),
            WatchAction::Alert
        );
        // And the debounce is measured from the new failure, not the first.
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(16)),
            WatchAction::Nothing
        );
        assert_eq!(
            watch.observe(false, t0 + Duration::from_secs(21)),
            WatchAction::Emergency
        );
    }

    fn manifest(targets: &[&str]) -> RuntimeManifest {
        RuntimeManifest {
            hidden_root: PathBuf::from("/mnt/data"),
            overlay_targets: targets.iter().map(PathBuf::from).collect(),
        }
    }

    /// Make the hidden root list successfully, standing in for a backing store
    /// that still answers a `readdir`.
    fn root_lists(fs: &MockFilesystem) {
        fs.mock_set_path_exists("/mnt/data", true);
        fs.mock_set_directory_contents(
            Path::new("/mnt/data"),
            vec![PathBuf::from("/mnt/data/state.json")],
        );
    }

    #[test]
    fn probe_is_healthy_when_root_readable_and_targets_mounted() {
        let fs = MockFilesystem::new();
        root_lists(&fs);
        mounted(&fs, "/home", true);
        mounted(&fs, "/etc", true);

        assert!(probe_backend(&fs, &manifest(&["/home", "/etc"])));
    }

    #[test]
    fn probe_fails_when_a_target_is_no_longer_mounted() {
        let fs = MockFilesystem::new();
        root_lists(&fs);
        mounted(&fs, "/home", true);
        mounted(&fs, "/etc", false);

        assert!(!probe_backend(&fs, &manifest(&["/home", "/etc"])));
    }

    #[test]
    fn probe_fails_when_the_hidden_root_is_gone() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/data", false);
        mounted(&fs, "/home", true);

        assert!(!probe_backend(&fs, &manifest(&["/home"])));
    }

    #[test]
    fn probe_fails_when_the_backend_errors_in_place() {
        // A dm error target (or yanked disk) leaves the mount point and inode
        // cached — path_exists still succeeds and the overlays stay mounted — but
        // a real read of the hidden root returns an error. The probe must treat
        // that as unhealthy so the watcher alerts. Here the mock has no directory
        // contents configured for the root, so `list_directory` errors, standing
        // in for the `EIO` a readdir hits once the backing store has failed.
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/data", true);
        // Even an openable root is not enough: the device read is what fails.
        fs.mock_set_readable("/mnt/data", true);
        mounted(&fs, "/home", true);
        mounted(&fs, "/etc", true);

        assert!(!probe_backend(&fs, &manifest(&["/home", "/etc"])));
    }

    #[test]
    fn probe_fails_when_the_hidden_root_is_not_writable() {
        // A write probe is the surest health signal: a remount-ro returns EROFS and
        // a dead device EIO, independent of how the mount table reports the flags.
        let fs = MockFilesystem::new();
        root_lists(&fs);
        mounted(&fs, "/home", true);
        mounted(&fs, "/etc", true);
        fs.mock_set_writable("/mnt/data", false);

        assert!(!probe_backend(&fs, &manifest(&["/home", "/etc"])));
    }

    #[test]
    fn probe_fails_when_the_hidden_root_is_remounted_read_only() {
        // A backend that fails in place keeps its dentry cache, so the readdir
        // above still answers, but the kernel remounts the filesystem read-only on
        // the I/O error. NAILS keeps the hidden volume writable, so a read-only
        // hidden root is a failed backend and the probe must report it unhealthy.
        let fs = MockFilesystem::new();
        root_lists(&fs);
        mounted(&fs, "/home", true);
        mounted(&fs, "/etc", true);
        fs.mock_set_mount_read_only(Path::new("/mnt/data"));

        assert!(!probe_backend(&fs, &manifest(&["/home", "/etc"])));
    }

    #[test]
    fn run_loop_stops_after_an_automatic_emergency() {
        // A fast poll so the test is quick; auto_emergency with a zero debounce so
        // the second failed probe tears down and ends the loop.
        let config = BackendWatchConfig {
            auto_emergency: true,
            debounce_secs: 0,
            poll_interval_secs: 0,
            enabled: true,
        };
        let mut probes = vec![false, false].into_iter();
        let mut alerts = 0;
        let mut emergencies = 0;
        let mut ticks = 0;
        run_loop(
            &config,
            || probes.next().unwrap_or(false),
            || alerts += 1,
            || emergencies += 1,
            || ticks += 1,
        );
        assert_eq!(alerts, 1, "first failure alerts");
        assert_eq!(emergencies, 1, "persistent failure tears down once");
        assert_eq!(ticks, 2, "every round ticks first");
    }

    fn block_sources(mount: &MountEntry) -> bool {
        mount.source.starts_with("/dev/")
    }

    #[test]
    fn only_read_write_disk_mounts_outside_the_session_alert_once() {
        let table = |extra: &str| {
            nails_teardown::mountinfo::parse_mountinfo(&format!(
                "1 0 0:30 / / rw - overlay overlay rw,upperdir=/u\n\
                 2 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
                 3 2 8:2 / /mnt/data/root/decoy/home rw - ext4 /dev/vda3 rw\n\
                 4 1 8:1 / /boot ro - vfat /dev/vda1 ro\n\
                 5 1 0:31 / /home rw - overlay overlay rw\n\
                 6 1 0:32 / /tmp rw - tmpfs tmpfs rw\n\
                 7 1 8:2 / /run/nextroot rw - ext4 /dev/vda2 rw\n{extra}"
            ))
        };
        let mut watch = MountWatch::new(Path::new("/mnt/data"));
        assert!(watch.observe(&table(""), &block_sources).is_empty());
        let usb = "8 1 8:33 / /run/media/user/USB rw - vfat /dev/sdc1 rw\n\
                   9 1 8:34 / /mnt/ro ro - ext4 /dev/sdc2 ro\n";
        let found = watch.observe(&table(usb), &block_sources);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].mount_point, Path::new("/run/media/user/USB"));
        // Reported once while it stays.
        assert!(watch.observe(&table(usb), &block_sources).is_empty());
        // Unmounted and mounted again under the same id: reported again.
        assert!(watch.observe(&table(""), &block_sources).is_empty());
        assert_eq!(watch.observe(&table(usb), &block_sources).len(), 1);
    }
}
