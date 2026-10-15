// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the in-session watcher.

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
        hidden_dev: None,
        overlay_targets: targets.iter().map(PathBuf::from).collect(),
    }
}

/// Make the hidden root a mounted volume that lists successfully, standing
/// in for a backing store that still answers a `readdir`. With no recorded
/// device in the manifest, the root overlay's upper on the root's own device
/// shows it is the session's volume.
fn root_lists(fs: &MockFilesystem) {
    fs.mock_set_mounted(Path::new("/mnt/data"), true);
    fs.mock_set_device_id(Path::new("/mnt/data"), 42);
    fs.mock_set_device_id(Path::new("/mnt/data/root/upper"), 42);
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

    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/etc"])),
        BackendProbe::Healthy
    );
}

#[test]
fn probe_fails_when_a_target_is_no_longer_mounted() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    mounted(&fs, "/home", true);
    mounted(&fs, "/etc", false);

    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/etc"])),
        BackendProbe::Failed
    );
}

#[test]
fn probe_fails_when_the_hidden_root_is_gone() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/data", false);
    mounted(&fs, "/home", true);

    assert_eq!(
        probe_backend(&fs, &manifest(&["/home"])),
        BackendProbe::Failed
    );
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

    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/etc"])),
        BackendProbe::Failed
    );
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

    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/etc"])),
        BackendProbe::Failed
    );
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

    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/etc"])),
        BackendProbe::Failed
    );
}

/// The hidden root and the overlay targets `/home` and `/srv/share`, plus
/// `extra` mount lines.
fn session_table(extra: &str) -> String {
    format!(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         10 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         20 1 0:40 / /home rw - overlay overlay rw\n\
         30 1 8:2 / /srv rw - ext4 /dev/vda2 rw\n\
         31 30 0:41 / /srv/share rw - overlay overlay rw\n{extra}"
    )
}

#[test]
fn probe_fails_when_a_target_is_covered_by_a_mount_on_its_parent() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    fs.mock_set_mount_table(&session_table(""));
    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/srv/share"])),
        BackendProbe::Healthy
    );

    // A later mount on /srv covers the target, which stays in the table.
    fs.mock_set_mount_table(&session_table("32 30 0:42 / /srv rw - tmpfs tmpfs rw\n"));
    assert_eq!(
        probe_backend(&fs, &manifest(&["/home", "/srv/share"])),
        BackendProbe::Failed
    );
}

#[test]
fn probe_reads_the_flags_of_the_mount_on_top_of_the_hidden_root() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    // A read-only bind of the volume stacked on the hidden root is what a
    // write reaches.
    fs.mock_set_mount_table(&session_table(
        "11 10 253:0 / /mnt/data ro - ext4 /dev/mapper/data rw\n",
    ));
    assert_eq!(
        probe_backend(&fs, &manifest(&["/home"])),
        BackendProbe::Failed
    );
}

fn recorded(targets: &[&str]) -> RuntimeManifest {
    RuntimeManifest {
        hidden_dev: Some("253:0".to_string()),
        ..manifest(targets)
    }
}

#[test]
fn probe_is_healthy_on_the_recorded_volume() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    fs.mock_set_mount_table(&session_table(""));
    assert_eq!(
        probe_backend(&fs, &recorded(&["/home"])),
        BackendProbe::Healthy
    );
}

#[test]
fn probe_writes_nothing_while_another_disk_covers_the_hidden_root() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    // A write probe would fail on this root: reaching it would give Failed.
    fs.mock_set_writable("/mnt/data", false);
    // A stick mounted over the hidden root.
    let covered = session_table("11 10 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n");
    fs.mock_set_mount_table(&covered);
    assert_eq!(
        probe_backend(&fs, &recorded(&["/home"])),
        BackendProbe::Covered
    );
    // The same without a recorded device: the upper is not on the stick.
    assert_eq!(
        probe_backend(&fs, &manifest(&["/home"])),
        BackendProbe::Covered
    );
    assert!(!BackendProbe::Covered.is_failure());
}

#[test]
fn probe_reports_a_replaced_volume_as_covered() {
    // The hidden volume is gone from the table and another disk sits at its
    // mount point alone: not the device the entry recorded.
    let fs = MockFilesystem::new();
    root_lists(&fs);
    fs.mock_set_writable("/mnt/data", false);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         12 1 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n\
         20 1 0:40 / /home rw - overlay overlay rw\n",
    );
    assert_eq!(
        probe_backend(&fs, &recorded(&["/home"])),
        BackendProbe::Covered
    );
}

#[test]
fn a_mount_on_the_roots_parent_is_a_cover_not_a_failure() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    fs.mock_set_writable("/mnt/data", false);
    // A stick mounted on /mnt: the volume stays in the table at /mnt/data,
    // but a lookup of the root ends on the stick.
    let covered = session_table("12 1 8:16 / /mnt rw - vfat /dev/sdb1 rw\n");
    fs.mock_set_mount_table(&covered);
    assert_eq!(
        probe_backend(&fs, &recorded(&["/home"])),
        BackendProbe::Covered
    );
    assert_eq!(
        probe_backend(&fs, &manifest(&["/home"])),
        BackendProbe::Covered
    );
}

#[test]
fn a_symlinked_root_is_watched_where_the_mount_table_names_it() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    fs.create_symlink(Path::new("/mnt/data"), Path::new("/srv/hidden"))
        .unwrap();
    let linked = RuntimeManifest {
        hidden_root: PathBuf::from("/srv/hidden"),
        ..recorded(&["/home"])
    };
    let resolved = resolved_root(&fs, &linked);
    assert_eq!(resolved, Path::new("/mnt/data"));
    let covered = nails_teardown::mountinfo::parse_mountinfo(&session_table(
        "11 10 8:16 / /mnt/data rw - vfat /dev/sdb1 rw\n",
    ));
    let mut watch = CoverWatch::new(&resolved, linked.hidden_dev.as_deref());
    let cover = watch.observe(&covered).expect("the stick covers the root");
    assert_eq!(cover.mount_id, 11);
}

#[test]
fn probe_fails_when_the_hidden_root_is_no_longer_a_mount_point() {
    let fs = MockFilesystem::new();
    root_lists(&fs);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         20 1 0:40 / /home rw - overlay overlay rw\n",
    );
    assert_eq!(
        probe_backend(&fs, &recorded(&["/home"])),
        BackendProbe::Failed
    );
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
    let (alert, alerts) = std::sync::mpsc::channel();
    let alert = std::sync::Mutex::new(alert);
    let mut emergencies = 0;
    let mut ticks = 0;
    run_loop(
        &config,
        || probes.next().unwrap_or(false),
        move || {
            let _ = alert.lock().map(|alert| alert.send(()));
        },
        || emergencies += 1,
        || ticks += 1,
    );
    // The alert went out on a thread of its own.
    assert!(
        alerts.recv_timeout(Duration::from_secs(10)).is_ok(),
        "first failure alerts"
    );
    assert!(alerts.try_recv().is_err(), "once");
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

/// A notification daemon that never answers holds up neither the probes nor
/// the automatic emergency: the alert waits on its own thread.
#[test]
fn an_alert_that_never_returns_delays_no_emergency() {
    let config = BackendWatchConfig {
        auto_emergency: true,
        poll_interval_secs: 0,
        debounce_secs: 0,
        ..BackendWatchConfig::default()
    };
    let (fired, emergency) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        run_loop(
            &config,
            || false,
            || loop {
                std::thread::park();
            },
            move || {
                let _ = fired.send(());
            },
            || {},
        );
    });
    assert!(
        emergency.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the emergency waited for the alert"
    );
}
