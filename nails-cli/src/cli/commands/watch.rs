// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden `watch` command: the in-session watcher.
//!
//! This is not an operator-facing command. It runs from the RAM-backed runtime
//! copy as a runtime unit of the hidden session (installed in `/run` by the
//! entry transition) for the life of the session, polling the hidden backend
//! and alerting the operator the moment it fails, alerting on every disk
//! mounted read-write outside the hidden volume (`[session_mounts] alert`) and
//! on every mount stacked on the hidden root, and sweeping unused disks
//! read-only when that is opted into. It is marked
//! `hide = true` so it never appears in help, and it keeps all of its state in the
//! `/run` copy so it keeps working even after the hidden volume is gone.

use std::path::Path;

use nails_core::notification::{Notification, send_immediate};
use nails_core::{RealFilesystem, runtime_copy, watcher};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::disk_guard;

use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the watcher.
///
/// Reads the mount manifest and the mirrored configuration from the `/run` copy,
/// then polls the backend on the configured interval. On a failed probe it alerts
/// the operator; it tears the session down on its own only when the operator
/// opted into `auto_emergency` and the failure outlasts the debounce window.
///
/// Always exits [`ExitStatus::Ok`]: the watcher is a best-effort safety net, so a
/// missing manifest (no activation wrote one) or an unreadable copy is a quiet
/// no-op rather than an error dialog.
pub fn execute(
    _settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    config_override: Option<&Path>,
) -> ExitStatus {
    let filesystem = RealFilesystem;

    let manifest = match runtime_copy::read_manifest(&filesystem) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            tracing::debug!("No runtime manifest present; nothing to watch");
            return ExitStatus::Ok;
        }
        Err(e) => {
            tracing::warn!(error = %e, "Could not read the runtime manifest; watcher exiting");
            return ExitStatus::Ok;
        }
    };

    // Prefer the configuration mirrored into the runtime copy, since the real
    // config file lives on the hidden volume that may already be failing. Fall
    // back to the binary-relative config only if the copy cannot be read.
    let config = match runtime_copy::read_config_copy(&filesystem) {
        Ok(Some(config)) => config,
        _ => super::load_config_or_defaults(config_override).into_config(),
    };

    let watch_config = config.backend_watch.clone();
    let mounts_config = config.session_mounts.clone();
    if !watch_config.enabled && !mounts_config.needs_watcher() {
        tracing::debug!("Nothing to watch in config; watcher exiting");
        return ExitStatus::Ok;
    }

    tracing::info!(
        poll_interval_secs = watch_config.poll_interval_secs,
        auto_emergency = watch_config.auto_emergency,
        backend = watch_config.enabled,
        mount_alert = mounts_config.alert,
        read_only_disks = mounts_config.read_only,
        "Session watcher started"
    );

    // The read-only sweep needs the whole plan; the udev rule is the first
    // line, this the fallback.
    let plan = nails_teardown::whole_root::plan::Plan::load(
        &nails_teardown::whole_root::plan::default_plan_path(),
    )
    .ok()
    .filter(|plan| mounts_config.read_only && plan.read_only_disks);
    let sysfs = disk_guard::Sysfs::system();
    // The mount table names the root with its symlinks resolved.
    let hidden_root = watcher::resolved_root(&filesystem, &manifest);
    let mut mount_watch = watcher::MountWatch::new(&hidden_root);
    let mut cover_watch = watcher::CoverWatch::new(&hidden_root, manifest.hidden_dev.as_deref());
    let is_block = |mount: &MountEntry| disk_guard::mount_device(mount).is_some();

    let alert_env = env.clone();
    watcher::run_loop(
        &watch_config,
        // A probe of a covered hidden root writes nothing and is no failure of
        // the backend: it neither alerts as one nor leads to an emergency.
        || !watch_config.enabled || !watcher::probe_backend(&filesystem, &manifest).is_failure(),
        move || {
            if let Err(e) = send_immediate(&backend_alert(), &alert_env) {
                tracing::warn!(error = %e, "Could not deliver the backend-failure alert");
            }
        },
        || {
            tracing::warn!("Backend failure outlasted the debounce; running the emergency");
            super::emergency::run_hot_path_with(
                nails_teardown::whole_root::emergency::Finish::Return,
            );
        },
        || {
            let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap_or_default();
            if let Some(plan) = &plan {
                let set = disk_guard::sweep(
                    plan,
                    &mounts,
                    &sysfs,
                    Path::new(nails_teardown::whole_root::plan::RUNTIME_DIR),
                );
                if !set.is_empty() {
                    tracing::info!(devices = set.len(), "Unused disks set read-only");
                }
            }
            let alerts = tick_alerts(
                &mounts,
                &mut cover_watch,
                &mut mount_watch,
                mounts_config.alert,
                &is_block,
            );
            let env = env.clone();
            send_all_in_background(alerts, move |alert| send_immediate(alert, &env));
        },
    );

    ExitStatus::Ok
}

/// The alerts one round of the watch loop raises for the mount table
/// `mounts`, each with the name the log gives it.
///
/// A mount stacked on the hidden root takes every file saved there from now
/// on: the gate refuses NAILS' own writes, and the operator is told once per
/// mount. Then, with `alert_mounts`, each disk newly mounted read-write
/// outside the session; a cover on a parent of the root lies outside it, and
/// its own alert already names it.
fn tick_alerts(
    mounts: &[MountEntry],
    cover_watch: &mut watcher::CoverWatch,
    mount_watch: &mut watcher::MountWatch,
    alert_mounts: bool,
    is_block: &dyn Fn(&MountEntry) -> bool,
) -> Vec<(Notification, &'static str)> {
    let mut alerts = Vec::new();
    if let Some(cover) = cover_watch.observe(mounts) {
        tracing::warn!(
            mount_point = %cover.mount_point.display(),
            "A disk is mounted over the folder in use"
        );
        alerts.push((cover_alert(&cover), "cover"));
    }
    if alert_mounts {
        let cover = cover_watch.cover(mounts).map(|m| m.mount_id);
        for mount in mount_watch
            .observe(mounts, is_block)
            .into_iter()
            .filter(|m| Some(m.mount_id) != cover)
        {
            tracing::warn!(
                mount_point = %mount.mount_point.display(),
                "A disk is mounted read-write"
            );
            alerts.push((mount_alert(&mount), "disk-mount"));
        }
    }
    alerts
}

/// Send each alert through `send` from a thread of its own
/// ([`watcher::in_background`]), so the watch loop never waits for the
/// notification daemon.
fn send_all_in_background<S>(alerts: Vec<(Notification, &'static str)>, send: S)
where
    S: Fn(&Notification) -> nails_core::Result<()> + Clone + Send + 'static,
{
    for (alert, what) in alerts {
        let send = send.clone();
        watcher::in_background(move || {
            if let Err(e) = send(&alert) {
                tracing::warn!(error = %e, "Could not deliver the {what} alert");
            }
        });
    }
}

/// The neutral desktop alert raised when a disk is mounted read-write during
/// the session: worded as an ordinary storage notice.
fn mount_alert(mount: &MountEntry) -> Notification {
    Notification {
        title: "Disk mounted with write access".to_string(),
        body: format!(
            "{} ({}) is mounted read-write. Files written there stay on that disk.",
            mount.mount_point.display(),
            mount.source.display()
        ),
        urgency: "critical".to_string(),
        icon: Some("drive-removable-media".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// The neutral desktop alert raised when a disk is mounted over the hidden
/// root, or over one of its parents: it names the disk and how to take it off
/// again (at the root, the cover's mount point is the root).
fn cover_alert(cover: &MountEntry) -> Notification {
    let source = cover.source.display();
    let root = cover.mount_point.display();
    Notification {
        title: "Disk mounted over a folder in use".to_string(),
        body: format!(
            "{source} is mounted over {root}, a folder in use. Files saved there now go to \
             {source}. To undo it, run: sudo umount {root}"
        ),
        urgency: "critical".to_string(),
        icon: Some("drive-removable-media".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// The neutral desktop alert raised when the backend stops responding.
///
/// Worded so it reveals nothing about a hidden environment: to anyone watching
/// the screen it reads as an ordinary removable-storage warning.
fn backend_alert() -> Notification {
    Notification {
        title: "Storage unavailable".to_string(),
        body: "A mounted volume stopped responding. Save your work and reconnect it.".to_string(),
        urgency: "critical".to_string(),
        icon: Some("drive-harddisk".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Words that would tell a bystander reading the screen what this is.
    const REVEALING: &[&str] = &["hidden", "nails", "decoy", "session", "overlay"];

    fn assert_neutral(alert: &Notification) {
        let text = format!("{} {}", alert.title, alert.body).to_lowercase();
        for word in REVEALING {
            assert!(!text.contains(word), "{word:?} in {text:?}");
        }
    }

    fn mounts(table: &str) -> Vec<MountEntry> {
        nails_teardown::mountinfo::parse_mountinfo(table)
    }

    fn block(mount: &MountEntry) -> bool {
        mount.source.starts_with("/dev/")
    }

    const SESSION: &str = "1 0 0:30 / / rw - overlay overlay rw,upperdir=/u\n\
                           2 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n";

    #[test]
    fn a_round_alerts_a_cover_first_then_each_new_read_write_disk_once() {
        let mut cover_watch = watcher::CoverWatch::new(Path::new("/mnt/data"), Some("253:0"));
        let mut mount_watch = watcher::MountWatch::new(Path::new("/mnt/data"));
        let mut round = |table: &str, alert_mounts: bool| {
            tick_alerts(
                &mounts(table),
                &mut cover_watch,
                &mut mount_watch,
                alert_mounts,
                &block,
            )
            .into_iter()
            .map(|(alert, what)| (alert.title, what))
            .collect::<Vec<_>>()
        };
        assert!(round(SESSION, true).is_empty());
        let usb = format!("{SESSION}3 1 8:33 / /media/usb rw - vfat /dev/sdc1 rw\n");
        assert_eq!(
            round(&usb, true),
            [("Disk mounted with write access".to_string(), "disk-mount")]
        );
        assert!(round(&usb, true).is_empty(), "once per mount");
        let covered = format!("{usb}4 2 8:34 / /mnt/data rw - ext4 /dev/sdc2 rw\n");
        assert_eq!(
            round(&covered, false),
            [("Disk mounted over a folder in use".to_string(), "cover")]
        );
    }

    /// A notification daemon that never answers holds up neither the round
    /// nor the other alerts.
    #[test]
    fn an_alert_that_never_returns_holds_up_no_round() {
        let (sent, received) = std::sync::mpsc::channel();
        let sent = std::sync::Arc::new(std::sync::Mutex::new(sent));
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            send_all_in_background(
                vec![(backend_alert(), "backend"), (backend_alert(), "backend")],
                move |alert: &Notification| -> nails_core::Result<()> {
                    let _ = sent.lock().map(|sent| sent.send(alert.title.clone()));
                    loop {
                        std::thread::park();
                    }
                },
            );
            let _ = done.send(());
        });
        let wait = std::time::Duration::from_secs(10);
        assert!(
            finished.recv_timeout(wait).is_ok(),
            "the round waited for an alert"
        );
        for _ in 0..2 {
            assert_eq!(
                received.recv_timeout(wait).as_deref(),
                Ok("Storage unavailable")
            );
        }
    }

    #[test]
    fn the_backend_alert_reads_as_an_ordinary_storage_warning() {
        let alert = backend_alert();
        assert_eq!(alert.title, "Storage unavailable");
        assert_eq!(
            alert.body,
            "A mounted volume stopped responding. Save your work and reconnect it."
        );
        assert_eq!(alert.urgency, "critical");
        assert_eq!(alert.icon.as_deref(), Some("drive-harddisk"));
        chrono::DateTime::parse_from_rfc3339(&alert.created_at)
            .expect("the alert carries an RFC 3339 timestamp");
        assert_neutral(&alert);
    }

    #[test]
    fn the_cover_alert_names_the_disk_and_how_to_unmount_it() {
        let cover = MountEntry {
            mount_id: 91,
            parent_id: 10,
            dev: "8:33".to_string(),
            root: "/".into(),
            mount_point: "/mnt".into(),
            mount_opts: "rw,relatime".to_string(),
            fstype: "vfat".to_string(),
            source: "/dev/sdc1".into(),
            super_opts: "rw".to_string(),
        };
        let alert = cover_alert(&cover);
        assert_eq!(alert.title, "Disk mounted over a folder in use");
        assert_eq!(
            alert.body,
            "/dev/sdc1 is mounted over /mnt, a folder in use. Files saved there now go to \
             /dev/sdc1. To undo it, run: sudo umount /mnt"
        );
        assert_eq!(alert.urgency, "critical");
        assert_neutral(&alert);
    }

    #[test]
    fn the_mount_alert_names_the_mount_point_and_its_device() {
        let mount = MountEntry {
            mount_id: 90,
            parent_id: 1,
            dev: "8:17".to_string(),
            root: "/".into(),
            mount_point: "/media/usb".into(),
            mount_opts: "rw,relatime".to_string(),
            fstype: "vfat".to_string(),
            source: "/dev/sdb1".into(),
            super_opts: "rw".to_string(),
        };
        let alert = mount_alert(&mount);
        assert_eq!(alert.title, "Disk mounted with write access");
        assert_eq!(
            alert.body,
            "/media/usb (/dev/sdb1) is mounted read-write. Files written there stay on that disk."
        );
        assert_eq!(alert.urgency, "critical");
        assert_eq!(alert.icon.as_deref(), Some("drive-removable-media"));
        assert_neutral(&alert);
    }
}
