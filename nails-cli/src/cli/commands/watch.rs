// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hidden `watch` command: the in-session watcher.
//!
//! This is not an operator-facing command. It runs from the RAM-backed runtime
//! copy as a runtime unit of the hidden session (installed in `/run` by the
//! entry transition) for the life of the session, polling the hidden backend
//! and alerting the operator the moment it fails, alerting on every disk
//! mounted read-write outside the hidden volume (`[session_mounts] alert`), and
//! sweeping unused disks read-only when that is opted into. It is marked
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
    let mut mount_watch = watcher::MountWatch::new(&manifest.hidden_root);
    let is_block = |mount: &MountEntry| disk_guard::mount_device(mount).is_some();

    watcher::run_loop(
        &watch_config,
        || !watch_config.enabled || watcher::probe_backend(&filesystem, &manifest),
        || {
            if let Err(e) = send_immediate(&backend_alert(), env) {
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
            if mounts_config.alert {
                for mount in mount_watch.observe(&mounts, &is_block) {
                    tracing::warn!(
                        mount_point = %mount.mount_point.display(),
                        "A disk is mounted read-write"
                    );
                    if let Err(e) = send_immediate(&mount_alert(&mount), env) {
                        tracing::warn!(error = %e, "Could not deliver the disk-mount alert");
                    }
                }
            }
        },
    );

    ExitStatus::Ok
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
