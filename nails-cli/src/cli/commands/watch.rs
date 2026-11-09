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
//!
//! Where a copy in `/run` cannot be read it takes another copy of the same
//! facts ([`start`]): the hidden volume's own configuration for the
//! settings, the settings' hidden root for the session plan. Where neither
//! can be read it never tears the session down unasked: it watches
//! alert-only, or not at all, and tells the operator so once. Without the
//! plan a return to the decoy does nothing, so the automatic emergency the
//! settings ask for powers the machine off instead ([`auto_emergency`]), and
//! the watcher says so once.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use nails_core::config::{CONFIG_DIR_NAME, CONFIG_FILE_NAME, Config};
use nails_core::notification::{Notification, send_immediate};
use nails_core::runtime_copy::RuntimeManifest;
use nails_core::{RealFilesystem, runtime_copy, watcher};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::disk_guard;
use nails_teardown::whole_root::emergency::{Finish, HotReport};

use crate::cli::output::{ExitStatus, OutputSettings};

/// What the watcher starts with, each from the first copy it can read.
#[derive(Debug)]
enum Start {
    /// There is no session plan: no session to watch.
    Nothing,
    /// Watch `manifest`'s hidden root by `config`, with an automatic
    /// emergency, where `config` asks for one, that ends in `finish`.
    /// `notice` is the alert to deliver once: where the settings could not
    /// be read anywhere (`config` is then alert-only), or where the plan
    /// could not be read and the settings ask for an automatic emergency,
    /// which then powers off.
    Watch {
        manifest: RuntimeManifest,
        config: Box<Config>,
        finish: Finish,
        notice: Option<Notification>,
    },
    /// Nothing tells what to watch: deliver `notice` once, then exit.
    Without(Notification),
}

/// What the watcher starts with, from what reading the session plan
/// (`plan`) and the settings copy (`copy`) in `/run` gave.
///
/// The settings are the copy's, else those of `file` (a configuration file
/// that was found, `--config` or the one beside the binary), else those of
/// the hidden volume's own configuration at the root the plan names, which
/// `on_volume` reads. The hidden root is the plan's, else the settings'.
/// Where no settings can be read, the watcher watches alert-only and says so
/// once: it never runs the emergency itself then. Where the plan cannot be
/// read, a return to the decoy would do nothing at all, so the automatic
/// emergency powers the machine off instead, and the watcher says so once
/// where the settings ask for one. Where neither the plan nor the settings
/// can be read, it says the session runs without it. A plan that is not there
/// is no session.
fn start(
    plan: nails_core::Result<Option<RuntimeManifest>>,
    copy: nails_core::Result<Option<Config>>,
    file: impl FnOnce() -> Option<Config>,
    on_volume: impl FnOnce(&Path) -> nails_core::Result<Config>,
) -> Start {
    let manifest = match plan {
        Ok(Some(manifest)) => Some(manifest),
        Ok(None) => return Start::Nothing,
        Err(e) => {
            tracing::warn!(error = %e, "Could not read the session plan; taking the hidden root from the settings");
            None
        }
    };
    let config = match copy {
        Ok(Some(config)) => Some(config),
        Ok(None) => file(),
        Err(e) => {
            tracing::warn!(error = %e, "Could not read the settings copy");
            file()
        }
    }
    .or_else(|| {
        let path = manifest
            .as_ref()?
            .hidden_root
            .join(CONFIG_DIR_NAME)
            .join(CONFIG_FILE_NAME);
        on_volume(&path)
            .inspect_err(
                |e| tracing::warn!(error = %e, "Could not read the hidden volume's configuration"),
            )
            .ok()
    });
    match (manifest, config) {
        (Some(manifest), Some(config)) => Start::Watch {
            manifest,
            config: Box::new(config),
            finish: Finish::Return,
            notice: None,
        },
        (None, Some(config)) => {
            let watch = &config.backend_watch;
            let powers_off = watch.enabled && watch.auto_emergency;
            if powers_off {
                tracing::warn!(
                    "Without the session plan the automatic emergency cannot return; it powers off"
                );
            }
            Start::Watch {
                manifest: RuntimeManifest {
                    hidden_root: config.hidden_volume_root.clone(),
                    hidden_dev: None,
                    overlay_targets: Vec::new(),
                },
                config: Box::new(config),
                finish: Finish::Poweroff,
                notice: powers_off.then(power_off_notice),
            }
        }
        (Some(manifest), None) => {
            tracing::warn!("No copy of the settings can be read; watching alert-only");
            Start::Watch {
                manifest,
                config: Box::new(alert_only()),
                finish: Finish::Return,
                notice: Some(alert_only_notice()),
            }
        }
        (None, None) => Start::Without(unwatched_notice()),
    }
}

/// The settings of a watcher that could not read its own: the defaults,
/// which alert on a failed volume and on disks mounted read-write, and never
/// run the emergency.
fn alert_only() -> Config {
    let mut config = Config::default();
    config.backend_watch.enabled = true;
    config.backend_watch.auto_emergency = false;
    config
}

/// A configuration file that was found: `--config`, or the one beside the
/// binary. `None` where there is none, or it cannot be read.
fn found_file(config_override: Option<&Path>) -> Option<Config> {
    match super::resolve_config(config_override) {
        Ok(loaded) if config_override.is_some() || loaded.file_found => Some(loaded.into_config()),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "Could not read the configuration file");
            None
        }
    }
}

/// An alert delivered once: tried again at each round until one delivery
/// succeeds. At the start of a session no one is logged in yet, so the
/// first tries find no desktop to alert.
#[derive(Debug, Clone)]
struct Once {
    alert: Notification,
    /// [`PENDING`], [`SENDING`] or [`DELIVERED`].
    state: Arc<AtomicU8>,
}

const PENDING: u8 = 0;
const SENDING: u8 = 1;
const DELIVERED: u8 = 2;

impl Once {
    fn new(alert: Notification) -> Self {
        Self {
            alert,
            state: Arc::new(AtomicU8::new(PENDING)),
        }
    }

    /// Try to deliver the alert through `send`, from a thread of its own
    /// ([`watcher::in_background`]), unless it was delivered or a try is
    /// still on its way.
    fn try_deliver<S>(&self, send: S)
    where
        S: FnOnce(&Notification) -> nails_core::Result<()> + Send + 'static,
    {
        if self
            .state
            .compare_exchange(PENDING, SENDING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let once = self.clone();
        watcher::in_background(move || {
            let delivered = send(&once.alert);
            if let Err(e) = &delivered {
                tracing::debug!(error = %e, "Could not deliver the alert yet; trying again");
            }
            once.state.store(
                if delivered.is_ok() {
                    DELIVERED
                } else {
                    PENDING
                },
                Ordering::Release,
            );
        });
    }

    fn delivered(&self) -> bool {
        self.state.load(Ordering::Acquire) == DELIVERED
    }
}

/// Execute the watcher.
///
/// Reads the mount manifest and the mirrored configuration from the `/run` copy,
/// then polls the backend on the configured interval. On a failed probe it alerts
/// the operator; it tears the session down on its own only when the operator
/// opted into `auto_emergency` and the failure outlasts the debounce window.
/// Where a copy cannot be read it takes another ([`start`]).
///
/// Always exits [`ExitStatus::Ok`]: the watcher is a best-effort safety net, so a
/// missing manifest (no activation wrote one) is a quiet no-op rather than an
/// error dialog.
pub fn execute(
    _settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    config_override: Option<&Path>,
) -> ExitStatus {
    let filesystem = RealFilesystem;

    // Prefer the configuration mirrored into the runtime copy, since the real
    // config file lives on the hidden volume that may already be failing.
    let started = start(
        runtime_copy::read_manifest(&filesystem),
        runtime_copy::read_config_copy(&filesystem),
        || found_file(config_override),
        Config::load,
    );
    let interval = nails_core::config::BackendWatchConfig::default().poll_interval();
    let Some(Watching {
        manifest,
        config,
        finish,
        notice,
    }) = watching(started, |notice| {
        let env = env.clone();
        deliver_until_delivered(&notice, interval, move |alert| send_immediate(alert, &env));
    })
    else {
        return ExitStatus::Ok;
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
            auto_emergency(finish, super::emergency::run_hot_path_with)
        },
        || {
            if let Some(notice) = &notice {
                let env = env.clone();
                notice.try_deliver(move |alert| send_immediate(alert, &env));
            }
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

/// Run the automatic emergency through `run`, the hot path, to `finish`: a
/// return to the decoy where the watcher read the session plan, else a
/// power-off ([`start`]). A return that finds no plan when it fires does
/// nothing at all, so the watcher then powers off the same way, as the sleep
/// guard does without a plan. Says whether the emergency acted, which ends
/// the watch loop: where not even a power-off could be asked for, the
/// watcher watches on.
fn auto_emergency(finish: Finish, mut run: impl FnMut(Finish) -> HotReport) -> bool {
    let mut report = run(finish);
    if finish == Finish::Return && report.found_nothing() {
        tracing::warn!("The emergency found no session plan to return with; powering off instead");
        report = run(Finish::Poweroff);
    }
    let acted = !report.found_nothing() || report.dispatched.is_some() || report.kernel_power_off;
    tracing::warn!(
        acted,
        "The automatic emergency ended; the watcher watches on where it did not act"
    );
    acted
}

/// What the watcher watches with ([`watching`]).
#[derive(Debug)]
struct Watching {
    manifest: RuntimeManifest,
    config: Config,
    /// How its automatic emergency ends ([`auto_emergency`]).
    finish: Finish,
    /// The alert to deliver once while it watches.
    notice: Option<Once>,
}

/// What the watcher watches with, from what it `started` with: `None` where
/// there is nothing to watch, once `deliver_once` has delivered the alert of a
/// watcher that cannot run; else the plan, the settings, how the automatic
/// emergency ends and the alert to deliver once while it watches.
fn watching(started: Start, deliver_once: impl FnOnce(Once)) -> Option<Watching> {
    match started {
        Start::Nothing => {
            tracing::debug!("No runtime manifest present; nothing to watch");
            None
        }
        Start::Without(alert) => {
            tracing::warn!("Neither the session plan nor the settings can be read; not watching");
            deliver_once(Once::new(alert));
            None
        }
        Start::Watch {
            manifest,
            config,
            finish,
            notice,
        } => Some(Watching {
            manifest,
            config: *config,
            finish,
            notice: notice.map(Once::new),
        }),
    }
}

/// Try to deliver `notice` through `send` every `interval` until one
/// delivery succeeds, then return.
fn deliver_until_delivered<S>(notice: &Once, interval: std::time::Duration, send: S)
where
    S: Fn(&Notification) -> nails_core::Result<()> + Clone + Send + 'static,
{
    while !notice.delivered() {
        notice.try_deliver(send.clone());
        std::thread::sleep(interval);
    }
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
    let umount = nails_core::next_step::shell_word(cover.mount_point.as_os_str());
    Notification {
        title: "Disk mounted over a folder in use".to_string(),
        body: format!(
            "{source} is mounted over {root}, a folder in use. Files saved there now go to \
             {source}. To undo it, run: sudo umount {umount}"
        ),
        urgency: "critical".to_string(),
        icon: Some("drive-removable-media".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// The neutral desktop alert of a watcher that could not read its settings:
/// it still warns, but takes no action on its own.
fn alert_only_notice() -> Notification {
    Notification {
        title: "Storage monitor in alert-only mode".to_string(),
        body: "The storage monitor could not read its settings. It still warns you when a \
               mounted volume stops responding, but takes no action on its own."
            .to_string(),
        urgency: "critical".to_string(),
        icon: Some("drive-harddisk".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// The neutral desktop alert of a watcher that could not read the session
/// plan a return needs, where the settings ask for the automatic emergency:
/// a failure that outlasts the debounce powers the machine off.
fn power_off_notice() -> Notification {
    Notification {
        title: "Storage monitor in power-off mode".to_string(),
        body: "The storage monitor could not read everything it needs. If a mounted volume \
               stops responding and does not recover, it turns the computer off."
            .to_string(),
        urgency: "critical".to_string(),
        icon: Some("drive-harddisk".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// The neutral desktop alert of a watcher that could read neither what to
/// watch nor its settings: nothing is watched.
fn unwatched_notice() -> Notification {
    Notification {
        title: "Storage monitor not running".to_string(),
        body: "The storage monitor could not read what to watch, nor its settings, so mounted \
               volumes are not watched."
            .to_string(),
        urgency: "critical".to_string(),
        icon: Some("drive-harddisk".to_string()),
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
#[path = "watch_tests.rs"]
mod tests;
