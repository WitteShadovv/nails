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
//! alert-only, or not at all, and tells the operator so once.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use nails_core::config::{CONFIG_DIR_NAME, CONFIG_FILE_NAME, Config};
use nails_core::notification::{Notification, send_immediate};
use nails_core::runtime_copy::RuntimeManifest;
use nails_core::{RealFilesystem, runtime_copy, watcher};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::disk_guard;

use crate::cli::output::{ExitStatus, OutputSettings};

/// What the watcher starts with, each from the first copy it can read.
#[derive(Debug)]
enum Start {
    /// There is no session plan: no session to watch.
    Nothing,
    /// Watch `manifest`'s hidden root by `config`. `notice`, when the
    /// settings could not be read anywhere, is the alert to deliver once:
    /// `config` is then alert-only.
    Watch {
        manifest: RuntimeManifest,
        config: Box<Config>,
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
/// once: it never runs the emergency itself then. Where neither the plan nor
/// the settings can be read, it says the session runs without it. A plan that
/// is not there is no session.
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
            notice: None,
        },
        (None, Some(config)) => Start::Watch {
            manifest: RuntimeManifest {
                hidden_root: config.hidden_volume_root.clone(),
                hidden_dev: None,
                overlay_targets: Vec::new(),
            },
            config: Box::new(config),
            notice: None,
        },
        (Some(manifest), None) => Start::Watch {
            manifest,
            config: Box::new(alert_only()),
            notice: Some(alert_only_notice()),
        },
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
    let (manifest, config, notice) = match start(
        runtime_copy::read_manifest(&filesystem),
        runtime_copy::read_config_copy(&filesystem),
        || found_file(config_override),
        Config::load,
    ) {
        Start::Nothing => {
            tracing::debug!("No runtime manifest present; nothing to watch");
            return ExitStatus::Ok;
        }
        Start::Without(alert) => {
            tracing::warn!("Neither the session plan nor the settings can be read; not watching");
            deliver_then_exit(&Once::new(alert), env);
            return ExitStatus::Ok;
        }
        Start::Watch {
            manifest,
            config,
            notice,
        } => (manifest, *config, notice.map(Once::new)),
    };
    if notice.is_some() {
        tracing::warn!("Watching alert-only: the settings cannot be read");
    }

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

/// Try to deliver `notice` at each round of the default poll interval until
/// one delivery succeeds, then return.
fn deliver_then_exit(notice: &Once, env: &nails_core::RuntimeEnv) {
    let interval = nails_core::config::BackendWatchConfig::default().poll_interval();
    while !notice.delivered() {
        let env = env.clone();
        notice.try_deliver(move |alert| send_immediate(alert, &env));
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
mod tests {
    use super::*;
    use std::path::PathBuf;

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

    fn manifest(root: &str) -> RuntimeManifest {
        RuntimeManifest {
            hidden_root: PathBuf::from(root),
            hidden_dev: Some("253:0".to_string()),
            overlay_targets: Vec::new(),
        }
    }

    fn settings(root: &str, auto_emergency: bool) -> Config {
        let mut config = Config::test_default();
        config.hidden_volume_root = PathBuf::from(root);
        config.backend_watch.auto_emergency = auto_emergency;
        config
    }

    fn unreadable(path: &str) -> nails_core::NailsError {
        nails_core::NailsError::io(path, std::io::Error::from_raw_os_error(nix::libc::EIO))
    }

    /// Whether a watcher by `config` would ever run the emergency itself, for
    /// a failure that lasts far past the debounce window.
    fn ever_tears_down(config: &Config) -> bool {
        let mut watch = watcher::BackendWatch::new(&config.backend_watch);
        let start = std::time::Instant::now();
        (0..100u64).any(|second| {
            watch.observe(false, start + std::time::Duration::from_secs(second))
                == watcher::WatchAction::Emergency
        })
    }

    #[test]
    fn the_copies_in_run_decide_and_no_other_is_read() {
        let started = start(
            Ok(Some(manifest("/mnt/data"))),
            Ok(Some(settings("/mnt/data", true))),
            || panic!("no file read beside a copy"),
            |_| panic!("no volume read beside a copy"),
        );
        let Start::Watch {
            manifest,
            config,
            notice,
        } = started
        else {
            panic!("{started:?}");
        };
        assert_eq!(manifest.hidden_root, Path::new("/mnt/data"));
        assert!(config.backend_watch.auto_emergency);
        assert!(notice.is_none());
        assert!(matches!(
            start(Ok(None), Ok(None), || None, |_| panic!("no session")),
            Start::Nothing
        ));
    }

    /// A settings copy that cannot be read gives way to the hidden volume's
    /// own configuration at the root the plan names: the emergency the
    /// operator opted into stays armed.
    #[test]
    fn an_unreadable_settings_copy_gives_way_to_the_hidden_volumes_own() {
        let mut asked = None;
        let started = start(
            Ok(Some(manifest("/mnt/data"))),
            Err(unreadable("/run/overlay-runtime/settings.toml")),
            || None,
            |path| {
                asked = Some(path.to_path_buf());
                Ok(settings("/mnt/data", true))
            },
        );
        assert_eq!(
            asked.as_deref(),
            Some(Path::new("/mnt/data/config/nails.toml"))
        );
        let Start::Watch { config, notice, .. } = started else {
            panic!("{started:?}");
        };
        assert!(config.backend_watch.auto_emergency);
        assert!(notice.is_none());
        assert!(ever_tears_down(&config));
    }

    /// Where no copy of the settings can be read the watcher watches
    /// alert-only, says so once, and never tears the session down unasked.
    #[test]
    fn without_any_settings_it_watches_alert_only_and_says_so() {
        for copy in [
            Err(unreadable("/run/overlay-runtime/settings.toml")),
            Ok(None),
        ] {
            let started = start(
                Ok(Some(manifest("/mnt/data"))),
                copy,
                || None,
                |path| Err(unreadable(&path.display().to_string())),
            );
            let Start::Watch {
                manifest,
                config,
                notice,
            } = started
            else {
                panic!("{started:?}");
            };
            assert_eq!(manifest.hidden_root, Path::new("/mnt/data"));
            assert!(config.backend_watch.enabled && config.session_mounts.alert);
            assert!(!config.backend_watch.auto_emergency);
            assert!(!ever_tears_down(&config));
            let notice = notice.expect("an alert");
            assert_eq!(notice.title, "Storage monitor in alert-only mode");
            assert_neutral(&notice);
        }
    }

    /// A session plan that cannot be read gives way to the hidden root the
    /// settings name; with neither, the watcher says the session runs
    /// without it, and reads no volume.
    #[test]
    fn an_unreadable_plan_gives_way_to_the_settings_hidden_root() {
        let started = start(
            Err(unreadable("/run/overlay-runtime/plan.json")),
            Ok(Some(settings("/mnt/vault", true))),
            || None,
            |_| panic!("the copy names the root"),
        );
        let Start::Watch {
            manifest, notice, ..
        } = started
        else {
            panic!("{started:?}");
        };
        assert_eq!(manifest.hidden_root, Path::new("/mnt/vault"));
        assert_eq!(manifest.hidden_dev, None);
        assert!(notice.is_none());

        let started = start(
            Err(unreadable("/run/overlay-runtime/plan.json")),
            Err(unreadable("/run/overlay-runtime/settings.toml")),
            || None,
            |_| panic!("no root to read a volume at"),
        );
        let Start::Without(notice) = started else {
            panic!("{started:?}");
        };
        assert_eq!(notice.title, "Storage monitor not running");
        assert_neutral(&notice);
    }

    /// The one alert is tried at each round until a delivery succeeds, and
    /// never again after that.
    #[test]
    fn the_one_alert_is_tried_until_it_is_delivered_once() {
        let once = Once::new(alert_only_notice());
        let tries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wait = std::time::Duration::from_secs(10);
        for attempt in 0..3 {
            let (done, finished) = std::sync::mpsc::channel();
            let counted = Arc::clone(&tries);
            once.try_deliver(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = done.send(());
                if attempt < 2 {
                    Err(nails_core::NailsError::InvalidState(
                        "no desktop yet".into(),
                    ))
                } else {
                    Ok(())
                }
            });
            finished.recv_timeout(wait).expect("the try ran");
            let deadline = std::time::Instant::now() + wait;
            while once.state.load(Ordering::Acquire) == SENDING {
                assert!(std::time::Instant::now() < deadline, "the try never ended");
                std::thread::yield_now();
            }
        }
        assert!(once.delivered());
        once.try_deliver(|_| panic!("delivered once already"));
        assert_eq!(tries.load(Ordering::SeqCst), 3);
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
