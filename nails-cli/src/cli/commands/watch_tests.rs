// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the session watcher's start, alerts and rounds.

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
/// settings name, watched alert-only: an automatic emergency without the
/// plan cannot return, so none is armed, and where the settings ask for
/// one an alert says so once. With neither, the watcher says the session
/// runs without it, and reads no volume.
#[test]
fn an_unreadable_plan_gives_way_to_the_settings_hidden_root() {
    let started = start(
        Err(unreadable("/run/overlay-runtime/plan.json")),
        Ok(Some(settings("/mnt/vault", true))),
        || None,
        |_| panic!("the copy names the root"),
    );
    let Start::Watch {
        manifest,
        config,
        notice,
    } = started
    else {
        panic!("{started:?}");
    };
    assert_eq!(manifest.hidden_root, Path::new("/mnt/vault"));
    assert_eq!(manifest.hidden_dev, None);
    assert!(config.backend_watch.enabled && config.session_mounts.alert);
    assert!(!config.backend_watch.auto_emergency);
    assert!(!ever_tears_down(&config));
    let notice = notice.expect("an alert");
    assert_eq!(notice.title, "Storage monitor in alert-only mode");
    assert_eq!(
        notice.body,
        "The storage monitor could not read what it needs to take action. It still warns \
         you when a mounted volume stops responding, but takes no action on its own."
    );
    assert_neutral(&notice);

    // Settings that ask for no automatic emergency lose nothing: no alert.
    let started = start(
        Err(unreadable("/run/overlay-runtime/plan.json")),
        Ok(Some(settings("/mnt/vault", false))),
        || None,
        |_| panic!("the copy names the root"),
    );
    let Start::Watch { notice, .. } = started else {
        panic!("{started:?}");
    };
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

/// A watcher that cannot run delivers its one alert, then watches
/// nothing; one that watches alert-only keeps its alert for the rounds.
#[test]
fn a_watcher_that_cannot_watch_delivers_its_alert_and_stops() {
    let mut delivered = None;
    let watched = watching(Start::Without(unwatched_notice()), |notice| {
        delivered = Some(notice.alert.title.clone());
    });
    assert!(watched.is_none());
    assert_eq!(delivered.as_deref(), Some("Storage monitor not running"));

    assert!(watching(Start::Nothing, |_| panic!("no alert")).is_none());

    let watched = watching(
        Start::Watch {
            manifest: manifest("/mnt/data"),
            config: Box::new(alert_only()),
            notice: Some(alert_only_notice()),
        },
        |_| panic!("delivered while it watches"),
    );
    let (manifest, config, notice) = watched.expect("it watches");
    assert_eq!(manifest.hidden_root, Path::new("/mnt/data"));
    assert!(!config.backend_watch.auto_emergency);
    assert_eq!(
        notice.map(|notice| notice.alert.title).as_deref(),
        Some("Storage monitor in alert-only mode")
    );
}

/// A configuration file is taken only where one was found: here the one
/// `--config` names. One that cannot be read gives none.
#[test]
fn only_a_configuration_file_that_was_found_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("nails.toml");
    std::fs::write(&file, "hidden_volume_root = \"/mnt/vault\"\n").unwrap();
    let found = found_file(Some(&file)).expect("the file it names");
    assert_eq!(found.hidden_volume_root, Path::new("/mnt/vault"));
    assert!(found_file(Some(&dir.path().join("missing.toml"))).is_none());
}

/// The alert of a watcher that cannot run is tried until one delivery
/// succeeds, and then no more.
#[test]
fn the_alert_of_a_watcher_that_cannot_run_is_tried_until_delivered() {
    let tries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&tries);
    let notice = Once::new(unwatched_notice());
    deliver_until_delivered(&notice, std::time::Duration::from_millis(1), move |_| {
        if counted.fetch_add(1, Ordering::SeqCst) < 2 {
            Err(nails_core::NailsError::InvalidState(
                "no desktop yet".into(),
            ))
        } else {
            Ok(())
        }
    });
    assert!(notice.delivered());
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
