// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::notification::write_notification;
use std::cell::RefCell;
use std::collections::VecDeque;

fn notification(title: &str) -> Notification {
    Notification {
        title: title.to_string(),
        body: format!("{title} body"),
        urgency: "critical".to_string(),
        icon: Some("dialog-error".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

fn operator() -> SessionUser {
    SessionUser {
        uid: 1000,
        name: "operator".to_string(),
    }
}

/// A notifier whose bus availability and per-send results are scripted, and
/// which records what it sent.
struct ScriptedNotifier {
    bus: bool,
    results: RefCell<VecDeque<Result<()>>>,
    sent: RefCell<Vec<String>>,
}

impl ScriptedNotifier {
    fn new(bus: bool, results: Vec<Result<()>>) -> Self {
        Self {
            bus,
            results: RefCell::new(results.into()),
            sent: RefCell::new(Vec::new()),
        }
    }
}

impl SessionNotifier for ScriptedNotifier {
    fn session_bus_available(&self, _user: &SessionUser) -> bool {
        self.bus
    }

    fn send(&self, _user: &SessionUser, notification: &Notification) -> Result<()> {
        self.sent.borrow_mut().push(notification.title.clone());
        self.results.borrow_mut().pop_front().unwrap_or(Ok(()))
    }
}

fn queued_titles(root: &Path) -> Vec<String> {
    read_pending(root)
        .unwrap()
        .into_iter()
        .map(|(_, n)| n.title)
        .collect()
}

#[test]
fn push_delivers_the_queue_into_the_session_and_marks_it_delivered() {
    let root = tempfile::tempdir().unwrap();
    write_notification(root.path(), &notification("NAILS Overlay Active")).unwrap();
    write_notification(root.path(), &notification("NixOS Rebuild Failed")).unwrap();
    let notifier = ScriptedNotifier::new(true, vec![]);

    let outcome = push_pending(root.path(), Some(&operator()), &notifier).unwrap();

    assert_eq!(outcome, PushOutcome::Delivered(2));
    assert_eq!(
        *notifier.sent.borrow(),
        vec!["NAILS Overlay Active", "NixOS Rebuild Failed"]
    );
    assert!(
        queued_titles(root.path()).is_empty(),
        "delivered = dequeued"
    );
}

#[test]
fn without_a_session_bus_the_queue_is_left_for_the_login_dispatcher() {
    let root = tempfile::tempdir().unwrap();
    write_notification(root.path(), &notification("NixOS Rebuild Failed")).unwrap();
    let notifier = ScriptedNotifier::new(false, vec![]);

    let outcome = push_pending(root.path(), Some(&operator()), &notifier).unwrap();

    assert_eq!(outcome, PushOutcome::NoSession);
    assert!(notifier.sent.borrow().is_empty());
    assert_eq!(queued_titles(root.path()), vec!["NixOS Rebuild Failed"]);
}

#[test]
fn without_an_operator_nothing_is_pushed() {
    let root = tempfile::tempdir().unwrap();
    write_notification(root.path(), &notification("NAILS Overlay Active")).unwrap();
    let notifier = ScriptedNotifier::new(true, vec![]);

    assert_eq!(
        push_pending(root.path(), None, &notifier).unwrap(),
        PushOutcome::NoSession
    );
    assert_eq!(queued_titles(root.path()).len(), 1);
}

#[test]
fn a_failed_send_keeps_it_and_the_rest_queued() {
    let root = tempfile::tempdir().unwrap();
    write_notification(root.path(), &notification("A first")).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    write_notification(root.path(), &notification("B second")).unwrap();
    std::thread::sleep(Duration::from_millis(2));
    write_notification(root.path(), &notification("C third")).unwrap();
    let notifier = ScriptedNotifier::new(
        true,
        vec![
            Ok(()),
            Err(crate::NailsError::io(
                "/run/user/1000/bus",
                std::io::Error::other("bus gone"),
            )),
        ],
    );

    let outcome = push_pending(root.path(), Some(&operator()), &notifier).unwrap();

    assert!(
        matches!(outcome, PushOutcome::Failed { delivered: 1, ref error } if error.contains("bus gone")),
        "{outcome:?}"
    );
    assert_eq!(queued_titles(root.path()), vec!["B second", "C third"]);
}

#[test]
fn the_in_progress_marker_lives_exactly_as_long_as_its_guard() {
    let root = tempfile::tempdir().unwrap();
    assert!(!result_pending(root.path(), SystemTime::now()));
    {
        let _marker = ResultPendingMarker::arm(root.path());
        assert!(result_pending(root.path(), SystemTime::now()));
    }
    assert!(!result_pending(root.path(), SystemTime::now()));
}

#[test]
fn a_stale_in_progress_marker_is_ignored_after_the_cap() {
    let root = tempfile::tempdir().unwrap();
    let marker = ResultPendingMarker::arm(root.path());
    let later = SystemTime::now() + DISPATCH_POLL_CAP + Duration::from_secs(1);
    assert!(
        !result_pending(root.path(), later),
        "a marker left by a crashed activation must not hold every login for 15 minutes"
    );
    drop(marker);
}

#[test]
fn a_missing_notify_send_is_recorded_once_and_cleared_on_delivery() {
    let root = tempfile::tempdir().unwrap();
    assert!(!notify_send_missing(root.path()));

    assert!(
        record_notify_send_missing(root.path()).unwrap(),
        "first record"
    );
    assert!(
        !record_notify_send_missing(root.path()).unwrap(),
        "only once"
    );
    assert!(notify_send_missing(root.path()));

    clear_notify_send_missing(root.path());
    assert!(!notify_send_missing(root.path()));
}

#[test]
fn markers_are_not_mistaken_for_queued_notifications() {
    let root = tempfile::tempdir().unwrap();
    let _marker = ResultPendingMarker::arm(root.path());
    record_notify_send_missing(root.path()).unwrap();
    assert!(read_pending(root.path()).unwrap().is_empty());
}

#[test]
fn the_session_commands_use_the_users_manager_then_runuser() {
    let args =
        RealSessionNotifier::notify_send_args(Path::new("/bin/notify-send"), &notification("T"));
    let systemd_run = RealSessionNotifier::systemd_run_command(&operator(), &args);
    let rendered = format!("{systemd_run:?}");
    assert!(rendered.contains("--machine=operator@.host"), "{rendered}");
    assert!(rendered.contains("--user"), "{rendered}");
    assert!(
        rendered.contains("--description=notification"),
        "{rendered}"
    );
    assert!(rendered.contains("/bin/notify-send"), "{rendered}");

    let runuser = format!(
        "{:?}",
        RealSessionNotifier::runuser_command(&operator(), &args)
    );
    assert!(runuser.contains("operator"), "{runuser}");
    assert!(
        runuser.contains("unix:path=/run/user/1000/bus"),
        "{runuser}"
    );
}

/// A dispatch environment driven by a script: how many notifications each
/// dispatch finds, whether the activation is in progress at each check, and a
/// clock that advances only when the loop sleeps.
struct FakeEnv {
    dispatches: VecDeque<Result<usize>>,
    in_progress: VecDeque<bool>,
    elapsed: Duration,
    sleeps: usize,
}

impl FakeEnv {
    fn new(dispatches: Vec<Result<usize>>, in_progress: Vec<bool>) -> Self {
        Self {
            dispatches: dispatches.into(),
            in_progress: in_progress.into(),
            elapsed: Duration::ZERO,
            sleeps: 0,
        }
    }
}

impl DispatchEnv for FakeEnv {
    fn dispatch(&mut self) -> Result<usize> {
        self.dispatches.pop_front().unwrap_or(Ok(0))
    }
    fn activation_in_progress(&mut self) -> bool {
        self.in_progress.pop_front().unwrap_or(false)
    }
    fn elapsed(&self) -> Duration {
        self.elapsed
    }
    fn sleep(&mut self, duration: Duration) {
        self.elapsed += duration;
        self.sleeps += 1;
    }
}

#[test]
fn with_no_activation_in_progress_one_sweep_is_enough() {
    let mut env = FakeEnv::new(vec![Ok(2)], vec![false]);
    let total =
        dispatch_until_settled(&mut env, DISPATCH_POLL_INTERVAL, DISPATCH_POLL_CAP).unwrap();
    assert_eq!(total, 2);
    assert_eq!(env.sleeps, 0);
}

#[test]
fn polls_until_the_activation_settles_then_collects_its_last_results() {
    // In progress for three checks; the rebuild result arrives in the final
    // sweep after the activation settled.
    let mut env = FakeEnv::new(
        vec![Ok(1), Ok(0), Ok(0), Ok(0), Ok(1)],
        vec![true, true, true, false],
    );
    let total =
        dispatch_until_settled(&mut env, DISPATCH_POLL_INTERVAL, DISPATCH_POLL_CAP).unwrap();
    assert_eq!(
        total, 2,
        "initial overlay notice plus the late rebuild result"
    );
    assert_eq!(env.sleeps, 3);
}

#[test]
fn polling_stops_at_the_cap_even_if_the_activation_never_settles() {
    let mut env = FakeEnv::new(vec![], vec![true; 10_000]);
    dispatch_until_settled(&mut env, DISPATCH_POLL_INTERVAL, DISPATCH_POLL_CAP).unwrap();
    assert_eq!(
        env.elapsed, DISPATCH_POLL_CAP,
        "stops once fifteen minutes have passed"
    );
    assert_eq!(env.sleeps, 180);
}

#[test]
fn a_dispatch_error_is_returned_only_when_nothing_was_delivered() {
    let err = || {
        Err(crate::NailsError::io(
            "/mnt/hidden/notifications",
            std::io::Error::other("unreadable"),
        ))
    };
    let mut env = FakeEnv::new(vec![err()], vec![true]);
    assert!(dispatch_until_settled(&mut env, DISPATCH_POLL_INTERVAL, DISPATCH_POLL_CAP).is_err());

    let mut env = FakeEnv::new(vec![Ok(1), err()], vec![true, true]);
    assert_eq!(
        dispatch_until_settled(&mut env, DISPATCH_POLL_INTERVAL, DISPATCH_POLL_CAP).unwrap(),
        1
    );
}
