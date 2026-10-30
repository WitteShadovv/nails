// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The emergency while the helper is busy with a long request.
//!
//! The helper serves one request at a time, and a verify or a rehearsal's
//! scan can keep it busy for minutes: an emergency fired meanwhile reaches
//! its pipe at once, but the helper reads it only once that request is
//! answered. The window does not wait for that: once its grace has passed
//! (the real one, [`HELPER_GRACE`]), it asks for the power-off of its own,
//! here through a stand-in for `systemctl` (no test reaches a real power
//! action). Each test holds the helper on a verify or a scan for longer than
//! that and shows the power-off asked for while the helper is still busy,
//! and the engine's emergency read only after it. Run with `--no-capture`,
//! each prints how long each step took.

mod screen;
mod support;
mod wired;

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use i_slint_backend_testing::AccessibleRole;
use nails_api::protocol::{EmergencyArgs, Op, Request};
use nails_gui::emergency::{EMERGENCY_ID, Emergency, HELPER_GRACE, Outcome};
use nails_gui::model::Model;
use nails_gui::text;
use nails_gui::worker::{Connect, Kind, Update, Worker, spawn};
use screen::Screen;
use serde_json::{Value, json};
use support::{FakeHelper, FakePowerOff, fixture, hello_answer, result};
use wired::{PATIENCE, hold};

/// How long the helper stays on the long request: well past the grace, and
/// well short of the pipe's read timeout.
const LONG: Duration = Duration::from_secs(8);

/// When the helper read each request, after it started.
type Seen = Receiver<(Request, Instant)>;

/// A hidden session's helper that answers the status, a rehearsal's status
/// and the emergency at once, and `long` only after [`LONG`].
fn busy_helper(
    long: fn(&Op) -> bool,
    answer: Value,
) -> (std::os::unix::net::UnixStream, FakeHelper, Seen) {
    let (seen, requests) = channel();
    let (stream, helper) = FakeHelper::start(nails_gui::client::ours(), move |request| {
        let _ = seen.send((request.clone(), Instant::now()));
        let id = request.id;
        Some(match &request.op {
            Op::Hello(hello) => vec![hello_answer(id, hello)],
            Op::Status => vec![result(
                id,
                0,
                json!({"schema_version": 2, "command": "status", "ok": true, "data": {
                    "place": "hidden", "attention": null, "hidden_root": "/mnt/data"}}),
            )],
            Op::RehearseStatus => vec![result(id, 0, fixture("rehearse-status-planted"))],
            Op::Emergency(_) => vec![result(
                EMERGENCY_ID,
                0,
                json!({"schema_version": 2, "command": "emergency", "ok": true, "data": {}}),
            )],
            op if long(op) => {
                std::thread::sleep(LONG);
                vec![result(id, 9, answer.clone())]
            }
            op => panic!("no answer for {op:?}"),
        })
    });
    (stream, helper, requests)
}

/// The window, its worker, and when the emergency's thread reported each
/// step.
struct Window {
    screen: Screen,
    worker: Worker,
    heard: Receiver<Update>,
    outcomes: Receiver<(Outcome, Instant)>,
}

impl Window {
    fn new(connect: Connect, power_off: &FakePowerOff) -> Self {
        let (tell, outcomes) = channel();
        let emergency = Emergency::start(power_off.fallback(HELPER_GRACE), move |outcome| {
            let _ = tell.send((outcome, Instant::now()));
        });
        let (tell, heard) = channel();
        let worker = spawn(connect, Some(emergency.clone()), move |update| {
            let _ = tell.send(update);
        });
        let model =
            Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
        let screen = Screen::with_emergency(
            model,
            Box::new(move || {
                emergency.fire();
            }),
        );
        screen.tall();
        Self {
            screen,
            worker,
            heard,
            outcomes,
        }
    }

    /// Hand over asks and updates until one `last` holds for.
    fn pump_until(&self, last: impl Fn(&Update) -> bool) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            for ask in self.screen.asks() {
                assert!(self.worker.ask(ask), "the worker listens");
            }
            let left = deadline.saturating_duration_since(Instant::now());
            let update = self.heard.recv_timeout(left).expect("the worker reports");
            let done = last(&update);
            self.screen.update(update);
            if done {
                for ask in self.screen.asks() {
                    assert!(self.worker.ask(ask), "the worker listens");
                }
                return;
            }
        }
    }

    fn press(&self, label: &str) {
        self.screen
            .find_with(label, AccessibleRole::Button)
            .invoke_accessible_default_action();
    }

    fn outcome(&self) -> (Outcome, Instant) {
        self.outcomes
            .recv_timeout(PATIENCE)
            .expect("the emergency reports")
    }
}

/// The next request the helper read that is not a hello, and when.
fn next(seen: &Seen) -> (Op, Instant) {
    loop {
        let (request, at) = seen.recv_timeout(PATIENCE).expect("the helper reads");
        if !matches!(request.op, Op::Hello(_)) {
            return (request.op, at);
        }
    }
}

/// Fire the emergency while the helper is on the long request the window
/// sent last, and show the power-off asked for within the grace, before the
/// helper read the emergency, and the emergency read once the long request
/// was answered.
fn fire_while_busy(window: &Window, seen: &Seen, what: &str) {
    let (op, busy_since) = next(seen);
    assert!(
        !matches!(op, Op::Emergency(_)),
        "the long request reached the helper first: {op:?}"
    );
    let fired = Instant::now();
    hold(&window.screen);
    assert!(window.screen.shows(text::EMERGENCY_NOW));
    let (outcome, written) = window.outcome();
    assert_eq!(outcome, Outcome::HelperAsked, "the request is on the pipe");
    let (outcome, powered_off) = window.outcome();
    assert_eq!(outcome, Outcome::PowerOffAsked);
    let (op, read) = next(seen);
    assert_eq!(
        op,
        Op::Emergency(EmergencyArgs {
            poweroff: true,
            reboot: false
        })
    );
    let to_written = written.duration_since(fired);
    let to_power_off = powered_off.duration_since(fired);
    let to_read = read.duration_since(fired);
    eprintln!(
        "emergency during a long {what}: on the helper's pipe after {to_written:?}, \
         the power-off of the window's own asked for after {to_power_off:?}, the helper read \
         the emergency after {to_read:?} (it was busy for {:?} before the emergency)",
        fired.duration_since(busy_since)
    );
    // The power-off came within the grace and a little: it waited for the
    // helper no longer than that, whatever the helper was busy with.
    assert!(to_power_off >= HELPER_GRACE, "{to_power_off:?}");
    assert!(
        to_power_off < HELPER_GRACE + Duration::from_secs(2),
        "{to_power_off:?}"
    );
    // And before the helper so much as read the emergency: it was still on
    // the long request.
    assert!(powered_off < read, "{to_power_off:?} against {to_read:?}");
    assert!(
        read.duration_since(busy_since) >= LONG,
        "the helper read the emergency only once the long request was answered"
    );
}

#[test]
fn an_emergency_during_a_long_scan_powers_off_without_waiting_for_it() {
    let (stream, _helper, seen) = busy_helper(
        |op| matches!(op, Op::RehearseScan(_)),
        fixture("rehearse-scan-blind"),
    );
    let power_off = FakePowerOff::new("exit 0");
    let window = Window::new(Connect::Stream(stream), &power_off);
    window.pump_until(|update| matches!(update, Update::Answered(Kind::Status, _)));
    window.press(text::REHEARSAL);
    window.pump_until(|update| matches!(update, Update::Answered(Kind::Rehearse, _)));
    window.press(text::SCAN);
    window.pump_until(|update| *update == Update::Running(Kind::Rehearse));
    assert_eq!(next(&seen).0, Op::Status);
    assert_eq!(next(&seen).0, Op::RehearseStatus);
    fire_while_busy(&window, &seen, "scan");
    assert_eq!(power_off.calls(), ["poweroff --no-ask-password"]);
}

#[test]
fn an_emergency_during_a_long_verify_powers_off_without_waiting_for_it() {
    let (stream, _helper, seen) =
        busy_helper(|op| matches!(op, Op::Verify(_)), fixture("verify-clean"));
    let power_off = FakePowerOff::new("exit 0");
    let window = Window::new(Connect::Stream(stream), &power_off);
    window.pump_until(|update| matches!(update, Update::Answered(Kind::Status, _)));
    window.press(text::VERIFY);
    window.press(text::DEEP_SCAN);
    window.pump_until(|update| *update == Update::Running(Kind::Verify));
    assert_eq!(next(&seen).0, Op::Status);
    fire_while_busy(&window, &seen, "deep verify");
    assert_eq!(power_off.calls(), ["poweroff --no-ask-password"]);
}
