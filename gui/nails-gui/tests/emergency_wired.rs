// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The emergency end to end, without a display: the window on Slint's
//! headless platform, the real worker and the real emergency line against a
//! fake helper, and a stand-in for `systemctl`. Each test makes one of the
//! things that could hold the emergency up and shows that it does not: a
//! worker stuck on a request the helper never answers, an open question
//! whose plan waits, a flood of updates the window has not drawn, and a
//! window with no helper at all.

mod screen;
mod support;

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use i_slint_backend_testing::{AccessibleRole, ElementHandle};
use nails_api::Event;
use nails_api::protocol::{EmergencyArgs, Frame, Op, Request};
use nails_gui::client::ours;
use nails_gui::emergency::{EMERGENCY_ID, Emergency, Outcome};
use nails_gui::mailbox::Mailbox;
use nails_gui::model::Model;
use nails_gui::text;
use nails_gui::worker::{Ask, Connect, Kind, Update, Worker, spawn};
use screen::Screen;
use serde_json::json;
use support::{FakeHelper, FakePowerOff, event, hello_answer, result};

/// How long a test waits for the worker, the helper or the emergency.
const PATIENCE: Duration = Duration::from_secs(20);

/// How long the emergency waits for the helper here.
const GRACE: Duration = Duration::from_millis(500);

/// The emergency's own request, as the helper reads it.
fn emergency_op() -> Op {
    Op::Emergency(EmergencyArgs {
        poweroff: true,
        reboot: false,
    })
}

/// A fake helper that answers the hello and passes every other request to
/// `respond`, telling `seen` of each one.
fn helper<F>(seen: Sender<Request>, mut respond: F) -> (std::os::unix::net::UnixStream, FakeHelper)
where
    F: FnMut(&Request) -> Vec<Frame> + Send + 'static,
{
    FakeHelper::start(ours(), move |request| {
        let _ = seen.send(request.clone());
        Some(match &request.op {
            Op::Hello(hello) => vec![hello_answer(request.id, hello)],
            _ => respond(request),
        })
    })
}

/// The window, its worker and its emergency, wired as `main` wires them,
/// but for the updates, which the test hands over itself.
struct Wired {
    screen: Screen,
    worker: Worker,
    heard: Receiver<Update>,
    outcomes: Receiver<Outcome>,
}

impl Wired {
    fn new(connect: Connect, power_off: &FakePowerOff) -> Self {
        let (tell, outcomes) = channel();
        let emergency = Emergency::start(power_off.fallback(GRACE), move |outcome| {
            let _ = tell.send(outcome);
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
        Self {
            screen,
            worker,
            heard,
            outcomes,
        }
    }

    /// Hand the worker the window's asks and the window the worker's
    /// updates, until one for which `last` holds was handed over.
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

    fn outcome(&self) -> Outcome {
        self.outcomes
            .recv_timeout(PATIENCE)
            .expect("the emergency reports")
    }
}

/// The Emergency control at rest.
fn control(screen: &Screen) -> ElementHandle {
    screen.find_with(text::EMERGENCY, AccessibleRole::Button)
}

/// The person's gesture: hold the control until its bar is full, let go.
fn hold(screen: &Screen) {
    let at = screen.middle(&control(screen));
    screen.press_at(at);
    screen.wait_ms(1100);
    screen.release_at(at);
    assert_eq!(screen.emergencies(), 1, "the emergency fired");
}

/// The next request the helper read that is not a hello.
fn next_request(seen: &Receiver<Request>) -> Request {
    loop {
        let request = seen.recv_timeout(PATIENCE).expect("the helper reads");
        if !matches!(request.op, Op::Hello(_)) {
            return request;
        }
    }
}

#[test]
fn a_worker_stuck_on_a_request_does_not_hold_the_emergency_up() {
    let (seen, requests) = channel();
    // The status is never answered: the worker waits on it for good.
    let (stream, _helper) = helper(seen, |request| match &request.op {
        Op::Emergency(_) => vec![result(EMERGENCY_ID, 0, json!({"command": "emergency"}))],
        _ => vec![],
    });
    let power_off = FakePowerOff::new("exit 0");
    let wired = Wired::new(Connect::Stream(stream), &power_off);
    wired.pump_until(|update| *update == Update::Running(Kind::Status));
    assert_eq!(next_request(&requests).op, Op::Status);

    hold(&wired.screen);
    assert!(wired.screen.shows(text::EMERGENCY_NOW));
    let request = next_request(&requests);
    assert_eq!((request.id, request.op), (EMERGENCY_ID, emergency_op()));
    assert_eq!(wired.outcome(), Outcome::HelperAsked);
    // Still here after the grace, as no engine's emergency ended this test:
    // the power-off of the window's own follows.
    assert_eq!(wired.outcome(), Outcome::PowerOffAsked);
    assert_eq!(power_off.calls(), ["poweroff --no-ask-password"]);
}

#[test]
fn an_open_question_does_not_hold_the_emergency_up_nor_answer_itself() {
    let (seen, requests) = channel();
    let (stream, _helper) = helper(seen, |request| match &request.op {
        Op::Status => vec![result(
            request.id,
            0,
            json!({"schema_version": 2, "command": "status", "ok": true, "data": {
                "place": "hidden", "attention": null, "hidden_root": "/mnt/data"}}),
        )],
        Op::DeactivatePlan(_) => vec![result(
            request.id,
            0,
            json!({"schema_version": 2, "command": "deactivate", "ok": true, "data": {
                "poweroff": false, "warnings": [], "token": "0".repeat(32)}}),
        )],
        _ => vec![],
    });
    let power_off = FakePowerOff::new("exit 0");
    let wired = Wired::new(Connect::Stream(stream), &power_off);
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Status, _)));
    wired
        .screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    assert!(wired.screen.window.get_question_open());

    hold(&wired.screen);
    assert!(!wired.screen.window.get_question_open());
    let ops: Vec<Op> = (0..3).map(|_| next_request(&requests).op).collect();
    assert_eq!(
        ops,
        [
            Op::Status,
            Op::DeactivatePlan(nails_api::protocol::DeactivateArgs { poweroff: false }),
            emergency_op()
        ],
        "the plan was neither applied nor withdrawn first"
    );
    assert_eq!(wired.outcome(), Outcome::HelperAsked);
}

#[test]
fn a_flood_of_updates_the_window_has_not_drawn_does_not_hold_it_up() {
    let (seen, requests) = channel();
    const FLOOD: u64 = 20_000;
    let (stream, _helper) = helper(seen, |request| match &request.op {
        Op::Status => (0..FLOOD)
            .map(|second| {
                event(
                    request.id,
                    Event::Heartbeat {
                        phase: "status".to_string(),
                        elapsed_seconds: second,
                    },
                )
            })
            .chain([result(request.id, 0, json!({"command": "status"}))])
            .collect(),
        _ => vec![],
    });
    let power_off = FakePowerOff::new("exit 0");
    let (tell, _outcomes) = channel();
    let emergency = Emergency::start(power_off.fallback(GRACE), move |outcome| {
        let _ = tell.send(outcome);
    });
    // The event loop is busy for good: no turn ever takes the updates.
    let mailbox = Mailbox::new(|_| {});
    let inbox = mailbox.clone();
    let worker = spawn(
        Connect::Stream(stream),
        Some(emergency.clone()),
        move |update| inbox.put(update),
    );
    assert!(worker.ask(Ask::Status));
    let deadline = Instant::now() + PATIENCE;
    while mailbox.waiting() < FLOOD as usize {
        assert!(Instant::now() < deadline, "the flood came in");
        std::thread::sleep(Duration::from_millis(10));
    }
    let model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    let fire = emergency.clone();
    let screen = Screen::with_emergency(
        model,
        Box::new(move || {
            fire.fire();
        }),
    );

    hold(&screen);
    assert!(emergency.fired());
    let request = next_request(&requests);
    assert_eq!(request.op, Op::Status);
    let request = next_request(&requests);
    assert_eq!((request.id, request.op), (EMERGENCY_ID, emergency_op()));
    assert!(
        mailbox.waiting() >= FLOOD as usize,
        "none of the flood was drawn first"
    );
}

#[test]
fn a_window_without_a_helper_powers_off_by_itself() {
    let power_off = FakePowerOff::new("exit 0");
    let wired = Wired::new(
        Connect::pkexec(
            Err("no set-user-ID pkexec was found".to_string()),
            std::path::Path::new("/mnt/data/nails"),
        ),
        &power_off,
    );
    wired.pump_until(|update| matches!(update, Update::Ended(_)));
    assert!(wired.screen.shows(text::NOT_STARTED));
    let start = Instant::now();
    hold(&wired.screen);
    assert_eq!(wired.outcome(), Outcome::PowerOffAsked);
    assert!(start.elapsed() < PATIENCE);
    assert_eq!(power_off.calls(), ["poweroff --no-ask-password"]);
}
