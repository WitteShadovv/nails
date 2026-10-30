// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The emergency end to end, without a display: the window on Slint's
//! headless platform, the real worker and the real emergency line against a
//! fake helper, and a stand-in for `systemctl`. Each test makes one of the
//! things that could hold the emergency up and shows that it does not: a
//! worker stuck on a request the helper never answers, an open question
//! whose plan waits, a flood of updates the window draws a turn at a time
//! through its mailbox, as its event loop does, and a window with no helper
//! at all.

mod screen;
mod support;
mod wired;

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use i_slint_backend_testing::AccessibleRole;
use nails_api::Event;
use nails_api::protocol::{DeactivateArgs, EmergencyArgs, Op};
use nails_gui::emergency::{EMERGENCY_ID, Emergency, Outcome};
use nails_gui::mailbox::{Mailbox, TURN};
use nails_gui::model::Model;
use nails_gui::text;
use nails_gui::worker::{Connect, Kind, Update, spawn};
use screen::Screen;
use serde_json::json;
use support::{FakePowerOff, event, result};
use wired::{GRACE, PATIENCE, Wired, helper, next_request};

/// The emergency's own request, as the helper reads it.
fn emergency_op() -> Op {
    Op::Emergency(EmergencyArgs {
        poweroff: true,
        reboot: false,
    })
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
    let wired = Wired::new(Connect::Stream(stream), &power_off, true);
    wired.pump_until(|update| *update == Update::Running(Kind::Status));
    assert_eq!(next_request(&requests).op, Op::Status);

    wired.hold();
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
    let wired = Wired::new(Connect::Stream(stream), &power_off, true);
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Status, _)));
    wired
        .screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    assert!(wired.screen.window.get_question_open());

    wired.hold();
    assert!(!wired.screen.window.get_question_open());
    let ops: Vec<Op> = (0..3).map(|_| next_request(&requests).op).collect();
    assert_eq!(
        ops,
        [
            Op::Status,
            Op::DeactivatePlan(DeactivateArgs { poweroff: false }),
            emergency_op()
        ],
        "the plan was neither applied nor withdrawn first"
    );
    assert_eq!(wired.outcome(), Outcome::HelperAsked);
}

#[test]
fn a_flood_drawn_a_turn_at_a_time_leaves_room_for_the_hold() {
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
    // The turns the mailbox asks for, which this test runs one at a time,
    // as the window's event loop runs them, with the person's input between.
    let (post, turns) = channel::<Mailbox>();
    let mailbox = Mailbox::new(move |mailbox| {
        let _ = post.send(mailbox);
    });
    let inbox = mailbox.clone();
    let worker = spawn(
        Connect::Stream(stream),
        Some(emergency.clone()),
        move |update| inbox.put(update),
    );
    let model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    let fire = emergency.clone();
    let screen = Screen::with_emergency(
        model,
        Box::new(move || {
            fire.fire();
        }),
    );
    let turn = || {
        let posted = turns.recv_timeout(PATIENCE).expect("a turn is asked for");
        screen.controller.borrow_mut().take_turn(&posted);
        for ask in screen.asks() {
            assert!(worker.ask(ask), "the worker listens");
        }
    };
    // The handshake's turn: the window asks for the status, whose answer is
    // the flood.
    turn();
    let deadline = Instant::now() + PATIENCE;
    while mailbox.waiting() < 10 * TURN {
        assert!(Instant::now() < deadline, "the flood came in");
        std::thread::sleep(Duration::from_millis(10));
    }

    let control = screen.find_with(text::EMERGENCY, AccessibleRole::Button);
    let at = screen.middle(&control);
    screen.press_at(at);
    turn();
    screen.wait_ms(600);
    turn();
    screen.wait_ms(500);
    turn();
    screen.release_at(at);
    assert_eq!(
        screen.emergencies(),
        1,
        "the hold went through between turns"
    );
    assert!(
        mailbox.waiting() > TURN,
        "more than a turn of the flood still waits: {}",
        mailbox.waiting()
    );
    assert_eq!(next_request(&requests).op, Op::Status);
    let request = next_request(&requests);
    assert_eq!((request.id, request.op), (EMERGENCY_ID, emergency_op()));
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
        true,
    );
    wired.pump_until(|update| matches!(update, Update::Ended(_)));
    assert!(wired.screen.shows(text::NOT_STARTED));
    let start = Instant::now();
    wired.hold();
    assert_eq!(wired.outcome(), Outcome::PowerOffAsked);
    assert!(start.elapsed() < PATIENCE);
    assert_eq!(power_off.calls(), ["poweroff --no-ask-password"]);
}
