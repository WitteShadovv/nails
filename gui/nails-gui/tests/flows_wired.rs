// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's new flows end to end, without a display: the window on
//! Slint's headless platform and the real worker against a fake helper.
//! A deactivation returns to the decoy, or powers off through a plan of its
//! own, and the helper sees exactly the requests and tokens the protocol
//! asks for. An activation past its point of no return leaves Logging Out
//! when the engine says the logout will not come, and gets a way out when
//! the logout it asked for does not come.

mod screen;
mod support;
mod wired;

use std::sync::mpsc::channel;

use i_slint_backend_testing::AccessibleRole;
use nails_api::Event;
use nails_api::protocol::{ActivateArgs, DeactivateArgs, Op, Token};
use nails_gui::text;
use nails_gui::worker::{Connect, Kind, Update};
use serde_json::{Value, json};
use support::{FakePowerOff, event, result};
use wired::{Wired, helper, next_request};

/// The tokens the fake helper hands out: one for the plan of a return, one
/// for that of a power-off, one for an activation.
fn token(of: &str) -> String {
    match of {
        "return" => "a".repeat(32),
        "poweroff" => "b".repeat(32),
        _ => "c".repeat(32),
    }
}

fn status(place: &str) -> Value {
    json!({"schema_version": 2, "command": "status", "ok": true, "data": {
        "place": place, "attention": null, "hidden_root": "/mnt/data"}})
}

/// A hidden session's helper that plans and applies a deactivation, warning
/// before a return with `warning`.
fn deactivating(
    warning: &'static str,
) -> (
    Wired,
    std::sync::mpsc::Receiver<nails_api::protocol::Request>,
    FakePowerOff,
) {
    let (seen, requests) = channel();
    let (stream, _helper) = helper(seen, move |request| {
        let id = request.id;
        match &request.op {
            Op::Status => vec![result(id, 0, status("hidden"))],
            Op::DeactivatePlan(args) => {
                let (of, warnings) = if args.poweroff {
                    ("poweroff", json!([]))
                } else {
                    ("return", json!([warning]))
                };
                vec![result(
                    id,
                    0,
                    json!({"schema_version": 2, "command": "deactivate", "ok": true, "data": {
                        "poweroff": args.poweroff, "warnings": warnings, "token": token(of)}}),
                )]
            }
            Op::DeactivateApply(Token { token: applied }) => {
                let status = if *applied == token("poweroff") {
                    "poweroff_requested"
                } else {
                    "return_requested"
                };
                vec![result(
                    id,
                    0,
                    json!({"schema_version": 2, "command": "deactivate", "ok": true,
                        "data": {"status": status}}),
                )]
            }
            _ => vec![],
        }
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
    (wired, requests, power_off)
}

/// Every request the helper read after its hello, up to the one `last`
/// holds for.
fn requests_until(
    requests: &std::sync::mpsc::Receiver<nails_api::protocol::Request>,
    last: impl Fn(&Op) -> bool,
) -> Vec<Op> {
    let mut ops = Vec::new();
    loop {
        let op = next_request(requests).op;
        let done = last(&op);
        ops.push(op);
        if done {
            return ops;
        }
    }
}

#[test]
fn return_to_decoy_applies_the_plan_of_a_return_through_the_helper() {
    let warning =
        "The return finds no `nft` (nftables) in the hidden session's system directories.";
    let (wired, requests, _power_off) = deactivating(warning);
    assert!(
        wired
            .screen
            .find_with(text::DEACTIVATE_QUESTION, AccessibleRole::Groupbox)
            .accessible_description()
            .unwrap_or_default()
            .contains("The return finds no nft (nftables)"),
        "the engine's warning, as it came"
    );
    wired
        .screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Apply, _)));
    assert!(wired.screen.shows(text::ENDING));
    assert!(wired.screen.shows(text::RETURNING));
    let ops = requests_until(&requests, |op| matches!(op, Op::DeactivateApply(_)));
    assert_eq!(
        ops,
        [
            Op::Status,
            Op::DeactivatePlan(DeactivateArgs { poweroff: false }),
            Op::DeactivateApply(Token {
                token: token("return")
            }),
        ]
    );
}

#[test]
fn power_off_applies_a_plan_of_its_own_and_never_the_returns() {
    let (wired, requests, _power_off) = deactivating("A warning of the return.");
    wired
        .screen
        .find_with(text::POWER_OFF, AccessibleRole::Button)
        .invoke_accessible_default_action();
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Apply, _)));
    assert!(wired.screen.shows(text::ENDING));
    assert!(wired.screen.shows(text::POWERING_OFF));
    assert!(!wired.screen.window.get_question_open(), "asked once");
    let ops = requests_until(&requests, |op| matches!(op, Op::DeactivateApply(_)));
    assert_eq!(
        ops,
        [
            Op::Status,
            Op::DeactivatePlan(DeactivateArgs { poweroff: false }),
            Op::DeactivatePlan(DeactivateArgs { poweroff: true }),
            Op::DeactivateApply(Token {
                token: token("poweroff")
            }),
        ]
    );
}

/// A decoy's helper whose activation plays `apply` (given the request id)
/// past its plan, and whose check passes.
fn activating(apply: fn(u64) -> Vec<nails_api::protocol::Frame>) -> (Wired, FakePowerOff) {
    let (seen, _requests) = channel();
    let (stream, _helper) = helper(seen, move |request| {
        let id = request.id;
        match &request.op {
            Op::Status => vec![result(id, 0, status("decoy"))],
            Op::Check(_) => vec![result(
                id,
                0,
                json!({"schema_version": 2, "command": "check", "ok": true, "data": {
                    "ready": true, "checks": [],
                    "summary": {"passed": 1, "warnings": 0, "failed": 0}}}),
            )],
            Op::ActivatePlan(ActivateArgs { .. }) => vec![result(
                id,
                0,
                json!({"schema_version": 2, "command": "activate", "ok": true, "data": {
                    "warning": null, "defaults_notice": null, "builds_hidden_system": false,
                    "token": token("activate")}}),
            )],
            Op::ActivateApply(_) => apply(id),
            _ => vec![],
        }
    });
    let power_off = FakePowerOff::new("exit 0");
    let wired = Wired::new(Connect::Stream(stream), &power_off, false);
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Check, _)));
    wired
        .screen
        .find_with(text::ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    wired
        .screen
        .find_with(text::LOG_OUT_AND_ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    wired.pump_until(|update| *update == Update::Event(Event::PointOfNoReturn));
    assert!(wired.screen.shows(text::LOGGING_OUT));
    (wired, power_off)
}

#[test]
fn a_logout_the_engine_could_not_ask_for_leaves_logging_out_and_checks_again() {
    let (wired, _power_off) = activating(|id| {
        vec![
            event(id, Event::PointOfNoReturn),
            event(id, Event::Finished { success: false }),
            result(
                id,
                1,
                json!({"schema_version": 2, "command": "activate", "ok": false, "error": {
                    "code": "soft_reboot",
                    "message": "systemctl could not enqueue soft-reboot.target",
                    "next": null}}),
            ),
        ]
    });
    wired.pump_until(|update| *update == Update::Event(Event::Finished { success: false }));
    assert!(wired.screen.shows(text::ACTIVATION_FAILED));
    assert!(wired.screen.shows(text::LOGOUT_NOT_ASKED));
    // The answer brings the status and the check again, through the helper.
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Check, _)));
    assert!(wired.screen.shows(text::READY));
    assert!(
        wired
            .screen
            .shows("Systemctl could not enqueue soft-reboot.target.")
    );
}

#[test]
fn a_logout_that_was_asked_for_and_does_not_come_gets_its_way_out() {
    let (wired, _power_off) = activating(|id| {
        vec![
            event(id, Event::PointOfNoReturn),
            event(id, Event::Finished { success: true }),
            result(
                id,
                0,
                json!({"schema_version": 2, "command": "activate", "ok": true,
                    "data": {"status": "entering"}}),
            ),
        ]
    });
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Apply, _)));
    let close = || {
        wired
            .screen
            .find_with("Close", AccessibleRole::Button)
            .accessible_enabled()
    };
    assert_eq!(close(), Some(false));
    wired.screen.wait_ms(61_000);
    assert!(wired.screen.shows(text::LOGOUT_LATE));
    assert_eq!(close(), Some(true));
}
