// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's tools end to end, without a display: the window on Slint's
//! headless platform and the real worker against a fake helper that answers
//! with envelopes recorded from the real CLI. Each flow shows the requests
//! the helper reads, in their order, and that an apply carries the token of
//! the plan the person answered, and nothing applies without that answer.

mod screen;
mod support;
mod wired;

use std::sync::mpsc::{Receiver, channel};

use i_slint_backend_testing::AccessibleRole;
use nails_api::protocol::{
    CheckArgs, DiscardPlanArgs, InitArgs, Op, RehearsePlantArgs, RehearseScanArgs, Request, Token,
    VerifyArgs,
};
use nails_gui::text;
use nails_gui::worker::{Connect, Kind, Update};
use serde_json::{Value, json};
use support::{FakePowerOff, fixture, result};
use wired::{Wired, helper, next_request};

fn status(place: &str) -> Value {
    json!({"schema_version": 2, "command": "status", "ok": true, "data": {
        "place": place, "attention": null, "hidden_root": "/mnt/data"}})
}

fn ready() -> Value {
    json!({"schema_version": 2, "command": "check", "ok": true, "data": {
        "ready": true, "checks": [], "summary": {"passed": 3, "warnings": 0, "failed": 0}}})
}

/// A window on a helper that answers status, check and each operation of
/// the tools as `respond` says, the others with its recorded envelopes;
/// shown once the session's page settled.
fn window(
    place: &'static str,
    mut respond: impl FnMut(&Op) -> Option<(u8, Value)> + Send + 'static,
) -> (Wired, Receiver<Request>, FakePowerOff) {
    let (seen, requests) = channel();
    let (stream, _helper) = helper(seen, move |request| {
        let (exit, envelope) = match &request.op {
            Op::Status => (0, status(place)),
            Op::Check(_) => (0, ready()),
            op => respond(op).unwrap_or_else(|| panic!("no answer for {op:?}")),
        };
        vec![result(request.id, exit, envelope)]
    });
    let power_off = FakePowerOff::new("exit 0");
    let wired = Wired::new(Connect::Stream(stream), &power_off, place == "hidden");
    let settled = if place == "decoy" {
        Kind::Check
    } else {
        Kind::Status
    };
    wired.pump_until(|update| matches!(update, Update::Answered(kind, _) if *kind == settled));
    wired.screen.tall();
    (wired, requests, power_off)
}

fn press(wired: &Wired, label: &str) {
    wired
        .screen
        .find_with(label, AccessibleRole::Button)
        .invoke_accessible_default_action();
}

/// Pump until the request of `kind` was answered.
fn until_answered(wired: &Wired, kind: Kind) {
    wired.pump_until(|update| matches!(update, Update::Answered(of, _) if *of == kind));
}

/// The requests the helper read after the hello, `n` of them.
fn ops(requests: &Receiver<Request>, n: usize) -> Vec<Op> {
    (0..n).map(|_| next_request(requests).op).collect()
}

#[test]
fn verify_goes_through_the_helper_and_shows_its_answer() {
    let (wired, requests, _power_off) = window("hidden", |op| match op {
        Op::Verify(_) => Some((11, fixture("verify-findings"))),
        _ => None,
    });
    press(&wired, text::VERIFY);
    press(&wired, text::DEEP_SCAN);
    until_answered(&wired, Kind::Verify);
    assert!(wired.screen.shows(text::TRACES_FOUND));
    assert_eq!(
        ops(&requests, 2),
        [
            Op::Status,
            Op::Verify(VerifyArgs {
                deep: true,
                ..VerifyArgs::default()
            })
        ]
    );
}

#[test]
fn a_rehearsal_reads_its_status_and_plants_through_the_helper() {
    let (wired, requests, _power_off) = window("hidden", |op| match op {
        Op::RehearseStatus => Some((0, fixture("rehearse-status-none"))),
        Op::RehearsePlant(_) => Some((0, fixture("rehearse-status-planted"))),
        _ => None,
    });
    press(&wired, text::REHEARSAL);
    until_answered(&wired, Kind::Rehearse);
    press(&wired, text::PLANT);
    until_answered(&wired, Kind::Rehearse);
    assert!(wired.screen.shows(text::PLANTED));
    assert_eq!(
        ops(&requests, 3),
        [
            Op::Status,
            Op::RehearseStatus,
            Op::RehearsePlant(RehearsePlantArgs::default())
        ]
    );
}

#[test]
fn on_the_decoy_a_rehearsal_scans_and_removes_through_the_helper() {
    let (wired, requests, _power_off) = window("decoy", |op| match op {
        Op::RehearseStatus => Some((0, fixture("rehearse-status-planted"))),
        Op::RehearseScan(_) => Some((11, fixture("rehearse-scan-found"))),
        Op::RehearseReset => Some((
            0,
            json!({"schema_version": 2, "command": "rehearse", "ok": true, "data": {
                "phase": "none", "channels": [], "removed": ["/mnt/data/rehearse/state.json"],
                "next_step": "Step 1 of 3"}}),
        )),
        _ => None,
    });
    press(&wired, text::REHEARSAL);
    until_answered(&wired, Kind::Rehearse);
    press(&wired, text::SCAN);
    until_answered(&wired, Kind::Rehearse);
    assert!(wired.screen.shows(text::TEST_WORDS_FOUND));
    press(&wired, text::REMOVE_TEST_WORDS);
    until_answered(&wired, Kind::Rehearse);
    assert!(wired.screen.shows(text::TEST_WORDS_REMOVED));
    assert_eq!(
        ops(&requests, 5),
        [
            Op::Status,
            Op::Check(CheckArgs::default()),
            Op::RehearseStatus,
            Op::RehearseScan(RehearseScanArgs::default()),
            Op::RehearseReset,
        ]
    );
}

fn token(of: &str) -> String {
    match of {
        "discard" => "d".repeat(32),
        _ => "e".repeat(32),
    }
}

/// A decoy's helper that plans and applies a discard of `/home`.
fn discarding() -> (Wired, Receiver<Request>, FakePowerOff) {
    let (wired, requests, power_off) = window("decoy", |op| match op {
        Op::DiscardPlan(args) => Some((
            0,
            json!({"schema_version": 2, "command": "discard", "ok": true, "data": {
                "target": args.target, "removals": ["/mnt/data/root/upper/home"],
                "resets_nix_store": false, "token": token("discard")}}),
        )),
        Op::DiscardApply(_) => Some((
            0,
            json!({"schema_version": 2, "command": "discard", "ok": true, "data": {
                "target": "/home", "removed": ["/mnt/data/root/upper/home"]}}),
        )),
        _ => None,
    });
    press(&wired, text::DISCARD);
    while wired.screen.focused() != text::FIELD_FOLDER {
        wired.screen.press(slint::platform::Key::Tab);
    }
    wired.screen.type_text("/home");
    press(&wired, text::DISCARD_ACTION);
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    assert!(wired.screen.window.get_question_open());
    (wired, requests, power_off)
}

#[test]
fn a_discard_applies_the_token_of_its_plan_once_the_folder_is_typed() {
    let (wired, requests, _power_off) = discarding();
    let delete = wired.screen.find_with(text::DELETE, AccessibleRole::Button);
    assert_eq!(delete.accessible_enabled(), Some(false));
    wired.screen.type_text("/home");
    delete.invoke_accessible_default_action();
    until_answered(&wired, Kind::Apply);
    assert!(wired.screen.shows(text::DISCARDED));
    // Back brings the status and, as the discard may change it, the check.
    press(&wired, text::BACK);
    until_answered(&wired, Kind::Check);
    assert!(wired.screen.shows(text::READY));
    assert_eq!(
        ops(&requests, 6),
        [
            Op::Status,
            Op::Check(CheckArgs::default()),
            Op::DiscardPlan(DiscardPlanArgs {
                target: "/home".to_string(),
                allow_decoy_storage: false,
            }),
            Op::DiscardApply(Token {
                token: token("discard")
            }),
            Op::Status,
            Op::Check(CheckArgs::default()),
        ]
    );
}

#[test]
fn a_discard_answered_no_is_withdrawn_and_never_applied() {
    let (wired, requests, _power_off) = discarding();
    press(&wired, "Cancel");
    until_answered(&wired, Kind::Status);
    assert!(!wired.screen.window.get_question_open());
    assert!(
        wired.screen.shows(text::DISCARD_WHAT),
        "the tool stays open"
    );
    assert_eq!(
        ops(&requests, 4),
        [
            Op::Status,
            Op::Check(CheckArgs::default()),
            Op::DiscardPlan(DiscardPlanArgs {
                target: "/home".to_string(),
                allow_decoy_storage: false,
            }),
            // Any other request withdraws the plan on the helper's side.
            Op::Status,
        ]
    );
}

#[test]
fn set_up_applies_the_token_of_its_plan_through_the_helper() {
    let (wired, requests, _power_off) = window("decoy", |op| match op {
        Op::InitPlan(args) => Some((
            0,
            json!({"schema_version": 2, "command": "init", "ok": true, "data": {
                "path": args.path, "hardware_config": null,
                "skipped": "host 'debian' has no NixOS config layer", "warnings": [],
                "token": token("init")}}),
        )),
        Op::InitApply(_) => Some((
            0,
            json!({"schema_version": 2, "command": "init", "ok": true, "data": {
                "root": "/mnt/data",
                "items": [{"path": "/mnt/data/logs", "status": "created"}],
                "next_steps": ["check readiness"]}}),
        )),
        _ => None,
    });
    press(&wired, text::SET_UP);
    press(&wired, text::SET_UP_ACTION);
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    press(&wired, text::SET_UP_CONFIRM);
    until_answered(&wired, Kind::Apply);
    assert!(wired.screen.shows(text::SET_UP_DONE));
    assert_eq!(
        ops(&requests, 4),
        [
            Op::Status,
            Op::Check(CheckArgs::default()),
            Op::InitPlan(InitArgs {
                path: "/mnt/data".to_string(),
                allow_decoy_storage: false,
                hardware_config: None,
                no_hardware_config: false,
            }),
            Op::InitApply(Token {
                token: token("init")
            }),
        ]
    );
}

#[test]
fn a_set_up_the_engine_refused_shows_its_words() {
    let (wired, requests, _power_off) = window("decoy", |op| match op {
        Op::InitPlan(_) => Some((4, fixture("init-refused"))),
        _ => None,
    });
    press(&wired, text::SET_UP);
    press(&wired, text::SET_UP_ACTION);
    until_answered(&wired, Kind::Plan);
    assert!(wired.screen.shows(text::SET_UP_FAILED));
    assert!(!wired.screen.window.get_question_open());
    let ops = ops(&requests, 3);
    assert!(matches!(ops[2], Op::InitPlan(_)), "{ops:?}");
}
