// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's tools end to end, without a display: the window on Slint's
//! headless platform and the real worker against a fake helper that answers
//! with envelopes recorded from the real CLI. Each flow shows the requests
//! the helper reads, in their order.

mod screen;
mod support;
mod wired;

use std::sync::mpsc::{Receiver, channel};

use i_slint_backend_testing::AccessibleRole;
use nails_api::protocol::{
    CheckArgs, Op, RehearsePlantArgs, RehearseScanArgs, Request, VerifyArgs,
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
