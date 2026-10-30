// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The pages of a switch the window waits for, through the model: the
//! engine saying the logout will not come, and the way out once a switch it
//! asked for did not come in time.

use super::*;
use crate::client::Answer;
use nails_api::protocol::{CheckArgs, DeactivatePlanData};
use serde_json::{Value, json};

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

fn model() -> Model {
    Model::new(Some(PathBuf::from("/mnt/data/nails")), false)
}

/// A decoy's window with its activation past the point of no return.
fn past_the_point() -> Model {
    let mut model = model();
    model.apply(Update::Connected(crate::client::ours()));
    let asks = model.apply(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "decoy", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    assert_eq!(asks, vec![Ask::Check(CheckArgs::default())]);
    model.apply(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true, "checks": [], "summary": {"passed": 1, "warnings": 0, "failed": 0}}}),
    ));
    assert!(matches!(model.action(), Some(Effect::Ask(Ask::Plan(_)))));
    model.apply(Update::Planned(PlanData::Activate(
        nails_api::protocol::ActivatePlanData {
            warning: None,
            defaults_notice: None,
            builds_hidden_system: false,
            token: "0".repeat(32),
        },
    )));
    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    model.apply(Update::Event(Event::PointOfNoReturn));
    assert_eq!(model.page().heading, text::LOGGING_OUT);
    assert!(model.switch_pending());
    model
}

/// A hidden session's window with a return to the decoy under way.
fn ending() -> Model {
    let mut model = model();
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "hidden", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    model.action();
    model.apply(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: false,
        warnings: vec![],
        token: "0".repeat(32),
    })));
    assert_eq!(model.alternative(), Some(Ask::Apply));
    assert!(model.switch_pending());
    model
}

#[test]
fn the_engine_saying_the_logout_will_not_come_leaves_logging_out_at_once() {
    let mut model = past_the_point();
    model.apply(Update::Event(Event::Finished { success: false }));
    let page = model.page();
    assert_eq!(page.heading, text::ACTIVATION_FAILED);
    assert_eq!(page.description, text::LOGOUT_NOT_ASKED);
    assert!(!model.switch_pending(), "nothing to wait for");
    // Its answer says why, and the page checks again from the status.
    let asks = model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "activate", "ok": false, "error": {
            "code": "soft_reboot",
            "message": "Invalid state: systemctl could not enqueue soft-reboot.target. The next root was removed again; nothing changed",
            "next": null}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    let page = model.page();
    assert!(
        page.note
            .starts_with("Invalid state: systemctl could not enqueue"),
        "{}",
        page.note
    );
    assert!(!page.no_input);
}

#[test]
fn a_helper_gone_after_saying_the_logout_will_not_come_is_a_lost_session() {
    let mut model = past_the_point();
    model.apply(Update::Event(Event::Finished { success: false }));
    model.apply(Update::Ended(Failure::Lost { in_flight: true }));
    let page = model.page();
    assert_eq!(page.heading, text::LOST);
    assert!(!page.no_input, "its Close works");
}

#[test]
fn an_enqueued_logout_keeps_the_page_until_it_is_overdue() {
    let mut model = past_the_point();
    model.apply(Update::Event(Event::Finished { success: true }));
    model.apply(answered(
        Kind::Apply,
        json!({"command": "activate", "ok": true, "data": {"status": "entering"}}),
    ));
    let waiting = model.page();
    assert_eq!(waiting.heading, text::LOGGING_OUT);
    assert!(waiting.no_input && waiting.note.is_empty());
    assert!(model.switch_pending());

    model.set_switch_overdue(true);
    let late = model.page();
    assert_eq!(late.heading, text::LOGGING_OUT);
    assert_eq!(late.note, text::LOGOUT_LATE);
    assert_eq!(
        late.fix,
        "Close this window and open it again from a terminal to see where things stand: \
         sudo /mnt/data/nails gui"
    );
    assert!(!late.no_input, "its Close works again");
    assert!(late.action.is_none(), "nothing to cancel any more");
    assert_eq!(model.escape(), None);
}

#[test]
fn a_helper_gone_past_the_point_leaves_it_to_the_timer() {
    let mut model = past_the_point();
    model.apply(Update::Ended(Failure::Lost { in_flight: true }));
    assert_eq!(model.page().heading, text::LOGGING_OUT);
    assert!(model.switch_pending());
    model.set_switch_overdue(true);
    assert_eq!(model.page().note, text::LOGOUT_LATE);
}

#[test]
fn a_deactivation_that_does_not_end_points_to_the_emergency() {
    let mut model = ending();
    model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": true,
            "data": {"status": "return_requested", "backend_left_open": ["x"]}}),
    ));
    model.set_switch_overdue(true);
    let page = model.page();
    assert_eq!(page.heading, text::ENDING);
    // It no longer says the session ends in a few seconds.
    assert_eq!(page.description, text::ENDING_LATE);
    assert_eq!(page.note, text::BACKEND_LEFT_OPEN);
    assert_eq!(page.fix, text::END_ANOTHER_WAY);
    assert!(!page.no_input && page.emergency);
}

#[test]
fn only_a_switch_that_is_pending_can_be_overdue() {
    let mut decoy = model();
    decoy.set_switch_overdue(true);
    assert!(!decoy.switch_pending());
    assert!(decoy.page().note.is_empty());

    // A failed deactivation is no switch any more.
    let mut model = ending();
    model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
            "code": "invalid_state", "message": "refused", "next": null}}),
    ));
    assert!(!model.switch_pending());
    model.set_switch_overdue(true);
    assert_eq!(model.page().heading, text::HIDDEN_SESSION);

    // Nor is the emergency's page, which names the power button already.
    let mut model = ending();
    model.emergency();
    assert!(!model.switch_pending());
}
