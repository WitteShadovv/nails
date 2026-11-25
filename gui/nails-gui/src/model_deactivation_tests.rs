// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The deactivation through the model: the plan of a power-off and its
//! question, the apply on Power Off, the page while the session ends, and
//! the answers that bring the session's page back.

use super::*;
use crate::client::Answer;
use nails_api::protocol::{DeactivateArgs, DeactivatePlanData};
use serde_json::{Value, json};

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

/// A warning of the engine's, in its own words, for a plan that has one: the
/// window shows any it gets.
const WARNING: &str = "A program still holds `/mnt/data/work`: it closes with the session.";

fn status(attention: Value) -> Update {
    answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "hidden", "attention": attention, "uptime_seconds": 600,
            "hidden_root": "/mnt/data", "hidden_root_mounted": true}}),
    )
}

/// A hidden session's window, its status read.
fn hidden() -> Model {
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    assert_eq!(
        model.apply(Update::Connected(crate::client::ours())),
        vec![Ask::Status]
    );
    assert_eq!(
        model.apply(status(Value::Null)),
        [Ask::ConfigShow],
        "no check here: the settings, for the Emergency control"
    );
    model
}

fn plan(poweroff: bool, warnings: &[&str]) -> Update {
    Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff,
        warnings: warnings.iter().map(|w| (*w).to_string()).collect(),
        powers_off_instead: None,
        token: "0".repeat(32),
    }))
}

/// `model` with Deactivate… pressed and the plan of the power-off holding.
fn asked(model: &mut Model, warnings: &[&str]) {
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Deactivate(DeactivateArgs {
            poweroff: true
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert!(model.apply(plan(true, warnings)).is_empty());
}

fn enqueued(status: &str, warnings: Value, left_open: Value) -> Update {
    answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": true, "data": {
            "status": status, "warnings": warnings, "backend_left_open": left_open}}),
    )
}

#[test]
fn a_hidden_session_deactivates_but_not_without_its_volume() {
    let model = hidden();
    let page = model.page();
    assert_eq!(page.heading, text::HIDDEN_SESSION);
    assert_eq!(page.action, Some(text::DEACTIVATE));
    assert_eq!(page.fix, "", "no terminal line");
    for (attention, action) in [
        ("no_way_back", Some(text::DEACTIVATE)),
        ("volume_lost", None),
        ("volume_covered", Some(text::DEACTIVATE)),
        ("almost_full", Some(text::DEACTIVATE)),
    ] {
        let mut model = hidden();
        model.apply(status(json!(attention)));
        assert_eq!(model.page().action, action, "{attention}");
    }
}

/// The plan as the helper gives it now (`deactivate-plan`): a power-off,
/// with nothing to warn of.
#[test]
fn the_question_says_the_computer_powers_off_and_offers_only_that() {
    let recorded: Value =
        serde_json::from_str(include_str!("../tests/fixtures/deactivate-plan.json")).unwrap();
    let mut model = hidden();
    model.action();
    model.apply(Update::Running(Kind::Plan));
    assert!(
        model
            .apply(Update::Planned(PlanData::Deactivate(
                serde_json::from_value(recorded["data"].clone()).unwrap()
            )))
            .is_empty()
    );
    let question = model.page().question.expect("a question");
    assert_eq!(question.heading, text::DEACTIVATE_QUESTION);
    assert_eq!(question.body, text::DEACTIVATE_CONSEQUENCE);
    assert!(question.body.contains("powers off the computer"));
    assert_eq!(question.confirm, text::POWER_OFF);
    assert!(!question.destructive, "the suggested button");
    assert!(question.prompt.is_none());
    let shown = format!("{question:?}").to_lowercase();
    for word in ["return", "way back", "login screen"] {
        assert!(!shown.contains(word), "{word}: {shown}");
    }
}

#[test]
fn the_question_names_the_engines_warnings_after_the_consequence() {
    let mut model = hidden();
    asked(&mut model, &[WARNING]);
    let question = model.page().question.expect("a question");
    let lines: Vec<&str> = question.body.lines().collect();
    assert_eq!(
        lines,
        [
            text::DEACTIVATE_CONSEQUENCE,
            "A program still holds /mnt/data/work: it closes with the session."
        ],
        "the engine's words, its code quotes dropped"
    );
}

#[test]
fn power_off_applies_the_plan_and_the_page_ends_with_the_session() {
    let mut model = hidden();
    asked(&mut model, &[]);
    assert_eq!(model.answer(true), Some(Ask::Apply), "no second plan");
    let page = model.page();
    assert!(page.question.is_none());
    assert_eq!(page.heading, text::ENDING);
    assert_eq!(page.description, text::POWERING_OFF);
    assert!(page.urgent && page.no_input && page.action.is_none());

    model.apply(Update::Running(Kind::Apply));
    let device = "cargo-hidden";
    let asks = model.apply(enqueued(
        "poweroff_requested",
        json!([format!("The hidden backend device {device} could not be marked to close: it stays open after the switch, its key in RAM, until power-off")]),
        json!([device]),
    ));
    assert!(asks.is_empty());
    let page = model.page();
    assert_eq!(page.heading, text::ENDING);
    assert_eq!(page.description, text::POWERING_OFF);
    assert_eq!(page.note, text::BACKEND_LEFT_OPEN);
    let shown = format!("{page:?}");
    assert!(!shown.contains(device), "no device is named: {shown}");

    // The power-off ends the window with the session.
    assert!(
        model
            .apply(Update::Ended(Failure::Lost { in_flight: false }))
            .is_empty()
    );
    assert_eq!(model.page().heading, text::ENDING);
}

/// An older engine's answer that names the return it enqueued reads as the
/// power-off the window asked for: the page never promises a return.
#[test]
fn any_switch_an_answer_names_reads_as_the_power_off() {
    for status in ["return_requested", "something_else"] {
        let mut model = hidden();
        asked(&mut model, &[]);
        model.answer(true);
        model.apply(Update::Running(Kind::Apply));
        assert!(
            model
                .apply(enqueued(status, json!([]), json!([])))
                .is_empty()
        );
        let page = model.page();
        assert_eq!(
            (page.heading.as_str(), page.description.as_str()),
            (text::ENDING, text::POWERING_OFF),
            "{status}"
        );
        assert_eq!(page.note, "");
    }
}

#[test]
fn cancel_withdraws_the_plan_and_the_session_page_comes_back() {
    let mut model = hidden();
    asked(&mut model, &[]);
    assert_eq!(model.answer(false), Some(Ask::Withdraw));
    model.apply(Update::Withdrawn);
    let page = model.page();
    assert!(page.question.is_none());
    assert_eq!(page.heading, text::HIDDEN_SESSION);
    assert_eq!(page.action, Some(text::DEACTIVATE));
}

#[test]
fn a_failed_apply_brings_the_session_back_with_the_engines_words() {
    let mut model = hidden();
    asked(&mut model, &[]);
    model.answer(true);
    model.apply(Update::Running(Kind::Apply));
    let asks = model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
            "code": "invalid_state", "message": "systemctl could not enqueue poweroff.target",
            "next": {"command": "emergency"}}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    model.apply(status(Value::Null));
    let page = model.page();
    assert_eq!(page.heading, text::HIDDEN_SESSION);
    assert!(
        page.note
            .starts_with("Systemctl could not enqueue poweroff.target."),
        "{}",
        page.note
    );
    assert_eq!(page.action, Some(text::DEACTIVATE));
}

#[test]
fn a_plan_that_settles_switches_nothing_and_says_why() {
    let mut model = hidden();
    model.action();
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(
        model.apply(answered(
            Kind::Plan,
            json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
                "code": "invalid_state", "message": "not in a hidden session; nothing to deactivate",
                "next": {"command": "recover"}}}),
        )),
        vec![Ask::Status]
    );
    assert!(model.page().question.is_none());
    assert_eq!(
        model.page().note,
        "Not in a hidden session; nothing to deactivate."
    );
    model.apply(status(Value::Null));
    assert_eq!(model.page().heading, text::HIDDEN_SESSION);
}

#[test]
fn a_lost_session_before_the_choice_is_a_failure_and_after_it_is_the_power_off() {
    let mut model = hidden();
    asked(&mut model, &[]);
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page().heading, text::LOST);

    let mut model = hidden();
    asked(&mut model, &[]);
    model.answer(true);
    model.apply(Update::Running(Kind::Apply));
    model.apply(Update::Ended(Failure::Lost { in_flight: true }));
    assert_eq!(model.page().heading, text::ENDING);
}

#[test]
fn a_refused_token_drops_the_deactivation() {
    let mut model = hidden();
    asked(&mut model, &[]);
    model.answer(true);
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().heading, text::HIDDEN_SESSION);
}

#[test]
fn a_plan_that_does_not_power_off_is_dropped() {
    let mut model = hidden();
    model.action();
    assert_eq!(model.apply(plan(false, &[])), vec![Ask::Withdraw]);
    assert!(model.page().question.is_none());
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().heading, text::HIDDEN_SESSION);
}
