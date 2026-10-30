// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The deactivation through the model: the plan of a return and its
//! question with both endings, the plan of a power-off applied without a
//! second question, the page while the session ends, and the answers that
//! bring the session's page back.

use super::*;
use crate::client::Answer;
use nails_api::protocol::{DeactivateArgs, DeactivatePlanData};
use serde_json::{Value, json};

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

/// What `nails deactivate` warns of before it asks on a hidden session whose
/// way back finds no `ip` and no `nft` (the engine's own words).
const NO_IP: &str = "The return finds no `ip` (iproute2) in the hidden session's system \
    directories, so the virtual links the session made, the MAC addresses it changed and the \
    policy-routing rules it added stay on the decoy until power-off. `sudo /mnt/data/nails \
    deactivate --poweroff` leaves none of them.";
const NO_NFT: &str = "The return finds no `nft` (nftables) in the hidden session's system \
    directories, so the nftables tables the session added stay on the decoy until power-off (a \
    VPN app's table that blocks all traffic outside its tunnel keeps the decoy offline). `sudo \
    /mnt/data/nails deactivate --poweroff` leaves none of them.";
/// The warning of an engine whose way back powers off when it cannot put the
/// network state back.
const POWERS_OFF_INSTEAD: &str = "The return finds no `iw` in the hidden session's system \
    directories, so a Wi-Fi interface the session added on one of the decoy's radios (a monitor \
    or access point interface, or the one iwd makes in place of the decoy's, as it does by \
    default when it starts) makes the machine power off instead of returning. `sudo \
    /mnt/data/nails deactivate --poweroff` leaves none of them.";

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
    assert!(model.apply(status(Value::Null)).is_empty(), "no check here");
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

/// `model` with Deactivate… pressed and the plan of a return holding.
fn asked(model: &mut Model, warnings: &[&str]) {
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Deactivate(DeactivateArgs {
            poweroff: false
        }))))
    );
    model.apply(Update::Running(Kind::Plan));
    assert!(model.apply(plan(false, warnings)).is_empty());
}

fn enqueued(status: &str, warnings: Value, left_open: Value) -> Update {
    answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": true, "data": {
            "status": status, "warnings": warnings, "backend_left_open": left_open}}),
    )
}

#[test]
fn a_hidden_session_deactivates_but_not_without_a_way_back_or_its_volume() {
    let model = hidden();
    let page = model.page();
    assert_eq!(page.heading, text::HIDDEN_SESSION);
    assert_eq!(page.action, Some(text::DEACTIVATE));
    assert_eq!(page.fix, "", "no terminal line");
    for (attention, action) in [
        ("no_way_back", None),
        ("volume_lost", None),
        ("volume_covered", Some(text::DEACTIVATE)),
        ("almost_full", Some(text::DEACTIVATE)),
    ] {
        let mut model = hidden();
        model.apply(status(json!(attention)));
        assert_eq!(model.page().action, action, "{attention}");
    }
}

/// The plan of a return the helper gave, recorded on a hidden session's tree
/// whose way back finds `name`: a link the kernel keeps
/// (`deactivate-plan-powers-off`), or one it would delete with an `ip` it
/// does not find (`deactivate-plan-may-power-off`).
fn recorded_plan(name: &str) -> Update {
    let text = match name {
        "deactivate-plan-powers-off" => {
            include_str!("../tests/fixtures/deactivate-plan-powers-off.json")
        }
        "deactivate-plan-may-power-off" => {
            include_str!("../tests/fixtures/deactivate-plan-may-power-off.json")
        }
        other => panic!("no fixture {other}"),
    };
    let recorded: Value = serde_json::from_str(text).unwrap();
    Update::Planned(PlanData::Deactivate(
        serde_json::from_value(recorded["data"].clone()).unwrap(),
    ))
}

/// Where the way back powers off whatever happens before it runs, the
/// question says the session ends with a power-off, in the CLI's words, and
/// offers no Return to Decoy: Power Off plans and applies a power-off.
#[test]
fn a_return_that_powers_off_anyway_offers_only_the_power_off() {
    let mut model = hidden();
    model.action();
    model.apply(Update::Running(Kind::Plan));
    assert!(
        model
            .apply(recorded_plan("deactivate-plan-powers-off"))
            .is_empty()
    );
    let question = model.page().question.expect("a question");
    let lines: Vec<&str> = question.body.lines().collect();
    assert_eq!(
        lines[0],
        "This ends the hidden session now, and the machine powers off instead of returning to \
         the decoy."
    );
    assert_eq!(lines[1], text::DEACTIVATE_CONSEQUENCE);
    assert!(
        lines[2].starts_with("The way back cannot delete tunl0, which the kernel keeps"),
        "{lines:?}"
    );
    assert_eq!(question.confirm, text::POWER_OFF);
    assert_eq!(question.alternative, None, "no return to offer");
    assert_eq!(model.alternative(), None);
    assert_eq!(
        model.answer(true),
        Some(Ask::Plan(Plan::Deactivate(DeactivateArgs {
            poweroff: true
        })))
    );
}

/// Where the way back powers off unless that changes before it runs, the
/// question says so, in the CLI's words, and keeps both endings.
#[test]
fn a_return_that_may_power_off_says_so_and_keeps_both_endings() {
    let mut model = hidden();
    model.action();
    model.apply(recorded_plan("deactivate-plan-may-power-off"));
    let question = model.page().question.expect("a question");
    assert_eq!(
        question.body.lines().next(),
        Some(
            "This ends the hidden session now, and unless that changes before it runs, the \
             machine powers off instead of returning to the decoy."
        )
    );
    assert_eq!(question.alternative.as_deref(), Some(text::RETURN_TO_DECOY));
    assert_eq!(model.alternative(), Some(Ask::Apply));
}

#[test]
fn the_question_names_what_the_return_leaves_and_offers_both_endings() {
    let mut model = hidden();
    asked(&mut model, &[NO_IP, NO_NFT]);
    let question = model.page().question.expect("a question");
    assert_eq!(question.heading, text::DEACTIVATE_QUESTION);
    let lines: Vec<&str> = question.body.lines().collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[0], text::DEACTIVATE_CONSEQUENCE);
    assert!(
        lines[1].starts_with("The return finds no ip (iproute2) in the hidden session's"),
        "the engine's words, its code quotes dropped: {lines:?}"
    );
    assert!(lines[2].ends_with("sudo /mnt/data/nails deactivate --poweroff leaves none of them."));
    assert_eq!(question.confirm, text::POWER_OFF);
    assert!(
        !question.destructive,
        "the safer ending is the suggested one"
    );
    assert_eq!(question.alternative.as_deref(), Some(text::RETURN_TO_DECOY));
    assert!(question.prompt.is_none());
}

#[test]
fn a_return_that_would_power_off_instead_is_said_before_the_choice() {
    let mut model = hidden();
    asked(&mut model, &[POWERS_OFF_INSTEAD]);
    let body = model.page().question.expect("a question").body;
    assert!(
        body.contains("makes the machine power off instead of returning"),
        "{body}"
    );
}

#[test]
fn return_to_decoy_applies_the_plan_and_the_page_ends_with_the_session() {
    let mut model = hidden();
    asked(&mut model, &[NO_IP]);
    assert_eq!(model.alternative(), Some(Ask::Apply));
    let page = model.page();
    assert!(page.question.is_none());
    assert_eq!(page.heading, text::ENDING);
    assert_eq!(page.description, text::RETURNING);
    assert!(page.urgent && page.no_input && page.action.is_none());

    model.apply(Update::Running(Kind::Apply));
    let device = "cargo-hidden";
    let asks = model.apply(enqueued(
        "return_requested",
        json!([NO_IP, format!("The hidden backend device {device} could not be marked to close: it stays open after the switch, its key in RAM, until power-off")]),
        json!([device]),
    ));
    assert!(asks.is_empty());
    let page = model.page();
    assert_eq!(page.heading, text::ENDING);
    assert_eq!(page.note, text::BACKEND_LEFT_OPEN);
    let shown = format!("{page:?}");
    assert!(!shown.contains(device), "no device is named: {shown}");

    // The switch ends the window with the session.
    assert!(
        model
            .apply(Update::Ended(Failure::Lost { in_flight: false }))
            .is_empty()
    );
    assert_eq!(model.page().heading, text::ENDING);
}

#[test]
fn power_off_asks_for_its_own_plan_and_applies_it_without_a_second_question() {
    let mut model = hidden();
    asked(&mut model, &[NO_IP]);
    assert_eq!(
        model.answer(true),
        Some(Ask::Plan(Plan::Deactivate(DeactivateArgs {
            poweroff: true
        })))
    );
    let page = model.page();
    assert!(page.question.is_none());
    assert_eq!(page.heading, text::ENDING);
    assert_eq!(page.description, text::POWERING_OFF);

    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.apply(plan(true, &[])), vec![Ask::Apply]);
    assert!(model.page().question.is_none(), "no second question");
    model.apply(Update::Running(Kind::Apply));
    assert!(
        model
            .apply(enqueued("poweroff_requested", json!([]), json!([])))
            .is_empty()
    );
    let page = model.page();
    assert_eq!(page.description, text::POWERING_OFF);
    assert_eq!(page.note, "");
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
    model.alternative();
    model.apply(Update::Running(Kind::Apply));
    let asks = model.apply(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
            "code": "invalid_state", "message": "systemctl could not enqueue soft-reboot.target",
            "next": {"command": "emergency"}}}),
    ));
    assert_eq!(asks, vec![Ask::Status]);
    model.apply(status(Value::Null));
    let page = model.page();
    assert_eq!(page.heading, text::HIDDEN_SESSION);
    assert!(
        page.note
            .starts_with("Systemctl could not enqueue soft-reboot.target."),
        "{}",
        page.note
    );
    assert_eq!(page.action, Some(text::DEACTIVATE));
}

#[test]
fn a_plan_that_settles_switches_nothing_and_says_why() {
    let settled = || {
        answered(
            Kind::Plan,
            json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
                "code": "invalid_state", "message": "not in a hidden session; nothing to deactivate",
                "next": {"command": "recover"}}}),
        )
    };
    // The plan of a return.
    let mut model = hidden();
    model.action();
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.apply(settled()), vec![Ask::Status]);
    assert!(model.page().question.is_none());
    assert_eq!(
        model.page().note,
        "Not in a hidden session; nothing to deactivate."
    );
    // The plan of a power-off, once Power Off was chosen.
    let mut model = hidden();
    asked(&mut model, &[]);
    model.answer(true);
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.apply(settled()), vec![Ask::Status]);
    model.apply(status(Value::Null));
    assert_eq!(model.page().heading, text::HIDDEN_SESSION);
}

#[test]
fn a_lost_session_before_the_choice_is_a_failure_and_after_it_is_the_switch() {
    let mut model = hidden();
    asked(&mut model, &[]);
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page().heading, text::LOST);

    let mut model = hidden();
    asked(&mut model, &[]);
    model.alternative();
    model.apply(Update::Running(Kind::Apply));
    model.apply(Update::Ended(Failure::Lost { in_flight: true }));
    assert_eq!(model.page().heading, text::ENDING);
}

#[test]
fn a_refused_token_drops_the_deactivation() {
    let mut model = hidden();
    asked(&mut model, &[]);
    model.alternative();
    model.apply(Update::Withdrawn);
    assert_eq!(model.page().heading, text::HIDDEN_SESSION);
}

#[test]
fn only_a_deactivations_question_has_a_second_action() {
    let mut model = hidden();
    assert_eq!(model.alternative(), None, "no question");
    asked(&mut model, &[]);
    // A plan of another ending than the one asked for is dropped.
    let mut model = hidden();
    model.action();
    assert_eq!(model.apply(plan(true, &[])), vec![Ask::Withdraw]);
    assert!(model.page().question.is_none());
    assert_eq!(model.alternative(), None);
}
