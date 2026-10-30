// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The Emergency control through the model: where it shows, what firing it
//! does to the page and the question, and that nothing comes after it.

use super::*;
use crate::client::Answer;
use nails_api::protocol::DeactivatePlanData;
use serde_json::{Value, json};

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

fn status(place: &str, attention: Value) -> Update {
    answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": attention, "hidden_root": "/mnt/data"}}),
    )
}

fn model() -> Model {
    Model::new(Some(PathBuf::from("/mnt/data/nails")), false)
}

/// A window whose helper said it is in a hidden session.
fn hidden() -> Model {
    let mut model = model();
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("hidden", Value::Null));
    model
}

#[test]
fn it_shows_in_a_hidden_session_and_nowhere_else() {
    let mut decoy = model();
    assert!(!decoy.page().emergency, "not before anything is known");
    decoy.apply(Update::Connected(crate::client::ours()));
    decoy.apply(status("decoy", Value::Null));
    assert!(!decoy.page().emergency);
    assert_eq!(decoy.emergency(), None, "nothing to fire on the decoy");

    assert!(hidden().page().emergency);
    let mut no_way_back = hidden();
    no_way_back.apply(status("hidden", json!("no_way_back")));
    assert!(no_way_back.page().emergency, "it is the way out there");

    // The window's own reading shows it from the start, before the helper
    // answered and once it is gone.
    let mut own = model().in_hidden_session(true);
    assert!(own.page().emergency);
    own.apply(Update::Ended(Failure::Lost { in_flight: false }));
    let page = own.page();
    assert_eq!(page.heading, text::LOST);
    assert!(page.emergency);
    let waiting = Model::new(None, true).in_hidden_session(true);
    assert!(waiting.page().emergency, "also while pkexec asks");
}

#[test]
fn firing_ends_the_page_once_and_nothing_comes_after_it() {
    let mut model = hidden();
    assert_eq!(model.emergency(), Some(Effect::Emergency));
    let page = model.page();
    assert_eq!(page.heading, text::ENDING);
    assert_eq!(page.description, text::EMERGENCY_NOW);
    assert_eq!(page.fix, text::POWER_BUTTON_IF_STILL_ON);
    assert!(page.urgent && page.no_input);
    assert!(!page.emergency, "fired, it is gone");
    assert!(page.action.is_none() && page.question.is_none());
    assert_eq!(model.emergency(), None, "once");

    // Whatever the worker still reports changes nothing and asks nothing.
    for update in [
        Update::Connected(crate::client::ours()),
        status("hidden", Value::Null),
        Update::Running(Kind::Status),
        Update::Withdrawn,
        Update::Ended(Failure::Lost { in_flight: true }),
    ] {
        assert!(model.apply(update).is_empty());
        assert_eq!(model.page(), page);
    }
    assert_eq!(model.answer(true), None);
    assert_eq!(model.alternative(), None);
    assert_eq!(model.action(), None);
}

#[test]
fn firing_closes_an_open_question_without_answering_it() {
    let mut model = hidden();
    model.action();
    model.apply(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: false,
        warnings: vec![],
        powers_off_instead: None,
        token: "0".repeat(32),
    })));
    assert!(model.page().question.is_some());
    assert!(model.page().emergency, "it shows over the question");
    assert_eq!(model.emergency(), Some(Effect::Emergency));
    assert!(model.page().question.is_none());
}

#[test]
fn the_page_of_a_deactivation_that_ends_keeps_it() {
    let mut model = hidden();
    model.action();
    model.apply(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: false,
        warnings: vec![],
        powers_off_instead: None,
        token: "0".repeat(32),
    })));
    model.alternative();
    let page = model.page();
    assert_eq!(page.heading, text::ENDING);
    assert!(page.no_input, "nothing else acts");
    assert!(page.emergency, "the emergency does");
    assert_eq!(model.emergency(), Some(Effect::Emergency));
    assert_eq!(model.page().description, text::EMERGENCY_NOW);
}
