// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The Emergency control through the model: where it shows, what firing it
//! does to the page and the question, that nothing comes after it, and how
//! the setting read in advance decides how it ends the session.

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
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
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
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
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
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
    assert_eq!(model.page().description, text::EMERGENCY_NOW);
}

/// The recorded settings with `window.emergency` set to `spelling`, as
/// `config show` gives them.
fn settings_with(spelling: Value) -> Update {
    let mut shown: Value =
        serde_json::from_str(include_str!("../tests/fixtures/config-show.json")).unwrap();
    shown["data"]["config"]["window"]["emergency"] = spelling;
    answered(Kind::Config, shown)
}

/// The fact of a hidden session's page that says what Emergency does.
fn fact(model: &Model) -> String {
    let page = model.page();
    let facts: Vec<&(String, String)> = page
        .facts
        .iter()
        .filter(|(title, _)| title == text::FACT_EMERGENCY)
        .collect();
    assert_eq!(facts.len(), 1, "{:?}", page.facts);
    facts[0].1.clone()
}

#[test]
fn the_settings_are_read_once_a_hidden_session_has_its_status_and_never_on_the_decoy() {
    let mut decoy = model();
    decoy.apply(Update::Connected(crate::client::ours()));
    let asks = decoy.apply(status("decoy", Value::Null));
    assert!(matches!(asks[..], [Ask::Check(_)]), "{asks:?}");

    let mut hidden = model();
    hidden.apply(Update::Connected(crate::client::ours()));
    assert_eq!(
        hidden.apply(status("hidden", Value::Null)),
        [Ask::ConfigShow]
    );
    assert!(
        hidden.apply(status("hidden", Value::Null)).is_empty(),
        "once: the reads after it keep it up to date"
    );

    // By the window's own reading too, whatever the status says.
    let mut own = model().in_hidden_session(true);
    own.apply(Update::Connected(crate::client::ours()));
    assert_eq!(
        own.apply(status("unknown", json!("record_unreadable"))),
        [Ask::ConfigShow]
    );
}

#[test]
fn the_emergency_ends_as_the_setting_says_and_the_page_says_so_first() {
    for (spelling, finish, name, now, then) in [
        (
            "return",
            Finish::Return,
            "Return to the decoy",
            text::EMERGENCY_RETURNING_NOW,
            text::POWER_OFF_IF_STILL_HERE,
        ),
        (
            "poweroff",
            Finish::PowerOff,
            "Power off",
            text::EMERGENCY_NOW,
            text::POWER_BUTTON_IF_STILL_ON,
        ),
        (
            "reboot",
            Finish::Reboot,
            "Restart",
            text::EMERGENCY_RESTARTING_NOW,
            text::POWER_OFF_IF_STILL_HERE,
        ),
    ] {
        let mut model = hidden();
        assert!(model.apply(settings_with(json!(spelling))).is_empty());
        // Before it is used: the page's fact and the control's description.
        assert_eq!(fact(&model), name, "{spelling}");
        assert_eq!(model.page().emergency_how, text::emergency_how(finish));
        assert_eq!(model.emergency(), Some(Effect::Emergency(finish)));
        let page = model.page();
        assert_eq!(page.heading, text::ENDING);
        assert_eq!((page.description.as_str(), page.fix.as_str()), (now, then));
    }
}

#[test]
fn a_setting_not_read_unreadable_or_unknown_powers_off_and_the_page_says_why() {
    let not_read = hidden();
    assert_eq!(
        fact(&not_read),
        format!("Power off, {}", text::EMERGENCY_NOT_READ)
    );
    assert_eq!(
        not_read.page().emergency_how,
        text::emergency_how(Finish::PowerOff)
    );
    let mut not_read = not_read;
    assert_eq!(
        not_read.emergency(),
        Some(Effect::Emergency(Finish::PowerOff))
    );

    let mut missing: Value =
        serde_json::from_str(include_str!("../tests/fixtures/config-show.json")).unwrap();
    missing["data"]["config"]
        .as_object_mut()
        .unwrap()
        .remove("window");
    let invalid: Value =
        serde_json::from_str(include_str!("../tests/fixtures/config-show-invalid.json")).unwrap();
    for (what, update) in [
        ("an unknown value", settings_with(json!("halt"))),
        ("a value of another kind", settings_with(json!(true))),
        ("no value", answered(Kind::Config, missing)),
        (
            "a file the engine cannot read",
            answered(Kind::Config, invalid),
        ),
        (
            "another command's answer",
            answered(Kind::Config, json!({"command": "status"})),
        ),
    ] {
        let mut model = hidden();
        model.apply(update);
        assert_eq!(
            fact(&model),
            format!("Power off, {}", text::EMERGENCY_UNREADABLE),
            "{what}"
        );
        assert_eq!(
            model.emergency(),
            Some(Effect::Emergency(Finish::PowerOff)),
            "{what}"
        );
        assert_eq!(model.page().description, text::EMERGENCY_NOW);
    }

    // The last read decides: one that fails after one that worked powers
    // off, and one that works again ends as it says.
    let mut model = hidden();
    model.apply(settings_with(json!("return")));
    model.apply(answered(Kind::Config, json!({"command": "config"})));
    assert_eq!(model.emergency_finish().0, Finish::PowerOff);
    model.apply(settings_with(json!("reboot")));
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::Reboot)));
}

#[test]
fn a_return_without_a_way_back_powers_off_and_a_restart_does_not() {
    let mut model = hidden();
    model.apply(settings_with(json!("return")));
    model.apply(status("hidden", json!("no_way_back")));
    assert_eq!(model.page().heading, text::NO_WAY_BACK);
    assert_eq!(
        fact(&model),
        format!("Power off, {}", text::EMERGENCY_NO_WAY_BACK)
    );
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));

    // A full restart needs no way back.
    let mut model = hidden();
    model.apply(settings_with(json!("reboot")));
    model.apply(status("hidden", json!("no_way_back")));
    assert_eq!(fact(&model), "Restart");
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::Reboot)));
}

#[test]
fn without_its_helper_the_window_powers_off_whatever_the_setting() {
    let mut model = hidden();
    model.apply(settings_with(json!("return")));
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page().heading, text::LOST);
    assert_eq!(
        model.page().emergency_how,
        text::emergency_how(Finish::PowerOff)
    );
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
    assert_eq!(model.page().description, text::EMERGENCY_NOW);

    // Also where the page stays that of a deactivation that ends.
    let mut model = hidden();
    model.apply(settings_with(json!("reboot")));
    model.action();
    model.apply(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: false,
        warnings: vec![],
        powers_off_instead: None,
        token: "0".repeat(32),
    })));
    model.alternative();
    model.apply(Update::Ended(Failure::Lost { in_flight: true }));
    assert_eq!(model.page().heading, text::ENDING, "the page stays");
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));

    // Before the helper answered, nothing was read.
    let mut waiting = Model::new(None, true).in_hidden_session(true);
    assert_eq!(
        waiting.page().emergency_how,
        text::emergency_how(Finish::PowerOff)
    );
    assert_eq!(
        waiting.emergency(),
        Some(Effect::Emergency(Finish::PowerOff))
    );
}

#[test]
fn a_change_saved_on_settings_holds_from_the_read_after_it() {
    let mut model = hidden();
    model.apply(settings_with(json!("return")));
    let settings = model
        .page()
        .links
        .iter()
        .position(|link| link.tool == ToolKind::Settings)
        .unwrap();
    assert_eq!(model.open(settings), Some(Ask::ConfigShow));
    // The Settings page's own read: the tool shows it, and the Emergency
    // control ends as it says.
    model.apply(settings_with(json!("poweroff")));
    assert_eq!(model.page().view, View::Tool(ToolKind::Settings));
    assert!(!model.page().choices.is_empty(), "the list is shown");
    assert_eq!(
        model.page().emergency_how,
        text::emergency_how(Finish::PowerOff)
    );
    assert_eq!(model.back(), Some(Ask::Status));
    model.apply(status("hidden", Value::Null));
    assert_eq!(fact(&model), "Power off");
}

#[test]
fn a_read_of_the_settings_is_no_answer_of_another_tool() {
    let mut model = hidden();
    // Verify opens before the settings came in.
    let verify = model
        .page()
        .links
        .iter()
        .position(|link| link.tool == ToolKind::Verify)
        .unwrap();
    model.open(verify);
    let before = model.page();
    assert!(model.apply(settings_with(json!("reboot"))).is_empty());
    let after = model.page();
    assert_eq!(
        Page {
            emergency_how: before.emergency_how.clone(),
            ..after.clone()
        },
        before,
        "Verify's page is as it was"
    );
    assert_eq!(after.emergency_how, text::emergency_how(Finish::Reboot));
}
