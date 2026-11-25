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
    let mut without_plan = hidden();
    without_plan.apply(status("hidden", json!("no_way_back")));
    assert!(without_plan.page().emergency, "without its plan too");

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
    assert_eq!(model.action(), None);
}

#[test]
fn firing_closes_an_open_question_without_answering_it() {
    let mut model = hidden();
    model.action();
    model.apply(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: true,
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
    deactivation_asked(&mut model);
    assert_eq!(model.answer(true), Some(Ask::Apply));
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

/// The fact of `page` that says what Emergency does, if it has one; never
/// more than one.
fn fact_of(page: &Page) -> Option<String> {
    let facts: Vec<&(String, String)> = page
        .facts
        .iter()
        .filter(|(title, _)| title == text::FACT_EMERGENCY)
        .collect();
    assert!(facts.len() < 2, "{:?}", page.facts);
    facts.first().map(|(_, value)| value.clone())
}

/// The fact of the page that says what Emergency does.
fn fact(model: &Model) -> String {
    let page = model.page();
    fact_of(&page).unwrap_or_else(|| panic!("no fact of the Emergency: {:?}", page.facts))
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
    model.apply(settings_with(json!("reboot")));
    model.apply(answered(Kind::Config, json!({"command": "config"})));
    assert_eq!(model.emergency_finish().0, Finish::PowerOff);
    model.apply(settings_with(json!("reboot")));
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::Reboot)));
}

/// The `return` of an older engine's settings, the ending before every
/// hidden session ended in a power-off, is a power-off, as the engine reads
/// it now: nothing says the computer powers off instead of something else.
#[test]
fn an_older_return_in_the_settings_reads_as_a_power_off() {
    let mut model = hidden();
    model.apply(settings_with(json!("return")));
    assert_eq!(fact(&model), "Power off");
    assert_eq!(
        model.page().emergency_how,
        text::emergency_how(Finish::PowerOff)
    );
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
    assert_eq!(model.page().description, text::EMERGENCY_NOW);
}

/// A hidden session without its session plan ends as the setting says: a
/// restart needs no plan, and neither does Deactivate's power-off.
#[test]
fn without_its_session_plan_the_emergency_ends_as_set() {
    for (spelling, name, finish) in [
        ("poweroff", "Power off", Finish::PowerOff),
        ("reboot", "Restart", Finish::Reboot),
    ] {
        let mut model = hidden();
        model.apply(settings_with(json!(spelling)));
        model.apply(status("hidden", json!("no_way_back")));
        let page = model.page();
        assert_eq!(page.heading, text::NO_SESSION_PLAN);
        assert_eq!(page.action, Some(text::DEACTIVATE));
        assert_eq!(fact(&model), name);
        assert_eq!(model.emergency(), Some(Effect::Emergency(finish)));
    }
}

#[test]
fn without_its_helper_the_window_powers_off_whatever_the_setting() {
    let no_helper = format!("Power off, {}", text::EMERGENCY_NO_HELPER);
    let mut model = hidden();
    model.apply(settings_with(json!("reboot")));
    model.apply(Update::Ended(Failure::Lost { in_flight: false }));
    assert_eq!(model.page().heading, text::LOST);
    assert_eq!(fact(&model), no_helper, "the page says so, and why");
    assert_eq!(
        model.page().emergency_how,
        text::emergency_how(Finish::PowerOff)
    );
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
    assert_eq!(model.page().description, text::EMERGENCY_NOW);

    // The page of a deactivation that ends stays as it is when the
    // power-off takes the helper with the session. Once the power-off is
    // overdue and the page names the control as a way out, it says the
    // control powers off, and why.
    let mut model = hidden();
    model.apply(settings_with(json!("reboot")));
    deactivation_asked(&mut model);
    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    model.apply(Update::Ended(Failure::Lost { in_flight: true }));
    let page = model.page();
    assert_eq!(page.heading, text::ENDING, "the page stays");
    assert_eq!(page.description, text::POWERING_OFF);
    assert_eq!(fact_of(&page), None);
    assert_eq!(page.emergency_how, text::emergency_how(Finish::PowerOff));
    model.set_switch_overdue(true);
    let page = model.page();
    assert_eq!(
        (page.description.as_str(), page.fix.as_str()),
        (text::ENDING_LATE, text::END_ANOTHER_WAY)
    );
    assert_eq!(fact(&model), no_helper, "overdue");
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));

    // A window that never had its helper, by its own reading of the mount
    // table.
    let mut never = Model::new(None, false).in_hidden_session(true);
    never.apply(Update::Ended(Failure::NotStarted(
        "pkexec could not be started".to_string(),
    )));
    assert_eq!(never.page().heading, text::NOT_STARTED);
    assert_eq!(fact(&never), no_helper);

    // Before the helper answered, nothing was read.
    let mut waiting = Model::new(None, true).in_hidden_session(true);
    assert_eq!(waiting.page().heading, text::WAITING_FOR_PASSWORD);
    assert_eq!(
        fact(&waiting),
        format!("Power off, {}", text::EMERGENCY_NOT_READ)
    );
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
    model.apply(settings_with(json!("reboot")));
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
    // A tool's page names what Emergency does only where it powers off
    // instead of ending as the setting says.
    assert_eq!(
        fact_of(&before),
        Some(format!("Power off, {}", text::EMERGENCY_NOT_READ))
    );
    assert!(model.apply(settings_with(json!("reboot"))).is_empty());
    let after = model.page();
    assert_eq!(fact_of(&after), None);
    assert_eq!(
        Page {
            emergency_how: before.emergency_how.clone(),
            facts: before.facts.clone(),
            ..after.clone()
        },
        before,
        "Verify's page is as it was"
    );
    assert_eq!(after.emergency_how, text::emergency_how(Finish::Reboot));
}

/// The recorded answer `name` of the helper's.
fn recorded(name: &str) -> Value {
    let text = match name {
        "verify-clean" => include_str!("../tests/fixtures/verify-clean.json"),
        "rehearse-status-planted" => include_str!("../tests/fixtures/rehearse-status-planted.json"),
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(text).unwrap()
}

/// The question before a deactivation open on `model`, on the plan of its
/// power-off.
fn deactivation_asked(model: &mut Model) {
    assert!(matches!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::Deactivate(_))))
    ));
    model.apply(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: true,
        warnings: vec![],
        powers_off_instead: None,
        token: "0".repeat(32),
    })));
    assert!(model.page().question.is_some());
}

#[test]
fn while_the_helper_verifies_or_rehearses_it_powers_off_and_says_why() {
    let busy = format!("Power off, {}", text::EMERGENCY_BUSY);
    for (tool, kind, answer) in [
        (ToolKind::Verify, Kind::Verify, "verify-clean"),
        (
            ToolKind::Rehearsal,
            Kind::Rehearse,
            "rehearse-status-planted",
        ),
    ] {
        for (spelling, finish) in [("reboot", Finish::Reboot), ("poweroff", Finish::PowerOff)] {
            let mut model = hidden();
            model.apply(settings_with(json!(spelling)));
            let index = model
                .page()
                .links
                .iter()
                .position(|link| link.tool == tool)
                .unwrap();
            let asked = model.open(index);
            if tool == ToolKind::Rehearsal {
                // Rehearsal opens with the read of where the rehearsal
                // stands, a request of its own as much as a step is.
                assert_eq!(asked, Some(Ask::Rehearse(crate::worker::Rehearse::Status)));
            }
            assert_eq!(fact_of(&model.page()), None, "{spelling}: as set, at rest");
            // The helper reads the emergency only once the request that runs
            // is answered, and the window does not wait that long.
            model.apply(Update::Running(kind));
            let page = model.page();
            assert!(page.busy.is_some(), "{tool:?}");
            assert_eq!(fact(&model), busy, "{tool:?}, {spelling}");
            assert_eq!(page.emergency_how, text::emergency_how(Finish::PowerOff));
            let mut fired = model.clone();
            assert_eq!(
                fired.emergency(),
                Some(Effect::Emergency(Finish::PowerOff)),
                "{tool:?}, {spelling}"
            );
            assert_eq!(fired.page().description, text::EMERGENCY_NOW);
            // Once it is answered, the setting holds again.
            model.apply(answered(kind, recorded(answer)));
            assert_eq!(fact_of(&model.page()), None, "{tool:?}, {spelling}");
            assert_eq!(model.emergency(), Some(Effect::Emergency(finish)));
        }
    }
    // A short request of the session's own is no reason.
    let mut model = hidden();
    model.apply(settings_with(json!("reboot")));
    model.apply(Update::Running(Kind::Status));
    assert_eq!(fact(&model), "Restart");
    assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::Reboot)));
}

#[test]
fn while_a_deactivation_powers_off_a_restart_powers_off_too() {
    let powering_off = format!("Power off, {}", text::EMERGENCY_POWERING_OFF);
    for (spelling, finish) in [("reboot", Finish::Reboot), ("poweroff", Finish::PowerOff)] {
        let mut model = hidden();
        model.apply(settings_with(json!(spelling)));
        deactivation_asked(&mut model);
        // Asked, nothing is chosen yet.
        assert_eq!(model.emergency_finish(), (finish, None), "{spelling}");
        // Power Off: the plan is applied.
        assert_eq!(model.answer(true), Some(Ask::Apply));
        let expected = (finish != Finish::PowerOff).then(|| powering_off.clone());
        let page = model.page();
        assert_eq!(page.description, text::POWERING_OFF);
        assert_eq!(fact_of(&page), expected, "{spelling}, applied");
        assert_eq!(page.emergency_how, text::emergency_how(Finish::PowerOff));
        model.apply(Update::Running(Kind::Apply));
        assert!(
            model
                .apply(answered(
                    Kind::Apply,
                    json!({"schema_version": 2, "command": "deactivate", "ok": true,
                        "data": {"status": "poweroff_requested"}}),
                ))
                .is_empty()
        );
        assert_eq!(fact_of(&model.page()), expected, "{spelling}, answered");
        assert_eq!(model.emergency(), Some(Effect::Emergency(Finish::PowerOff)));
        assert_eq!(model.page().description, text::EMERGENCY_NOW);
    }
}
