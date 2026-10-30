// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Activating from the window, on Slint's headless platform: Activate… on a
//! ready page, the question with the plan's own lines, the steps as they
//! stream, Cancel and Escape before the point of no return, the Logging Out
//! page that takes no input, and a risk allowed only behind its typed word.

mod screen;
mod support;

use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole};
use nails_api::Event;
use nails_api::protocol::{ActivateArgs, ActivatePlanData, CheckArgs};
use nails_gui::client::{Answer, Plan, PlanData, ours};
use nails_gui::text;
use nails_gui::worker::{Ask, Kind, Update};
use screen::Screen;
use serde_json::{Value, json};
use slint::platform::Key;

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

/// A decoy whose check gave `checks`, `failed` of them failed.
fn decoy(checks: Value, failed: usize) -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "decoy", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    screen.update(Update::Running(Kind::Check));
    screen.update(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": failed == 0, "data": {
            "ready": failed == 0, "checks": checks,
            "summary": {"passed": 1, "warnings": 0, "failed": failed}}}),
    ));
    screen.asks();
    screen
}

fn ready() -> Screen {
    decoy(
        json!([{"name": "swap", "status": "pass", "message": "swap is off"}]),
        0,
    )
}

/// A decoy that keeps a persistent record, which can be allowed.
fn persistent() -> Screen {
    decoy(
        json!([{"name": "decoy-persistence", "status": "fail",
            "message": "decoy keeps a persistent record of the hidden session: a journal on disk",
            "remediation": "make the decoy amnesic, or pass --allow-persistent-decoy"}]),
        1,
    )
}

/// `screen` with its activation's question open.
fn asked(screen: &Screen) {
    screen
        .find_with(text::ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(
        screen.asks(),
        vec![Ask::Plan(Plan::Activate(ActivateArgs::default()))]
    );
    screen.update(Update::Running(Kind::Plan));
    screen.update(Update::Planned(PlanData::Activate(ActivatePlanData {
        warning: None,
        defaults_notice: None,
        builds_hidden_system: true,
        token: "0".repeat(32),
    })));
}

/// `screen` with its activation confirmed and its apply running.
fn activating(screen: &Screen) {
    asked(screen);
    screen
        .find_with(text::LOG_OUT_AND_ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    screen.update(Update::Running(Kind::Apply));
}

fn step(label: &str, index: u32) -> Update {
    Update::Event(Event::Step {
        phase: "x".to_string(),
        label: label.to_string(),
        index,
        total: 6,
    })
}

/// The state each step row shows, by its label.
fn step_state(screen: &Screen, label: &str) -> String {
    screen
        .find_with(label, AccessibleRole::ListItem)
        .accessible_description()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_ready_page_activates_through_a_question_that_starts_on_cancel() {
    let screen = ready();
    assert!(screen.shows(text::READY));
    assert_eq!(
        screen.labels(AccessibleRole::Button),
        ["Close", text::ACTIVATE]
    );
    asked(&screen);
    let dialog = screen.find_with(text::ACTIVATE_QUESTION, AccessibleRole::Groupbox);
    let body = dialog.accessible_description().unwrap_or_default();
    assert_eq!(
        body.lines().collect::<Vec<_>>(),
        [text::ACTIVATE_CONSEQUENCE, text::BUILDS_HIDDEN_SYSTEM]
    );
    assert_eq!(screen.focused(), "Cancel");
    // Return on Cancel, where the focus starts, withdraws the plan.
    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
    assert!(!screen.window.get_question_open());
}

#[test]
fn the_steps_show_as_they_stream_and_cancel_hangs_up_on_the_helper() {
    let screen = ready();
    activating(&screen);
    assert!(screen.shows(text::ACTIVATING));
    assert!(screen.shows(text::ACTIVATING_WHERE));
    assert_eq!(step_state(&screen, text::STEP_CHECKING), "Now");
    screen.update(step("Staging the runtime", 1));
    assert_eq!(step_state(&screen, text::STEP_CHECKING), "Done");
    assert_eq!(step_state(&screen, "Staging the runtime"), "Now");
    let busy = screen.with_role(AccessibleRole::ProgressIndicator);
    assert_eq!(
        busy[0].accessible_label().as_deref(),
        Some("Staging the runtime")
    );

    screen
        .find_with(text::CANCEL, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(screen.hang_ups(), 1);
    assert!(screen.asks().is_empty(), "a cancel is no request");
    assert_eq!(screen.labels(AccessibleRole::Button), ["Close"]);
    let busy = screen.with_role(AccessibleRole::ProgressIndicator);
    assert_eq!(
        busy[0].accessible_label().as_deref(),
        Some(text::CANCELLING)
    );

    screen.update(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "activate", "ok": false, "error": {
            "code": "cancelled", "message": "Activation cancelled; nothing was changed.", "next": null}}),
    ));
    assert!(screen.shows(text::ACTIVATION_CANCELLED));
    assert!(screen.shows("Activation cancelled; nothing was changed."));
    assert!(screen.shows(&text::open_again(Some(std::path::Path::new(
        "/mnt/data/nails"
    )))));
    assert_eq!(screen.labels(AccessibleRole::Button), ["Close"]);
    assert!(screen.asks().is_empty());
}

#[test]
fn escape_cancels_before_the_point_of_no_return_and_only_once() {
    let screen = ready();
    activating(&screen);
    screen.press(Key::Escape);
    assert_eq!(screen.hang_ups(), 1);
    screen.press(Key::Escape);
    assert_eq!(screen.hang_ups(), 1);
    assert!(!screen.closed(), "Escape never closes the window");
}

#[test]
fn past_the_point_of_no_return_the_window_takes_no_input() {
    let screen = ready();
    activating(&screen);
    screen.update(step("Staging the runtime", 1));
    screen.update(Update::Event(Event::PointOfNoReturn));
    assert!(screen.shows(text::LOGGING_OUT));
    assert!(screen.shows(text::LOG_IN_AGAIN));
    let heading = screen.find_with(text::LOGGING_OUT, AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    assert!(screen.with_role(AccessibleRole::ListItem).is_empty());
    // Not even the window's Close acts.
    assert_eq!(screen.labels(AccessibleRole::Button), ["Close"]);
    let close = screen.find_with("Close", AccessibleRole::Button);
    assert_eq!(close.accessible_enabled(), Some(false));
    close.invoke_accessible_default_action();
    for key in [Key::Escape, Key::Tab, Key::Return, Key::Space, Key::Backtab] {
        screen.press(key);
    }
    assert_eq!(screen.hang_ups(), 0);
    assert!(screen.asks().is_empty());
    assert!(!screen.closed());
    // The switch ends the session, and the page stays.
    screen.update(answered(
        Kind::Apply,
        json!({"command": "activate", "ok": true, "data": {"status": "entering"}}),
    ));
    screen.update(Update::Ended(nails_gui::worker::Failure::Lost {
        in_flight: false,
    }));
    assert!(screen.shows(text::LOGGING_OUT));
}

#[test]
fn a_risk_is_allowed_only_once_its_word_is_typed() {
    let screen = persistent();
    assert!(screen.shows(text::NOT_READY));
    screen
        .find_with(text::ALLOW, AccessibleRole::Button)
        .invoke_accessible_default_action();
    let dialog = screen.find_with(text::ALLOW_QUESTION, AccessibleRole::Groupbox);
    assert_eq!(
        dialog.accessible_description().as_deref(),
        Some(
            "Decoy keeps a persistent record of the hidden session: a journal on disk.\n\
             This is allowed for one activation only."
        )
    );
    let prompt = text::type_to_continue(text::ALLOW_WORD);
    screen.find_with(&prompt, AccessibleRole::TextInput);
    assert_eq!(screen.focused(), prompt, "the field takes the focus");
    let allow = || screen.find_with(text::ALLOW_CONFIRM, AccessibleRole::Button);
    assert_eq!(allow().accessible_enabled(), Some(false));
    allow().invoke_accessible_default_action();
    assert!(screen.asks().is_empty(), "no click allows it");

    screen.type_text("Allo");
    assert_eq!(allow().accessible_enabled(), Some(false));
    screen.type_text("w ");
    assert_eq!(allow().accessible_enabled(), Some(true));
    allow().invoke_accessible_default_action();
    assert_eq!(
        screen.asks(),
        vec![Ask::Check(CheckArgs {
            allow_persistent_decoy: true,
            ..CheckArgs::default()
        })]
    );
    assert!(!screen.window.get_question_open());

    // The check with the flag passes, and the page names what was allowed.
    screen.update(Update::Running(Kind::Check));
    screen.update(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true,
            "checks": [{"name": "decoy-persistence", "status": "warn", "message": "allowed for this run"}],
            "summary": {"passed": 0, "warnings": 1, "failed": 0}}}),
    ));
    let fact = screen.find_with(text::FACT_ALLOWED, AccessibleRole::ListItem);
    assert_eq!(
        fact.accessible_description().as_deref(),
        Some(text::RISK_PERSISTENT_DECOY)
    );
    screen
        .find_with(text::ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(
        screen.asks(),
        vec![Ask::Plan(Plan::Activate(ActivateArgs {
            allow_persistent_decoy: true,
            ..ActivateArgs::default()
        }))]
    );
}

#[test]
fn the_field_takes_a_value_from_a_screen_reader_too() {
    let screen = persistent();
    screen
        .find_with(text::ALLOW, AccessibleRole::Button)
        .invoke_accessible_default_action();
    let prompt = text::type_to_continue(text::ALLOW_WORD);
    screen
        .find_with(&prompt, AccessibleRole::TextInput)
        .set_accessible_value("ALLOW");
    let allow = screen.find_with(text::ALLOW_CONFIRM, AccessibleRole::Button);
    assert_eq!(allow.accessible_enabled(), Some(true));
}

#[test]
fn the_typed_question_keeps_the_keyboard_and_escape_cancels_it() {
    let screen = persistent();
    screen
        .find_with(text::ALLOW, AccessibleRole::Button)
        .invoke_accessible_default_action();
    let prompt = text::type_to_continue(text::ALLOW_WORD);
    // Allow waits for the word, so the keyboard skips it.
    let walk = screen.walk(Key::Tab, 3);
    assert_eq!(walk, ["Cancel", prompt.as_str(), "Cancel"]);
    screen.press(Key::Tab);
    screen.type_text("allow");
    let walk = screen.walk(Key::Tab, 3);
    assert_eq!(walk, ["Cancel", text::ALLOW_CONFIRM, prompt.as_str()]);
    // Return in the field does not confirm.
    screen.press(Key::Return);
    assert!(screen.asks().is_empty());
    assert!(screen.window.get_question_open());
    screen.press(Key::Escape);
    assert!(!screen.window.get_question_open());
    assert!(screen.asks().is_empty(), "Escape allows nothing");
    // The row still offers it.
    screen.find_with(text::ALLOW, AccessibleRole::Button);
}

#[test]
fn a_problem_that_can_be_allowed_is_followed_by_its_button_in_the_tab_order() {
    let screen = persistent();
    let row = format!(
        "Failed: {}",
        "Decoy keeps a persistent record of the hidden session: a journal on disk."
    );
    let walk = screen.walk(Key::Tab, 5);
    assert_eq!(
        walk,
        [
            "Hidden volume",
            "This computer",
            row.as_str(),
            text::ALLOW,
            text::CHECK_AGAIN
        ]
    );
}
