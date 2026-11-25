// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Deactivating from the window, on Slint's headless platform: Deactivate…
//! on a hidden session's page, the question that says the computer powers
//! off, Power Off applying the plan, Cancel and Escape withdrawing, and the
//! page while the session ends.

mod screen;
mod support;

use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole};
use nails_api::protocol::{DeactivateArgs, DeactivatePlanData};
use nails_gui::client::{Answer, Plan, PlanData, ours};
use nails_gui::text;
use nails_gui::worker::{Ask, Kind, Update};
use screen::Screen;
use serde_json::{Value, json};
use slint::platform::Key;

/// A warning of the engine's, in its own words: the window shows any it
/// gets.
const WARNING: &str = "A program still holds `/mnt/data/work`: it closes with the session.";

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

/// A hidden session's window.
fn hidden() -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "hidden", "attention": null, "uptime_seconds": 600,
            "hidden_root": "/mnt/data", "hidden_root_mounted": true}}),
    ));
    screen.asks();
    screen
}

fn plan(warnings: &[&str]) -> Update {
    Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: true,
        warnings: warnings.iter().map(|w| (*w).to_string()).collect(),
        powers_off_instead: None,
        token: "0".repeat(32),
    }))
}

/// `screen` with Deactivate… pressed and its question open.
fn asked(screen: &Screen, warnings: &[&str]) {
    screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(
        screen.asks(),
        vec![Ask::Plan(Plan::Deactivate(DeactivateArgs {
            poweroff: true
        }))]
    );
    screen.update(Update::Running(Kind::Plan));
    screen.update(plan(warnings));
    assert!(screen.window.get_question_open());
}

fn enqueued(status: &str) -> Update {
    answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": true,
            "data": {"status": status}}),
    )
}

/// The page while the session ends takes no input from the page or the
/// window's Close.
fn assert_ending(screen: &Screen) {
    let heading = screen.find_with(text::ENDING, AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    assert!(screen.shows(text::POWERING_OFF));
    let close = screen.find_with("Close", AccessibleRole::Button);
    assert_eq!(close.accessible_enabled(), Some(false));
    assert!(!screen.shows(text::DEACTIVATE));
    // But for the Emergency, which stays the way out.
    let emergency = screen.find_with(text::EMERGENCY, AccessibleRole::Button);
    assert_eq!(emergency.accessible_enabled(), Some(true));
    for key in [Key::Escape, Key::Return, Key::Space] {
        screen.press(key);
    }
    assert!(screen.asks().is_empty());
    assert!(!screen.closed());
}

#[test]
fn a_hidden_session_deactivates_through_a_question_that_says_it_powers_off() {
    let screen = hidden();
    assert!(screen.shows(text::HIDDEN_SESSION));
    asked(&screen, &[WARNING]);
    let dialog = screen.find_with(text::DEACTIVATE_QUESTION, AccessibleRole::Groupbox);
    let body = dialog.accessible_description().unwrap_or_default();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines,
        [
            text::DEACTIVATE_CONSEQUENCE,
            "A program still holds /mnt/data/work: it closes with the session."
        ],
        "the engine's warning, its code quotes dropped"
    );
    screen.find_with(text::POWER_OFF, AccessibleRole::Button);
    let buttons: Vec<String> = screen
        .with_role(AccessibleRole::Button)
        .iter()
        .filter_map(|button| button.accessible_label())
        .map(|label| label.to_string())
        .collect();
    assert!(
        !buttons.iter().any(|label| label.contains("Decoy")),
        "Power Off is the only ending: {buttons:?}"
    );
    assert_eq!(screen.focused(), "Cancel", "the focus starts on Cancel");
    // Return on Cancel withdraws the plan.
    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
    assert!(!screen.window.get_question_open());
}

#[test]
fn the_keyboard_walks_the_two_answers_and_the_emergency_and_nothing_else() {
    let screen = hidden();
    asked(&screen, &[]);
    let walk = screen.walk(Key::Tab, 3);
    assert_eq!(walk, [text::POWER_OFF, text::EMERGENCY, "Cancel"]);
    let back = screen.walk(Key::Backtab, 2);
    assert_eq!(back, [text::EMERGENCY, text::POWER_OFF]);
    // Escape anywhere in the question cancels it.
    screen.press(Key::Escape);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
}

#[test]
fn power_off_applies_the_plan_and_the_session_ends() {
    let screen = hidden();
    asked(&screen, &[]);
    while screen.focused() != text::POWER_OFF {
        screen.press(Key::Tab);
    }
    screen.press(Key::Space);
    assert_eq!(screen.asks(), vec![Ask::Apply], "no second plan");
    assert!(!screen.window.get_question_open());
    assert_ending(&screen);
    screen.update(Update::Running(Kind::Apply));
    assert_ending(&screen);
    screen.update(enqueued("poweroff_requested"));
    assert_ending(&screen);
}

#[test]
fn a_failed_deactivation_brings_the_session_page_back_with_why() {
    let screen = hidden();
    asked(&screen, &[]);
    screen
        .find_with(text::POWER_OFF, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.asks();
    screen.update(Update::Running(Kind::Apply));
    screen.update(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
            "code": "invalid_state", "message": "systemctl could not enqueue poweroff.target",
            "next": {"command": "emergency"}}}),
    ));
    assert_eq!(screen.asks(), vec![Ask::Status]);
    assert!(screen.shows("Systemctl could not enqueue poweroff.target."));
    screen.find_with(text::DEACTIVATE, AccessibleRole::Button);
}

/// The plan as the helper gives it now (`deactivate-plan`): the question
/// says the computer powers off, with nothing more to warn of.
#[test]
fn the_helpers_plan_asks_only_whether_to_power_off() {
    let screen = hidden();
    screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.asks();
    let recorded = support::fixture("deactivate-plan");
    screen.update(Update::Planned(PlanData::Deactivate(
        serde_json::from_value(recorded["data"].clone()).unwrap(),
    )));
    assert!(screen.window.get_question_open());
    let dialog = screen.find_with(text::DEACTIVATE_QUESTION, AccessibleRole::Groupbox);
    assert_eq!(
        dialog.accessible_description().as_deref(),
        Some(text::DEACTIVATE_CONSEQUENCE)
    );
    assert_eq!(screen.focused(), "Cancel");
    screen
        .find_with(text::POWER_OFF, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Apply]);
}
