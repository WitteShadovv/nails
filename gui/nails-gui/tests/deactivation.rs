// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Deactivating from the window, on Slint's headless platform: Deactivate…
//! on a hidden session's page, the question with the engine's warnings and
//! both endings, Return to Decoy applying the plan, Power Off planning again
//! and applying without a second question, Cancel and Escape withdrawing,
//! and the page while the session ends.

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

/// The warning of a way back that powers off when it cannot put the
/// network state back, in the engine's words.
const POWERS_OFF_INSTEAD: &str = "The return finds no `ip` (iproute2) in the hidden session's \
    system directories, so the policy-routing rules the session added stay on the decoy until \
    power-off, and a virtual link it made or a MAC address it changed makes the machine power \
    off instead of returning. `sudo /mnt/data/nails deactivate --poweroff` leaves none of them.";

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

fn plan(poweroff: bool, warnings: &[&str]) -> Update {
    Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff,
        warnings: warnings.iter().map(|w| (*w).to_string()).collect(),
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
            poweroff: false
        }))]
    );
    screen.update(Update::Running(Kind::Plan));
    screen.update(plan(false, warnings));
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
fn assert_ending(screen: &Screen, description: &str) {
    let heading = screen.find_with(text::ENDING, AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    assert!(screen.shows(description));
    let close = screen.find_with("Close", AccessibleRole::Button);
    assert_eq!(close.accessible_enabled(), Some(false));
    assert!(!screen.shows(text::DEACTIVATE));
    for key in [Key::Escape, Key::Return, Key::Space] {
        screen.press(key);
    }
    assert!(screen.asks().is_empty());
    assert!(!screen.closed());
}

#[test]
fn a_hidden_session_deactivates_through_a_question_with_both_endings() {
    let screen = hidden();
    assert!(screen.shows(text::HIDDEN_SESSION));
    asked(&screen, &[POWERS_OFF_INSTEAD]);
    let dialog = screen.find_with(text::DEACTIVATE_QUESTION, AccessibleRole::Groupbox);
    let body = dialog.accessible_description().unwrap_or_default();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], text::DEACTIVATE_CONSEQUENCE);
    // The engine's warning, its code quotes dropped: here, that the return
    // would power off instead.
    assert!(
        lines[1].contains("makes the machine power off instead of returning"),
        "{body}"
    );
    assert!(lines[1].ends_with("sudo /mnt/data/nails deactivate --poweroff leaves none of them."));
    screen.find_with(text::POWER_OFF, AccessibleRole::Button);
    screen.find_with(text::RETURN_TO_DECOY, AccessibleRole::Button);
    assert_eq!(screen.focused(), "Cancel", "the focus starts on Cancel");
    // Return on Cancel withdraws the plan.
    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
    assert!(!screen.window.get_question_open());
}

#[test]
fn the_keyboard_walks_the_three_answers_and_stays_with_them() {
    let screen = hidden();
    asked(&screen, &[]);
    let walk = screen.walk(Key::Tab, 3);
    assert_eq!(walk, [text::POWER_OFF, text::RETURN_TO_DECOY, "Cancel"]);
    let back = screen.walk(Key::Backtab, 2);
    assert_eq!(back, [text::RETURN_TO_DECOY, text::POWER_OFF]);
    // Escape anywhere in the question cancels it.
    screen.press(Key::Escape);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
}

#[test]
fn return_to_decoy_applies_the_plan_and_the_session_ends() {
    let screen = hidden();
    asked(&screen, &[]);
    screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    assert!(!screen.window.get_question_open());
    screen.update(Update::Running(Kind::Apply));
    assert_ending(&screen, text::RETURNING);
    screen.update(enqueued("return_requested"));
    assert_ending(&screen, text::RETURNING);
}

#[test]
fn power_off_plans_again_and_applies_without_asking_twice() {
    let screen = hidden();
    asked(&screen, &[]);
    while screen.focused() != text::POWER_OFF {
        screen.press(Key::Tab);
    }
    screen.press(Key::Space);
    assert_eq!(
        screen.asks(),
        vec![Ask::Plan(Plan::Deactivate(DeactivateArgs {
            poweroff: true
        }))]
    );
    assert_ending(&screen, text::POWERING_OFF);
    screen.update(Update::Running(Kind::Plan));
    screen.update(plan(true, &[]));
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    assert!(!screen.window.get_question_open(), "no second question");
    screen.update(Update::Running(Kind::Apply));
    screen.update(enqueued("poweroff_requested"));
    assert_ending(&screen, text::POWERING_OFF);
}

#[test]
fn a_failed_deactivation_brings_the_session_page_back_with_why() {
    let screen = hidden();
    asked(&screen, &[]);
    screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.asks();
    screen.update(Update::Running(Kind::Apply));
    screen.update(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
            "code": "invalid_state", "message": "systemctl could not enqueue soft-reboot.target",
            "next": {"command": "emergency"}}}),
    ));
    assert_eq!(screen.asks(), vec![Ask::Status]);
    assert!(screen.shows("Systemctl could not enqueue soft-reboot.target."));
    screen.find_with(text::DEACTIVATE, AccessibleRole::Button);
}
