// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The Emergency control on Slint's headless platform, its time mocked: the
//! hold whose bar fills in about a second and ends the session on release,
//! the short press that only says to hold, the pointer moving off, the
//! keyboard's two presses with Escape and Tab cancelling, a screen reader's
//! two actions, and the control above an open question and on the page of
//! a deactivation that ends.

mod screen;
mod support;

use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole, ElementHandle};
use nails_api::protocol::DeactivatePlanData;
use nails_gui::client::{Answer, PlanData, ours};
use nails_gui::text;
use nails_gui::worker::{Failure, Kind, Update};
use screen::Screen;
use serde_json::{Value, json};
use slint::LogicalPosition;
use slint::platform::Key;

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

fn status(place: &str) -> Update {
    answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": null, "uptime_seconds": 600,
            "hidden_root": "/mnt/data", "hidden_root_mounted": true}}),
    )
}

/// A hidden session's window, its status read.
fn hidden() -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(status("hidden"));
    screen.asks();
    screen
}

/// The control, by whatever its label says now.
fn control(screen: &Screen) -> ElementHandle {
    let found: Vec<ElementHandle> = [
        text::EMERGENCY,
        text::EMERGENCY_KEEP_HOLDING,
        text::EMERGENCY_RELEASE,
        text::EMERGENCY_HOLD_HINT,
        text::EMERGENCY_AGAIN,
    ]
    .iter()
    .flat_map(|label| {
        screen
            .with_role(AccessibleRole::Button)
            .into_iter()
            .filter(move |b| b.accessible_label().as_deref() == Some(*label))
    })
    .collect();
    assert_eq!(found.len(), 1, "one Emergency control");
    found.into_iter().next().unwrap()
}

fn label(screen: &Screen) -> String {
    control(screen)
        .accessible_label()
        .unwrap_or_default()
        .to_string()
}

/// Hold the control for `ms` of mocked time at its middle, then let go at
/// `release` (its middle when `None`).
fn hold(screen: &Screen, ms: u64, release: Option<LogicalPosition>) {
    let at = screen.middle(&control(screen));
    screen.press_at(at);
    screen.wait_ms(ms);
    screen.release_at(release.unwrap_or(at));
}

fn assert_ended(screen: &Screen) {
    assert_eq!(screen.emergencies(), 1, "the emergency fired once");
    let heading = screen.find_with(text::ENDING, AccessibleRole::Text);
    assert_eq!(
        heading.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    assert!(screen.shows(text::EMERGENCY_NOW));
    assert!(screen.shows(text::POWER_BUTTON_IF_STILL_ON));
    assert!(
        screen
            .with_role(AccessibleRole::Button)
            .iter()
            .all(|b| b.accessible_label().as_deref() == Some("Close")
                && b.accessible_enabled() == Some(false)),
        "nothing acts any more"
    );
}

#[test]
fn it_sits_at_the_start_of_a_hidden_sessions_header_bar_and_says_how() {
    let screen = hidden();
    let button = control(&screen);
    assert_eq!(label(&screen), text::EMERGENCY);
    assert_eq!(
        button.accessible_description().as_deref(),
        Some(text::EMERGENCY_HOW)
    );
    assert_eq!(
        button.accessible_live_region(),
        Some(AccessibleLiveness::Assertive)
    );
    let (at, size) = (button.absolute_position(), button.size());
    assert!(size.width >= 44.0 && size.height >= 44.0, "{size:?}");
    assert!(
        at.x < 20.0 && at.y < 2.0,
        "at the start, in the header bar: {at:?}"
    );
    assert_ne!(
        screen.focused(),
        text::EMERGENCY,
        "the focus never starts there"
    );

    // Not on the decoy.
    let decoy = Screen::new(false);
    decoy.update(Update::Connected(ours()));
    decoy.update(status("decoy"));
    assert!(!decoy.shows(text::EMERGENCY));
}

#[test]
fn holding_until_the_bar_is_full_and_letting_go_ends_the_session() {
    let screen = hidden();
    let at = screen.middle(&control(&screen));
    screen.press_at(at);
    assert_eq!(label(&screen), text::EMERGENCY_KEEP_HOLDING);
    screen.wait_ms(500);
    assert_eq!(label(&screen), text::EMERGENCY_KEEP_HOLDING);
    assert_eq!(screen.emergencies(), 0, "holding alone does nothing");
    screen.wait_ms(600);
    assert_eq!(label(&screen), text::EMERGENCY_RELEASE);
    assert_eq!(screen.emergencies(), 0, "not before the release");
    screen.release_at(at);
    assert_ended(&screen);
}

#[test]
fn a_press_too_short_says_to_hold_for_two_seconds() {
    let screen = hidden();
    hold(&screen, 300, None);
    assert_eq!(screen.emergencies(), 0);
    assert_eq!(label(&screen), text::EMERGENCY_HOLD_HINT);
    screen.wait_ms(1500);
    assert_eq!(label(&screen), text::EMERGENCY_HOLD_HINT);
    screen.wait_ms(600);
    assert_eq!(label(&screen), text::EMERGENCY);
}

#[test]
fn moving_off_the_button_cancels_even_a_full_hold() {
    let screen = hidden();
    let at = screen.middle(&control(&screen));
    let off = LogicalPosition::new(at.x, at.y + 200.0);
    screen.press_at(at);
    screen.wait_ms(1200);
    screen.move_to(off);
    screen.release_at(off);
    assert_eq!(screen.emergencies(), 0);
    // Coming back before the release does not undo the cancel.
    screen.press_at(at);
    screen.wait_ms(1200);
    screen.move_to(off);
    screen.move_to(at);
    screen.release_at(at);
    assert_eq!(screen.emergencies(), 0);
    assert_eq!(label(&screen), text::EMERGENCY);
    // A hold that stays on it still works.
    hold(&screen, 1100, None);
    assert_ended(&screen);
}

#[test]
fn another_buttons_release_ends_the_press_for_good() {
    use slint::ComponentHandle;
    use slint::platform::{PointerEventButton, WindowEvent};
    let screen = hidden();
    let button = control(&screen);
    let (at, size) = (button.absolute_position(), button.size());
    let middle = screen.middle(&button);
    let off = LogicalPosition::new(middle.x, 300.0);
    let beside = LogicalPosition::new(at.x + size.width + 4.0, middle.y);
    // Held, then the right button pressed and let go on it: the toolkit's
    // hold on the pointer ends there, with no cancel for the left press.
    screen.press_at(middle);
    for event in [
        WindowEvent::PointerPressed {
            position: middle,
            button: PointerEventButton::Right,
        },
        WindowEvent::PointerReleased {
            position: middle,
            button: PointerEventButton::Right,
        },
    ] {
        screen.window.window().dispatch_event(event);
    }
    // The left button let go off it, where its release goes elsewhere.
    screen.move_to(off);
    screen.release_at(off);
    assert_eq!(screen.emergencies(), 0);
    // Long after, a press beside it let go on it is no hold of its own.
    screen.wait_ms(1100);
    screen.press_at(beside);
    screen.move_to(middle);
    screen.release_at(middle);
    assert_eq!(screen.emergencies(), 0, "the old press was over");
    assert_eq!(label(&screen), text::EMERGENCY);
    // A hold of its own still ends the session.
    hold(&screen, 1100, None);
    assert_ended(&screen);
}

#[test]
fn a_press_beside_it_let_go_on_it_does_nothing() {
    let screen = hidden();
    let button = control(&screen);
    let (at, size) = (button.absolute_position(), button.size());
    let middle = screen.middle(&button);
    // Long after it appeared: a press it never saw must not count as held.
    screen.wait_ms(1100);
    for beside in [
        // The header bar's strip left of it, its row above it and the bar
        // right of its label, where a window drag starts; and the page.
        LogicalPosition::new(at.x - 3.0, middle.y),
        LogicalPosition::new(middle.x, at.y - 0.5),
        LogicalPosition::new(at.x + size.width + 4.0, middle.y),
        LogicalPosition::new(middle.x, 300.0),
    ] {
        screen.press_at(beside);
        screen.wait_ms(1100);
        screen.move_to(middle);
        screen.release_at(middle);
        assert_eq!(screen.emergencies(), 0, "pressed at {beside:?}");
        assert_eq!(label(&screen), text::EMERGENCY, "not even a hint");
    }
    // A hold of its own still ends the session.
    hold(&screen, 1100, None);
    assert_ended(&screen);
}

#[test]
fn the_keyboard_takes_two_presses_and_escape_or_tab_cancels() {
    let screen = hidden();
    let walk = screen.walk(Key::Tab, 5);
    assert_eq!(
        walk,
        [
            "Hidden volume",
            text::VERIFY,
            text::REHEARSAL,
            text::DEACTIVATE,
            text::EMERGENCY
        ],
        "after the page, never first"
    );
    screen.press(Key::Return);
    assert_eq!(label(&screen), text::EMERGENCY_AGAIN);
    assert_eq!(screen.emergencies(), 0, "one press does nothing");
    // No time limit: it waits.
    screen.wait_ms(60_000);
    assert_eq!(label(&screen), text::EMERGENCY_AGAIN);
    screen.press(Key::Escape);
    assert_eq!(label(&screen), text::EMERGENCY);
    screen.press(Key::Space);
    assert_eq!(label(&screen), text::EMERGENCY_AGAIN);
    // Tab moves the focus on, which cancels.
    screen.press(Key::Tab);
    assert_eq!(screen.focused(), "Close");
    assert_eq!(label(&screen), text::EMERGENCY);
    screen.press(Key::Backtab);
    assert_eq!(screen.focused(), text::EMERGENCY);
    screen.press(Key::Space);
    screen.press(Key::Return);
    assert_ended(&screen);
}

#[test]
fn a_key_held_down_is_one_press_however_long_it_repeats() {
    let screen = hidden();
    let walk = screen.walk(Key::Tab, 5);
    assert_eq!(walk.last().map(String::as_str), Some(text::EMERGENCY));
    for (key, name) in [(Key::Return, "Return"), (Key::Space, "Space")] {
        // Past a keyboard's repeat delay and well past the pointer's hold.
        screen.hold_key(key, 20, 100);
        assert_eq!(screen.emergencies(), 0, "{name} held down");
        assert_eq!(label(&screen), text::EMERGENCY_AGAIN);
        screen.press(Key::Escape);
        assert_eq!(label(&screen), text::EMERGENCY);
    }
    // Two presses of their own still end it.
    screen.hold_key(Key::Return, 3, 100);
    assert_eq!(screen.emergencies(), 0);
    screen.press(Key::Return);
    assert_ended(&screen);
}

#[test]
fn a_screen_readers_activate_action_takes_the_same_two_steps() {
    let screen = hidden();
    control(&screen).invoke_accessible_default_action();
    assert_eq!(label(&screen), text::EMERGENCY_AGAIN);
    assert_eq!(screen.emergencies(), 0);
    control(&screen).invoke_accessible_default_action();
    assert_ended(&screen);
}

/// `screen` with the question before a deactivation open.
fn deactivation_asked(screen: &Screen) {
    screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.asks();
    screen.update(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: false,
        warnings: vec![],
        token: "0".repeat(32),
    })));
    assert!(screen.window.get_question_open());
}

#[test]
fn an_open_question_keeps_neither_the_pointer_nor_the_keyboard_from_it() {
    let screen = hidden();
    deactivation_asked(&screen);
    // The keyboard: Tab goes from the question's buttons to it and back.
    let walk = screen.walk(Key::Tab, 4);
    assert_eq!(
        walk,
        [
            text::EMERGENCY,
            text::POWER_OFF,
            text::RETURN_TO_DECOY,
            "Cancel"
        ]
    );
    // The pointer: the question's dimming lies under it.
    hold(&screen, 1100, None);
    assert_ended(&screen);
    assert!(!screen.window.get_question_open(), "the question is gone");
    assert!(screen.asks().is_empty(), "the question was not answered");
}

#[test]
fn the_page_of_a_deactivation_that_ends_keeps_it_working() {
    let screen = hidden();
    deactivation_asked(&screen);
    screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(Update::Running(Kind::Apply));
    assert!(screen.shows(text::RETURNING));
    let button = control(&screen);
    assert_eq!(button.accessible_enabled(), Some(true));
    hold(&screen, 1100, None);
    assert_ended(&screen);
}

#[test]
fn a_hidden_session_window_without_its_helper_still_has_it() {
    let screen = Screen::in_hidden_session();
    assert_eq!(label(&screen), text::EMERGENCY, "before the helper answers");
    screen.update(Update::Ended(Failure::NotStarted(
        "pkexec could not be started".to_string(),
    )));
    assert!(screen.shows(text::NOT_STARTED));
    hold(&screen, 1100, None);
    assert_ended(&screen);
}
