// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The pages of a switch the window waits for, on Slint's headless platform
//! with its time mocked: Logging Out once an activation passed its point of
//! no return, and Ending the Hidden Session once a deactivation was chosen.
//! Each takes no input while the switch may still come, leaves at once when
//! the engine says it will not, and gives a way out once a minute passed.

mod screen;
mod support;

use i_slint_backend_testing::AccessibleRole;
use nails_api::Event;
use nails_api::protocol::{ActivatePlanData, DeactivatePlanData};
use nails_gui::client::{Answer, PlanData, ours};
use nails_gui::text;
use nails_gui::worker::{Ask, Failure, Kind, Update};
use screen::Screen;
use serde_json::{Value, json};
use slint::platform::Key;

fn answered(kind: Kind, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

fn status(place: &str) -> Update {
    answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": null, "hidden_root": "/mnt/data"}}),
    )
}

/// A decoy's window whose activation passed its point of no return.
fn logging_out() -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(status("decoy"));
    screen.update(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true, "checks": [], "summary": {"passed": 1, "warnings": 0, "failed": 0}}}),
    ));
    screen
        .find_with(text::ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(Update::Planned(PlanData::Activate(ActivatePlanData {
        warning: None,
        defaults_notice: None,
        builds_hidden_system: false,
        advisories: Vec::new(),
        token: "0".repeat(32),
    })));
    screen
        .find_with(text::LOG_OUT_AND_ACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(Update::Running(Kind::Apply));
    screen.update(Update::Event(Event::PointOfNoReturn));
    screen.asks();
    assert!(screen.shows(text::LOGGING_OUT));
    screen
}

fn close_enabled(screen: &Screen) -> bool {
    screen
        .find_with("Close", AccessibleRole::Button)
        .accessible_enabled()
        == Some(true)
}

#[test]
fn logging_out_takes_no_input_for_a_minute_and_then_offers_its_way_out() {
    let screen = logging_out();
    screen.update(Update::Event(Event::Finished { success: true }));
    screen.update(answered(
        Kind::Apply,
        json!({"command": "activate", "ok": true, "data": {"status": "entering"}}),
    ));
    screen.wait_ms(59_000);
    assert!(screen.shows(text::LOGGING_OUT));
    assert!(!close_enabled(&screen), "the switch may still come");
    assert!(!screen.shows(text::LOGOUT_LATE));

    screen.wait_ms(2_000);
    assert!(screen.shows(text::LOGGING_OUT));
    assert!(screen.shows(text::LOGOUT_LATE));
    assert!(screen.shows(
        "Close this window and open it again from a terminal to see where things stand: \
         sudo /mnt/data/nails gui"
    ));
    assert!(close_enabled(&screen));
    // Escape still cancels nothing, and Close closes.
    screen.press(Key::Escape);
    assert_eq!(screen.hang_ups(), 0);
    screen
        .find_with("Close", AccessibleRole::Button)
        .invoke_accessible_default_action();
    assert!(screen.closed());
}

#[test]
fn a_helper_gone_past_the_point_still_gets_the_way_out_in_a_minute() {
    let screen = logging_out();
    screen.update(Update::Ended(Failure::Lost { in_flight: true }));
    assert!(screen.shows(text::LOGGING_OUT));
    assert!(!close_enabled(&screen));
    screen.wait_ms(61_000);
    assert!(screen.shows(text::LOGOUT_LATE));
    assert!(close_enabled(&screen));
}

#[test]
fn the_engine_saying_the_logout_will_not_come_leaves_logging_out_at_once() {
    let screen = logging_out();
    screen.update(Update::Event(Event::Finished { success: false }));
    assert!(screen.shows(text::ACTIVATION_FAILED));
    assert!(screen.shows(text::LOGOUT_NOT_ASKED));
    screen.update(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "activate", "ok": false, "error": {
            "code": "soft_reboot",
            "message": "systemctl could not enqueue soft-reboot.target",
            "next": null}}),
    ));
    assert_eq!(screen.asks(), vec![Ask::Status]);
    assert!(screen.shows("Systemctl could not enqueue soft-reboot.target."));
    assert!(close_enabled(&screen));
    // The timer of the page it left has nothing more to say.
    screen.wait_ms(61_000);
    assert!(!screen.shows(text::LOGOUT_LATE));
}

#[test]
fn a_hidden_session_that_does_not_end_points_to_the_emergency_in_a_minute() {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(status("hidden"));
    screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(Update::Planned(PlanData::Deactivate(DeactivatePlanData {
        poweroff: false,
        warnings: vec![],
        powers_off_instead: None,
        token: "0".repeat(32),
    })));
    screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(Update::Running(Kind::Apply));
    screen.update(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": true,
            "data": {"status": "return_requested"}}),
    ));
    screen.wait_ms(30_000);
    assert!(!screen.shows(text::ENDING_LATE));
    assert!(!close_enabled(&screen));
    screen.wait_ms(31_000);
    assert!(screen.shows(text::ENDING));
    assert!(screen.shows(text::ENDING_LATE));
    assert!(screen.shows(text::END_ANOTHER_WAY));
    assert!(close_enabled(&screen));
    screen.find_with(text::EMERGENCY, AccessibleRole::Button);
}

#[test]
fn a_new_switch_is_timed_from_its_own_start() {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(status("hidden"));
    let plan = || {
        Update::Planned(PlanData::Deactivate(DeactivatePlanData {
            poweroff: false,
            warnings: vec![],
            powers_off_instead: None,
            token: "0".repeat(32),
        }))
    };
    // A first deactivation the engine refuses after 50 s.
    screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(plan());
    screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.wait_ms(50_000);
    screen.update(answered(
        Kind::Apply,
        json!({"schema_version": 2, "command": "deactivate", "ok": false, "error": {
            "code": "invalid_state", "message": "refused", "next": null}}),
    ));
    assert!(screen.shows(text::HIDDEN_SESSION));
    // A second one, 20 s later: 70 s after the first, but 20 s after its own.
    screen.asks();
    screen
        .find_with(text::DEACTIVATE, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.update(plan());
    screen
        .find_with(text::RETURN_TO_DECOY, AccessibleRole::Button)
        .invoke_accessible_default_action();
    screen.wait_ms(20_000);
    assert!(screen.shows(text::ENDING));
    assert!(!screen.shows(text::ENDING_LATE));
    screen.wait_ms(41_000);
    assert!(screen.shows(text::ENDING_LATE));
}
