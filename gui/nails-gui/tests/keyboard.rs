// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window by keyboard alone: Tab reaches every control and row in page
//! order, the Close button included, and a question holds the keyboard until
//! it is answered: Tab and Shift+Tab stay inside it, Escape cancels it from
//! anywhere in it, and Return presses only the focused button.

mod screen;
mod support;

use nails_api::protocol::{CheckArgs, DiscardPlanArgs, DiscardPlanData};
use nails_gui::client::{Answer, Plan, PlanData, ours};
use nails_gui::model::Question;
use nails_gui::worker::{Ask, Kind, Update};
use screen::Screen;
use serde_json::json;
use slint::platform::Key;

fn answered(kind: Kind, envelope: serde_json::Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

/// A decoy that is not ready: one fact row, two problems, and Check Again.
fn not_ready() -> Screen {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(answered(
        Kind::Status,
        json!({"schema_version": 2, "command": "status", "ok": true,
            "data": {"place": "decoy", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    screen.update(answered(
        Kind::Check,
        json!({"schema_version": 2, "command": "check", "ok": false, "data": {
            "ready": false,
            "checks": [
                {"name": "journal", "status": "fail", "message": "the journal is kept on disk", "remediation": "set Storage=volatile"},
                {"name": "swap", "status": "fail", "message": "swap is on"},
                {"name": "space", "status": "pass", "message": "space is free"},
            ],
            "summary": {"passed": 1, "warnings": 0, "failed": 2}}}),
    ));
    screen.asks();
    screen
}

/// The Tab stops of the page in order: its rows, its action, and then the
/// window's Close.
const TAB_ORDER: [&str; 8] = [
    "Hidden volume",
    "This computer",
    "Failed: The journal is kept on disk.",
    "Failed: Swap is on.",
    nails_gui::text::VERIFY,
    nails_gui::text::REHEARSAL,
    "Check Again",
    "Close",
];

#[test]
fn the_focus_starts_inside_the_page_on_nothing_that_acts() {
    let screen = not_ready();
    assert_eq!(screen.focused(), "");
    for key in [Key::Return, Key::Space, Key::Escape] {
        screen.press(key);
    }
    assert!(screen.asks().is_empty());
    assert!(!screen.closed());
}

#[test]
fn tab_reaches_every_control_and_row_in_page_order_and_wraps() {
    let screen = not_ready();
    let walk = screen.walk(Key::Tab, TAB_ORDER.len() + 1);
    let mut expected: Vec<&str> = TAB_ORDER.to_vec();
    expected.push(TAB_ORDER[0]);
    assert_eq!(walk, expected);
}

#[test]
fn shift_tab_walks_the_same_order_backwards() {
    let screen = not_ready();
    let walk = screen.walk(Key::Backtab, TAB_ORDER.len());
    let mut expected: Vec<&str> = TAB_ORDER.to_vec();
    expected.reverse();
    assert_eq!(walk, expected);
}

#[test]
fn return_and_space_press_the_focused_button() {
    let screen = not_ready();
    while screen.focused() != "Check Again" {
        screen.press(Key::Tab);
    }
    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Check(CheckArgs::default())]);
    while screen.focused() != "Close" {
        screen.press(Key::Tab);
    }
    screen.press(Key::Space);
    assert!(screen.closed(), "Close closes the window");
}

fn question(_: &PlanData) -> Question {
    Question {
        heading: "Discard Hidden Changes?".to_string(),
        body: "The hidden copy of /srv/notes is deleted.".to_string(),
        confirm: "Discard".to_string(),
        destructive: true,
        ..Question::default()
    }
}

/// `screen` with a discard plan holding and its question open.
fn ask_question(screen: &Screen) {
    screen.controller.borrow_mut().plan(
        Plan::Discard(DiscardPlanArgs {
            target: "/srv/notes".to_string(),
            allow_decoy_storage: false,
        }),
        question,
    );
    assert!(matches!(screen.asks()[..], [Ask::Plan(_)]));
    screen.update(Update::Running(Kind::Plan));
    screen.update(Update::Planned(PlanData::Discard(DiscardPlanData {
        target: "/srv/notes".to_string(),
        removals: vec![],
        resets_nix_store: false,
        token: "0".repeat(32),
    })));
}

#[test]
fn a_question_starts_on_cancel_and_tab_never_leaves_it() {
    let screen = not_ready();
    // Focus on the page's main action before the question opens.
    while screen.focused() != "Check Again" {
        screen.press(Key::Tab);
    }
    ask_question(&screen);
    let walk = screen.walk(Key::Tab, 5);
    assert_eq!(walk, ["Discard", "Cancel", "Discard", "Cancel", "Discard"]);
    let walk = screen.walk(Key::Backtab, 3);
    assert_eq!(walk, ["Cancel", "Discard", "Cancel"]);
    assert!(
        screen.asks().is_empty(),
        "no key pressed a button behind the question"
    );
}

#[test]
fn the_question_takes_the_focus_when_it_opens() {
    let screen = not_ready();
    ask_question(&screen);
    // The first key the question gets: Return on Cancel, where the focus
    // starts, cancels; it never confirms by itself.
    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
}

#[test]
fn escape_cancels_the_question_from_anywhere_in_it() {
    for tabs in 0..4 {
        let screen = not_ready();
        ask_question(&screen);
        screen.walk(Key::Tab, tabs);
        screen.press(Key::Escape);
        assert_eq!(screen.asks(), vec![Ask::Withdraw], "after {tabs} Tabs");
        assert!(!screen.window.get_question_open());
        assert!(!screen.closed());
    }
}

#[test]
fn return_on_the_confirming_button_applies_the_plan() {
    let screen = not_ready();
    ask_question(&screen);
    assert_eq!(screen.walk(Key::Tab, 1), ["Discard"]);
    screen.press(Key::Return);
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    assert!(!screen.window.get_question_open());
}

#[test]
fn once_the_question_is_answered_the_page_is_reachable_again() {
    let screen = not_ready();
    ask_question(&screen);
    screen.press(Key::Escape);
    screen.update(Update::Withdrawn);
    let walk = screen.walk(Key::Tab, TAB_ORDER.len());
    for label in TAB_ORDER {
        assert!(
            walk.iter().any(|seen| seen == label),
            "{label} not reached again: {walk:?}"
        );
    }
}
