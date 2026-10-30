// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! What a screen reader finds on every page: each control and row with a
//! role and a name, the header bar as the window's title bar, the page as
//! the main landmark, and a dialog that names itself and leaves the window
//! behind it disabled.

mod screen;
mod support;

use i_slint_backend_testing::AccessibleRole;
use nails_api::protocol::{DiscardPlanArgs, DiscardPlanData};
use nails_gui::client::{Answer, Plan, PlanData, ours};
use nails_gui::model::Question;
use nails_gui::worker::{Failure, Kind, Update};
use screen::Screen;
use support::{fixture, fixture_events};

/// Every role a person reaches by keyboard or a screen reader announces,
/// with the name it must carry.
const NAMED: [AccessibleRole; 5] = [
    AccessibleRole::Button,
    AccessibleRole::ListItem,
    AccessibleRole::ProgressIndicator,
    AccessibleRole::WindowTitleBar,
    AccessibleRole::Groupbox,
];

/// Every element of a named role has a name, and the frame of every page is
/// there: the title bar named "Session", its Close button, and the main
/// landmark.
fn assert_named(screen: &Screen, page: &str) {
    for role in NAMED {
        for element in screen.with_role(role) {
            let label = element.accessible_label().unwrap_or_default();
            assert!(
                !label.trim().is_empty(),
                "{page}: a {role:?} without a name"
            );
        }
    }
    assert_eq!(
        screen.labels(AccessibleRole::WindowTitleBar),
        ["Session"],
        "{page}"
    );
    let close = screen.find_with("Close", AccessibleRole::Button);
    assert_eq!(close.accessible_label().as_deref(), Some("Close"), "{page}");
    assert_eq!(screen.with_role(AccessibleRole::Main).len(), 1, "{page}");
}

fn answered(kind: Kind, envelope: serde_json::Value) -> Update {
    Update::Answered(kind, Answer { exit: 0, envelope })
}

#[test]
fn every_page_names_each_control_and_row() {
    let screen = Screen::new(true);
    assert_named(&screen, "waiting for the password");

    let screen = Screen::new(false);
    screen.tall();
    assert_named(&screen, "starting");
    screen.update(Update::Connected(ours()));
    screen.update(answered(Kind::Status, fixture("status-decoy")));
    assert_named(&screen, "checking");
    screen.update(Update::Running(Kind::Check));
    for event in fixture_events("check-decoy") {
        screen.update(Update::Event(event));
    }
    assert_named(&screen, "checks streaming");
    screen.update(answered(Kind::Check, fixture("check-decoy")));
    assert_named(&screen, "checked");
    assert!(!screen.with_role(AccessibleRole::ListItem).is_empty());
    // The recorded decoy keeps a persistent record, which can be allowed for
    // one activation: its row has the button for that.
    // The rows that open the tools follow the checks.
    assert_eq!(
        screen.labels(AccessibleRole::Button),
        [
            "Close",
            nails_gui::text::ALLOW,
            nails_gui::text::VERIFY,
            nails_gui::text::REHEARSAL,
            "Check Again"
        ]
    );

    for failure in [
        Failure::Lost { in_flight: true },
        Failure::PasswordUnavailable,
        Failure::NotStarted("pkexec could not be started".to_string()),
    ] {
        let screen = Screen::new(false);
        screen.update(Update::Ended(failure.clone()));
        assert_named(&screen, &format!("{failure:?}"));
        // A refusal page has no main action, only the window's Close.
        assert_eq!(
            screen.labels(AccessibleRole::Button),
            ["Close"],
            "{failure:?}"
        );
    }
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

#[test]
fn a_question_names_itself_and_disables_the_window_behind_it() {
    let screen = Screen::new(false);
    screen.update(Update::Connected(ours()));
    screen.update(answered(Kind::Status, fixture("status-decoy")));
    screen.update(answered(Kind::Check, fixture("check-decoy")));
    screen.asks();
    screen.controller.borrow_mut().plan(
        Plan::Discard(DiscardPlanArgs {
            target: "/srv/notes".to_string(),
            allow_decoy_storage: false,
        }),
        question,
    );
    screen.update(Update::Planned(PlanData::Discard(DiscardPlanData {
        target: "/srv/notes".to_string(),
        removals: vec![],
        resets_nix_store: false,
        token: "0".repeat(32),
    })));
    assert_named(&screen, "question");
    let dialog = screen.find_with("Discard Hidden Changes?", AccessibleRole::Groupbox);
    assert_eq!(
        dialog.accessible_description().as_deref(),
        Some("The hidden copy of /srv/notes is deleted.")
    );
    for label in ["Cancel", "Discard"] {
        let button = screen.find_with(label, AccessibleRole::Button);
        assert_eq!(button.accessible_enabled(), Some(true), "{label}");
    }
    for label in ["Close", "Check Again"] {
        let button = screen.find_with(label, AccessibleRole::Button);
        assert_eq!(
            button.accessible_enabled(),
            Some(false),
            "{label} behind the question"
        );
        // A screen reader's default action does nothing behind it either.
        button.invoke_accessible_default_action();
    }
    // The plan was asked for, and nothing behind the question asked anything.
    assert!(matches!(
        screen.asks()[..],
        [nails_gui::worker::Ask::Plan(_)]
    ));
    assert!(!screen.closed());
}
