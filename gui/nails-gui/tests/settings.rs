// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Settings on Slint's headless platform: the list of every setting with
//! its value and where it comes from, a setting's page for each kind, the
//! question before a change with each key before and after, and their
//! keyboard and screen reader, from envelopes recorded from the real CLI and
//! the real helper.

mod screen;
mod support;

use i_slint_backend_testing::AccessibleRole;
use nails_api::protocol::{ConfigEditArgs, SettingArg, SettingValue};
use nails_api::settings::SETTINGS;
use nails_gui::client::{Answer, Plan, PlanData, ours};
use nails_gui::text;
use nails_gui::worker::{Ask, Kind, Update};
use screen::Screen;
use serde_json::{Value, json};
use slint::platform::Key;
use support::fixture;

fn answered(kind: Kind, exit: u8, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit, envelope })
}

fn press(screen: &Screen, label: &str) {
    screen
        .find_with(label, AccessibleRole::Button)
        .invoke_accessible_default_action();
}

/// A hidden session's window with Settings open on the recorded settings.
fn settings() -> Screen {
    let screen = Screen::in_hidden_session();
    screen.tall();
    screen.update(Update::Connected(ours()));
    screen.update(answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": "hidden", "attention": null, "hidden_root": "/mnt/data"}}),
    ));
    screen.asks();
    let row = screen.find_with(text::SETTINGS, AccessibleRole::Button);
    assert_eq!(
        row.accessible_description().as_deref(),
        Some(text::SETTINGS_ROW)
    );
    row.invoke_accessible_default_action();
    assert_eq!(screen.asks(), vec![Ask::ConfigShow]);
    screen.update(Update::Running(Kind::Config));
    let busy = screen.with_role(AccessibleRole::ProgressIndicator);
    assert_eq!(
        busy[0].accessible_label().as_deref(),
        Some(text::READING_SETTINGS)
    );
    screen.update(answered(Kind::Config, 0, fixture("config-show")));
    screen
}

/// The title of each setting's row, in the list's order.
fn titles() -> Vec<&'static str> {
    SETTINGS
        .iter()
        .map(|setting| text::setting(setting.key).0)
        .collect()
}

/// The recorded plan `name` as the worker hands it over.
fn planned(name: &str) -> Update {
    Update::Planned(PlanData::ConfigEdit(
        serde_json::from_value(fixture(name)["data"].clone()).unwrap(),
    ))
}

fn set(key: &str, value: SettingValue) -> Ask {
    Ask::Plan(Plan::ConfigEdit(ConfigEditArgs {
        set: vec![SettingArg {
            key: key.to_string(),
            value,
        }],
        unset: Vec::new(),
    }))
}

/// Tab until the control labelled `label` has the focus, or fail.
fn focus(screen: &Screen, label: &str) {
    for _ in 0..64 {
        if screen.focused() == label {
            return;
        }
        screen.press(Key::Tab);
    }
    panic!("Tab never reached {label:?}");
}

/// Whether a text in view starts with `start`.
fn says(screen: &Screen, start: &str) -> bool {
    screen.texts().iter().any(|text| text.starts_with(start))
}

#[test]
fn the_list_names_every_setting_its_value_and_where_it_comes_from() {
    let screen = settings();
    assert!(screen.shows(text::SETTINGS_WHEN));
    assert!(screen.shows("The settings file: /mnt/data/config/nails.toml"));
    let mut buttons = vec!["Close", text::BACK];
    buttons.extend(titles());
    buttons.push(text::EMERGENCY);
    assert_eq!(screen.labels(AccessibleRole::Button), buttons);
    for (title, line) in [
        ("Hidden volume", "/mnt/data. The folder NAILS runs from"),
        ("Space to keep free", "500\u{a0}MB. The default"),
        ("Home in the session", "Decoy home. The default"),
        ("Hidden NixOS system", "Not set. The default"),
        ("Failure delay", "15\u{a0}s. The default"),
    ] {
        let row = screen.find_with(title, AccessibleRole::Button);
        assert_eq!(row.accessible_description().as_deref(), Some(line));
    }
    // The keyboard reaches Back and every row, in the list's order.
    assert_eq!(screen.focused(), "");
    let mut stops = vec![text::BACK];
    stops.extend(titles());
    assert_eq!(screen.walk(Key::Tab, stops.len()), stops);
}

#[test]
fn a_choice_asks_with_its_value_before_and_after_and_saves_only_on_save() {
    let screen = settings();
    // Return on a row opens its page, which asks nothing yet.
    focus(&screen, "Home in the session");
    screen.press(Key::Return);
    assert!(screen.asks().is_empty());
    assert!(screen.shows("Which home the hidden session starts in."));
    let decoy = screen.find_with("Decoy home", AccessibleRole::Button);
    let line = decoy.accessible_description().unwrap_or_default();
    assert!(line.starts_with("Now. "), "{line}");
    press(&screen, "Decoy home");
    assert!(screen.asks().is_empty(), "the value it has already");

    press(&screen, "Empty home");
    assert_eq!(
        screen.asks(),
        vec![set(
            "persona.mode",
            SettingValue::Text("fresh-home".to_string())
        )]
    );
    screen.update(Update::Running(Kind::Plan));
    assert!(screen.shows(text::CHECKING_CHANGE));
    screen.update(planned("config-edit-plan"));
    let dialog = screen.find_with(text::SAVE_QUESTION, AccessibleRole::Groupbox);
    let body = dialog.accessible_description().unwrap_or_default();
    assert_eq!(
        body.lines().collect::<Vec<_>>(),
        [
            "Home in the session: from the default to Empty home.",
            text::SETTINGS_WHEN,
            "It is saved in /mnt/data/config/nails.toml.",
        ]
    );
    assert_eq!(screen.focused(), "Cancel", "the focus starts on Cancel");
    // Escape withdraws the plan.
    screen.press(Key::Escape);
    assert_eq!(screen.asks(), vec![Ask::Withdraw]);
    assert!(!screen.window.get_question_open());

    press(&screen, "Empty home");
    screen.asks();
    screen.update(planned("config-edit-plan"));
    press(&screen, text::SAVE);
    assert_eq!(screen.asks(), vec![Ask::Apply]);
    screen.update(Update::Running(Kind::Apply));
    assert!(screen.shows(text::SAVING));
    screen.update(answered(Kind::Apply, 0, fixture("config-edit-apply")));
    assert_eq!(screen.asks(), vec![Ask::ConfigShow], "read back");
    assert!(says(&screen, text::SAVED));
    screen.update(answered(Kind::Config, 0, fixture("config-show-set")));
    let row = screen.find_with("Home in the session", AccessibleRole::Button);
    assert_eq!(
        row.accessible_description().as_deref(),
        Some("Empty home. The settings file")
    );
}

#[test]
fn a_number_is_typed_and_save_waits_for_a_whole_number() {
    let screen = settings();
    press(&screen, "Space to keep free");
    let field = screen.find_with(text::FIELD_VALUE, AccessibleRole::TextInput);
    assert_eq!(field.accessible_value().as_deref(), Some("500"));
    assert!(screen.shows(text::field_hint("integer")));
    let save = screen.find_with(text::SAVE_ACTION, AccessibleRole::Button);
    assert_eq!(save.accessible_enabled(), Some(true), "the value now");

    // Tab selects the value in the field, so what is typed replaces it.
    focus(&screen, text::FIELD_VALUE);
    screen.type_text("lots");
    assert_eq!(field.accessible_value().as_deref(), Some("lots"));
    assert_eq!(save.accessible_enabled(), Some(false));
    for _ in 0..4 {
        screen.press(Key::Backspace);
    }
    screen.type_text("2000");
    assert_eq!(field.accessible_value().as_deref(), Some("2000"));
    assert_eq!(save.accessible_enabled(), Some(true));
    // Return in the field does nothing: only the button acts.
    screen.press(Key::Return);
    assert!(screen.asks().is_empty());
    save.invoke_accessible_default_action();
    assert_eq!(
        screen.asks(),
        vec![set("minimum_space_mb", SettingValue::Integer(2000))]
    );
}

#[test]
fn the_volume_and_the_record_say_why_they_cannot_move_and_offer_nothing() {
    for title in ["Hidden volume", "Record"] {
        let screen = settings();
        press(&screen, title);
        assert!(screen.shows(text::SESSION_KEY_FIXED), "{title}");
        assert_eq!(
            screen.labels(AccessibleRole::Button),
            ["Close", text::BACK, text::EMERGENCY],
            "{title}"
        );
    }
}

#[test]
fn back_leads_from_a_setting_to_the_list_and_on_to_the_session() {
    let screen = settings();
    press(&screen, "When the computer would sleep");
    assert!(screen.shows("Keep awake"));
    press(&screen, text::BACK);
    assert!(screen.asks().is_empty());
    assert!(screen.shows("Space to keep free"), "the list again");
    screen.press(Key::Escape);
    assert_eq!(screen.asks(), vec![Ask::Status]);
    screen.find_with(text::SETTINGS, AccessibleRole::Button);
}

#[test]
fn settings_that_cannot_be_read_offer_only_reading_them_again() {
    let screen = settings();
    screen.update(answered(Kind::Config, 3, fixture("config-show-invalid")));
    let heading = screen.find_with(text::SETTINGS_UNREADABLE, AccessibleRole::Text);
    assert!(heading.accessible_label().is_some());
    assert_eq!(
        screen.labels(AccessibleRole::Button),
        ["Close", text::BACK, text::READ_AGAIN, text::EMERGENCY]
    );
    press(&screen, text::READ_AGAIN);
    assert_eq!(screen.asks(), vec![Ask::ConfigShow]);
}
