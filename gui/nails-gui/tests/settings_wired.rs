// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Settings end to end, without a display: the window on Slint's headless
//! platform and the real worker against a fake helper that answers with
//! envelopes recorded from the real CLI and the real helper. Each flow shows
//! the requests the helper reads, in their order: a change goes out as a
//! plan, its apply carries that plan's token only once the person said
//! Save, and the settings are read again after it.

mod screen;
mod support;
mod wired;

use std::sync::mpsc::{Receiver, channel};

use i_slint_backend_testing::AccessibleRole;
use nails_api::protocol::{
    ConfigEditArgs, ConfigShowArgs, Op, Request, SettingArg, SettingValue, Token,
};
use nails_gui::text;
use nails_gui::worker::{Connect, Kind, Update};
use serde_json::{Value, json};
use slint::platform::Key;
use support::{FakePowerOff, fixture, result};
use wired::{Wired, helper, next_request};

/// A hidden session's window on a helper that answers its status, the
/// settings with `shows` one after the other, and each change as `respond`
/// says; shown once the session's page settled.
fn window(
    shows: &'static [&'static str],
    mut respond: impl FnMut(&Op) -> Option<(u8, Value)> + Send + 'static,
) -> (Wired, Receiver<Request>, FakePowerOff) {
    let (seen, requests) = channel();
    let mut reads = shows.iter();
    let (stream, _helper) = helper(seen, move |request| {
        let (exit, envelope) = match &request.op {
            Op::Status => (
                0,
                json!({"schema_version": 2, "command": "status", "ok": true, "data": {
                    "place": "hidden", "attention": null, "hidden_root": "/mnt/data"}}),
            ),
            Op::ConfigShow(_) => (0, fixture(reads.next().expect("a read of the settings"))),
            op => respond(op).unwrap_or_else(|| panic!("no answer for {op:?}")),
        };
        vec![result(request.id, exit, envelope)]
    });
    let power_off = FakePowerOff::new("exit 0");
    let wired = Wired::new(Connect::Stream(stream), &power_off, true);
    wired.pump_until(|update| matches!(update, Update::Answered(Kind::Status, _)));
    wired.screen.tall();
    (wired, requests, power_off)
}

fn press(wired: &Wired, label: &str) {
    wired
        .screen
        .find_with(label, AccessibleRole::Button)
        .invoke_accessible_default_action();
}

/// Pump until the request of `kind` was answered.
fn until_answered(wired: &Wired, kind: Kind) {
    wired.pump_until(|update| matches!(update, Update::Answered(of, _) if *of == kind));
}

/// Settings open on the first read, and the page of the setting `title`.
fn open(wired: &Wired, title: &str) {
    press(wired, text::SETTINGS);
    until_answered(wired, Kind::Config);
    press(wired, title);
}

/// Put `typed` in place of the value in the field of the setting's page:
/// Tab selects the value in the field, and what is typed replaces it.
fn retype(wired: &Wired, typed: &str) {
    let screen = &wired.screen;
    for _ in 0..64 {
        if screen.focused() == text::FIELD_VALUE {
            break;
        }
        screen.press(Key::Tab);
    }
    assert_eq!(screen.focused(), text::FIELD_VALUE);
    screen.type_text(typed);
    let field = screen.find_with(text::FIELD_VALUE, AccessibleRole::TextInput);
    assert_eq!(field.accessible_value().as_deref(), Some(typed));
}

/// The requests the helper read after the hello, `n` of them.
fn ops(requests: &Receiver<Request>, n: usize) -> Vec<Op> {
    (0..n).map(|_| next_request(requests).op).collect()
}

fn set(key: &str, value: SettingValue) -> Op {
    Op::ConfigEditPlan(ConfigEditArgs {
        set: vec![SettingArg {
            key: key.to_string(),
            value,
        }],
        unset: Vec::new(),
    })
}

fn apply(token: char) -> Op {
    Op::ConfigEditApply(Token {
        token: token.to_string().repeat(32),
    })
}

fn show() -> Op {
    Op::ConfigShow(ConfigShowArgs::default())
}

/// Whether a text in view starts with `start`.
fn says(wired: &Wired, start: &str) -> bool {
    wired
        .screen
        .texts()
        .iter()
        .any(|text| text.starts_with(start))
}

#[test]
fn a_change_is_planned_asked_and_applied_with_its_token_then_read_back() {
    let (wired, requests, _power_off) =
        window(&["config-show", "config-show-set"], |op| match op {
            Op::ConfigEditPlan(_) => Some((0, fixture("config-edit-plan"))),
            Op::ConfigEditApply(_) => Some((0, fixture("config-edit-apply"))),
            _ => None,
        });
    open(&wired, "Home in the session");
    press(&wired, "Empty home");
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    assert!(wired.screen.window.get_question_open());
    press(&wired, text::SAVE);
    until_answered(&wired, Kind::Apply);
    until_answered(&wired, Kind::Config);
    assert!(says(&wired, text::SAVED));
    let row = wired
        .screen
        .find_with("Home in the session", AccessibleRole::Button);
    assert_eq!(
        row.accessible_description().as_deref(),
        Some("Empty home. The settings file")
    );
    assert_eq!(
        ops(&requests, 5),
        [
            Op::Status,
            show(),
            set("persona.mode", SettingValue::Text("fresh-home".to_string())),
            apply('a'),
            show(),
        ]
    );
}

#[test]
fn a_change_answered_no_is_withdrawn_and_never_applied() {
    let (wired, requests, _power_off) = window(&["config-show"], |op| match op {
        Op::ConfigEditPlan(_) => Some((0, fixture("config-edit-plan"))),
        _ => None,
    });
    open(&wired, "Home in the session");
    press(&wired, "Empty home");
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    press(&wired, "Cancel");
    until_answered(&wired, Kind::Status);
    assert!(!wired.screen.window.get_question_open());
    assert!(
        wired
            .screen
            .shows("Which home the hidden session starts in."),
        "the setting's page stays"
    );
    assert_eq!(
        ops(&requests, 4),
        [
            Op::Status,
            show(),
            set("persona.mode", SettingValue::Text("fresh-home".to_string())),
            // Any other request withdraws the plan on the helper's side.
            Op::Status,
        ]
    );
}

#[test]
fn a_file_changed_before_save_writes_nothing_and_is_read_again() {
    let (wired, requests, _power_off) = window(&["config-show", "config-show"], |op| match op {
        Op::ConfigEditPlan(_) => Some((0, fixture("config-edit-plan-stale"))),
        Op::ConfigEditApply(_) => Some((1, fixture("config-edit-apply-stale"))),
        _ => None,
    });
    open(&wired, "Space to keep free");
    retype(&wired, "3000");
    press(&wired, text::SAVE_ACTION);
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    press(&wired, text::SAVE);
    until_answered(&wired, Kind::Apply);
    until_answered(&wired, Kind::Config);
    assert!(says(&wired, text::STALE));
    let field = wired
        .screen
        .find_with(text::FIELD_VALUE, AccessibleRole::TextInput);
    assert_eq!(
        field.accessible_value().as_deref(),
        Some("3000"),
        "what was typed stays, to save again"
    );
    assert_eq!(
        ops(&requests, 5),
        [
            Op::Status,
            show(),
            set("minimum_space_mb", SettingValue::Integer(3000)),
            apply('c'),
            show(),
        ]
    );
}

#[test]
fn a_change_the_engine_refuses_is_said_in_its_words_and_nothing_is_asked() {
    let (wired, requests, _power_off) = window(&["config-show"], |op| match op {
        Op::ConfigEditPlan(_) => Some((3, fixture("config-set-invalid"))),
        _ => None,
    });
    open(&wired, "Log folder");
    retype(&wired, "/elsewhere/logs");
    press(&wired, text::SAVE_ACTION);
    until_answered(&wired, Kind::Plan);
    assert!(!wired.screen.window.get_question_open());
    assert!(says(
        &wired,
        "Invalid config /mnt/data/config/nails.toml: log_path = \"/elsewhere/logs\": must lie \
         inside the hidden volume root /mnt/data. Nothing was written."
    ));
    assert_eq!(
        ops(&requests, 3),
        [
            Op::Status,
            show(),
            set(
                "log_path",
                SettingValue::Text("/elsewhere/logs".to_string())
            ),
        ]
    );
}

#[test]
fn use_the_default_removes_a_key_the_file_sets_through_its_plan() {
    let (wired, requests, _power_off) =
        window(&["config-show-set", "config-show-after"], |op| match op {
            Op::ConfigEditPlan(_) => Some((0, fixture("config-edit-plan-unset"))),
            Op::ConfigEditApply(_) => Some((0, fixture("config-edit-apply-unset"))),
            _ => None,
        });
    open(&wired, "Home in the session");
    press(&wired, text::USE_DEFAULT);
    wired.pump_until(|update| matches!(update, Update::Planned(_)));
    let dialog = wired
        .screen
        .find_with(text::SAVE_QUESTION, AccessibleRole::Groupbox);
    let body = dialog.accessible_description().unwrap_or_default();
    assert_eq!(
        body.lines().next(),
        Some("Home in the session: from Empty home to the default.")
    );
    press(&wired, text::SAVE);
    until_answered(&wired, Kind::Apply);
    until_answered(&wired, Kind::Config);
    assert!(says(&wired, text::SAVED));
    assert_eq!(
        ops(&requests, 5),
        [
            Op::Status,
            show(),
            Op::ConfigEditPlan(ConfigEditArgs {
                set: Vec::new(),
                unset: vec!["persona.mode".to_string()],
            }),
            apply('b'),
            show(),
        ]
    );
}
