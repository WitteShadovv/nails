// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Settings through the model, from envelopes recorded from the real CLI and
//! the real helper: the list, a key's page for each kind, the plan and its
//! question, the apply with its token, a file that changed meanwhile, the
//! engine's refusals, the keys a session holds, and answers the window does
//! not expect.

use std::path::PathBuf;

use nails_api::protocol::{
    ConfigEditArgs, ConfigEditPlanData, MAX_LIST_ENTRIES, MAX_SETTING_BYTES, SettingArg,
    SettingValue,
};
use serde_json::{Value, json};

use super::*;
use crate::client::{Answer, Plan, PlanData};
use crate::model::View;
use crate::worker::{Ask, Kind, Update};

fn fixture(name: &str) -> Value {
    let text = match name {
        "config-show" => include_str!("../../tests/fixtures/config-show.json"),
        "config-show-set" => include_str!("../../tests/fixtures/config-show-set.json"),
        "config-show-after" => include_str!("../../tests/fixtures/config-show-after.json"),
        "config-show-invalid" => include_str!("../../tests/fixtures/config-show-invalid.json"),
        "config-edit-plan" => include_str!("../../tests/fixtures/config-edit-plan.json"),
        "config-edit-apply" => include_str!("../../tests/fixtures/config-edit-apply.json"),
        "config-edit-plan-unchanged" => {
            include_str!("../../tests/fixtures/config-edit-plan-unchanged.json")
        }
        "config-edit-plan-unset" => {
            include_str!("../../tests/fixtures/config-edit-plan-unset.json")
        }
        "config-edit-plan-stale" => {
            include_str!("../../tests/fixtures/config-edit-plan-stale.json")
        }
        "config-edit-apply-stale" => {
            include_str!("../../tests/fixtures/config-edit-apply-stale.json")
        }
        "config-edit-plan-session-paths" => {
            include_str!("../../tests/fixtures/config-edit-plan-session-paths.json")
        }
        "config-set-usage" => include_str!("../../tests/fixtures/config-set-usage.json"),
        "config-set-invalid" => include_str!("../../tests/fixtures/config-set-invalid.json"),
        "config-set-off-volume" => include_str!("../../tests/fixtures/config-set-off-volume.json"),
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(text).unwrap()
}

fn answered(kind: Kind, exit: u8, envelope: Value) -> Update {
    Update::Answered(kind, Answer { exit, envelope })
}

fn status(place: &str) -> Update {
    answered(
        Kind::Status,
        0,
        json!({"schema_version": 2, "command": "status", "ok": true, "data": {
            "place": place, "attention": null, "hidden_root": "/mnt/data"}}),
    )
}

/// Open Settings from the session page of `model` and read `shown` there.
fn open_on(mut model: Model, shown: Value) -> Model {
    let index = model
        .page()
        .links
        .iter()
        .position(|link| link.tool == ToolKind::Settings)
        .expect("Settings in a hidden session");
    assert_eq!(model.open(index), Some(Ask::ConfigShow));
    model.apply(Update::Running(Kind::Config));
    assert_eq!(model.page().busy.as_deref(), Some(text::READING_SETTINGS));
    assert!(model.page().choices.is_empty(), "nothing to pick yet");
    assert!(model.apply(answered(Kind::Config, 0, shown)).is_empty());
    model
}

/// A hidden session's window with Settings open on `show`.
fn settings(show: &str) -> Model {
    settings_on(fixture(show))
}

/// A hidden session's window with Settings open on the envelope `shown`.
fn settings_on(shown: Value) -> Model {
    let mut model =
        Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("hidden"));
    open_on(model, shown)
}

/// The place of `key` in the list.
fn row(key: &str) -> usize {
    nails_api::settings::SETTINGS
        .iter()
        .position(|setting| setting.key == key)
        .unwrap()
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

/// The recorded plan `name` as the worker hands it over.
fn planned(name: &str) -> Update {
    Update::Planned(PlanData::ConfigEdit(
        serde_json::from_value(fixture(name)["data"].clone()).unwrap(),
    ))
}

/// The answer the helper never gives for the asks of these tests: a plan of
/// `changes`.
fn planned_of(changes: Value) -> Update {
    Update::Planned(PlanData::ConfigEdit(ConfigEditPlanData {
        path: "/mnt/data/config/nails.toml".to_string(),
        changes: serde_json::from_value(changes).unwrap(),
        token: "a".repeat(32),
    }))
}

#[test]
fn settings_open_in_a_hidden_session_only() {
    let model = settings("config-show");
    assert_eq!(model.page().view, View::Tool(ToolKind::Settings));
    let mut decoy = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    decoy.apply(Update::Connected(crate::client::ours()));
    decoy.apply(status("decoy"));
    decoy.apply(answered(
        Kind::Check,
        0,
        json!({"schema_version": 2, "command": "check", "ok": true, "data": {
            "ready": true, "checks": [], "summary": {"passed": 1, "warnings": 0, "failed": 0}}}),
    ));
    assert!(
        decoy
            .page()
            .links
            .iter()
            .all(|link| link.tool != ToolKind::Settings),
        "settings change in a hidden session"
    );
}

#[test]
fn the_list_names_each_setting_with_its_value_and_where_it_comes_from() {
    let model = settings("config-show");
    let page = model.page();
    assert_eq!(page.heading, text::SETTINGS);
    assert_eq!(page.description, text::SETTINGS_WHEN);
    assert_eq!(
        page.note,
        text::settings_file("/mnt/data/config/nails.toml", true)
    );
    assert_eq!(page.choices.len(), nails_api::settings::SETTINGS.len());
    let line = |key: &str| {
        let choice = &page.choices[row(key)];
        (choice.title.as_str(), choice.subtitle.as_str())
    };
    assert_eq!(
        line("hidden_volume_root"),
        ("Hidden volume", "/mnt/data. The folder NAILS runs from")
    );
    assert_eq!(
        line("minimum_space_mb"),
        ("Space to keep free", "500\u{a0}MB. The default")
    );
    assert_eq!(line("nixos_flake").1, "Not set. The default");
    assert_eq!(line("persona.mask_inherited").1, "None. The default");
    assert_eq!(line("persona.mode").1, "Decoy home. The default");
    assert_eq!(line("sleep_policy.mode").1, "Warn. The default");
    assert_eq!(
        line("backend_watch.debounce_secs").1,
        "15\u{a0}s. The default"
    );
    assert_eq!(line("show_opsec_reminders").1, "On. The default");
    assert_eq!(line("session_mounts.read_only").1, "Off. The default");
    // Every key has words of its own.
    for choice in &page.choices {
        assert_ne!(choice.title, "Setting");
    }
    // A file not there yet says so.
    assert_eq!(
        text::settings_file("/mnt/data/config/nails.toml", false),
        "No settings file yet at /mnt/data/config/nails.toml: every setting has its default."
    );
}

#[test]
fn a_choice_plans_its_change_asks_with_before_and_after_and_applies_its_token() {
    let mut model = settings("config-show");
    assert_eq!(
        model.choose(row("persona.mode")),
        None,
        "the key's page opens"
    );
    let page = model.page();
    assert_eq!(page.heading, "Home in the session");
    assert_eq!(
        page.facts,
        [
            ("Now".to_string(), "Decoy home".to_string()),
            ("Comes from".to_string(), "The default".to_string()),
        ]
    );
    assert_eq!(page.choices[0].title, "Decoy home");
    assert!(page.choices[0].subtitle.starts_with("Now. "));
    assert_eq!(page.choices[1].title, "Empty home");
    assert!(!page.choices[1].subtitle.starts_with("Now"));
    assert_eq!(page.secondary, None, "the file does not set it");
    assert_eq!(model.choose(0), None, "what holds already asks nothing");

    assert_eq!(
        model.choose(1),
        Some(set(
            "persona.mode",
            SettingValue::Text("fresh-home".to_string())
        ))
    );
    model.apply(Update::Running(Kind::Plan));
    assert_eq!(model.page().busy.as_deref(), Some(text::CHECKING_CHANGE));
    assert!(model.page().choices.is_empty(), "nothing to pick meanwhile");
    assert_eq!(model.choose(0), None);
    assert!(model.apply(planned("config-edit-plan")).is_empty());
    let question = model.page().question.unwrap();
    assert_eq!(question.heading, text::SAVE_QUESTION);
    assert_eq!(
        question.body.lines().collect::<Vec<_>>(),
        [
            "Home in the session: from the default to Empty home.",
            text::SETTINGS_WHEN,
            "It is saved in /mnt/data/config/nails.toml.",
        ]
    );
    assert!(!question.destructive);
    assert_eq!(question.confirm, text::SAVE);
    assert_eq!(model.choose(1), None, "not while it asks");

    assert_eq!(model.answer(true), Some(Ask::Apply));
    model.apply(Update::Running(Kind::Apply));
    assert_eq!(model.page().busy.as_deref(), Some(text::SAVING));
    assert_eq!(
        model.apply(answered(Kind::Apply, 0, fixture("config-edit-apply"))),
        vec![Ask::ConfigShow],
        "the saved change is read back"
    );
    let page = model.page();
    assert_eq!(page.heading, text::SETTINGS, "back on the list");
    assert!(page.note.starts_with(text::SAVED), "{}", page.note);
    model.apply(answered(Kind::Config, 0, fixture("config-show-set")));
    let page = model.page();
    assert_eq!(
        page.choices[row("persona.mode")].subtitle,
        "Empty home. The settings file"
    );
    assert!(page.note.starts_with(text::SAVED), "it stays said");
    // Opening a setting leaves what was said behind.
    model.choose(row("persona.mode"));
    assert_eq!(model.page().note, "");
}

#[test]
fn a_switch_offers_on_and_off() {
    let mut model = settings("config-show");
    model.choose(row("session_mounts.read_only"));
    let page = model.page();
    let titles: Vec<&str> = page.choices.iter().map(|c| c.title.as_str()).collect();
    assert_eq!(titles, [text::ON, text::OFF]);
    assert_eq!(page.choices[1].subtitle, text::CHOSEN);
    assert_eq!(page.choices[0].subtitle, "");
    assert_eq!(model.choose(1), None, "off already");
    assert_eq!(
        model.choose(0),
        Some(set("session_mounts.read_only", SettingValue::Bool(true)))
    );
    // Out of range asks nothing.
    let mut model = settings("config-show");
    model.choose(row("sleep_policy.mode"));
    assert_eq!(model.choose(3), None);
    let mut model = settings("config-show");
    assert_eq!(model.choose(nails_api::settings::SETTINGS.len()), None);
    assert_eq!(model.page().heading, text::SETTINGS);
}

#[test]
fn a_plan_of_other_keys_than_asked_is_withdrawn() {
    let mut model = settings("config-show");
    model.choose(row("persona.mode"));
    model.choose(1);
    assert_eq!(
        model.apply(planned_of(json!([
            {"key": "minimum_space_mb", "before": null, "after": 2000}]))),
        vec![Ask::Withdraw]
    );
    assert_eq!(model.page().question, None);
    // Nor one that names more than asked.
    let mut model = settings("config-show");
    model.choose(row("persona.mode"));
    model.choose(1);
    assert_eq!(
        model.apply(planned_of(json!([
            {"key": "persona.mode", "before": null, "after": "fresh-home"},
            {"key": "state_file_path", "before": null, "after": "/mnt/data/elsewhere.json"}]))),
        vec![Ask::Withdraw]
    );
}

#[test]
fn a_field_saves_only_a_value_of_its_kind_that_fits_in_a_request() {
    let mut model = settings("config-show");
    model.choose(row("minimum_space_mb"));
    let page = model.page();
    assert_eq!(page.field.as_ref().unwrap().text, "500");
    assert_eq!(page.field.unwrap().hint, text::field_hint("integer"));
    assert_eq!(page.action, Some(text::SAVE_ACTION));
    for wrong in [
        "",
        "plenty",
        "-1",
        "1.5",
        "9223372036854775808",
        "99999999999999999999",
    ] {
        model.edited(wrong);
        assert!(model.page().action_locked, "{wrong}");
        assert_eq!(model.action(), None, "{wrong}");
    }
    model.edited("9223372036854775807");
    assert!(!model.page().action_locked, "the largest the engine takes");
    model.edited(" 2000 ");
    assert!(!model.page().action_locked);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(set(
            "minimum_space_mb",
            SettingValue::Integer(2000)
        )))
    );

    let mut model = settings("config-show");
    model.choose(row("log_path"));
    assert_eq!(model.page().field.unwrap().text, "/mnt/data/logs");
    model.edited("logs");
    assert!(model.page().action_locked, "a path is a full path");
    model.edited("/mnt/data/\u{7}logs");
    assert!(model.page().action_locked, "no control character");
    model.edited(&format!("/{}", "a".repeat(MAX_SETTING_BYTES)));
    assert!(model.page().action_locked, "too long for a request");
    model.edited("/mnt/data/logs2");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(set(
            "log_path",
            SettingValue::Text("/mnt/data/logs2".to_string())
        )))
    );

    let mut model = settings("config-show");
    model.choose(row("persona.mask_inherited"));
    assert_eq!(model.page().field.unwrap().text, "");
    assert_eq!(model.page().field.unwrap().hint, text::field_hint("names"));
    // One name at least, as `config set` takes them.
    for none in ["", " , ", ","] {
        model.edited(none);
        assert!(model.page().action_locked, "{none:?}");
        assert_eq!(model.action(), None, "{none:?}");
    }
    model.edited("org.gnome.Software, nextcloud  syncthing.service");
    assert_eq!(
        model.action(),
        Some(Effect::Ask(set(
            "persona.mask_inherited",
            SettingValue::List(vec![
                "org.gnome.Software".to_string(),
                "nextcloud".to_string(),
                "syncthing.service".to_string()
            ])
        )))
    );
    let many: Vec<String> = (0..=MAX_LIST_ENTRIES).map(|n| format!("n{n}")).collect();
    model.edited(&many.join(","));
    assert!(model.page().action_locked, "too many names for a request");

    let mut model = settings("config-show");
    model.choose(row("nixos_flake"));
    assert!(model.page().action_locked, "a flake is not empty");
    model.edited("/mnt/data/nixos#my-host");
    assert!(!model.page().action_locked);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(set(
            "nixos_flake",
            SettingValue::Text("/mnt/data/nixos#my-host".to_string())
        )))
    );
}

#[test]
fn a_list_of_names_shows_as_typed() {
    let mut shown = fixture("config-show");
    shown["data"]["config"]["persona"]["mask_inherited"] = json!(["nextcloud", "syncthing"]);
    let mut model =
        Model::new(Some(PathBuf::from("/mnt/data/nails")), false).in_hidden_session(true);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("hidden"));
    let index = model
        .page()
        .links
        .iter()
        .position(|link| link.tool == ToolKind::Settings)
        .unwrap();
    model.open(index);
    model.apply(answered(Kind::Config, 0, shown.clone()));
    assert!(
        model.page().choices[row("persona.mask_inherited")]
            .subtitle
            .starts_with("nextcloud, syncthing. ")
    );
    model.choose(row("persona.mask_inherited"));
    assert_eq!(model.page().field.unwrap().text, "nextcloud, syncthing");
    shown["data"]["config"]["persona"]["mask_inherited"] = json!(["*"]);
    model.apply(Update::Running(Kind::Config));
    model.apply(answered(Kind::Config, 0, shown));
    assert_eq!(model.page().facts[0].1, text::ALL);
}

#[test]
fn the_volume_and_the_record_say_why_they_cannot_move_and_offer_nothing() {
    for key in ["hidden_volume_root", "state_file_path"] {
        let mut model = settings("config-show");
        model.choose(row(key));
        let page = model.page();
        assert_eq!(page.note, text::SESSION_KEY_FIXED, "{key}");
        assert_eq!(page.field, None, "{key}");
        assert!(page.choices.is_empty(), "{key}");
        assert_eq!((page.action, page.secondary), (None, None), "{key}");
        assert_eq!(model.tool_action(text::SAVE_ACTION), None, "{key}");
        assert_eq!(model.tool_action(text::USE_DEFAULT), None, "{key}");
    }
}

#[test]
fn once_the_engine_holds_the_volume_and_the_record_they_stay_held_in_its_words() {
    // The window does not read a hidden session of its own, and the status
    // turns to the decoy under an open Settings: an entry left behind, which
    // the engine sees.
    let mut model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false);
    model.apply(Update::Connected(crate::client::ours()));
    model.apply(status("hidden"));
    let mut model = open_on(model, fixture("config-show"));
    model.apply(status("decoy"));
    model.choose(row("state_file_path"));
    assert_eq!(model.page().action, Some(text::SAVE_ACTION));
    model.edited("/mnt/data/elsewhere.json");
    let Some(Effect::Ask(ask)) = model.action() else {
        panic!("a plan")
    };
    assert_eq!(
        ask,
        set(
            "state_file_path",
            SettingValue::Text("/mnt/data/elsewhere.json".to_string())
        )
    );
    let refusal = fixture("config-edit-plan-session-paths");
    let words = text::sentence(refusal["error"]["message"].as_str().unwrap());
    assert!(model.apply(answered(Kind::Plan, 4, refusal)).is_empty());
    let page = model.page();
    assert_eq!(page.note, words, "said once");
    assert_eq!((page.field, page.action), (None, None));
    // Both keys stay held, the volume's too.
    model.back();
    model.choose(row("hidden_volume_root"));
    let page = model.page();
    assert_eq!(page.note, words);
    assert_eq!(page.field, None);
    assert_eq!(model.tool_action(text::SAVE_ACTION), None);
    // Other keys still change.
    model.back();
    model.choose(row("log_path"));
    assert_eq!(model.page().action, Some(text::SAVE_ACTION));
}

#[test]
fn use_the_default_comes_where_the_file_sets_a_key() {
    let mut model = settings("config-show-set");
    model.choose(row("persona.mode"));
    let page = model.page();
    assert_eq!(page.facts[0].1, "Empty home");
    assert_eq!(page.facts[1].1, "The settings file");
    assert_eq!(page.action, Some(text::USE_DEFAULT));
    assert_eq!(page.secondary, None);
    assert_eq!(
        model.action(),
        Some(Effect::Ask(Ask::Plan(Plan::ConfigEdit(ConfigEditArgs {
            set: Vec::new(),
            unset: vec!["persona.mode".to_string()],
        }))))
    );
    model.apply(planned("config-edit-plan-unset"));
    assert_eq!(
        model.page().question.unwrap().body.lines().next(),
        Some("Home in the session: from Empty home to the default.")
    );
    // Another key of the table the file holds is not the file's: there is
    // no default to go back to.
    let mut model = settings("config-show-set");
    model.choose(row("persona.mask_inherited"));
    let page = model.page();
    assert_eq!(page.facts[1].1, "The default");
    assert_eq!(
        (page.action, page.secondary),
        (Some(text::SAVE_ACTION), None)
    );
    assert_eq!(model.secondary(), None);
    assert_eq!(
        model.tool_action(text::USE_DEFAULT),
        None,
        "never what is not offered"
    );
    // After the unset only the table's empty header is left: the key is at
    // its default again, and nothing offers to take it back there.
    let mut model = settings("config-show-after");
    assert_eq!(
        model.page().choices[row("persona.mode")].subtitle,
        "Decoy home. The default"
    );
    model.choose(row("persona.mode"));
    let page = model.page();
    assert_eq!((page.action, page.secondary), (None, None));
    // A field's page keeps Save… and offers the default beside it, where the
    // file sets that key.
    let mut shown = fixture("config-show-set");
    shown["data"]["config"]["persona"]["mask_inherited"] = json!(["nextcloud"]);
    shown["data"]["sources"]["persona.mask_inherited"] = json!("file");
    let mut model = settings_on(shown);
    model.choose(row("persona.mask_inherited"));
    let page = model.page();
    assert_eq!(
        (page.action, page.secondary),
        (Some(text::SAVE_ACTION), Some(text::USE_DEFAULT))
    );
    assert_eq!(
        model.secondary(),
        Some(Effect::Ask(Ask::Plan(Plan::ConfigEdit(ConfigEditArgs {
            set: Vec::new(),
            unset: vec!["persona.mask_inherited".to_string()],
        }))))
    );
}

#[test]
fn a_key_with_no_source_of_its_own_is_not_the_files() {
    // The table is the file's, but the key's own source is missing.
    let mut shown = fixture("config-show-set");
    let sources = shown["data"]["sources"].as_object_mut().unwrap();
    sources.remove("persona.mode");
    let mut model = settings_on(shown);
    assert!(
        model.page().choices[row("persona.mode")]
            .subtitle
            .ends_with(". Not known")
    );
    model.choose(row("persona.mode"));
    let page = model.page();
    assert_eq!(page.facts[1].1, "Not known");
    assert_eq!((page.action, page.secondary), (None, None));
}

#[test]
fn a_file_changed_meanwhile_is_read_again_and_nothing_is_written() {
    let mut model = settings("config-show");
    model.choose(row("minimum_space_mb"));
    model.edited("3000");
    model.action();
    model.apply(planned("config-edit-plan-stale"));
    assert_eq!(
        model.page().question.unwrap().body.lines().next(),
        Some("Space to keep free: from the default to 3000\u{a0}MB.")
    );
    model.answer(true);
    assert_eq!(
        model.apply(answered(Kind::Apply, 1, fixture("config-edit-apply-stale"))),
        vec![Ask::ConfigShow]
    );
    let page = model.page();
    assert_eq!(page.heading, "Space to keep free", "the key's page stays");
    assert!(page.note.starts_with(text::STALE), "{}", page.note);
    model.apply(answered(Kind::Config, 0, fixture("config-show")));
    let page = model.page();
    assert_eq!(page.field.unwrap().text, "3000", "to save again");
    assert!(page.note.starts_with(text::STALE));
}

#[test]
fn the_engines_refusals_are_said_in_its_words() {
    for (name, exit) in [
        ("config-set-usage", 2),
        ("config-set-invalid", 3),
        ("config-set-off-volume", 4),
    ] {
        let mut model = settings("config-show");
        model.choose(row("minimum_space_mb"));
        model.edited("600");
        model.action();
        let envelope = fixture(name);
        let message = text::sentence(envelope["error"]["message"].as_str().unwrap());
        assert!(model.apply(answered(Kind::Plan, exit, envelope)).is_empty());
        assert_eq!(model.page().note, message, "{name}");
        assert_eq!(model.page().question, None);
        assert_eq!(model.page().action, Some(text::SAVE_ACTION), "to try again");
    }
    // A change the file holds already writes nothing, and the settings are
    // read again: the page may have shown another value.
    let mut model = settings("config-show");
    model.choose(row("persona.mode"));
    model.choose(1);
    assert_eq!(
        model.apply(answered(
            Kind::Plan,
            0,
            fixture("config-edit-plan-unchanged")
        )),
        vec![Ask::ConfigShow]
    );
    assert_eq!(model.page().note, text::ALREADY_SAID);
}

#[test]
fn an_answer_the_window_does_not_expect_changes_nothing_more() {
    // A read it cannot read: nothing is offered but reading again.
    let mut model = settings("config-show");
    model.choose(row("persona.mode"));
    model.apply(answered(Kind::Config, 0, json!({"command": "config"})));
    let page = model.page();
    assert_eq!(page.heading, text::SETTINGS_UNREADABLE);
    assert!(page.urgent);
    assert!(page.choices.is_empty());
    assert_eq!(page.action, Some(text::READ_AGAIN));
    assert_eq!(model.choose(0), None, "no key's page without the settings");
    assert_eq!(model.action(), Some(Effect::Ask(Ask::ConfigShow)));
    // A settings file the engine cannot read.
    let unreadable = fixture("config-show-invalid");
    let words = text::sentence(unreadable["error"]["message"].as_str().unwrap());
    model.apply(answered(Kind::Config, 3, unreadable));
    assert_eq!(model.page().note, words);
    assert_eq!(model.page().heading, text::SETTINGS_UNREADABLE);
    // An answer with neither data nor an error: nothing is read again by
    // itself, Read Again does it.
    assert!(
        model
            .apply(answered(
                Kind::Config,
                0,
                json!({"schema_version": 2, "command": "config", "ok": true}),
            ))
            .is_empty()
    );
    assert_eq!(model.page().note, text::UNEXPECTED_READ);
    assert_eq!(model.page().action, Some(text::READ_AGAIN));
    // A read that works again brings the list back.
    model.apply(answered(Kind::Config, 0, fixture("config-show")));
    assert_eq!(model.page().heading, text::SETTINGS);

    // A plan answer that wrote without an apply.
    let mut model = settings("config-show");
    model.choose(row("persona.mode"));
    model.choose(1);
    assert_eq!(
        model.apply(answered(Kind::Plan, 0, fixture("config-edit-apply"))),
        vec![Ask::ConfigShow]
    );
    assert_eq!(model.page().note, text::UNEXPECTED_SETTINGS);
    // An apply answer of another command, or with neither data nor error.
    for envelope in [
        json!({"schema_version": 2, "command": "verify", "ok": true, "data": {}}),
        json!({"schema_version": 2, "command": "config", "ok": false}),
    ] {
        let mut model = settings("config-show");
        model.choose(row("persona.mode"));
        model.choose(1);
        model.apply(planned("config-edit-plan"));
        model.answer(true);
        assert_eq!(
            model.apply(answered(Kind::Apply, 0, envelope)),
            vec![Ask::ConfigShow]
        );
        assert_eq!(model.page().note, text::UNEXPECTED_SETTINGS);
    }
}

#[test]
fn back_goes_from_a_setting_to_the_list_and_then_to_the_session() {
    let mut model = settings("config-show");
    model.choose(row("sleep_policy.mode"));
    let page = model.page();
    assert_eq!(page.choices.len(), 3);
    assert_eq!(page.choices[2].title, "Power off");
    assert_eq!(model.back(), None);
    assert_eq!(model.page().heading, text::SETTINGS);
    assert_eq!(model.escape(), Some(Effect::Ask(Ask::Status)));
    assert_eq!(model.page().view, View::Session);
    assert_eq!(model.open_tool(), None);
}
