// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use proptest::prelude::*;

use super::*;
use crate::config::{CONFIG_KEYS, Config, LoadedConfig};

fn key(name: &str) -> &'static Setting {
    setting(name).unwrap_or_else(|| panic!("{name} is a setting"))
}

fn set(name: &str, value: Value) -> Edit {
    Edit::Set(key(name), value)
}

fn unset(name: &str) -> Edit {
    Edit::Unset(key(name))
}

fn string(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn edited(text: &str, edits: &[Edit]) -> String {
    apply(text, edits)
        .unwrap_or_else(|error| panic!("{edits:?} on {text:?}: {error}"))
        .text
}

/// The loader `config validate` runs, on `text`.
fn loads(text: &str) -> Config {
    LoadedConfig::parse(Path::new("/mnt/data/config/nails.toml"), text)
        .unwrap_or_else(|error| panic!("{error}:\n{text}"))
        .into_config()
}

fn sorted_comments(text: &str) -> Vec<String> {
    let mut comments = comments(text).unwrap_or_else(|| panic!("not TOML:\n{text}"));
    comments.sort();
    comments
}

/// The keys of the reference's key table, as config_reference.rs derives
/// them: every top-level key in `CONFIG_KEYS` order, a table's keys sorted.
fn reference_keys() -> Vec<String> {
    let tree = serde_json::to_value(Config::default()).unwrap();
    let mut keys = Vec::new();
    for top in CONFIG_KEYS {
        match &tree[*top] {
            serde_json::Value::Object(fields) => {
                let mut names: Vec<&String> = fields.keys().collect();
                names.sort();
                keys.extend(names.into_iter().map(|name| format!("{top}.{name}")));
            }
            _ => keys.push((*top).to_string()),
        }
    }
    keys
}

#[test]
fn the_settings_are_every_key_of_the_reference_in_its_order() {
    let settings: Vec<String> = SETTINGS.iter().map(|s| s.key.to_string()).collect();
    assert_eq!(settings, reference_keys());
}

#[test]
fn each_kind_fits_the_default_of_its_key() {
    let tree = serde_json::to_value(Config::default()).unwrap();
    for setting in SETTINGS {
        let default = match setting.table() {
            Some(table) => &tree[table][setting.name()],
            None => &tree[setting.key],
        };
        let fits = match setting.kind {
            Kind::Bool => default.is_boolean(),
            Kind::Integer => default.is_u64(),
            Kind::Path => default.is_string(),
            Kind::Text => default.is_null(),
            Kind::Choice(choices) => default.as_str().is_some_and(|d| choices.contains(&d)),
            Kind::Names => default.is_array(),
        };
        assert!(fits, "{}: {:?} for {default}", setting.key, setting.kind);
    }
}

#[test]
fn every_choice_is_a_spelling_the_loader_takes_and_no_other_is() {
    use crate::config::{PersonaMode, SleepPolicyMode};
    let spellings = |values: Vec<serde_json::Value>| -> Vec<String> {
        values
            .into_iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    let persona = spellings(vec![
        serde_json::to_value(PersonaMode::SharedHome).unwrap(),
        serde_json::to_value(PersonaMode::FreshHome).unwrap(),
    ]);
    let sleep = spellings(vec![
        serde_json::to_value(SleepPolicyMode::Warn).unwrap(),
        serde_json::to_value(SleepPolicyMode::Block).unwrap(),
        serde_json::to_value(SleepPolicyMode::Teardown).unwrap(),
    ]);
    for (name, all) in [("persona.mode", persona), ("sleep_policy.mode", sleep)] {
        let Kind::Choice(choices) = key(name).kind else {
            panic!("{name} is a choice");
        };
        assert_eq!(choices, all, "{name}");
        for choice in choices {
            let text = edited("", &[set(name, string(choice))]);
            loads(&text);
        }
        let refused = key(name).parse(&["bogus".to_string()]).unwrap_err();
        assert!(refused.contains(&quoted_list(choices)), "{refused}");
    }
}

fn words(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_string()).collect()
}

#[test]
fn a_boolean_is_true_or_false_and_nothing_else() {
    let setting = key("show_opsec_reminders");
    assert_eq!(setting.parse(&words(&["true"])), Ok(Value::Bool(true)));
    assert_eq!(setting.parse(&words(&["false"])), Ok(Value::Bool(false)));
    for bad in ["True", "yes", "1", "on", ""] {
        let error = setting.parse(&words(&[bad])).unwrap_err();
        assert_eq!(
            error,
            format!("`show_opsec_reminders` takes true or false, not {bad:?}")
        );
    }
    assert!(setting.parse(&words(&["true", "false"])).is_err());
    assert!(setting.parse(&[]).is_err());
    assert!(setting.check(&string("true")).is_err());
}

#[test]
fn an_integer_is_a_whole_number_toml_can_hold() {
    let setting = key("minimum_space_mb");
    assert_eq!(setting.parse(&words(&["0"])), Ok(Value::Integer(0)));
    assert_eq!(setting.parse(&words(&["750"])), Ok(Value::Integer(750)));
    let max = MAX_INTEGER.to_string();
    assert_eq!(setting.parse(&[max]), Ok(Value::Integer(MAX_INTEGER)));
    for bad in [
        "-1",
        "+1",
        "1.5",
        "1_000",
        "",
        " 1",
        "9223372036854775808",
        "1e3",
    ] {
        assert!(setting.parse(&words(&[bad])).is_err(), "{bad:?}");
    }
    assert!(setting.check(&Value::Integer(MAX_INTEGER + 1)).is_err());
    assert!(setting.check(&Value::Bool(true)).is_err());
    let written = edited("", &[set("minimum_space_mb", Value::Integer(MAX_INTEGER))]);
    assert_eq!(loads(&written).minimum_space_mb, MAX_INTEGER);
}

#[test]
fn a_path_or_a_string_is_one_word_that_is_not_empty() {
    for name in [
        "hidden_volume_root",
        "state_file_path",
        "log_path",
        "nixos_flake",
    ] {
        let setting = key(name);
        assert_eq!(setting.parse(&words(&["/mnt/x"])), Ok(string("/mnt/x")));
        assert!(setting.parse(&words(&[""])).is_err(), "{name}");
        assert!(setting.parse(&words(&["/a", "/b"])).is_err(), "{name}");
        assert!(setting.check(&Value::Names(vec![])).is_err(), "{name}");
    }
}

#[test]
fn a_list_takes_one_word_per_entry() {
    let setting = key("persona.mask_inherited");
    assert_eq!(
        setting.parse(&words(&["dropbox", "syncthing.service"])),
        Ok(Value::Names(words(&["dropbox", "syncthing.service"])))
    );
    assert_eq!(
        setting.parse(&words(&["*"])),
        Ok(Value::Names(words(&["*"])))
    );
    assert!(setting.parse(&[]).is_err());
    // A window may send an empty list; the loader takes it.
    assert!(setting.check(&Value::Names(vec![])).is_ok());
    assert!(setting.check(&string("dropbox")).is_err());
}

#[test]
fn an_unknown_key_names_the_closest_setting() {
    assert_eq!(
        unknown_key("persona.mod"),
        "unknown key `persona.mod` (did you mean `persona.mode`?)"
    );
    assert!(unknown_key("colour").starts_with("unknown key `colour`"));
    assert!(setting("persona").is_none());
    assert!(setting("persona.mode.x").is_none());
}

#[test]
fn every_kind_is_written_as_the_loader_reads_it() {
    let edits = [
        set("hidden_volume_root", string("/mnt/data")),
        set("state_file_path", string("/mnt/data/state.json")),
        set("log_path", string("/mnt/data/logs")),
        set("minimum_space_mb", Value::Integer(750)),
        set("rebuild_space_mb", Value::Integer(8192)),
        set("show_opsec_reminders", Value::Bool(false)),
        set("nixos_flake", string("/mnt/data/nixos#my-host")),
        set(
            "persona.mask_inherited",
            Value::Names(words(&["dropbox", "x.service"])),
        ),
        set("persona.mode", string("fresh-home")),
        set("backend_watch.auto_emergency", Value::Bool(true)),
        set("backend_watch.debounce_secs", Value::Integer(30)),
        set("backend_watch.enabled", Value::Bool(false)),
        set("backend_watch.poll_interval_secs", Value::Integer(2)),
        set("session_mounts.alert", Value::Bool(false)),
        set("session_mounts.read_only", Value::Bool(true)),
        set("sleep_policy.mode", string("teardown")),
    ];
    assert_eq!(edits.len(), SETTINGS.len());
    let text = edited("", &edits);
    let config = loads(&text);
    assert_eq!(config.minimum_space_mb, 750);
    assert_eq!(config.rebuild_space_mb, 8192);
    assert!(!config.show_opsec_reminders);
    assert_eq!(
        config.nixos_flake.as_deref(),
        Some("/mnt/data/nixos#my-host")
    );
    assert_eq!(
        config.persona.mask_inherited,
        words(&["dropbox", "x.service"])
    );
    assert_eq!(config.persona.mode, crate::config::PersonaMode::FreshHome);
    assert!(config.backend_watch.auto_emergency && !config.backend_watch.enabled);
    assert_eq!(config.backend_watch.debounce_secs, 30);
    assert_eq!(config.backend_watch.poll_interval_secs, 2);
    assert!(!config.session_mounts.alert && config.session_mounts.read_only);
    assert_eq!(
        config.sleep_policy.mode,
        crate::config::SleepPolicyMode::Teardown
    );
    // Each table once, after the keys at the top.
    assert_eq!(text.matches("[persona]").count(), 1, "{text}");
    assert!(text.find("nixos_flake").unwrap() < text.find("[persona]").unwrap());
}

#[test]
fn a_new_key_goes_below_the_template_and_keeps_every_line_of_it() {
    let template = Config::init_template(Path::new("/mnt/data"));
    let text = edited(&template, &[set("minimum_space_mb", Value::Integer(2000))]);
    assert!(text.starts_with(&template), "the template stays as it was");
    assert_eq!(&text[template.len()..], "\nminimum_space_mb = 2000\n");
    assert_eq!(sorted_comments(&text), sorted_comments(&template));
    assert_eq!(loads(&text).minimum_space_mb, 2000);

    // A table goes below it too, and a second key after the first.
    let text = edited(&text, &[set("persona.mode", string("fresh-home"))]);
    let text = edited(&text, &[set("show_opsec_reminders", Value::Bool(false))]);
    assert!(text.starts_with(&template));
    assert_eq!(
        &text[template.len()..],
        "\nminimum_space_mb = 2000\nshow_opsec_reminders = false\n\n[persona]\nmode = \"fresh-home\"\n"
    );
    loads(&text);
}

#[test]
fn a_changed_value_keeps_its_line_its_comments_and_the_order() {
    let before = "\
# Space for the big stick.
minimum_space_mb = 500  # was 250
show_opsec_reminders = true

[persona]
# The home starts empty.
mode    =   'shared-home'   # for now
mask_inherited = [\"dropbox\"]
";
    let text = edited(
        before,
        &[
            set("minimum_space_mb", Value::Integer(2000)),
            set("persona.mode", string("fresh-home")),
        ],
    );
    assert_eq!(
        text,
        "\
# Space for the big stick.
minimum_space_mb = 2000  # was 250
show_opsec_reminders = true

[persona]
# The home starts empty.
mode    =   \"fresh-home\"   # for now
mask_inherited = [\"dropbox\"]
"
    );
}

#[test]
fn a_value_already_set_leaves_the_file_byte_for_byte() {
    let before = "minimum_space_mb = 0x2EE  # hex\n[persona]\nmode = 'fresh-home'\n";
    let result = apply(
        before,
        &[
            set("minimum_space_mb", Value::Integer(750)),
            set("persona.mode", string("fresh-home")),
            unset("nixos_flake"),
        ],
    )
    .unwrap();
    assert_eq!(result.text, before);
    assert!(result.changes.iter().all(|change| !change.changed()));
    assert_eq!(
        result.changes[0].before,
        Some(toml::Value::Integer(750)),
        "the file's own spelling, read as TOML"
    );
    assert_eq!(result.changes[2].before, None);
}

#[test]
fn a_new_key_of_a_table_goes_after_its_keys_and_before_the_next_table() {
    let before = "\
[backend_watch]
enabled = true
# auto_emergency = false

[sleep_policy]
mode = \"warn\"
";
    let text = edited(
        before,
        &[set("backend_watch.debounce_secs", Value::Integer(30))],
    );
    assert_eq!(
        text,
        "\
[backend_watch]
enabled = true
debounce_secs = 30
# auto_emergency = false

[sleep_policy]
mode = \"warn\"
"
    );
}

#[test]
fn a_new_table_goes_last_and_after_the_comments_that_end_the_file() {
    let before = "minimum_space_mb = 750\n\n[persona]\nmode = \"fresh-home\"\n\n# The end.\n";
    let text = edited(before, &[set("sleep_policy.mode", string("block"))]);
    assert_eq!(
        text,
        "minimum_space_mb = 750\n\n[persona]\nmode = \"fresh-home\"\n\n# The end.\n\n[sleep_policy]\nmode = \"block\"\n"
    );
    let text = edited(
        "minimum_space_mb = 750\n",
        &[set("sleep_policy.mode", string("block"))],
    );
    assert_eq!(
        text,
        "minimum_space_mb = 750\n\n[sleep_policy]\nmode = \"block\"\n"
    );
}

#[test]
fn a_key_at_the_top_of_a_file_of_tables_goes_below_its_opening_comments() {
    let before = "\
# My settings.
# Second line.

# The home starts empty.
[persona]
mode = \"fresh-home\"
";
    let text = edited(before, &[set("minimum_space_mb", Value::Integer(750))]);
    assert_eq!(
        text,
        "\
# My settings.
# Second line.

minimum_space_mb = 750

# The home starts empty.
[persona]
mode = \"fresh-home\"
"
    );
    assert_eq!(sorted_comments(&text), sorted_comments(before));
    // With no blank line, every comment belongs to the header: the key goes
    // above them.
    let before = "# The home starts empty.\n[persona]\nmode = \"fresh-home\"\n";
    let text = edited(before, &[set("minimum_space_mb", Value::Integer(750))]);
    assert_eq!(
        text,
        "minimum_space_mb = 750\n\n# The home starts empty.\n[persona]\nmode = \"fresh-home\"\n"
    );
}

#[test]
fn a_dotted_key_and_an_inline_table_are_edited_where_they_are() {
    let before = "persona.mode = \"shared-home\" # dotted\nminimum_space_mb = 750\n";
    let text = edited(
        before,
        &[
            set("persona.mode", string("fresh-home")),
            set("persona.mask_inherited", Value::Names(words(&["dropbox"]))),
        ],
    );
    assert_eq!(
        text,
        "persona.mode = \"fresh-home\" # dotted\npersona.mask_inherited = [\"dropbox\"]\nminimum_space_mb = 750\n"
    );
    loads(&text);

    let before = "persona = { mode = \"shared-home\" } # inline\n";
    let text = edited(
        before,
        &[
            set("persona.mode", string("fresh-home")),
            set("persona.mask_inherited", Value::Names(words(&["*"]))),
        ],
    );
    assert_eq!(
        text,
        "persona = { mode = \"fresh-home\", mask_inherited = [\"*\"] } # inline\n"
    );
    let config = loads(&text);
    assert!(config.persona.masks_all_inherited());
    let text = edited(&text, &[unset("persona.mode")]);
    assert_eq!(text, "persona = { mask_inherited = [\"*\"] } # inline\n");
    loads(&text);
}

#[test]
fn a_removed_key_leaves_its_comments_where_the_next_line_starts() {
    let before = "\
minimum_space_mb = 750
# Built from the hidden flake.
nixos_flake = \"/mnt/data/nixos#host\"  # since October
show_opsec_reminders = false
";
    let text = edited(before, &[unset("nixos_flake")]);
    assert_eq!(
        text,
        "\
minimum_space_mb = 750
# Built from the hidden flake.
# since October
show_opsec_reminders = false
"
    );
    assert_eq!(sorted_comments(&text), sorted_comments(before));
    assert!(loads(&text).nixos_flake.is_none());
}

#[test]
fn the_comments_of_the_last_key_of_a_table_stay_above_the_next_header() {
    let before = "\
[persona]
# The home starts empty.
mode = \"fresh-home\"

[sleep_policy]
mode = \"block\"
";
    let text = edited(before, &[unset("persona.mode")]);
    assert_eq!(
        text,
        "\
[persona]
# The home starts empty.

[sleep_policy]
mode = \"block\"
"
    );
    // At the end of the file they stay at the end.
    let text = edited(&text, &[unset("sleep_policy.mode")]);
    assert_eq!(
        text,
        "[persona]\n# The home starts empty.\n\n[sleep_policy]\n"
    );
    let before = "minimum_space_mb = 1\n# about the reminders\nshow_opsec_reminders = true\n";
    let text = edited(before, &[unset("show_opsec_reminders")]);
    assert_eq!(text, "minimum_space_mb = 1\n# about the reminders\n");
    // A key with no comment takes no line with it.
    let text = edited(
        "a_key = 1\nminimum_space_mb = 2\n\nb_key = 3\n",
        &[unset("minimum_space_mb")],
    );
    assert_eq!(text, "a_key = 1\n\nb_key = 3\n");
}

#[test]
fn a_list_written_over_lines_keeps_its_comments() {
    let before = "\
[persona]
mask_inherited = [
  # the sync client
  \"dropbox\",
  \"syncthing.service\", # its unit
]
";
    let text = edited(
        before,
        &[set(
            "persona.mask_inherited",
            Value::Names(words(&["telegram"])),
        )],
    );
    assert_eq!(sorted_comments(&text), sorted_comments(before));
    assert_eq!(loads(&text).persona.mask_inherited, words(&["telegram"]));
    assert!(
        text.starts_with("[persona]\n# the sync client\n# its unit\nmask_inherited = "),
        "{text}"
    );
    let text = edited(before, &[unset("persona.mask_inherited")]);
    assert_eq!(text, "[persona]\n# the sync client\n# its unit\n");
}

#[test]
fn keys_the_writer_does_not_know_stay_where_they_are() {
    // Unknown keys are the loader's to refuse; the edit itself keeps them.
    let before = "\
bogus = 1
minimum_space_mb = 750

[persona]
extra = \"kept\"

[elsewhere]
other = true
";
    let text = edited(
        before,
        &[
            set("persona.mode", string("fresh-home")),
            unset("minimum_space_mb"),
            set("show_opsec_reminders", Value::Bool(false)),
        ],
    );
    assert_eq!(
        text,
        "\
bogus = 1
show_opsec_reminders = false

[persona]
extra = \"kept\"
mode = \"fresh-home\"

[elsewhere]
other = true
"
    );
}

#[test]
fn a_value_where_a_table_goes_or_a_table_where_a_value_goes_is_refused() {
    let error = apply(
        "persona = 5\n",
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "`persona.mode` cannot be changed: `persona` is an integer in the file"
    );
    // There is nothing of persona.mode to remove.
    let result = apply("persona = 5\n", &[unset("persona.mode")]).unwrap();
    assert_eq!(result.text, "persona = 5\n");
    let error = apply("[minimum_space_mb]\n", &[unset("minimum_space_mb")]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "`minimum_space_mb` cannot be changed: `minimum_space_mb` is a table in the file"
    );
    assert!(
        apply(
            "[[persona]]\n",
            &[set("persona.mode", string("fresh-home"))]
        )
        .is_err()
    );
}

#[test]
fn a_setting_named_twice_a_bad_value_and_a_file_that_is_not_toml_are_refused() {
    let error = apply(
        "",
        &[
            unset("persona.mode"),
            set("persona.mode", string("fresh-home")),
        ],
    )
    .unwrap_err();
    assert_eq!(error, EditError::Repeated("persona.mode"));
    let error = apply("", &[set("persona.mode", string("separate-user"))]).unwrap_err();
    assert!(matches!(error, EditError::Value(_)), "{error}");
    let error = apply("minimum_space_mb = \n", &[unset("minimum_space_mb")]).unwrap_err();
    assert!(matches!(error, EditError::Syntax(_)), "{error}");
    let error = apply("a = 1\na = 2\n", &[unset("minimum_space_mb")]).unwrap_err();
    assert!(matches!(error, EditError::Syntax(_)), "{error}");
}

#[test]
fn the_changes_say_what_each_edit_did() {
    let result = apply(
        "minimum_space_mb = 750\n",
        &[
            set("minimum_space_mb", Value::Integer(1000)),
            set("persona.mode", string("fresh-home")),
        ],
    )
    .unwrap();
    assert_eq!(
        result.changes,
        vec![
            Change {
                key: "minimum_space_mb",
                before: Some(toml::Value::Integer(750)),
                after: Some(toml::Value::Integer(1000)),
            },
            Change {
                key: "persona.mode",
                before: None,
                after: Some(toml::Value::String("fresh-home".into())),
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// Properties: any layout, any edits.
// ---------------------------------------------------------------------------

/// A comment line the generated documents use.
fn comment() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("# a note".to_string()),
        Just("#".to_string()),
        Just("# key = \"value\" # inner".to_string()),
        "[a-z ]{0,12}".prop_map(|text| format!("# {text}")),
    ]
}

fn value_for(setting: &'static Setting) -> BoxedStrategy<Value> {
    match setting.kind {
        Kind::Bool => any::<bool>().prop_map(Value::Bool).boxed(),
        Kind::Integer => (0..=MAX_INTEGER).prop_map(Value::Integer).boxed(),
        Kind::Path => "/mnt/data(/[a-z]{1,6}){0,2}".prop_map(Value::Text).boxed(),
        Kind::Text => "/mnt/data/nixos#[a-z]{1,6}".prop_map(Value::Text).boxed(),
        Kind::Choice(choices) => proptest::sample::select(choices)
            .prop_map(|choice| Value::Text(choice.to_string()))
            .boxed(),
        Kind::Names => proptest::collection::vec("[a-z]{1,6}(\\.service)?", 0..3)
            .prop_map(Value::Names)
            .boxed(),
    }
}

/// How a generated document writes its tables.
#[derive(Debug, Clone, Copy)]
enum Layout {
    Header,
    Dotted,
    Inline,
}

/// One line of TOML for `value`.
fn written(value: &Value) -> String {
    value.to_toml().to_string()
}

/// A document holding `values`, laid out as `layout` says, with a comment
/// before some keys and tables and after some values, an unknown key, and
/// comments at the end.
fn document(values: &[(&'static Setting, Value)], layout: Layout, comments: &[String]) -> String {
    let mut next_comment = comments.iter().cycle();
    let mut comment = || next_comment.next().cloned().unwrap_or_default();
    let mut top = format!("{}\nunknown_top = 1\n", comment());
    let mut tables: Vec<(&str, Vec<String>)> = Vec::new();
    for (setting, value) in values {
        let line = format!("{} = {}", setting.name(), written(value));
        match setting.table() {
            None => top.push_str(&format!("{}\n{line} {}\n", comment(), comment())),
            Some(table) => match tables.iter_mut().find(|(name, _)| *name == table) {
                Some((_, lines)) => lines.push(line),
                None => tables.push((table, vec![line])),
            },
        }
    }
    let mut text = top;
    for (table, lines) in &tables {
        match layout {
            Layout::Header => {
                text.push_str(&format!("\n{}\n[{table}]\n", comment()));
                for line in lines {
                    text.push_str(&format!("{line} {}\n", comment()));
                }
            }
            Layout::Dotted => {
                for line in lines {
                    text.push_str(&format!("{}\n{table}.{line}\n", comment()));
                }
            }
            Layout::Inline => {
                text.push_str(&format!("{table} = {{ {} }}\n", lines.join(", ")));
            }
        }
    }
    text.push_str(&format!("{}\n", comment()));
    text
}

fn documents() -> impl Strategy<Value = String> {
    let values =
        proptest::sample::subsequence(SETTINGS.iter().collect::<Vec<_>>(), 0..=SETTINGS.len())
            .prop_flat_map(|chosen| {
                chosen
                    .into_iter()
                    .map(|setting| value_for(setting).prop_map(move |value| (setting, value)))
                    .collect::<Vec<_>>()
            });
    let layout = prop_oneof![
        Just(Layout::Header),
        Just(Layout::Dotted),
        Just(Layout::Inline)
    ];
    (values, layout, proptest::collection::vec(comment(), 1..6))
        .prop_map(|(values, layout, comments)| document(&values, layout, &comments))
}

fn edits() -> impl Strategy<Value = Vec<Edit>> {
    proptest::sample::subsequence(SETTINGS.iter().collect::<Vec<_>>(), 1..=4)
        .prop_flat_map(|chosen| {
            chosen
                .into_iter()
                .map(|setting| {
                    prop_oneof![
                        value_for(setting).prop_map(move |value| Edit::Set(setting, value)),
                        Just(Edit::Unset(setting)),
                    ]
                })
                .collect::<Vec<_>>()
        })
        .prop_shuffle()
}

/// The value `text` gives `setting`, read as TOML.
fn read(table: &toml::Table, setting: &Setting) -> Option<toml::Value> {
    match setting.table() {
        None => table.get(setting.name()).cloned(),
        Some(holder) => table.get(holder)?.get(setting.name()).cloned(),
    }
}

proptest! {
    #[test]
    fn fuzz_an_edit_does_what_it_says_and_nothing_else(text in documents(), edits in edits()) {
        let before: toml::Table = text.parse().expect("the generator writes TOML");
        let result = apply(&text, &edits).expect("every edit fits the generated documents");
        let after: toml::Table = result.text.parse().unwrap_or_else(|e| panic!("{e}:\n{}", result.text));
        for setting in SETTINGS {
            let edit = edits.iter().find(|edit| edit.setting() == setting);
            let expected = match edit {
                Some(Edit::Set(_, value)) => Some(value.to_toml()),
                Some(Edit::Unset(_)) => None,
                None => read(&before, setting),
            };
            prop_assert_eq!(read(&after, setting), expected, "{}:\n{}", setting.key, result.text);
        }
        prop_assert_eq!(after.get("unknown_top"), before.get("unknown_top"));
        prop_assert_eq!(sorted_comments(&result.text), sorted_comments(&text));
        let again = apply(&result.text, &edits).unwrap();
        prop_assert_eq!(&again.text, &result.text, "a second time changes nothing");
        prop_assert!(again.changes.iter().all(|change| !change.changed()));
    }
}
