// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The settings writer's edit of an operator's `nails.toml`
//! (`nails_base::config::edit`), which `config set`, `config unset` and the
//! window's settings run on whatever the file holds.
//!
//! The input is the file, then after a NUL one edit a line: a key alone to
//! unset it, or a key and its words, separated by spaces, to set it as
//! `config set` reads them. A line that names no setting, or words that are no
//! value of it, is left out. The target checks that an edit of a file that
//! parses writes TOML that parses; that every key it sets holds the value asked
//! for and every key it unsets is gone, while every other key, known or not,
//! holds what it held; that every comment of the file is still in it; that the
//! file comes back byte for byte when no value changed; and that the same edits
//! made a second time change nothing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::config::edit::{self, Edit, setting};

fuzz_target!(|data: &[u8]| {
    let parts = nails_fuzz::parts(data, 2);
    let text = parts[0].as_str();
    let edits = edits(parts.get(1).map_or("", String::as_str));
    let Ok(edited) = edit::apply(text, &edits) else {
        return;
    };
    let changed = edited.changes.iter().any(edit::Change::changed);
    if !changed {
        assert_eq!(edited.text, text, "no value changed, so the text did not");
    }

    let mut before = edit::comments(text).expect("the edit read the file as TOML");
    let mut after = edit::comments(&edited.text).expect("the edit writes TOML");
    before.sort();
    after.sort();
    assert_eq!(after, before, "every comment stays:\n{}", edited.text);

    if let Ok(read) = text.parse::<toml::Table>() {
        let written: toml::Table = edited
            .text
            .parse()
            .unwrap_or_else(|error| panic!("{error}:\n{}", edited.text));
        for edit in &edits {
            let wanted = match edit {
                Edit::Set(_, value) => Some(value.to_toml()),
                Edit::Unset(_) => None,
            };
            let setting = edit.setting();
            assert_eq!(value_of(&written, setting), wanted, "{}", setting.key);
        }
        assert_eq!(
            without(&written, &edits),
            without(&read, &edits),
            "every other key holds what it held:\n{}",
            edited.text
        );
    }

    let again = edit::apply(&edited.text, &edits).expect("the edits fit their own result");
    assert_eq!(again.text, edited.text, "a second time changes nothing");
});

/// The edits the lines name, each setting once.
fn edits(lines: &str) -> Vec<Edit> {
    let mut edits: Vec<Edit> = Vec::new();
    for line in lines.lines() {
        let mut words = line.split(' ');
        let Some(setting) = words.next().and_then(setting) else {
            continue;
        };
        if edits.iter().any(|edit| edit.setting() == setting) {
            continue;
        }
        let words: Vec<String> = words.map(str::to_string).collect();
        if words.is_empty() {
            edits.push(Edit::Unset(setting));
        } else if let Ok(value) = setting.parse(&words) {
            edits.push(Edit::Set(setting, value));
        }
    }
    edits
}

/// The value the file gives `setting`.
fn value_of(table: &toml::Table, setting: &edit::Setting) -> Option<toml::Value> {
    match setting.table() {
        None => table.get(setting.name()).cloned(),
        Some(holder) => table.get(holder)?.as_table()?.get(setting.name()).cloned(),
    }
}

/// `table` without the keys the edits name, and without a table they leave
/// empty.
fn without(table: &toml::Table, edits: &[Edit]) -> toml::Table {
    let mut table = table.clone();
    for edit in edits {
        let setting = edit.setting();
        match setting.table() {
            None => {
                table.remove(setting.name());
            }
            Some(holder) => {
                if let Some(toml::Value::Table(inner)) = table.get_mut(holder) {
                    inner.remove(setting.name());
                    if inner.is_empty() {
                        table.remove(holder);
                    }
                }
            }
        }
    }
    table
}
