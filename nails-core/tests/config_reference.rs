// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keeps docs/configuration.md in step with the configuration structs.
//!
//! The Key and Default columns of the key table, and the Path column of the
//! default exclusion table, are generated from the code. The other columns are
//! written by hand and kept across regenerations. After adding, removing or
//! changing a key, regenerate the generated columns with
//!
//! ```text
//! NAILS_REGEN_CONFIG_DOCS=1 cargo test -p nails-core --test config_reference
//! ```
//!
//! and describe any new row: a row with an empty hand-written cell fails.

use std::path::PathBuf;

use nails_core::config::{
    CONFIG_KEYS, Config, DEFAULT_OVERLAY_EXCLUSIONS, LoadedConfig, OverlayConfig, ValueSource,
};
use serde_json::Value;

const DOC_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/configuration.md");
const REGEN_VAR: &str = "NAILS_REGEN_CONFIG_DOCS";
const REGEN_HINT: &str =
    "regenerate with NAILS_REGEN_CONFIG_DOCS=1 cargo test -p nails-core --test config_reference";

/// A table between `<!-- BEGIN region -->` and `<!-- END region -->`.
struct Table {
    region: &'static str,
    header: &'static [&'static str],
    /// Columns filled from the code; every other column is hand-written.
    generated: &'static [usize],
    /// One entry per row, matched to the documented row by its first cell.
    rows: Vec<Vec<String>>,
}

#[test]
fn config_reference_matches_the_code() {
    let doc =
        std::fs::read_to_string(DOC_PATH).unwrap_or_else(|e| panic!("cannot read {DOC_PATH}: {e}"));
    let tables = [key_table(), exclusion_table()];

    let mut synced = doc.clone();
    let mut problems = Vec::new();
    for table in &tables {
        let (start, end) = region_bounds(&synced, table.region);
        let rendered = render(table, &parse_rows(&synced[start..end]), &mut problems);
        synced.replace_range(start..end, &rendered);
    }

    if std::env::var_os(REGEN_VAR).is_some_and(|v| v == "1") {
        if synced != doc {
            std::fs::write(DOC_PATH, &synced)
                .unwrap_or_else(|e| panic!("cannot write {DOC_PATH}: {e}"));
        }
    } else if synced != doc {
        panic!(
            "docs/configuration.md is out of date with the configuration structs; {REGEN_HINT}\n\n{}",
            first_difference(&doc, &synced)
        );
    }

    assert!(
        problems.is_empty(),
        "docs/configuration.md has rows to describe:\n{}",
        problems.join("\n")
    );
}

#[test]
fn config_reference_covers_every_top_level_key() {
    let mut serialized: Vec<String> = complete_tree(&file_defaults().config)
        .as_object()
        .expect("Config serializes to a table")
        .keys()
        .cloned()
        .collect();
    let mut listed: Vec<String> = CONFIG_KEYS.iter().map(|k| (*k).to_string()).collect();
    serialized.sort();
    listed.sort();

    assert_eq!(
        serialized, listed,
        "CONFIG_KEYS fixes the order of the reference; add or remove the key there"
    );
}

#[test]
fn config_reference_defaults_hold_without_a_file() {
    // The reference documents one default per key, so running with no file
    // at all must behave like an empty file. The built-in defaults also carry
    // example overlay tables; only explicit mode mounts those, and explicit
    // mode can only be selected in a file.
    let without_file = serde_json::to_value(Config::default()).expect("Config serializes");
    let empty_file = serde_json::to_value(file_defaults().config).expect("Config serializes");

    for key in CONFIG_KEYS.iter().filter(|key| **key != "overlays") {
        assert_eq!(without_file[*key], empty_file[*key], "default of {key}");
    }
}

/// Rows of the key table: `| Key | Type | Default | Effect |`.
fn key_table() -> Table {
    let loaded = file_defaults();
    let defaults = serde_json::to_value(&loaded.config).expect("Config serializes");
    let tree = complete_tree(&loaded.config);
    let root = loaded
        .config
        .hidden_volume_root
        .to_string_lossy()
        .into_owned();

    let mut rows = Vec::new();
    for key in CONFIG_KEYS {
        let derived = loaded.source(key) == ValueSource::Derived;
        push_rows(&mut rows, key, &tree[*key], &defaults[*key], derived, &root);
    }

    Table {
        region: "config-keys",
        header: &["Key", "Type", "Default", "Effect"],
        generated: &[0, 2],
        rows,
    }
}

/// Rows of the exclusion table: `| Path | Why it is excluded |`.
fn exclusion_table() -> Table {
    Table {
        region: "default-exclusions",
        header: &["Path", "Why it is excluded"],
        generated: &[0],
        rows: DEFAULT_OVERLAY_EXCLUSIONS
            .iter()
            .map(|path| vec![format!("`{path}`"), String::new()])
            .collect(),
    }
}

/// The configuration an empty `nails.toml` yields: the value each key takes
/// when the file leaves it out.
fn file_defaults() -> LoadedConfig {
    let file = tempfile::NamedTempFile::new().expect("temp file");
    LoadedConfig::load(file.path()).expect("an empty file is a valid configuration")
}

/// Every key the configuration accepts, including those a default leaves out
/// of the output: JSON keeps `None` as `null`, and one overlay table exposes
/// the keys inside `[[overlays]]`.
fn complete_tree(config: &Config) -> Value {
    let sample = Config {
        overlays: vec![OverlayConfig::default()],
        ..config.clone()
    };
    serde_json::to_value(&sample).expect("Config serializes")
}

fn push_rows(
    rows: &mut Vec<Vec<String>>,
    key: &str,
    shape: &Value,
    default: &Value,
    derived: bool,
    root: &str,
) {
    match shape {
        Value::Object(fields) => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            for name in names {
                let nested = format!("{key}.{name}");
                push_rows(rows, &nested, &fields[name], &default[name], false, root);
            }
        }
        Value::Array(items) if items.first().is_some_and(Value::is_object) => {
            rows.push(row(key, render_value(default)));
            let mut names: Vec<&String> = items[0].as_object().unwrap().keys().collect();
            names.sort();
            for name in names {
                rows.push(row(
                    &format!("{key}[].{name}"),
                    array_item_default(key, name),
                ));
            }
        }
        _ if derived => rows.push(row(key, render_derived(key, default, root))),
        _ => rows.push(row(key, render_value(default))),
    }
}

fn row(key: &str, default: String) -> Vec<String> {
    vec![format!("`{key}`"), String::new(), default, String::new()]
}

/// Default of `field` inside each table of the array `key`: "required" when
/// a table without it is rejected.
fn array_item_default(key: &str, field: &str) -> String {
    let sample = Config {
        overlays: vec![OverlayConfig::default()],
        ..file_defaults().config
    };
    let full = toml::Table::try_from(&sample).expect("Config serializes to TOML");
    let mut item = full[key].as_array().unwrap()[0].as_table().unwrap().clone();
    item.remove(field);

    let mut doc = toml::Table::new();
    doc.insert(
        key.to_string(),
        toml::Value::Array(vec![toml::Value::Table(item)]),
    );
    match toml::from_str::<Config>(&doc.to_string()) {
        Err(_) => "required".to_string(),
        Ok(config) => {
            let value = serde_json::to_value(&config).expect("Config serializes");
            render_value(&value[key][0][field])
        }
    }
}

fn render_value(value: &Value) -> String {
    if value.is_null() {
        return "unset".to_string();
    }
    let toml = toml::Value::try_from(value).expect("default is representable in TOML");
    format!("`{toml}`")
}

/// Derived paths are shown relative to the hidden volume root, which itself
/// comes from the binary location and so differs between machines.
fn render_derived(key: &str, value: &Value, root: &str) -> String {
    let path = value.as_str().expect("derived defaults are paths");
    if path == root {
        return "derived from the binary location".to_string();
    }
    let full = PathBuf::from(path);
    let relative = full
        .strip_prefix(root)
        .unwrap_or_else(|_| panic!("derived default of {key} ({path}) is not under {root}"));
    format!("`<hidden_volume_root>/{}`", relative.display())
}

/// Byte range of the text between the region's BEGIN and END markers.
fn region_bounds(doc: &str, region: &str) -> (usize, usize) {
    let begin = format!("<!-- BEGIN {region} -->\n");
    let end = format!("<!-- END {region} -->");
    let start = doc
        .find(&begin)
        .unwrap_or_else(|| panic!("docs/configuration.md lacks the line {}", begin.trim()))
        + begin.len();
    let stop = doc[start..]
        .find(&end)
        .unwrap_or_else(|| panic!("docs/configuration.md lacks the line {end}"))
        + start;
    (start, stop)
}

/// Body rows of the Markdown table in `text`, split into trimmed cells.
fn parse_rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .skip(1)
        .map(split_cells)
        .filter(|cells| {
            !cells
                .iter()
                .all(|c| !c.is_empty() && c.chars().all(|ch| matches!(ch, '-' | ':')))
        })
        .collect()
}

/// Cells of one table row. A pipe inside a cell is written `\|`, as GitHub
/// Markdown requires.
fn split_cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    for ch in inner.chars() {
        if ch == '|' && !escaped {
            cells.push(cell.trim().to_string());
            cell.clear();
        } else {
            cell.push(ch);
        }
        escaped = ch == '\\';
    }
    cells.push(cell.trim().to_string());
    cells
}

/// Render `table`, taking hand-written cells from `existing` rows with the
/// same first cell. Rows left with an empty hand-written cell are reported.
fn render(table: &Table, existing: &[Vec<String>], problems: &mut Vec<String>) -> String {
    let mut out = format!(
        "| {} |\n|{}\n",
        table.header.join(" | "),
        "---|".repeat(table.header.len())
    );
    for generated in &table.rows {
        let previous = existing
            .iter()
            .find(|cells| cells.first() == generated.first());
        let cells: Vec<String> = (0..table.header.len())
            .map(|column| {
                if table.generated.contains(&column) {
                    generated[column].clone()
                } else {
                    previous
                        .and_then(|cells| cells.get(column))
                        .cloned()
                        .unwrap_or_default()
                }
            })
            .collect();
        for (column, cell) in cells.iter().enumerate() {
            if cell.is_empty() {
                problems.push(format!(
                    "{}: row {} has no {}",
                    table.region, cells[0], table.header[column]
                ));
            }
        }
        out.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
    out
}

fn first_difference(expected: &str, actual: &str) -> String {
    expected
        .lines()
        .zip(actual.lines())
        .enumerate()
        .find(|(_, (a, b))| a != b)
        .map(|(n, (a, b))| format!("line {}:\n  doc:       {a}\n  generated: {b}", n + 1))
        .unwrap_or_else(|| "the documented table has a different number of rows".to_string())
}
