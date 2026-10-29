// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The rows of a decoy's Nix store database, which the forensic oracle reads
//! from the dump `run-scan.sh` writes of it, one JSON object a line
//! (`{"table": ..., "row": {...}}`), and compares across the images row by
//! row (`nails_oracle::nix_db`).
//!
//! The input is the dump of the database before a session and, after a NUL,
//! the rows the session adds. The target reads each line with a model of its
//! own: a JSON object holding a table's name and its row and nothing else (a
//! `ValidPaths` row naming its store path), keyed by the table and the JSON
//! of every column but those that only order, date or place a row (a
//! `ValidPaths` row's id and registration time, a schema entry's root page),
//! a NULL left out. It checks that the oracle reads exactly the lines the
//! model reads, one finding each, and refuses the dump exactly when it
//! refuses a line; that it reads a row the same when a later boot's dump
//! holds it under other ids, times and pages, its columns and lines in
//! another order; and that two rows give the same finding exactly when the
//! model holds them the same. Over images that hold the rows, the database
//! file rewritten on each, the canary and the planted control, the verdict
//! fails on exactly the session's rows that `before` holds no row like, as
//! added, and on the same rows as removed when the session takes them away
//! instead. It names the database file as one a reboot rewrites exactly when
//! no image holds a row of it.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use libfuzzer_sys::fuzz_target;
use nails_oracle::nix_db::{NIX_DB_PATH, nix_db_findings};
use nails_oracle::{
    Allowlist, Canary, Catalog, Change, Controls, Failure, Finding, OraclePolicy, PositiveControl,
    Scans, Tool, Unseen, decide,
};
use serde_json::Value;

/// The columns, by table, that only order, date or place a row: the oracle
/// keys a row by every other one (ci/oracle/README.md).
const NOT_CONTENT: [(&str, &str); 3] = [
    ("ValidPaths", "id"),
    ("ValidPaths", "registrationTime"),
    ("sqlite_master", "rootpage"),
];

/// The coverage canary every image carries.
const CANARY: &str = "canary@oracle.example";

/// The positive control planted on `after`.
const PLANTED: &str = "planted@oracle.example";

/// A row as the model reads it: its table, and the JSON of each column it is
/// keyed by.
type Row = (String, BTreeMap<String, String>);

/// One row of a dump: the model's reading, the oracle's finding, and the line
/// a later boot's dump holds for it.
struct Read {
    row: Row,
    finding: Finding,
    again: String,
}

fuzz_target!(|data: &[u8]| {
    let parts = nails_fuzz::parts(data, 2);
    let added = parts.get(1).map_or("", String::as_str);
    let (Some(before), Some(added)) = (read(&parts[0]), read(added)) else {
        return;
    };
    let before: Vec<&Read> = before.iter().collect();
    let both: Vec<&Read> = before.iter().copied().chain(&added).collect();
    let before_again = rebooted(&before);
    let both_again = rebooted(&both);
    let before_again: Vec<&Read> = before_again.iter().collect();
    let both_again: Vec<&Read> = both_again.iter().collect();
    let all = both.iter().chain(&before_again).chain(&both_again);
    same_exactly_when_the_model_says(all.copied());

    // The session's rows that `before` holds no row like.
    let held: BTreeSet<&Row> = before.iter().map(|read| &read.row).collect();
    let new: Vec<&str> = added
        .iter()
        .filter(|read| !held.contains(&read.row))
        .map(|read| read.finding.field.as_str())
        .collect();
    let with = |change: Change| -> BTreeSet<(Change, String)> {
        new.iter()
            .map(|field| (change, field.to_string()))
            .collect()
    };
    let no_row = both.is_empty();

    // The session registers them: `after` holds them besides `before`'s rows.
    let (residue, named) = verdict_over(&before, &before_again, &both);
    assert_eq!(residue, with(Change::Added), "the rows the session added");
    assert_eq!(named, no_row, "the database named as one a reboot rewrites");

    // The session removes them: `before` holds them, `after` does not.
    let (residue, named) = verdict_over(&both, &both_again, &before);
    assert_eq!(
        residue,
        with(Change::Removed),
        "the rows the session removed"
    );
    assert_eq!(named, no_row, "the database named as one a reboot rewrites");
});

/// The rows of `dump`, or `None` when the oracle refuses it. Fails unless the
/// oracle reads exactly the lines the model reads as rows, one finding each,
/// reads each row the same as a later boot's dump holds it, and refuses the
/// dump exactly when it refuses a line.
fn read(dump: &str) -> Option<Vec<Read>> {
    let mut rows = Vec::new();
    let mut refused = false;
    let lines = dump.lines().filter(|line| !line.trim().is_empty());
    for (index, line) in lines.enumerate() {
        let alone = nix_db_findings(line);
        let Some((row, again)) = model(line, index) else {
            assert!(
                alone.is_err(),
                "the oracle reads a line that is no row: {line:?}"
            );
            refused = true;
            continue;
        };
        // Written again, the row is read even where the line as it stands is
        // refused (a key it repeats, say), and reads as the same finding.
        let found = nix_db_findings(&again)
            .unwrap_or_else(|why| panic!("the oracle refuses a row: {again:?}: {why}"));
        let [finding] = <[Finding; 1]>::try_from(found).expect("one finding a line");
        let Ok(found) = alone else {
            refused = true;
            continue;
        };
        assert_eq!(
            found,
            [finding.clone()],
            "{line:?} reads otherwise than the same row a later boot holds: {again:?}"
        );
        assert_eq!(
            (finding.tool, finding.path.as_str()),
            (Tool::NixDb, NIX_DB_PATH)
        );
        rows.push(Read {
            row,
            finding,
            again,
        });
    }
    let whole = nix_db_findings(dump);
    assert_eq!(
        whole.is_err(),
        refused,
        "the dump is refused otherwise than its lines"
    );
    let whole = whole.ok()?;
    assert!(
        whole.iter().eq(rows.iter().map(|read| &read.finding)),
        "the dump reads otherwise than its lines"
    );
    Some(rows)
}

/// The model's reading of a line of the dump and the line a later boot's dump
/// holds for the same row, the `index`th: or `None` when the line is not a
/// JSON object holding a table's name and its row and nothing else, or is a
/// `ValidPaths` row that names no store path.
fn model(line: &str, index: usize) -> Option<(Row, String)> {
    let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(line) else {
        return None;
    };
    let (Some(Value::String(table)), Some(Value::Object(row))) =
        (object.remove("table"), object.remove("row"))
    else {
        return None;
    };
    let names_a_path =
        matches!(row.get("path"), Some(Value::String(path)) if path.starts_with('/'));
    if !object.is_empty() || (table == "ValidPaths" && !names_a_path) {
        return None;
    }
    let columns: BTreeMap<String, String> = row
        .iter()
        .filter(|(name, value)| {
            !value.is_null() && !NOT_CONTENT.contains(&(table.as_str(), name.as_str()))
        })
        .map(|(name, value)| (name.clone(), value.to_string()))
        .collect();
    let again = written_again(line, &table, index);
    Some(((table, columns), again))
}

/// The row of `table` that `line` holds as a later boot's dump holds it, the
/// `index`th: each value as `line` writes it, which sqlite3 writes the same
/// for the same value, but the columns that only order, date or place the row
/// given other values, and the columns and the line's own keys in the reverse
/// of their order. A value is not written again from what serde_json read of
/// it: a number past 64 bits reads as a float that need not read back the
/// same.
fn written_again(line: &str, table: &str, index: usize) -> String {
    let (_, row) = members(line)
        .into_iter()
        .rev()
        .find(|(key, _)| key == "row")
        .expect("the line holds a row");
    // A column the row repeats holds its last value, as serde_json reads it.
    let mut columns: BTreeMap<String, String> = members(row)
        .into_iter()
        .map(|(name, value)| (name, value.to_string()))
        .collect();
    for (of, column) in NOT_CONTENT {
        if of == table {
            columns.insert(column.to_string(), (1_000_000 + index).to_string());
        }
    }
    let columns: Vec<String> = columns
        .iter()
        .rev()
        .map(|(name, value)| format!("{}:{value}", Value::from(name.as_str())))
        .collect();
    format!(
        r#"{{"row":{{{}}},"table":{}}}"#,
        columns.join(","),
        Value::from(table)
    )
}

/// The members of the JSON object `text`, which serde_json has read as one,
/// in their order: each key as it decodes, with its value's text as `text`
/// writes it.
fn members(text: &str) -> Vec<(String, &str)> {
    let bytes = text.as_bytes();
    let mut at = past_blanks(bytes, 0);
    assert_eq!(bytes[at], b'{', "an object: {text:?}");
    at = past_blanks(bytes, at + 1);
    let mut members = Vec::new();
    while bytes[at] != b'}' {
        let key_end = value_end(bytes, at);
        let key = serde_json::from_str(&text[at..key_end]).expect("a key");
        at = past_blanks(bytes, key_end);
        assert_eq!(bytes[at], b':', "a key's colon: {text:?}");
        let start = past_blanks(bytes, at + 1);
        let end = value_end(bytes, start);
        members.push((key, &text[start..end]));
        at = past_blanks(bytes, end);
        if bytes[at] == b',' {
            at = past_blanks(bytes, at + 1);
        }
    }
    members
}

/// The first byte from `at` on that is not JSON's whitespace.
fn past_blanks(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

/// Where the JSON value that starts at `start` in `bytes`, valid JSON, ends: a
/// string at its closing quote, an object or an array at the bracket that
/// closes it, and a number or a literal at the first byte that is none of
/// theirs.
fn value_end(bytes: &[u8], start: usize) -> usize {
    let mut at = start;
    let mut depth = 0usize;
    loop {
        let byte = bytes[at];
        at += 1;
        match byte {
            b'"' => {
                while bytes[at] != b'"' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                at += 1;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            _ if depth == 0 => {
                while bytes
                    .get(at)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(byte))
                {
                    at += 1;
                }
            }
            _ => {}
        }
        if depth == 0 {
            return at;
        }
    }
}

/// The rows of `reads` as a later boot's dump holds them, in the reverse
/// order. Fails unless the oracle reads them as the same findings.
fn rebooted(reads: &[&Read]) -> Vec<Read> {
    let lines: Vec<&str> = reads.iter().rev().map(|read| read.again.as_str()).collect();
    let again = read(&lines.join("\n")).expect("the oracle reads a later boot's rows");
    let findings: BTreeSet<&Finding> = reads.iter().map(|read| &read.finding).collect();
    let again_findings: BTreeSet<&Finding> = again.iter().map(|read| &read.finding).collect();
    assert_eq!(
        again_findings, findings,
        "a later boot's rows read otherwise"
    );
    again
}

/// Fails unless two rows give the same finding exactly when the model holds
/// them the same.
fn same_exactly_when_the_model_says<'a>(reads: impl IntoIterator<Item = &'a Read>) {
    let mut by_row: BTreeMap<&Row, &str> = BTreeMap::new();
    let mut by_field: BTreeMap<&str, &Row> = BTreeMap::new();
    for read in reads {
        let field = read.finding.field.as_str();
        if let Some(seen) = by_row.insert(&read.row, field) {
            assert_eq!(seen, field, "one row gives two findings");
        }
        if let Some(seen) = by_field.insert(field, &read.row) {
            assert_eq!(seen, &read.row, "two rows give one finding: {field}");
        }
    }
}

/// One image: its rows, the database file as the restore carve finds it with
/// `digest`, another on every image as each start of the oracle's decoy VMs
/// rewrites it, the canary and, on `after`, the planted control.
fn image(rows: &[&Read], digest: &str, after: bool) -> BTreeSet<Finding> {
    let mut findings: BTreeSet<Finding> = rows.iter().map(|read| read.finding.clone()).collect();
    let file = Finding::new(Tool::BtrfsRestore, NIX_DB_PATH, format!("sha256:{digest}"));
    findings.insert(file);
    findings.insert(Finding::new(Tool::BulkExtractor, "email", CANARY));
    if after {
        findings.insert(Finding::new(Tool::BulkExtractor, "email", PLANTED));
    }
    findings
}

/// The verdict over the images holding `before`, `control` and `after`: how
/// each row it fails on changed, by its field, failing unless it fails on
/// rows of the database alone, and whether it names the database file as one
/// a reboot rewrites.
fn verdict_over(
    before: &[&Read],
    control: &[&Read],
    after: &[&Read],
) -> (BTreeSet<(Change, String)>, bool) {
    let scans = Scans {
        before: image(before, "0b", false),
        control: image(control, "0c", false),
        after: image(after, "0a", true),
        not_run: BTreeSet::new(),
    };
    let verdict = decide(&scans, &policy(), &Catalog::from_rows(Vec::new()));
    let residue: BTreeSet<(Change, String)> = verdict
        .failures
        .iter()
        .map(|failure| match failure {
            Failure::UnexplainedResidue {
                change,
                tool: Tool::NixDb,
                path,
                field,
            } if path == NIX_DB_PATH => (*change, field.clone()),
            other => panic!("the verdict fails on more than the rows: {other:?}"),
        })
        .collect();
    assert_eq!(verdict.is_clean(), residue.is_empty());
    let named = verdict.unseen.iter().any(|class| {
        matches!(class, Unseen::RebootRewritten { paths } if paths.iter().any(|path| path == NIX_DB_PATH))
    });
    (residue, named)
}

/// No allowlist entry, the planted control and the canary.
fn policy() -> OraclePolicy {
    OraclePolicy {
        allowlist: Allowlist::default(),
        controls: Controls {
            comment: None,
            positive_controls: vec![PositiveControl {
                name: "planted".to_string(),
                tool: Some(Tool::BulkExtractor),
                path: "email".to_string(),
                field: Some(PLANTED.to_string()),
                note: None,
            }],
            canary: Canary {
                tool: Some(Tool::BulkExtractor),
                path: "email".to_string(),
                field: Some(CANARY.to_string()),
            },
        },
    }
}
