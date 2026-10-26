// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keys for the rows of the Nix store database, so that what the database
//! holds subtracts across the three images exactly when its row does.
//!
//! The oracle's decoy VMs register their store paths at every start (the QEMU
//! test module's `register-nix-paths`), and each registration rewrites pages
//! of the database file, so the file's digest differs on every image and the
//! restore channel can only call it noise: a store path a session registered
//! there would go unseen. Its rows do not change with such a start.
//! `run-scan.sh` therefore dumps every row of each restored database before it
//! empties the file, one JSON object a line (`{"table": ..., "row": {...}}`):
//! the rows of each of its tables and of its schema (`sqlite_master`). Among
//! them are `ValidPaths`, one row per registered store path, `Refs`, the
//! references between those paths by their `ValidPaths` ids, and
//! `sqlite_sequence`, which keeps the highest id `ValidPaths` ever gave out, so
//! a store path the session registered and collected again leaves it raised.
//!
//! Each row is keyed by its table and every column but those that only order,
//! date or place it ([`NOT_CONTENT`]). Every other column is kept, so a path
//! the session registered or removed, or one registered again with another
//! hash, deriver, size, signature or content address, is a change, and so is a
//! reference, a raised sequence or a schema entry the session changed. Each
//! value is written as JSON, and so is a name that is not a plain identifier,
//! so two rows read alike only when they hold the same: a value with a blank
//! and `name=value` in it never reads as two columns, nor a number as its
//! digits in text. The rows are what the database holds; what its unused
//! space still holds of rows it deleted is not read.

use crate::model::{Finding, Tool};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Where the Nix store database sits on an image.
pub const NIX_DB_PATH: &str = "/nix/var/nix/db/db.sqlite";

/// The table with one row per store path the database registers.
const VALID_PATHS: &str = "ValidPaths";

/// The columns, by table, that only order, date or place a row rather than
/// say what it holds: a `ValidPaths` row's id, which follows the order of
/// registration, and its registration time, and the page a schema entry's tree
/// starts at, which says where in the file it sits.
const NOT_CONTENT: &[(&str, &str)] = &[
    (VALID_PATHS, "id"),
    (VALID_PATHS, "registrationTime"),
    ("sqlite_master", "rootpage"),
];

/// One line of the dump: a row of `table`, column by column.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DumpedRow {
    table: String,
    row: Map<String, Value>,
}

/// Parse the dump `run-scan.sh` wrote of a store database, one row a line,
/// into findings, or say why a line is not such a row. A database without a
/// single row, not even a schema entry, dumps nothing. Pure, so it is
/// unit-tested directly.
pub fn nix_db_findings(contents: &str) -> Result<Vec<Finding>, String> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            // serde reads a struct from a JSON array as well, its fields in
            // order, but the dump writes each row as an object.
            if !line.trim_start().starts_with('{') {
                return Err(format!("not a row of the dump (not an object): {line}"));
            }
            let dumped: DumpedRow = serde_json::from_str(line)
                .map_err(|e| format!("not a row of the dump ({e}): {line}"))?;
            row_finding(&dumped.table, &dumped.row)
        })
        .collect()
}

/// The finding of one row: the table's name, then every column but
/// [`NOT_CONTENT`] as `name=value` in name order, with a NULL left out. Each
/// value is written as JSON (a string in double quotes) and each name as
/// [`written_name`] writes it, so the field reads back as the one row it came
/// from. A `ValidPaths` row that names no store path is not one.
fn row_finding(table: &str, row: &Map<String, Value>) -> Result<Finding, String> {
    let names_a_path =
        matches!(row.get("path"), Some(Value::String(path)) if path.starts_with('/'));
    if table == VALID_PATHS && !names_a_path {
        return Err(format!(
            "a {VALID_PATHS} row with no store path: {}",
            Value::Object(row.clone())
        ));
    }
    // Keyed by name, so the columns come out in name order whatever order
    // sqlite3 printed them in.
    let mut columns: BTreeMap<&str, &Value> = BTreeMap::new();
    for (name, value) in row {
        if value.is_null() || NOT_CONTENT.contains(&(table, name.as_str())) {
            continue;
        }
        columns.insert(name, value);
    }
    let mut field = written_name(table);
    for (name, value) in columns {
        field.push(' ');
        field.push_str(&written_name(name));
        field.push('=');
        field.push_str(&value.to_string());
    }
    Ok(Finding::new(Tool::NixDb, NIX_DB_PATH, field))
}

/// A table's or a column's name as a row's finding writes it: as it stands
/// when it is a plain identifier (ASCII letters, digits and underscores), and
/// as a JSON string otherwise, so that a blank, an `=` or a quote in a name
/// never reads as where it ends.
fn written_name(name: &str) -> String {
    let plain = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if plain {
        name.to_string()
    } else {
        Value::from(name).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dump line of one `ValidPaths` row, for `path` registered at `time`
    /// with the row id `id`.
    fn row(id: u32, path: &str, time: u64) -> String {
        format!(
            r#"{{"table":"ValidPaths","row":{{"id":{id},"path":"{path}","hash":"sha256:00ab","registrationTime":{time},"deriver":null,"narSize":1216,"ultimate":null,"sigs":null,"ca":null}}}}"#
        )
    }

    /// The fields of the findings `dump` parses into.
    fn fields(dump: &str) -> Vec<String> {
        nix_db_findings(dump)
            .expect("rows")
            .into_iter()
            .map(|f| f.field)
            .collect()
    }

    const HIDDEN: &str = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hidden-package";

    #[test]
    fn a_store_path_row_is_keyed_by_what_it_registers() {
        let findings =
            nix_db_findings(&format!("{}\n", row(7, HIDDEN, 1_792_857_436))).expect("one row");
        assert_eq!(
            findings,
            [Finding::new(
                Tool::NixDb,
                NIX_DB_PATH,
                format!(r#"ValidPaths hash="sha256:00ab" narSize=1216 path="{HIDDEN}""#)
            )]
        );
    }

    #[test]
    fn the_row_id_and_registration_time_are_left_out() {
        // The same path registered again later, under another row id, is the
        // same finding: a boot that registers its closure anew changes neither.
        assert_eq!(fields(&row(1, HIDDEN, 100)), fields(&row(42, HIDDEN, 999)));
    }

    #[test]
    fn every_other_column_is_kept() {
        // A path registered with another signature or deriver is another row.
        let signed = r#"{"table":"ValidPaths","row":{"id":1,"path":"/nix/store/x","hash":"h","sigs":"key:abc","deriver":"/nix/store/x.drv","ultimate":1,"ca":"text:sha256:1"}}"#;
        assert_eq!(
            fields(signed),
            [
                r#"ValidPaths ca="text:sha256:1" deriver="/nix/store/x.drv" hash="h" path="/nix/store/x" sigs="key:abc" ultimate=1"#
            ]
        );
    }

    #[test]
    fn every_table_and_the_schema_are_read() {
        // The references, the outputs, the sequence and the schema are rows of
        // their own, each keyed by its table; a column a table has that
        // ValidPaths leaves out (an id) is kept there.
        let dump = [
            r#"{"table":"Refs","row":{"referrer":7,"reference":3}}"#,
            r#"{"table":"DerivationOutputs","row":{"drv":7,"id":"out","path":"/nix/store/o"}}"#,
            r#"{"table":"sqlite_sequence","row":{"name":"ValidPaths","seq":576}}"#,
            r#"{"table":"SchemaMigrations","row":{"migration":"20220326"}}"#,
            r#"{"table":"sqlite_master","row":{"type":"table","name":"Refs","tbl_name":"Refs","rootpage":4,"sql":"CREATE TABLE Refs (\n referrer integer)"}}"#,
        ]
        .join("\n");
        assert_eq!(
            fields(&dump),
            [
                "Refs reference=3 referrer=7",
                r#"DerivationOutputs drv=7 id="out" path="/nix/store/o""#,
                r#"sqlite_sequence name="ValidPaths" seq=576"#,
                r#"SchemaMigrations migration="20220326""#,
                r#"sqlite_master name="Refs" sql="CREATE TABLE Refs (\n referrer integer)" tbl_name="Refs" type="table""#,
            ]
        );
    }

    #[test]
    fn no_two_rows_that_differ_read_alike() {
        // Written as they stand, a value holding a blank and `name=value`
        // read like two columns, a number like its digits in text, and a
        // blank or an `=` in a name like where the name ends: a row the
        // session changed that way read as the row it replaced.
        let pairs = [
            (
                r#"{"table":"ValidPaths","row":{"path":"/nix/store/x","hash":"h","sigs":"a ultimate=1","ultimate":null}}"#,
                r#"{"table":"ValidPaths","row":{"path":"/nix/store/x","hash":"h","sigs":"a","ultimate":1}}"#,
            ),
            (
                r#"{"table":"sqlite_sequence","row":{"name":"ValidPaths","seq":576}}"#,
                r#"{"table":"sqlite_sequence","row":{"name":"ValidPaths","seq":"576"}}"#,
            ),
            (
                r#"{"table":"Refs referrer=7","row":{"reference":3}}"#,
                r#"{"table":"Refs","row":{"referrer=7 reference":3}}"#,
            ),
            (
                r#"{"table":"Refs","row":{"a=b":1}}"#,
                r#"{"table":"Refs","row":{"a":"b=1"}}"#,
            ),
        ];
        for (one, other) in pairs {
            assert_ne!(fields(one), fields(other), "{one} and {other}");
        }
        // A name that is not a plain identifier is written as JSON too.
        assert_eq!(
            fields(r#"{"table":"a table","row":{"a column":"x","_plain1":2}}"#),
            [r#""a table" _plain1=2 "a column"="x""#]
        );
    }

    #[test]
    fn a_sequence_raised_by_a_path_registered_and_collected_again_is_another_row() {
        let sequence = |seq: u32| {
            format!(r#"{{"table":"sqlite_sequence","row":{{"name":"ValidPaths","seq":{seq}}}}}"#)
        };
        assert_ne!(fields(&sequence(576)), fields(&sequence(577)));
    }

    #[test]
    fn the_page_a_schema_entry_starts_at_is_left_out() {
        // A database rebuilt page by page holds the same schema at other pages.
        let entry = |rootpage: u32| {
            format!(
                r#"{{"table":"sqlite_master","row":{{"type":"index","name":"IndexReferrer","tbl_name":"Refs","rootpage":{rootpage},"sql":"CREATE INDEX IndexReferrer on Refs(referrer)"}}}}"#
            )
        };
        assert_eq!(fields(&entry(5)), fields(&entry(9)));
    }

    #[test]
    fn every_line_of_the_dump_is_read() {
        // sqlite3 prints one row a line; a blank line is no row, and blanks
        // before a row's object are no part of it.
        let dump = format!(
            "{}\n\n \t{}\n",
            row(1, "/nix/store/a", 1),
            row(2, "/nix/store/b", 1)
        );
        let paths = fields(&dump);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with(r#"path="/nix/store/a""#), "{paths:?}");
        assert!(paths[1].ends_with(r#"path="/nix/store/b""#), "{paths:?}");
    }

    #[test]
    fn an_empty_dump_is_a_database_with_no_rows() {
        assert_eq!(nix_db_findings(""), Ok(Vec::new()));
        assert_eq!(nix_db_findings("\n"), Ok(Vec::new()));
    }

    #[test]
    fn a_dump_that_is_not_the_rows_is_refused() {
        for broken in [
            "not json",
            // The rows of one table as sqlite3 -json prints them, untagged.
            r#"[{"path":"/nix/store/a"}]"#,
            // A row as an array of its table and its columns, which serde
            // reads into the struct of a line.
            r#"["Refs",{"referrer":7,"reference":3}]"#,
            r#" ["Refs",{}]"#,
            r#"{"path":"/nix/store/a"}"#,
            r#"{"table":"Refs"}"#,
            r#"{"table":"Refs","row":[7,3]}"#,
            r#"{"table":7,"row":{}}"#,
            r#"{"table":"Refs","row":{},"rows":1}"#,
            r#"{"table":"ValidPaths","row":{"id":1,"hash":"h"}}"#,
            r#"{"table":"ValidPaths","row":{"id":1,"path":null}}"#,
            r#"{"table":"ValidPaths","row":{"id":1,"path":"relative"}}"#,
        ] {
            assert!(nix_db_findings(broken).is_err(), "{broken}");
        }
        // One bad line fails the whole dump.
        let mixed = format!("{}\nnot json\n", row(1, HIDDEN, 1));
        assert!(nix_db_findings(&mixed).is_err());
    }
}
