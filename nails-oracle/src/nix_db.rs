// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keys for the rows of the Nix store database, so that a store path the
//! database registers subtracts across the three images exactly when its row
//! does.
//!
//! The oracle's decoys register their store paths at every start of the
//! service manager, and each registration rewrites pages of the database
//! file, so the file's digest differs on every image and the restore channel
//! can only call it noise: a store path a session registered there would go
//! unseen. Its rows do not change with a boot. `run-scan.sh` therefore dumps
//! the `ValidPaths` table of each restored database with `sqlite3 -json`
//! before it empties the file, and each row is keyed by what it registers.
//! The row id and the registration time are left out, so the same path
//! registered again at another time is the same finding. Every other column is
//! kept, so a path the session registered or removed, or one registered again
//! with another hash, deriver, size, signature or content address, is a
//! change.

use crate::model::{Finding, Tool};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Where the Nix store database sits on an image.
pub const NIX_DB_PATH: &str = "/nix/var/nix/db/db.sqlite";

/// The table the scan reads: one row per store path the database registers.
pub const TABLE: &str = "ValidPaths";

/// The columns that place or date a row rather than say what it registers:
/// the row id, which follows the order of registration, and the registration
/// time.
const NOT_CONTENT: &[&str] = &["id", "registrationTime"];

/// Parse the rows `sqlite3 -json` printed for `SELECT * FROM ValidPaths` into
/// findings, or say why the output is not that. sqlite3 prints nothing at all
/// for a table with no rows, so empty output is no rows. Pure, so it is
/// unit-tested directly.
pub fn nix_db_findings(contents: &str) -> Result<Vec<Finding>, String> {
    if contents.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<Map<String, Value>> = serde_json::from_str(contents)
        .map_err(|e| format!("not the rows sqlite3 -json prints: {e}"))?;
    rows.iter().map(row_finding).collect()
}

/// The finding of one row: the table name, then every column but
/// [`NOT_CONTENT`] as `name=value` in name order, with a NULL left out. A row
/// that names no store path is not a `ValidPaths` row.
fn row_finding(row: &Map<String, Value>) -> Result<Finding, String> {
    let names_a_path =
        matches!(row.get("path"), Some(Value::String(path)) if path.starts_with('/'));
    if !names_a_path {
        return Err(format!(
            "a row with no store path: {}",
            Value::Object(row.clone())
        ));
    }
    // Keyed by name, so the columns come out in name order whatever order
    // sqlite3 printed them in.
    let mut columns: BTreeMap<&str, String> = BTreeMap::new();
    for (name, value) in row {
        if NOT_CONTENT.contains(&name.as_str()) {
            continue;
        }
        let text = match value {
            Value::Null => continue,
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        columns.insert(name, text);
    }
    let mut field = TABLE.to_string();
    for (name, text) in columns {
        field.push(' ');
        field.push_str(name);
        field.push('=');
        field.push_str(&text);
    }
    Ok(Finding::new(Tool::NixDb, NIX_DB_PATH, field))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `ValidPaths` row as `sqlite3 -json` prints it, for `path`
    /// registered at `time` with the row id `id`.
    fn row(id: u32, path: &str, time: u64) -> String {
        format!(
            r#"{{"id":{id},"path":"{path}","hash":"sha256:00ab","registrationTime":{time},"deriver":null,"narSize":1216,"ultimate":null,"sigs":null,"ca":null}}"#
        )
    }

    const HIDDEN: &str = "/nix/store/0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hidden-package";

    #[test]
    fn a_row_is_keyed_by_what_it_registers() {
        let findings =
            nix_db_findings(&format!("[{}]\n", row(7, HIDDEN, 1_792_857_436))).expect("one row");
        assert_eq!(
            findings,
            [Finding::new(
                Tool::NixDb,
                NIX_DB_PATH,
                format!("ValidPaths hash=sha256:00ab narSize=1216 path={HIDDEN}")
            )]
        );
    }

    #[test]
    fn the_row_id_and_registration_time_are_left_out() {
        // The same path registered again later, under another row id, is the
        // same finding: a boot that registers its closure anew changes neither.
        let first = nix_db_findings(&format!("[{}]", row(1, HIDDEN, 100))).expect("row");
        let again = nix_db_findings(&format!("[{}]", row(42, HIDDEN, 999))).expect("row");
        assert_eq!(first, again);
    }

    #[test]
    fn every_other_column_is_kept() {
        // A path registered with another signature or deriver is another row.
        let signed = r#"[{"id":1,"path":"/nix/store/x","hash":"h","sigs":"key:abc","deriver":"/nix/store/x.drv","ultimate":1,"ca":"text:sha256:1"}]"#;
        let [finding] = nix_db_findings(signed)
            .expect("row")
            .try_into()
            .expect("one");
        assert_eq!(
            finding.field,
            "ValidPaths ca=text:sha256:1 deriver=/nix/store/x.drv hash=h path=/nix/store/x \
             sigs=key:abc ultimate=1"
        );
    }

    #[test]
    fn every_row_of_the_dump_is_read() {
        // sqlite3 -json prints one row a line inside one array.
        let dump = format!(
            "[{},\n{}]\n",
            row(1, "/nix/store/a", 1),
            row(2, "/nix/store/b", 1)
        );
        let paths: Vec<String> = nix_db_findings(&dump)
            .expect("rows")
            .into_iter()
            .map(|f| f.field)
            .collect();
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("path=/nix/store/a"), "{paths:?}");
        assert!(paths[1].ends_with("path=/nix/store/b"), "{paths:?}");
    }

    #[test]
    fn an_empty_dump_is_a_table_with_no_rows() {
        assert_eq!(nix_db_findings(""), Ok(Vec::new()));
        assert_eq!(nix_db_findings("\n"), Ok(Vec::new()));
        assert_eq!(nix_db_findings("[]"), Ok(Vec::new()));
    }

    #[test]
    fn a_dump_that_is_not_the_rows_is_refused() {
        for broken in [
            "not json",
            r#"{"path":"/nix/store/a"}"#,
            r#"[["/nix/store/a"]]"#,
            r#"[{"id":1,"hash":"h"}]"#,
            r#"[{"id":1,"path":null}]"#,
            r#"[{"id":1,"path":"relative"}]"#,
        ] {
            assert!(nix_db_findings(broken).is_err(), "{broken}");
        }
    }
}
