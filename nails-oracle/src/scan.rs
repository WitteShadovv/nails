// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort parsers that normalize one `outputs/` tree into [`Scans`].
//!
//! The scan writes, per image label (`before`, `control`, `after`), one subtree
//! per tool:
//!
//! ```text
//! outputs/restore/<label>/...            btrfs restore file tree
//! outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
//! outputs/plaso/<label>.jsonl            plaso timeline, one JSON event a line
//! ```
//!
//! These parsers are deliberately lenient — a missing subtree or an
//! unparseable line is skipped, not fatal — because the synthetic slice firms
//! up the exact tool output later. Rigor lives in [`crate::verdict`], which is
//! tested over synthetic findings, not over these files. The pure per-format
//! helpers here ([`bulk_extractor_findings`], [`plaso_finding`],
//! [`restore_abs_path`]) are unit-tested without touching the filesystem.

use crate::model::{Finding, ImageLabel, Scans, Tool};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

/// Normalize a whole `outputs/` tree. Errors only when `outputs` itself cannot
/// be read; a missing per-tool subtree yields no findings for that tool.
pub fn scan_all(outputs: &Path) -> io::Result<Scans> {
    if !outputs.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("outputs directory not found: {}", outputs.display()),
        ));
    }
    Ok(Scans {
        before: scan_image(outputs, ImageLabel::Before),
        control: scan_image(outputs, ImageLabel::Control),
        after: scan_image(outputs, ImageLabel::After),
    })
}

/// Normalize one image's findings across all three tools.
fn scan_image(outputs: &Path, label: ImageLabel) -> BTreeSet<Finding> {
    let mut findings = BTreeSet::new();
    let name = label.dir_name();
    scan_restore(&outputs.join("restore").join(name), &mut findings);
    scan_bulk_extractor(&outputs.join("bulk_extractor").join(name), &mut findings);
    scan_plaso(
        &outputs.join("plaso").join(format!("{name}.jsonl")),
        &mut findings,
    );
    findings
}

/// Walk a btrfs-restore tree, emitting one finding per recovered regular file.
fn scan_restore(root: &Path, out: &mut BTreeSet<Finding>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(path),
                Ok(ft) if ft.is_file() => {
                    if let Some(abs) = restore_abs_path(root, &path) {
                        out.insert(Finding::new(Tool::BtrfsRestore, abs, ""));
                    }
                }
                _ => {}
            }
        }
    }
}

/// Map a file under the restore root to the absolute on-image path it stands
/// for: `root/var/log/x` becomes `/var/log/x`.
fn restore_abs_path(root: &Path, file: &Path) -> Option<String> {
    let rel = file.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in rel.components() {
        parts.push(component.as_os_str().to_string_lossy().into_owned());
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("/{}", parts.join("/")))
}

/// Read every bulk_extractor feature file in `dir` (each `*.txt` that is not a
/// `*_histogram.txt`), using the file stem as the feature type.
fn scan_bulk_extractor(dir: &Path, out: &mut BTreeSet<Finding>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".txt") || name.ends_with("_histogram.txt") {
            continue;
        }
        let feature_type = name.trim_end_matches(".txt");
        if let Ok(contents) = fs::read_to_string(&path) {
            out.extend(bulk_extractor_findings(feature_type, &contents));
        }
    }
}

/// Parse one bulk_extractor feature file's contents into findings. A feature
/// line is `offset \t feature \t context`; comment lines (`#...`) and blanks
/// are skipped. Pure, so it is unit-tested directly.
pub fn bulk_extractor_findings(feature_type: &str, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = line.split('\t').nth(1).unwrap_or(line);
        if !value.is_empty() {
            findings.push(Finding::new(Tool::BulkExtractor, feature_type, value));
        }
    }
    findings
}

/// Read a plaso timeline exported as JSON lines (`psort -o json_line`), one
/// event an object a line.
fn scan_plaso(file: &Path, out: &mut BTreeSet<Finding>) {
    let Ok(contents) = fs::read_to_string(file) else {
        return;
    };
    for line in contents.lines() {
        if let Some(finding) = plaso_finding(line) {
            out.insert(finding);
        }
    }
}

/// Parse one plaso JSON-line event into a finding: its source path and an event
/// descriptor. Returns `None` when no source path can be found. Pure, so it is
/// unit-tested directly.
pub fn plaso_finding(line: &str) -> Option<Finding> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let path = first_string(&value, &["path", "filename", "display_name", "pathspec"])?;
    let descriptor = first_string(
        &value,
        &["data_type", "timestamp_desc", "message", "parser"],
    )
    .unwrap_or_default();
    Some(Finding::new(Tool::Plaso, path, descriptor))
}

/// The first of `keys` that `value` (a JSON object) carries as a string.
fn first_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key).and_then(serde_json::Value::as_str) {
            return Some(found.to_string());
        }
    }
    None
}

/// Load an [`Allowlist`](crate::model::Allowlist) from a JSON file.
pub fn load_allowlist(path: &Path) -> io::Result<crate::model::Allowlist> {
    load_json(path, "allowlist")
}

/// Load the [`Controls`](crate::model::Controls) from a JSON file.
pub fn load_controls(path: &Path) -> io::Result<crate::model::Controls> {
    load_json(path, "controls")
}

/// Read and deserialize a JSON policy file, tagging errors with `what`.
fn load_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> io::Result<T> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            let msg = format!("cannot read {what} {}: {e}", path.display());
            return Err(io::Error::new(e.kind(), msg));
        }
    };
    match serde_json::from_str(&text) {
        Ok(value) => Ok(value),
        Err(e) => {
            let msg = format!("cannot parse {what} {}: {e}", path.display());
            Err(io::Error::new(io::ErrorKind::InvalidData, msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn bulk_extractor_skips_comments_and_keeps_the_feature_column() {
        let contents = "# banner\n4096\ta@b.example\tctx\n8192\tc@d.example\tmore\n\n";
        let findings = bulk_extractor_findings("email", contents);
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[0],
            Finding::new(Tool::BulkExtractor, "email", "a@b.example")
        );
        assert_eq!(findings[1].field, "c@d.example");
    }

    #[test]
    fn bulk_extractor_tolerates_a_single_column_line() {
        let findings = bulk_extractor_findings("note", "lonevalue\n");
        assert_eq!(
            findings,
            [Finding::new(Tool::BulkExtractor, "note", "lonevalue")]
        );
    }

    #[test]
    fn plaso_pulls_the_source_path_and_descriptor() {
        let line = r#"{"path":"/var/log/wtmp.db","data_type":"linux:wtmp:event","message":"boot"}"#;
        let finding = plaso_finding(line).expect("a path is present");
        assert_eq!(
            finding,
            Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event")
        );
    }

    #[test]
    fn plaso_without_a_path_is_skipped_and_bad_json_too() {
        assert!(plaso_finding(r#"{"message":"no path here"}"#).is_none());
        assert!(plaso_finding("not json at all").is_none());
    }

    #[test]
    fn restore_paths_become_absolute_on_image_paths() {
        let root = PathBuf::from("/tmp/outputs/restore/after");
        let file = root.join("var/log/wtmp.db");
        assert_eq!(
            restore_abs_path(&root, &file).as_deref(),
            Some("/var/log/wtmp.db")
        );
        // The root itself maps to nothing.
        assert_eq!(restore_abs_path(&root, &root), None);
    }
}
