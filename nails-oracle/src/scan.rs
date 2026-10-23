// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort parsers that normalize one `outputs/` tree into [`Scans`].
//!
//! The scan writes, per image label (`before`, `control`, `after`), one subtree
//! per tool:
//!
//! ```text
//! outputs/restore/<label>/...            restored file tree (btrfs restore, debugfs rdump)
//! outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
//! outputs/plaso/<label>.jsonl            plaso timeline, one JSON event a line
//! ```
//!
//! These parsers are deliberately lenient — a missing subtree or an
//! unparseable line is skipped here, not fatal — because the exact tool output
//! varies. Leniency never reads as clean: a channel that yields no finding for
//! an image fails the run in [`crate::verdict::scan_verdict`]. Rigor lives in
//! [`crate::verdict`], which is tested over synthetic findings, not over these
//! files. The pure per-format helpers here ([`bulk_extractor_findings`],
//! [`plaso_finding`], `restore_abs_path`) are unit-tested without touching
//! the filesystem.

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

/// Walk a restored file tree, emitting one finding per recovered entry: its
/// absolute on-image path, with the entry's kind as the field (empty for a
/// file). A directory (`dir`) and a symbolic link (`symlink`) are traces in
/// their own right, an empty staging directory or a unit's enablement link, so
/// each is reported as a finding like a file, with its kind as the field, and
/// never only walked through or skipped. Any other entry a carver recovers is
/// reported as a file, with an empty field.
fn scan_restore(root: &Path, out: &mut BTreeSet<Finding>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // `file_type` does not follow a symlink, so a link to a directory
            // is reported as a link and never walked: it may point anywhere,
            // out of the restored tree included.
            let kind = match entry.file_type() {
                Ok(ft) if ft.is_dir() => {
                    stack.push(path.clone());
                    "dir"
                }
                Ok(ft) if ft.is_symlink() => "symlink",
                _ => "",
            };
            let Some(abs) = restore_abs_path(root, &path) else {
                continue;
            };
            // A rotating journal file is compared by its parsed message content
            // (see plaso_finding), not by its per-boot unique filename, so it is
            // not a restore-path finding -- otherwise every new rotation would
            // be false residue. The directories that hold it are still reported.
            if !is_journal_file(&abs) {
                out.insert(Finding::new(Tool::BtrfsRestore, abs, kind));
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
        if is_carved_object_recorder(feature_type) {
            continue;
        }
        if let Ok(contents) = fs::read_to_string(&path) {
            out.extend(bulk_extractor_findings(feature_type, &contents));
        }
    }
}

/// bulk_extractor's carving scanners -- the `*_carved` recorders (`utmp_carved`,
/// `sqlite_carved`, `evtx_carved`, the `ntfsindx`/`ntfslogfile`/`ntfsmft`/
/// `ntfsusn_carved` set, `winpe_carved`, `unrar_carved`, `kml_carved`) -- do not
/// record stable feature *values*. Each line's "value" is the path of a binary
/// object bulk_extractor reconstructed and named by its byte *offset* in the
/// image (`utmp_carved/000/2288002688utmp`). That offset shifts with every
/// image -- even byte-identical content lands at a different offset across
/// before/control/after -- so a carved-object finding can never survive the
/// after - before - control set difference, and the channel contributes only
/// unsubtractable noise (confirmed on the real decoy images: reboot/login utmp
/// records and Nix-store sqlite pages from ordinary boot activity).
///
/// Dropping it loses no detection, because its content is already covered twice:
/// the restore channel recovers every real file by its on-image *path* (a
/// genuinely new file is caught there), and the value recorders (email, domain,
/// url, ...) scan the same raw bytes -- unallocated space included -- so any
/// leaked *string* is caught whatever object it sat in. Only the value recorders
/// feed the verdict. The match is on bulk_extractor's own `_carved` suffix, so a
/// carving scanner added upstream is skipped on the same principle.
fn is_carved_object_recorder(feature_type: &str) -> bool {
    feature_type.ends_with("_carved")
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
    let data_type = first_string(&value, &["data_type"]).unwrap_or_default();

    // A systemd-journal event is keyed on its content, not on the journal file:
    // journald rotates files named by a per-boot sequence and realtime stamp
    // (`system@<seq>-<first>-<time>.journal`), so the path is unique on every
    // image and could never subtract across before/control/after. The leak
    // signal in a journal is the log line, so a benign boot/shutdown line
    // (logged on every boot) subtracts and a genuinely new line surfaces.
    if data_type == "systemd:journal" {
        return journal_finding(&value);
    }

    let path = first_string(&value, &["path", "filename", "display_name", "pathspec"])?;
    // A non-journal event that still points at a rotating journal file (plaso's
    // own `fs:stat` for the file, say) is dropped for the same reason: the
    // file's identity is volatile; its content is compared above.
    if is_journal_file(&path) {
        return None;
    }
    let descriptor = first_string(
        &value,
        &["data_type", "timestamp_desc", "message", "parser"],
    )
    .unwrap_or_default();
    Some(Finding::new(Tool::Plaso, path, descriptor))
}

/// A systemd-journal file, `/var/log/journal/<machine-id>/<...>.journal`. plaso
/// prefixes the location with a type indicator (`EXT:`), which `contains`
/// tolerates. These rotate under per-boot unique names, so they are compared by
/// message content, never by path.
fn is_journal_file(path: &str) -> bool {
    path.contains("/var/log/journal/") && path.ends_with(".journal")
}

/// Key a systemd-journal event on its content: the reporting unit and the
/// normalized message body. The event's timestamp, PID, hostname and source
/// file are deliberately excluded -- they vary every boot and would stop any
/// line from ever subtracting. The locus is the fixed pseudo-path `journal`, so
/// a residual line is allowlistable by its exact content like any feature.
fn journal_finding(value: &serde_json::Value) -> Option<Finding> {
    let reporter = first_string(value, &["reporter", "_COMM", "parser"]).unwrap_or_default();
    let body = first_string(value, &["message_body", "message"])?;
    let normalized = normalize_journal_body(&body);
    let field = if reporter.is_empty() {
        normalized
    } else {
        format!("{reporter}: {normalized}")
    };
    Some(Finding::new(Tool::Plaso, "journal", field))
}

/// Mask the volatile tokens in a journal message body so the same line
/// subtracts across boots while a line carrying a new identifier still stands
/// out. Only two clearly-volatile token classes are masked, conservatively, to
/// avoid collapsing a real leak onto a benign line: a long hex id (>= 8 chars,
/// with both a digit and a hex letter -- boot/machine ids, UUIDs, hashes) ->
/// `X`, and a pure decimal run (PIDs, sizes, durations, session numbers) ->
/// `N`. Letters, words, paths, usernames and punctuation are left verbatim, so
/// a leaked string survives normalization and shows up as residue.
fn normalize_journal_body(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while !rest.is_empty() {
        // Take a maximal run of ASCII hex digits.
        let run_len = rest
            .char_indices()
            .find(|(_, c)| !c.is_ascii_hexdigit())
            .map_or(rest.len(), |(i, _)| i);
        if run_len == 0 {
            // Not a hex digit: copy one whole character.
            let ch = rest.chars().next().expect("rest is non-empty");
            out.push(ch);
            rest = &rest[ch.len_utf8()..];
            continue;
        }
        let run = &rest[..run_len];
        let has_digit = run.bytes().any(|b| b.is_ascii_digit());
        let has_hex_letter = run.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'));
        if run_len >= 8 && has_digit && has_hex_letter {
            out.push('X'); // a hex id (boot/machine id, UUID, hash)
        } else if has_digit && !has_hex_letter {
            out.push('N'); // a pure decimal run
        } else {
            out.push_str(run); // a hex-ish word like "cafe" or "sha": keep it
        }
        rest = &rest[run_len..];
    }
    out
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
#[path = "scan_tests.rs"]
mod tests;
