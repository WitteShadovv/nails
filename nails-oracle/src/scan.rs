// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Best-effort parsers that normalize one `outputs/` tree into [`Scans`].
//!
//! The scan writes, per image label (`before`, `control`, `after`), one subtree
//! per tool:
//!
//! ```text
//! outputs/restore/<label>/...            restored file tree (btrfs restore, debugfs rdump)
//! outputs/restore/<label>.sha256         a SHA-256 of every restored file
//! outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
//! outputs/bulk_extractor/<label>/*_carved/...  the objects its carvers saved
//! outputs/plaso/<label>.jsonl            plaso timeline, one JSON event a line
//! ```
//!
//! `run-scan.sh` hashes each restored file before it empties it to save disk,
//! into `<label>.sha256` (`sha256sum --zero`: `<hex>  ./<path>`, each record
//! ending in a NUL), so the restore channel compares what a file holds, not
//! only that it exists.
//!
//! These parsers are lenient with output they cannot parse (an unparseable
//! line is skipped) and with a tool that did not run (a missing subtree yields
//! no findings), because the exact tool output varies. Neither reads as clean:
//! a channel that yields no finding for an image fails the run in
//! [`crate::verdict::scan_verdict`]. What they never pass over is output they
//! cannot read, a directory or an entry they lack the rights to, a restored
//! file without its digest or a carved record that is not one: any of those is
//! an I/O error and stops the run, since skipping it would hide whatever it
//! held. Rigor lives in [`crate::verdict`], which is tested over synthetic
//! findings, not over these files. The pure per-format helpers
//! ([`bulk_extractor_findings`], [`parse_digest_manifest`],
//! [`crate::plaso::plaso_finding`], [`crate::carved::utmp_record_key`]) are
//! unit-tested without touching the filesystem.

use crate::carved::{self, Recorder};
use crate::model::{Finding, ImageLabel, Scans, Tool};
use crate::plaso::{is_journal_file, plaso_finding};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

/// Normalize a whole `outputs/` tree. Errors when `outputs` itself cannot be
/// read, or when an entry of it cannot (see the module docs); a missing
/// per-tool subtree yields no findings for that tool.
pub fn scan_all(outputs: &Path) -> io::Result<Scans> {
    if !outputs.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("outputs directory not found: {}", outputs.display()),
        ));
    }
    Ok(Scans {
        before: scan_image(outputs, ImageLabel::Before)?,
        control: scan_image(outputs, ImageLabel::Control)?,
        after: scan_image(outputs, ImageLabel::After)?,
    })
}

/// Normalize one image's findings across all three tools.
fn scan_image(outputs: &Path, label: ImageLabel) -> io::Result<BTreeSet<Finding>> {
    let mut findings = BTreeSet::new();
    let name = label.dir_name();
    let restore = outputs.join("restore");
    scan_restore(
        &restore.join(name),
        &restore.join(format!("{name}.sha256")),
        &mut findings,
    )?;
    scan_bulk_extractor(&outputs.join("bulk_extractor").join(name), &mut findings)?;
    scan_plaso(
        &outputs.join("plaso").join(format!("{name}.jsonl")),
        &mut findings,
    )?;
    Ok(findings)
}

/// `err` with the path it is about in its message, keeping its kind.
fn at(path: &Path, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {err}", path.display()))
}

/// An error for output that is there but is not what the scan wrote.
fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Whether `path` exists (as anything, a dangling link included). A path that
/// is missing is a tool that did not run; one that cannot be looked up is an
/// error.
fn present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(at(path, e)),
    }
}

/// Read a tool's text output, keeping a byte that is not UTF-8 as a
/// replacement character rather than failing on it.
fn read_text(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path).map_err(|e| at(path, e))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Walk a restored file tree, emitting one finding per recovered entry: its
/// absolute on-image path, with the entry's kind and content as the field:
/// `sha256:<digest>` for a file (its digest from `manifest`), `dir` for a
/// directory, `symlink:<target>` for a symbolic link and `other` for any other
/// entry a carver recovers. A directory and a symbolic link are traces in
/// their own right, an empty staging directory or a unit's enablement link, so
/// each is reported as a finding like a file, and never only walked through or
/// skipped. A missing tree is a carve that did not run, which yields nothing;
/// a tree without its manifest, a file the manifest has no digest for, a
/// digest for a file the tree lacks, or a directory or entry that cannot be
/// read, is an error.
fn scan_restore(root: &Path, manifest: &Path, out: &mut BTreeSet<Finding>) -> io::Result<()> {
    if !present(root)? {
        return Ok(());
    }
    let mut digests = parse_digest_manifest(&fs::read(manifest).map_err(|e| at(manifest, e))?)
        .map_err(|message| invalid(format!("{}: {message}", manifest.display())))?;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| at(&dir, e))? {
            let entry = entry.map_err(|e| at(&dir, e))?;
            let path = entry.path();
            // `file_type` does not follow a symlink, so a link to a directory
            // is reported as a link and never walked: it may point anywhere,
            // out of the restored tree included.
            let kind = entry.file_type().map_err(|e| at(&path, e))?;
            let Some(abs) = restore_abs_path(root, &path) else {
                continue;
            };
            let field = if kind.is_dir() {
                stack.push(path);
                "dir".to_string()
            } else if kind.is_symlink() {
                let target = fs::read_link(&path).map_err(|e| at(&path, e))?;
                format!("symlink:{}", target.to_string_lossy())
            } else if kind.is_file() {
                let digest = digests.remove(&abs).ok_or_else(|| {
                    invalid(format!("{}: no digest for {abs}", manifest.display()))
                })?;
                format!("sha256:{digest}")
            } else {
                "other".to_string()
            };
            // A rotating journal file is compared by its parsed message
            // content (see crate::plaso), not by its per-boot unique filename
            // and content, so it is not a restore finding -- otherwise every
            // new rotation would be false residue. The directories that hold
            // it are still reported.
            if !is_journal_file(&abs) {
                out.insert(Finding::new(Tool::BtrfsRestore, abs, field));
            }
        }
    }
    match digests.keys().next() {
        Some(extra) => Err(invalid(format!(
            "{}: a digest for {extra}, which the restored tree does not hold",
            manifest.display()
        ))),
        None => Ok(()),
    }
}

/// Parse a digest manifest, `sha256sum --zero` run over the files of a
/// restored tree from inside it: each record is `<64 hex>  ./<path>` (or
/// `<hex> *./<path>`) ending in a NUL, with the name unescaped. Returns each
/// file's lowercase digest by its absolute on-image path, or why the manifest
/// is not one. Pure, so it is unit-tested directly.
pub fn parse_digest_manifest(contents: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut digests = BTreeMap::new();
    for record in contents.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let line = String::from_utf8_lossy(record);
        let Some((hex, name)) = line.split_at_checked(64) else {
            return Err(format!("a record too short for a digest: {line:?}"));
        };
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("a record with no SHA-256 digest: {line:?}"));
        }
        let Some(relative) = name
            .strip_prefix("  ./")
            .or_else(|| name.strip_prefix(" *./"))
        else {
            return Err(format!("a record for a path outside the tree: {line:?}"));
        };
        let path = format!("/{relative}");
        if relative.is_empty() || digests.insert(path, hex.to_ascii_lowercase()).is_some() {
            return Err(format!("an empty or repeated path: {line:?}"));
        }
    }
    Ok(digests)
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
/// `*_histogram.txt`), using the file stem as the feature type, the way
/// [`carved::recorder`] says to read it. A missing directory is a
/// bulk_extractor that did not run, which yields nothing; one that cannot be
/// read is an error.
fn scan_bulk_extractor(dir: &Path, out: &mut BTreeSet<Finding>) -> io::Result<()> {
    if !present(dir)? {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|e| at(dir, e))? {
        let path = entry.map_err(|e| at(dir, e))?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".txt") || name.ends_with("_histogram.txt") {
            continue;
        }
        let feature_type = name.trim_end_matches(".txt");
        let recorder = carved::recorder(feature_type);
        if recorder == Recorder::Skipped {
            continue;
        }
        let contents = read_text(&path)?;
        if recorder == Recorder::Values {
            out.extend(bulk_extractor_findings(feature_type, &contents));
            continue;
        }
        for (feature, context) in feature_lines(&contents) {
            let field = if recorder == Recorder::LoginRecords {
                login_record_field(dir, feature)?
            } else {
                carved::carved_hash(context).ok_or_else(|| {
                    invalid(format!("{}: no content hash for {feature}", path.display()))
                })?
            };
            out.insert(Finding::new(Tool::BulkExtractor, feature_type, field));
        }
    }
    Ok(())
}

/// The key of the carved login record a `utmp_carved` line names: read from
/// the file the carver saved it to under `dir` (see
/// [`carved::utmp_record_key`]). A name that leaves `dir`, a file that cannot
/// be read and a file that is not one record are errors.
fn login_record_field(dir: &Path, feature: &str) -> io::Result<String> {
    let file = carved::carved_object_path(dir, feature).ok_or_else(|| {
        invalid(format!(
            "{}: a carved record outside it: {feature}",
            dir.display()
        ))
    })?;
    let record = fs::read(&file).map_err(|e| at(&file, e))?;
    carved::utmp_record_key(&record).ok_or_else(|| {
        invalid(format!(
            "{}: {} bytes, not one {}-byte login record",
            file.display(),
            record.len(),
            carved::UTMP_RECORD_SIZE
        ))
    })
}

/// The `(feature, context)` columns of each feature line of a bulk_extractor
/// feature file (`offset \t feature \t context`), skipping comments (`#...`)
/// and blanks. A line with a single column is its own feature.
fn feature_lines(contents: &str) -> impl Iterator<Item = (&str, &str)> {
    contents
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut columns = line.split('\t');
            let first = columns.next().unwrap_or(line);
            match columns.next() {
                Some(feature) => (feature, columns.next().unwrap_or("")),
                None => (first, ""),
            }
        })
}

/// Parse one bulk_extractor value recorder's feature file into findings. A
/// feature line is `offset \t feature \t context`; comment lines (`#...`) and
/// blanks are skipped. Pure, so it is unit-tested directly.
pub fn bulk_extractor_findings(feature_type: &str, contents: &str) -> Vec<Finding> {
    feature_lines(contents)
        .filter(|(value, _)| !value.is_empty())
        .map(|(value, _)| Finding::new(Tool::BulkExtractor, feature_type, value))
        .collect()
}

/// Read a plaso timeline exported as JSON lines (`psort -o json_line`), one
/// event an object a line. A missing timeline is a plaso that did not run (or
/// a channel `run-scan.sh` dropped), which yields nothing; one that cannot be
/// read is an error.
fn scan_plaso(file: &Path, out: &mut BTreeSet<Finding>) -> io::Result<()> {
    if !present(file)? {
        return Ok(());
    }
    out.extend(read_text(file)?.lines().filter_map(plaso_finding));
    Ok(())
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
