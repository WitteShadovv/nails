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
//! outputs/nix_db/<label>.jsonl           every row of the restored Nix store database, one a line
//! outputs/bulk_extractor/<label>/*.txt   bulk_extractor feature files
//! outputs/bulk_extractor/<label>/*_carved/...  the objects its carvers saved
//! outputs/plaso/<label>.jsonl            plaso timeline, one JSON event a line
//! outputs/plaso/not-run                  instead of the timelines: why none ran
//! ```
//!
//! On a btrfs image, which plaso cannot open, `run-scan.sh` runs no timeline
//! and writes `plaso/not-run` (holding `btrfs`) instead. [`scan_all`] records
//! that channel as left out by design ([`NotRun`]), which the verdict names and
//! never calls clean, and the restore channel then keeps the rotating journal
//! files it otherwise leaves to plaso. A marker that says anything else, or one
//! next to a timeline, stops the run.
//!
//! `run-scan.sh` hashes each restored file before it empties it to save disk,
//! into `<label>.sha256` (`sha256sum --zero`: `<hex>  ./<path>`, each record
//! ending in a NUL), so the restore channel compares what a file holds, not
//! only that it exists. Before it empties a restored Nix store database, it
//! dumps every row of the database, its schema included, into
//! `nix_db/<label>.jsonl` (see [`crate::nix_db`]), since the oracle's decoy VMs
//! rewrite that file at every start. It keeps the login record files whole
//! (`wtmp`, `btmp` and their rotations, see
//! [`crate::carved::is_login_record_file`]), and the control image's are read
//! for the records the control cycle wrote ([`Scans::control_login_records`]).
//!
//! These parsers are lenient with output they cannot parse (an unparseable
//! line is skipped) and with a tool that did not run (a missing subtree yields
//! no findings), because the exact tool output varies. Neither reads as clean:
//! a channel that yields no finding for an image fails the run in
//! [`crate::verdict::scan_verdict`]. What they never pass over is output they
//! cannot read, a directory or an entry they lack the rights to, a restored
//! file without its digest, a carved record that is not one, or a restored Nix
//! store database without its rows or with a row that is not one: any of those
//! is an I/O error and stops the run, since skipping it would hide whatever it
//! held. Rigor lives in [`crate::verdict`], which is tested over synthetic
//! findings, not over these files. The pure per-format helpers
//! ([`bulk_extractor_findings`], [`parse_digest_manifest`],
//! [`crate::plaso::plaso_finding`], [`crate::carved::utmp_record_key`],
//! [`crate::nix_db::nix_db_findings`]) are unit-tested without touching the
//! filesystem.

use crate::carved::{self, Recorder};
use crate::model::{Finding, ImageLabel, NotRun, Scans, Tool};
use crate::nix_db::{NIX_DB_PATH, nix_db_findings};
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
    let not_run = scan_not_run(&outputs.join("plaso"))?;
    // Without a timeline nothing compares the rotating journal files by their
    // messages, so the restore channel keeps them as files.
    let journal_files = if not_run.iter().any(|n| n.tool() == Tool::Plaso) {
        JournalFiles::Keep
    } else {
        JournalFiles::LeaveToPlaso
    };
    let restore = outputs.join("restore");
    let control = ImageLabel::Control.dir_name();
    Ok(Scans {
        before: scan_image(outputs, ImageLabel::Before, journal_files)?,
        control: scan_image(outputs, ImageLabel::Control, journal_files)?,
        after: scan_image(outputs, ImageLabel::After, journal_files)?,
        not_run,
        control_login_records: scan_login_records(
            &restore.join(control),
            &restore.join(format!("{control}.sha256")),
        )?,
    })
}

/// The SHA-256 of no bytes: what a digest manifest records for an empty file.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // pragma: allowlist secret

/// The keys of the login records the login record files of the restored tree
/// at `root` hold ([`carved::is_login_record_file`], [`carved::login_record_keys`]),
/// read from the files themselves, which `run-scan.sh` keeps whole. A file
/// found empty that `manifest` recorded as holding something was emptied
/// after the carve, and its records would be lost: that is an error. A missing
/// tree, a carve that did not run, yields none.
fn scan_login_records(root: &Path, manifest: &Path) -> io::Result<BTreeSet<String>> {
    let mut keys = BTreeSet::new();
    if !present(root)? {
        return Ok(keys);
    }
    let digests = parse_digest_manifest(&fs::read(manifest).map_err(|e| at(manifest, e))?)
        .map_err(|message| invalid(format!("{}: {message}", manifest.display())))?;
    for (abs, digest) in digests {
        if !carved::is_login_record_file(&abs) {
            continue;
        }
        let file = root.join(abs.trim_start_matches('/'));
        let data = fs::read(&file).map_err(|e| at(&file, e))?;
        if data.is_empty() && digest != EMPTY_SHA256 {
            return Err(invalid(format!(
                "{}: empty, but {} records it as holding data; the login record files must be kept whole",
                file.display(),
                manifest.display()
            )));
        }
        keys.extend(carved::login_record_keys(&data));
    }
    Ok(keys)
}

/// The marker `run-scan.sh` writes into `outputs/plaso/` when it leaves the
/// timeline out by design, on a btrfs image (see [`NotRun`]).
pub const NOT_RUN_MARKER: &str = "not-run";

/// The channels the scan left out by design, read from the marker in the
/// plaso output directory `plaso`: none without one. A marker that names no
/// such channel, one the scan cannot read, and a marker next to a timeline
/// are errors, so that a channel is never left out by a stray file and a
/// timeline is never both run and not run.
fn scan_not_run(plaso: &Path) -> io::Result<BTreeSet<NotRun>> {
    let marker = plaso.join(NOT_RUN_MARKER);
    if !present(&marker)? {
        return Ok(BTreeSet::new());
    }
    let bytes = fs::read(&marker).map_err(|e| at(&marker, e))?;
    let not_run = NotRun::from_marker(&bytes)
        .map_err(|message| invalid(format!("{}: {message}", marker.display())))?;
    for label in ImageLabel::ALL {
        let timeline = plaso.join(format!("{}.jsonl", label.dir_name()));
        if present(&timeline)? {
            return Err(invalid(format!(
                "{}: says the timeline did not run, but {} is there",
                marker.display(),
                timeline.display()
            )));
        }
    }
    Ok(BTreeSet::from([not_run]))
}

/// What the restore channel does with a rotating journal file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalFiles {
    /// Leave it out: plaso compares it by its messages (a full run).
    LeaveToPlaso,
    /// Report it like any file: no timeline ran to compare it.
    Keep,
}

/// Normalize one image's findings across every tool.
fn scan_image(
    outputs: &Path,
    label: ImageLabel,
    journal_files: JournalFiles,
) -> io::Result<BTreeSet<Finding>> {
    let mut findings = BTreeSet::new();
    let name = label.dir_name();
    let restore = outputs.join("restore");
    scan_restore(
        &restore.join(name),
        &restore.join(format!("{name}.sha256")),
        journal_files,
        &mut findings,
    )?;
    scan_nix_db(
        &restore.join(name),
        &outputs.join("nix_db").join(format!("{name}.jsonl")),
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
fn scan_restore(
    root: &Path,
    manifest: &Path,
    journal_files: JournalFiles,
    out: &mut BTreeSet<Finding>,
) -> io::Result<()> {
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
            // it are still reported. Without a timeline nothing reads its
            // messages, so it is reported like any file: a journal the session
            // left reads as residue rather than going unseen.
            if journal_files == JournalFiles::Keep || !is_journal_file(&abs) {
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

/// Read the rows of the Nix store database the restored tree at `root` holds,
/// from the dump `run-scan.sh` wrote of it (see [`crate::nix_db`]). The dump is
/// there exactly when the tree holds the database as a file: a database
/// without its rows would leave the file unread, its digest being noise on
/// the oracle's decoys, and rows of a database the tree lacks are not this
/// carve's, so either is an error. A tree with no database, a decoy that is
/// not a Nix system or a carve that did not run, yields nothing.
fn scan_nix_db(root: &Path, dump: &Path, out: &mut BTreeSet<Finding>) -> io::Result<()> {
    let db = root.join(NIX_DB_PATH.trim_start_matches('/'));
    let holds_db = present(&db)? && fs::symlink_metadata(&db).map_err(|e| at(&db, e))?.is_file();
    match (holds_db, present(dump)?) {
        (false, false) => Ok(()),
        (true, false) => Err(invalid(format!(
            "{} holds the Nix store database {NIX_DB_PATH}, but its rows, {}, are missing",
            root.display(),
            dump.display()
        ))),
        (false, true) => Err(invalid(format!(
            "{}: rows of a Nix store database {} does not hold",
            dump.display(),
            root.display()
        ))),
        (true, true) => {
            let rows = nix_db_findings(&read_text(dump)?)
                .map_err(|message| invalid(format!("{}: {message}", dump.display())))?;
            out.extend(rows);
            Ok(())
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
        let lines: Vec<_> = feature_records(&contents).collect();
        // The zip carver writes two lines for each member it saves: one that
        // describes the member (`<zipinfo>`, no hash) at the member's place,
        // and one for the saved file, keyed by its hash and named
        // `<place>-ZIP-<n>`. A description is passed over only when the saved
        // file of the member at its place is in the same file: that line keys
        // its content.
        let saved_members: BTreeSet<&str> = lines
            .iter()
            .filter(|(_, _, context)| carved::carved_hash(context).is_some())
            .filter_map(|(offset, _, _)| carved::zip_member_offset(offset))
            .collect();
        // The carver saves a record once: a later one with the same bytes is
        // named `<CACHED>`, with the hash of the one it saved. It is read
        // from that saved record, which must be in the same file.
        let saved_by_hash: BTreeMap<String, &str> = lines
            .iter()
            .filter(|(_, feature, _)| *feature != carved::CACHED)
            .filter_map(|(_, feature, context)| Some((carved::carved_hash(context)?, *feature)))
            .collect();
        for (offset, feature, context) in lines {
            let field = if recorder == Recorder::LoginRecords {
                let saved = if feature == carved::CACHED {
                    carved::carved_hash(context)
                        .and_then(|hash| saved_by_hash.get(&hash).copied())
                        .ok_or_else(|| {
                            invalid(format!(
                                "{}: a {} record at {offset} whose saved record is not in it",
                                path.display(),
                                carved::CACHED
                            ))
                        })?
                } else {
                    feature
                };
                login_record_field(dir, saved)?
            } else if let Some(hash) = carved::carved_hash(context) {
                hash
            } else if carved::is_zip_member_info(context) && saved_members.contains(offset) {
                continue;
            } else {
                return Err(invalid(format!(
                    "{}: no content hash for {feature}",
                    path.display()
                )));
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
    feature_records(contents).map(|(_, feature, context)| (feature, context))
}

/// The `offset \t feature \t context` columns of each feature line, with
/// comments and blanks skipped; a line of one column is its feature, with no
/// offset.
fn feature_records(contents: &str) -> impl Iterator<Item = (&str, &str, &str)> {
    contents
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut columns = line.split('\t');
            let first = columns.next().unwrap_or(line);
            match columns.next() {
                Some(feature) => (first, feature, columns.next().unwrap_or("")),
                None => ("", first, ""),
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
