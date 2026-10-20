// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! systemd daemon configuration resolution: the main file plus its drop-ins.
//!
//! systemd daemons (journald, logind, coredump, sleep) do not read a single
//! file. As described in systemd.conf.d(5) and journald.conf(5), for a
//! configuration named `NAME.conf` they read:
//!
//! 1. the main file: the first of `/etc/systemd/NAME.conf`,
//!    `/run/systemd/NAME.conf`, `/usr/local/lib/systemd/NAME.conf` and
//!    `/usr/lib/systemd/NAME.conf` that exists (only that one is used);
//! 2. then every `*.conf` drop-in found in `NAME.conf.d/` under the same four
//!    directories, sorted by file name across all of them. A drop-in in a
//!    higher-priority directory (`/etc` over `/run` over `/usr/local/lib` over
//!    `/usr/lib`) shadows a same-named file in a lower one; a drop-in symlinked
//!    to `/dev/null` (or empty) therefore masks the vendor one.
//!
//! The files are applied in that order and, per key, the last assignment wins.
//! A pre-flight check that reads only `/etc/systemd/NAME.conf` both refuses a
//! host configured through a drop-in and, worse, accepts one whose drop-in
//! overrides a safe main file, so every systemd configuration read goes through
//! [`section_assignments`].
//!
//! # Syntax
//!
//! Parsing follows systemd's `conf-parser`:
//! - a line ends at a newline, a carriage return or a NUL, as `read_line()`
//!   reads it (a CR LF pair ends one line);
//! - leading and trailing whitespace is stripped; empty lines and lines whose
//!   first non-blank character is `#` or `;` are comments (also in the middle
//!   of a continuation);
//! - a byte order mark is dropped once, from the first line that starts with
//!   one, after that line was told from a comment (so a mark before a `#`
//!   leaves no comment);
//! - a line ending in an unescaped backslash continues on the next line, with
//!   the backslash replaced by a space;
//! - `[Section]` headers select the section; assignments outside any section
//!   and in other sections are ignored; section names and keys are
//!   case-sensitive;
//! - an assignment splits at the first `=`, key and value are stripped. Values
//!   are not unquoted and there are no trailing comments: `Storage="volatile"`
//!   and `Storage=volatile # x` are both invalid values to journald;
//! - a malformed section header (a `[` line not ending in `]`, or a section
//!   name with a control character, a quote or a backslash) makes systemd
//!   stop reading that file and skip all the remaining ones; the assignments
//!   already read stay in effect.
//!
//! Files are read through [`Filesystem`], whose real implementation opens them
//! with `O_NOATIME`, so the probe does not update the access time of a file it
//! reads. The flag covers that file alone: on NixOS `/etc/systemd/NAME.conf` is
//! a link into `/etc/static`, and a lookup that follows the links, an existence
//! test as much as a read, can still update their access times
//! ([`nails_teardown::noatime`]).

use crate::Filesystem;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Configuration directories relative to the root, highest priority first.
const CONF_DIRS: &[&str] = &[
    "etc/systemd",
    "run/systemd",
    "usr/local/lib/systemd",
    "usr/lib/systemd",
];

/// One `Key=value` assignment, with key and value stripped of whitespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The key, case preserved.
    pub key: String,
    /// The raw value, not unquoted.
    pub value: String,
}

/// A `[` line without a closing `]`: systemd stops reading at this point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedSectionHeader;

/// The files systemd reads for configuration `name` (e.g. `journald.conf`) under
/// `root`, in application order: the main file first, then the drop-ins.
pub fn config_files<F: Filesystem>(fs: &F, root: &Path, name: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();

    // Only the first main file found is used.
    if let Some(main) = CONF_DIRS
        .iter()
        .map(|dir| root.join(dir).join(name))
        .find(|path| fs.path_exists(path).unwrap_or(false) && !is_dir(fs, path))
    {
        files.push(main);
    }

    // Drop-ins: iterate directories in priority order so the first file seen
    // for a name (the highest-priority one) shadows the others; the map keeps
    // them sorted by file name, byte-wise like systemd.
    let dropin_dir = format!("{name}.d");
    let mut dropins: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in CONF_DIRS {
        let Ok(entries) = fs.list_directory(&root.join(dir).join(&dropin_dir)) else {
            continue;
        };
        for entry in entries {
            let Some(file_name) = entry.file_name() else {
                continue;
            };
            let name_bytes = file_name.as_encoded_bytes();
            if name_bytes.starts_with(b".") || !name_bytes.ends_with(b".conf") {
                continue;
            }
            if is_dir(fs, &entry) {
                continue;
            }
            dropins.entry(file_name.to_os_string()).or_insert(entry);
        }
    }
    files.extend(dropins.into_values());
    files
}

fn is_dir<F: Filesystem>(fs: &F, path: &Path) -> bool {
    fs.is_directory(path).unwrap_or(false)
}

/// The effective assignments in `[section]` of configuration `name` under
/// `root`, in the order systemd applies them (so a later entry overrides an
/// earlier one for the same key). A file that cannot be read contributes
/// nothing; a malformed section header ends the resolution as it does in
/// systemd.
pub fn section_assignments<F: Filesystem>(
    fs: &F,
    root: &Path,
    name: &str,
    section: &str,
) -> Vec<Assignment> {
    let mut out = Vec::new();
    for file in config_files(fs, root, name) {
        let Some(text) = read_config_text(fs, &file) else {
            continue;
        };
        if parse_section(&text, section, &mut out).is_err() {
            break;
        }
    }
    out
}

/// The text of configuration file `path`, read the way systemd reads it.
///
/// systemd reads a configuration file line by line, so a line that is not valid
/// UTF-8 — a Latin-1 comment, say — is dropped, not the whole file.
/// [`Filesystem::read_file_content`] instead rejects a file with any invalid
/// byte outright, which would make a `Storage=persistent` below such a comment
/// vanish and a persistent decoy journal read as volatile. So on invalid UTF-8
/// the bytes are read and decoded line by line ([`decode_config_bytes`]).
///
/// The byte fallback runs only for the real filesystem — the in-memory test
/// double holds valid UTF-8 and never reports invalid data — and reads with
/// `O_NOATIME`, so it leaves no access-time trail on the decoy as the normal
/// read does. `None` when the file cannot be read.
pub fn read_config_text<F: Filesystem>(fs: &F, path: &Path) -> Option<String> {
    match fs.read_file_content(path) {
        Ok(text) => Some(text),
        Err(e) if e.io_kind() == Some(std::io::ErrorKind::InvalidData) => {
            read_config_bytes_noatime(path)
                .ok()
                .map(|bytes| decode_config_bytes(&bytes))
        }
        Err(_) => None,
    }
}

/// Read `path`'s bytes without updating its access time, for the UTF-8 fallback
/// in [`read_config_text`].
fn read_config_bytes_noatime(path: &Path) -> std::io::Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open};
    use std::io::Read;
    let fd = nails_teardown::noatime::with_noatime(|noatime| {
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | noatime,
            Mode::empty(),
        )
    })
    .map_err(std::io::Error::from)?;
    let mut bytes = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Decode a configuration file's bytes the way systemd reads it: line by line
/// ([`config_lines`]), keeping every line that is valid UTF-8 and dropping the
/// rest, then rejoining the kept lines with `\n` for [`parse_section`]. A line
/// that is not valid UTF-8 cannot be a `Key=value` systemd would apply, so
/// dropping it changes no assignment; it only stops one bad line (a Latin-1
/// comment) from hiding the rest of the file.
pub fn decode_config_bytes(bytes: &[u8]) -> String {
    config_lines(bytes)
        .into_iter()
        .filter_map(|line| std::str::from_utf8(line).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether any file of configuration `name` exists under `root`.
pub fn config_present<F: Filesystem>(fs: &F, root: &Path, name: &str) -> bool {
    !config_files(fs, root, name).is_empty()
}

/// Append the assignments of `[section]` in one configuration text to `out`.
///
/// Returns [`MalformedSectionHeader`] when systemd would stop reading at a bad
/// section header; the assignments before it are kept.
pub fn parse_section(
    text: &str,
    section: &str,
    out: &mut Vec<Assignment>,
) -> Result<(), MalformedSectionHeader> {
    let mut in_section = false;
    let mut continuation: Option<String> = None;
    let mut bom_seen = false;

    for raw in read_lines(text) {
        let stripped = raw.trim_start_matches(is_ws);
        if stripped.starts_with(['#', ';']) {
            continue;
        }
        let raw = match raw.strip_prefix('\u{feff}') {
            Some(rest) if !bom_seen => {
                bom_seen = true;
                rest
            }
            _ => raw,
        };

        let mut line = match continuation.take() {
            Some(mut joined) => {
                joined.push_str(raw);
                joined
            }
            None => raw.to_string(),
        };
        if ends_with_unescaped_backslash(&line) {
            line.pop();
            line.push(' ');
            continuation = Some(line);
            continue;
        }
        parse_line(&line, section, &mut in_section, out)?;
    }

    // A trailing continuation at end of file is still parsed.
    if let Some(line) = continuation {
        parse_line(&line, section, &mut in_section, out)?;
    }
    Ok(())
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// The byte lines of a configuration file as systemd's `read_line()` reads
/// them: a line ends at a newline, a carriage return or a NUL, and a run of
/// these ends one line as long as no kind repeats in it, so `\r\n` and `\n\r`
/// end one line and `\n\n` two. A NUL ends its line at once.
fn config_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while at < bytes.len() && !matches!(bytes[at], b'\n' | b'\r' | 0) {
            at += 1;
        }
        let end = at;
        let mut seen = 0u8;
        while let Some(kind) = bytes.get(at).and_then(|byte| match byte {
            b'\n' => Some(1u8),
            b'\r' => Some(2),
            0 => Some(4),
            _ => None,
        }) {
            if seen & 4 != 0 || seen & kind != 0 {
                break;
            }
            seen |= kind;
            at += 1;
        }
        lines.push(&bytes[start..end]);
    }
    lines
}

/// The lines of `text`, split as [`config_lines`] splits the bytes. The input
/// is UTF-8 and every split falls on an ASCII terminator, so each line slice is
/// itself valid UTF-8.
fn read_lines(text: &str) -> Vec<&str> {
    config_lines(text.as_bytes())
        .into_iter()
        .map(|line| std::str::from_utf8(line).unwrap_or_default())
        .collect()
}

/// Whether `line` ends in a backslash that is not itself escaped.
fn ends_with_unescaped_backslash(line: &str) -> bool {
    let mut escaped = false;
    for c in line.chars() {
        escaped = !escaped && c == '\\';
    }
    escaped
}

fn parse_line(
    line: &str,
    section: &str,
    in_section: &mut bool,
    out: &mut Vec<Assignment>,
) -> Result<(), MalformedSectionHeader> {
    // Comments went before the line was joined; a `#` here followed a byte
    // order mark and starts a key, as in systemd.
    let line = line.trim_matches(is_ws);
    if line.is_empty() {
        return Ok(());
    }
    if let Some(header) = line.strip_prefix('[') {
        let name = header.strip_suffix(']').ok_or(MalformedSectionHeader)?;
        // systemd's string_is_safe() refuses these in a section name.
        if name
            .chars()
            .any(|c| c.is_ascii_control() || matches!(c, '"' | '\'' | '\\'))
        {
            return Err(MalformedSectionHeader);
        }
        *in_section = name == section;
        return Ok(());
    }
    if !*in_section {
        return Ok(());
    }
    let Some((key, value)) = line.split_once('=') else {
        return Ok(());
    };
    let key = key.trim_matches(is_ws);
    if key.is_empty() {
        return Ok(());
    }
    out.push(Assignment {
        key: key.to_string(),
        value: value.trim_matches(is_ws).to_string(),
    });
    Ok(())
}

/// The last value assigned to `key` in `assignments`, if any.
pub fn last_value<'a>(assignments: &'a [Assignment], key: &str) -> Option<&'a str> {
    assignments
        .iter()
        .rev()
        .find(|a| a.key == key)
        .map(|a| a.value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealFilesystem;
    use std::fs;

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn values(root: &Path, key: &str) -> Vec<String> {
        section_assignments(&RealFilesystem, root, "journald.conf", "Journal")
            .into_iter()
            .filter(|a| a.key == key)
            .map(|a| a.value)
            .collect()
    }

    fn parse(text: &str) -> (Vec<(String, String)>, bool) {
        let mut out = Vec::new();
        let ok = parse_section(text, "Journal", &mut out).is_ok();
        (out.into_iter().map(|a| (a.key, a.value)).collect(), ok)
    }

    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_string(), value.to_string())
    }

    /// systemd drops a byte order mark from the first line that starts with
    /// one, which need not be the first line, and tells a comment before it
    /// does. Found by the `systemd_conf` fuzz target with a mark at the start
    /// of a later line, which NAILS kept.
    #[test]
    fn a_byte_order_mark_goes_where_systemd_drops_it() {
        // On a later line the mark goes, so the header counts.
        assert_eq!(
            parse("# a comment\n\u{feff}[Journal]\nStorage=volatile\n"),
            (vec![pair("Storage", "volatile")], true)
        );
        // Only the first mark goes.
        assert_eq!(
            parse("\u{feff}[Journal]\n\u{feff}Storage=none\nStorage=volatile\n"),
            (
                vec![pair("\u{feff}Storage", "none"), pair("Storage", "volatile")],
                true
            )
        );
        // A mark before `#` leaves no comment but a key systemd does not know.
        assert_eq!(
            parse("[Journal]\n\u{feff}#Storage=none\n"),
            (vec![pair("#Storage", "none")], true)
        );
    }

    /// systemd refuses a section name with a control character, a quote or a
    /// backslash, and stops reading there as at a header without its `]`.
    /// Found by the `systemd_conf` fuzz target with a DEL in the name, after
    /// which NAILS read on into the drop-ins.
    #[test]
    fn a_section_name_systemd_refuses_stops_the_reading() {
        for header in [
            "[Log\u{7f}in]",
            "[Lo\tgin]",
            "[\"Journal\"]",
            "['Journal']",
            "[Jour\\nal]",
        ] {
            let text = format!("[Journal]\nStorage=volatile\n{header}\n[Journal]\nStorage=none\n");
            assert_eq!(
                parse(&text),
                (vec![pair("Storage", "volatile")], false),
                "{header}"
            );
        }
    }

    /// systemd ends a line at a carriage return or a NUL too. Found by the
    /// `systemd_conf` fuzz target: the CR after `[` stayed inside the line,
    /// which then read as the header of another section, so the assignments
    /// after it counted, where systemd stops at the malformed header `[`.
    #[test]
    fn a_carriage_return_or_a_nul_ends_a_line() {
        assert_eq!(parse("[\rJournal]\nStorage=persistent\n"), (vec![], false));
        assert_eq!(
            parse("[Journal]\rStorage=volatile\r"),
            (vec![pair("Storage", "volatile")], true)
        );
        assert_eq!(
            parse("[Journal]\r\n\rStorage=none\n\rStorage=auto"),
            (vec![pair("Storage", "none"), pair("Storage", "auto")], true)
        );
        assert_eq!(
            parse("[Journal]\0Storage=volatile\0\0Storage=none"),
            (
                vec![pair("Storage", "volatile"), pair("Storage", "none")],
                true
            )
        );
        // A continued line goes on past a lone CR as past a newline.
        assert_eq!(
            parse("[Journal]\rStorage=vola\\\rtile"),
            (vec![pair("Storage", "vola tile")], true)
        );
    }

    #[test]
    fn only_the_named_section_counts() {
        let (out, ok) = parse(
            "Storage=persistent\n[Other]\nStorage=persistent\n[Journal]\nStorage=volatile\n[X-Foo]\nStorage=auto\n",
        );
        assert!(ok);
        assert_eq!(out, vec![pair("Storage", "volatile")]);
    }

    #[test]
    fn keys_and_sections_are_case_sensitive() {
        let (out, _) = parse("[journal]\nStorage=a\n[Journal]\nstorage=b\nStorage=c\n");
        assert_eq!(out, vec![pair("storage", "b"), pair("Storage", "c")]);
    }

    #[test]
    fn comments_whitespace_and_quoting_follow_systemd() {
        let text = "\u{feff}[Journal]\n  # Storage=persistent\n\t; Storage=none\n  Storage = \"volatile\"  \nSystemMaxUse=1G # trailing\nno equals sign\n=novalue\n";
        let (out, ok) = parse(text);
        assert!(ok);
        assert_eq!(
            out,
            vec![
                pair("Storage", "\"volatile\""),
                pair("SystemMaxUse", "1G # trailing"),
            ]
        );
    }

    #[test]
    fn continuation_lines_join_and_skip_comments() {
        let (out, _) = parse("[Journal]\nKey=a \\\n# comment\n  b\nEsc=x\\\\\nNext=y\nTail=z\\");
        assert_eq!(
            out,
            vec![
                pair("Key", "a    b"),
                pair("Esc", "x\\\\"),
                pair("Next", "y"),
                pair("Tail", "z"),
            ]
        );
    }

    #[test]
    fn malformed_header_stops_the_file() {
        let (out, ok) = parse("[Journal]\nStorage=volatile\n[Journal\nStorage=persistent\n");
        assert!(!ok);
        assert_eq!(out, vec![pair("Storage", "volatile")]);
    }

    #[test]
    fn missing_config_yields_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(config_files(&RealFilesystem, tmp.path(), "journald.conf").is_empty());
        assert!(!config_present(
            &RealFilesystem,
            tmp.path(),
            "journald.conf"
        ));
    }

    #[test]
    fn main_file_is_the_first_found_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "usr/lib/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert_eq!(values(root, "Storage"), vec!["persistent"]);

        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\n",
        );
        assert_eq!(values(root, "Storage"), vec!["volatile"]);
    }

    #[test]
    fn drop_in_overrides_main_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n",
        );
        write(
            root,
            "usr/lib/systemd/journald.conf.d/50-volatile.conf",
            "[Journal]\nStorage=volatile\n",
        );
        let all = section_assignments(&RealFilesystem, root, "journald.conf", "Journal");
        assert_eq!(last_value(&all, "Storage"), Some("volatile"));
    }

    #[test]
    fn etc_drop_in_shadows_same_named_lower_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "usr/lib/systemd/journald.conf.d/50-x.conf",
            "[Journal]\nStorage=persistent\nCompress=no\n",
        );
        write(
            root,
            "run/systemd/journald.conf.d/50-x.conf",
            "[Journal]\nStorage=auto\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/50-x.conf",
            "[Journal]\nStorage=volatile\n",
        );
        assert_eq!(values(root, "Storage"), vec!["volatile"]);
        assert!(
            values(root, "Compress").is_empty(),
            "the shadowed file is not read at all"
        );
    }

    #[test]
    fn drop_ins_are_ordered_by_file_name_across_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf.d/10-a.conf",
            "[Journal]\nStorage=persistent\n",
        );
        write(
            root,
            "usr/lib/systemd/journald.conf.d/90-z.conf",
            "[Journal]\nStorage=volatile\n",
        );
        write(
            root,
            "run/systemd/journald.conf.d/50-m.conf",
            "[Journal]\nStorage=none\n",
        );
        // Hidden files, other suffixes and directories are not drop-ins.
        write(
            root,
            "etc/systemd/journald.conf.d/99-off.conf.disabled",
            "[Journal]\nStorage=auto\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/.99-hidden.conf",
            "[Journal]\nStorage=auto\n",
        );
        fs::create_dir_all(root.join("etc/systemd/journald.conf.d/99-dir.conf")).unwrap();
        assert_eq!(
            values(root, "Storage"),
            vec!["persistent", "none", "volatile"]
        );
    }

    #[test]
    fn last_assignment_wins_within_and_across_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf",
            "[Journal]\nStorage=volatile\nStorage=persistent\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/10-a.conf",
            "[Journal]\nStorage=none\nStorage=volatile\n",
        );
        let all = section_assignments(&RealFilesystem, root, "journald.conf", "Journal");
        assert_eq!(last_value(&all, "Storage"), Some("volatile"));
        assert_eq!(last_value(&all, "Missing"), None);
    }

    #[test]
    fn malformed_header_skips_the_remaining_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "etc/systemd/journald.conf.d/10-a.conf",
            "[Journal]\nStorage=volatile\n[Broken\n",
        );
        write(
            root,
            "etc/systemd/journald.conf.d/20-b.conf",
            "[Journal]\nStorage=persistent\n",
        );
        assert_eq!(values(root, "Storage"), vec!["volatile"]);
    }

    /// systemd reads a configuration file line by line, so a comment that is
    /// not valid UTF-8 (a Latin-1 byte) does not hide the rest of the file. A
    /// whole-file UTF-8 read rejects the file outright and would miss the
    /// `Storage=persistent` below such a comment, reading a persistent decoy
    /// journal as volatile.
    #[test]
    fn a_latin1_comment_does_not_hide_a_later_assignment() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // 0xFC is 'ü' in Latin-1 and never a valid UTF-8 byte.
        let mut bytes = b"[Journal]\n# Gr".to_vec();
        bytes.push(0xFC);
        bytes.extend_from_slice(b"n\nStorage=persistent\n");
        let path = root.join("etc/systemd/journald.conf");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        // The whole-file UTF-8 read rejects it with InvalidData...
        assert_eq!(
            RealFilesystem
                .read_file_content(&path)
                .unwrap_err()
                .io_kind(),
            Some(std::io::ErrorKind::InvalidData)
        );
        // ...but the config read keeps the valid lines, so the assignment below
        // the Latin-1 comment is seen.
        assert_eq!(
            last_value(
                &section_assignments(&RealFilesystem, root, "journald.conf", "Journal"),
                "Storage"
            ),
            Some("persistent")
        );
    }

    #[test]
    fn decode_config_bytes_keeps_valid_lines_and_drops_the_rest() {
        let mut bytes = b"[Journal]\nStorage=persistent\n".to_vec();
        bytes.push(0xFF); // a lone invalid byte, on its own line
        bytes.extend_from_slice(b"\nCompress=no\n");
        let text = decode_config_bytes(&bytes);
        assert!(text.contains("Storage=persistent"), "{text}");
        assert!(text.contains("Compress=no"), "{text}");
        assert!(!text.as_bytes().contains(&0xFF), "{text:?}");
        // Pure ASCII round-trips unchanged.
        assert_eq!(
            decode_config_bytes(b"[Journal]\nStorage=auto\n"),
            "[Journal]\nStorage=auto"
        );
    }
}
