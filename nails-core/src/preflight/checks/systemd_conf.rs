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
//!    `/usr/lib/systemd/NAME.conf` that exists (only that one is used). This
//!    is how systemd 256 and later look for it; before 256 the daemons read
//!    the main file from `/etc` alone. NAILS looks where the running release
//!    looks. When it cannot read the release, a main file found outside `/etc`
//!    that changes what is read leaves the configuration [`Unread`];
//! 2. then every `*.conf` drop-in found in `NAME.conf.d/` under the same four
//!    directories, sorted by file name across all of them. A drop-in in a
//!    higher-priority directory (`/etc` over `/run` over `/usr/local/lib` over
//!    `/usr/lib`) shadows a same-named file in a lower one; an empty drop-in
//!    therefore masks the vendor one.
//!
//! The files are applied in that order and, per key, the last assignment wins.
//! A pre-flight check that reads only `/etc/systemd/NAME.conf` both refuses a
//! host configured through a drop-in and, worse, accepts one whose drop-in
//! overrides a safe main file, so every systemd configuration read goes through
//! [`section_assignments`].
//!
//! # Entries that are not regular files
//!
//! systemd lists a drop-in by its name alone, whatever is there: a directory,
//! a device (a link to `/dev/null` among them), a FIFO or a socket with a
//! drop-in's name shadows the same-named file below it as a regular file does.
//! The releases then read such an entry differently. Up to 259 they open it:
//! `/dev/null` reads as empty, while a directory fails the read where its turn
//! comes, so the files before it count and the rest are skipped. From 260 they
//! open every drop-in as a regular file before they parse anything, so any
//! such entry, or such a main file, leaves the whole configuration unread, the
//! main file included. A link that cannot be followed (a loop) differs as
//! well: from 258 it is not listed, so the file below it is read, while the
//! earlier releases fail on it. A link to a path that does not exist is the one
//! exception, in every release: it shadows the file below and adds nothing.
//!
//! A configuration with such an entry is [`Unread`] whatever release runs, and
//! so is one with a file or drop-in directory that NAILS cannot read where
//! systemd, running as root, can. The daemons read these files when they
//! start, and an update can bring another release before they next do, at the
//! latest when the decoy starts again after the way back. A caller counts an
//! unread configuration as the setting it guards against, never as the
//! defaults: what the daemon applies is not known.
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
//!   already read stay in effect;
//! - so does a line, continuation lines included, that is not valid UTF-8 by
//!   systemd's measure, which also refuses the Unicode noncharacters (U+FFFF
//!   among them). A comment is told before that test, so it is skipped
//!   whatever its bytes: a Latin-1 comment hides nothing, a Latin-1 value
//!   ends the reading.
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

/// The first systemd release whose daemons look for their main file in every
/// one of [`CONF_DIRS`]; the earlier ones read it from `/etc` alone.
const MAIN_FILE_OUTSIDE_ETC_SINCE: u32 = 256;

/// One `Key=value` assignment, with key and value stripped of whitespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The key, case preserved.
    pub key: String,
    /// The raw value, not unquoted.
    pub value: String,
}

/// A line systemd refuses: it stops reading there, skips every file after
/// this one, and keeps the assignments it read before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedLine {
    /// A `[` line without its closing `]`, or a section name with a control
    /// character, a quote or a backslash.
    MalformedSectionHeader,
    /// A line, not a comment, that is not valid UTF-8 by systemd's measure.
    NotUtf8,
}

/// A configuration NAILS cannot read the way systemd reads it, so what the
/// daemon applies is not known (see the [module docs](self)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    /// The entry that is not read as systemd reads it.
    pub path: PathBuf,
    /// Why it is not.
    pub cause: UnreadCause,
}

/// Why a configuration is [`Unread`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadCause {
    /// A main file or drop-in that is not a regular file once its links are
    /// followed: a directory, a device such as `/dev/null`, a FIFO, a socket,
    /// or a link that cannot be followed. The systemd releases do not read
    /// such a configuration alike.
    NotRegular,
    /// A file, or a drop-in directory, that NAILS cannot read, as an
    /// unprivileged `check` cannot read one only root may.
    CannotRead,
    /// A main file outside `/etc`, which systemd 256 and later read and the
    /// earlier releases do not, while NAILS cannot read which release runs,
    /// and reading it changes what is applied.
    UnknownRelease,
}

impl Unread {
    fn new(path: &Path, cause: UnreadCause) -> Self {
        Self {
            path: path.to_path_buf(),
            cause,
        }
    }

    /// What the operator can do about it, to follow the description.
    pub fn advice(&self) -> &'static str {
        match self.cause {
            UnreadCause::NotRegular => {
                "systemd releases do not read a configuration with such an entry alike, and from \
                 260 a directory or a device there leaves all of it unread; put a regular file \
                 there (an empty one masks a vendor file of the same name)"
            }
            UnreadCause::CannotRead => "run the command again with sudo",
            UnreadCause::UnknownRelease => {
                "put the main file in /etc/systemd, where every release reads it"
            }
        }
    }
}

impl std::fmt::Display for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cause {
            UnreadCause::NotRegular => write!(f, "{} is not a regular file", self.path.display()),
            UnreadCause::CannotRead => write!(f, "NAILS cannot read {}", self.path.display()),
            UnreadCause::UnknownRelease => write!(
                f,
                "only systemd 256 and later read the main file {}, and NAILS cannot read which \
                 release runs",
                self.path.display()
            ),
        }
    }
}

/// What systemd's reader makes of one configuration path.
enum Entry {
    /// A regular file once its links are followed: systemd reads it.
    Regular,
    /// No file, or a link to a path that does not exist: systemd's open fails
    /// with `ENOENT`, which it skips. A drop-in's name still shadows the files
    /// of that name below it.
    Missing,
    /// Anything else: the configuration is not read alike by every release,
    /// or NAILS cannot see what is there.
    Unread(UnreadCause),
}

/// Classify `path` without opening it: a FIFO would block the open, and a
/// device can be read without end.
fn entry<F: Filesystem>(fs: &F, path: &Path) -> Entry {
    if fs.is_regular_file(path).unwrap_or(false) {
        return Entry::Regular;
    }
    if fs.path_exists(path).unwrap_or(true) {
        return Entry::Unread(UnreadCause::NotRegular);
    }
    // Nothing that a lookup reaches: no file, a link to nothing, a link that
    // cannot be followed (a loop), or a path NAILS may not look up. A path
    // that resolves all the same is one the in-memory test double holds no
    // file for (it resolves links without asking whether the target is
    // there), or one that came into being since the lookup above.
    match fs.canonicalize(path) {
        Ok(_) => Entry::Missing,
        Err(e) => match e.io_kind() {
            Some(std::io::ErrorKind::NotFound) => Entry::Missing,
            Some(std::io::ErrorKind::PermissionDenied) => Entry::Unread(UnreadCause::CannotRead),
            _ => Entry::Unread(UnreadCause::NotRegular),
        },
    }
}

/// The main file and the drop-ins of a configuration, as [`listing`] finds
/// them.
struct Listing {
    /// The main file systemd reads, if any.
    main: Option<PathBuf>,
    /// A main file outside `/etc` while the running release is not known:
    /// systemd 256 and later read it, earlier releases do not.
    uncertain_main: Option<PathBuf>,
    /// The drop-ins, in the order systemd applies them.
    dropins: Vec<PathBuf>,
}

/// Find the files of configuration `name` under `root` for a systemd of major
/// version `systemd_major` (`None` when it is not known).
///
/// [`Unread`] when the main file systemd would read, or a drop-in that is not
/// shadowed, is no regular file, or when NAILS cannot read a drop-in directory.
/// Every drop-in is looked at, wherever a line refused in an earlier file
/// would stop the reading, because systemd 260 and later open them all first.
fn listing<F: Filesystem>(
    fs: &F,
    root: &Path,
    name: &str,
    systemd_major: Option<u32>,
) -> Result<Listing, Unread> {
    let main_dirs = match systemd_major {
        Some(major) if major < MAIN_FILE_OUTSIDE_ETC_SINCE => &CONF_DIRS[..1],
        _ => CONF_DIRS,
    };
    let (mut main, mut uncertain_main) = (None, None);

    // Only the first main file found is used; a link to a path that does not
    // exist is none, so systemd goes on to the next directory.
    for (index, dir) in main_dirs.iter().enumerate() {
        let path = root.join(dir).join(name);
        match entry(fs, &path) {
            Entry::Missing => continue,
            Entry::Unread(cause) => return Err(Unread::new(&path, cause)),
            Entry::Regular if index > 0 && systemd_major.is_none() => uncertain_main = Some(path),
            Entry::Regular => main = Some(path),
        }
        break;
    }

    // Drop-ins: iterate directories in priority order so the first entry seen
    // for a name (the highest-priority one) shadows the others, whatever it
    // is; the map keeps them sorted by file name, byte-wise like systemd.
    let dropin_dir = format!("{name}.d");
    let mut dropins: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in CONF_DIRS {
        let dir = root.join(dir).join(&dropin_dir);
        let entries = match fs.list_directory(&dir) {
            Ok(entries) => entries,
            // systemd skips a drop-in directory it cannot open, but it runs as
            // root: one that only NAILS cannot open may hold drop-ins it reads.
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) => {
                return Err(Unread::new(&dir, UnreadCause::CannotRead));
            }
            Err(_) => continue,
        };
        for listed in entries {
            let Some(file_name) = listed.file_name() else {
                continue;
            };
            let name_bytes = file_name.as_encoded_bytes();
            if name_bytes.starts_with(b".") || !name_bytes.ends_with(b".conf") {
                continue;
            }
            dropins.entry(file_name.to_os_string()).or_insert(listed);
        }
    }
    let mut files = Vec::new();
    for path in dropins.into_values() {
        match entry(fs, &path) {
            Entry::Regular => files.push(path),
            Entry::Missing => {}
            Entry::Unread(cause) => return Err(Unread::new(&path, cause)),
        }
    }
    Ok(Listing {
        main,
        uncertain_main,
        dropins: files,
    })
}

/// The files systemd of major version `systemd_major` (`None` when it is not
/// known) reads for configuration `name` (e.g. `journald.conf`) under `root`,
/// in application order: the main file first, then the drop-ins.
///
/// [`Unread`] as [`listing`] has it, and when only the release can tell
/// whether a main file outside `/etc` is read.
pub fn config_files<F: Filesystem>(
    fs: &F,
    root: &Path,
    name: &str,
    systemd_major: Option<u32>,
) -> Result<Vec<PathBuf>, Unread> {
    let listing = listing(fs, root, name, systemd_major)?;
    if let Some(path) = listing.uncertain_main {
        return Err(Unread::new(&path, UnreadCause::UnknownRelease));
    }
    Ok(listing.main.into_iter().chain(listing.dropins).collect())
}

/// The effective assignments in `[section]` of configuration `name` under
/// `root`, for a systemd of major version `systemd_major` (`None` when it is
/// not known), in the order systemd applies them (so a later entry overrides
/// an earlier one for the same key). A line systemd refuses ([`RefusedLine`])
/// ends the resolution as it does in systemd, and a file that is gone by the
/// time it is read adds nothing, as systemd skips it.
///
/// [`Unread`] when NAILS cannot read the configuration as systemd does: an
/// entry [`listing`] refuses, a file that systemd reads and NAILS cannot, or a
/// main file outside `/etc` that only the release would tell to read, where
/// reading it changes what is applied. The caller counts it as the setting it
/// guards against.
pub fn section_assignments<F: Filesystem>(
    fs: &F,
    root: &Path,
    name: &str,
    section: &str,
    systemd_major: Option<u32>,
) -> Result<Vec<Assignment>, Unread> {
    let listing = listing(fs, root, name, systemd_major)?;
    let Some(uncertain) = &listing.uncertain_main else {
        return read_files(fs, listing.main.iter().chain(&listing.dropins), section);
    };
    // 256 and later read this main file and earlier releases do not, so it may
    // count only where reading it changes nothing.
    let with_it = read_files(
        fs,
        std::iter::once(uncertain).chain(&listing.dropins),
        section,
    )?;
    if with_it != read_files(fs, listing.dropins.iter(), section)? {
        return Err(Unread::new(uncertain, UnreadCause::UnknownRelease));
    }
    Ok(with_it)
}

/// The assignments in `[section]` of `files`, read in turn as systemd reads
/// them.
fn read_files<'a, F: Filesystem>(
    fs: &F,
    files: impl Iterator<Item = &'a PathBuf>,
    section: &str,
) -> Result<Vec<Assignment>, Unread> {
    let mut out = Vec::new();
    for file in files {
        let Some(text) = read_listed_config(fs, file)? else {
            continue;
        };
        if parse_section(&text, section, &mut out).is_err() {
            break;
        }
    }
    Ok(out)
}

/// The text of configuration file `path`, for [`parse_section`] to read the way
/// systemd reads the file.
///
/// systemd reads a configuration file line by line: it skips a comment whatever
/// its bytes, and stops at the first other line that is not valid UTF-8,
/// keeping what it read before. [`Filesystem::read_file_content`] instead
/// rejects a file with any invalid byte outright, which would lose every
/// assignment in it: a `Storage=persistent` beside a Latin-1 comment would
/// vanish and a persistent decoy journal read as volatile. So on invalid UTF-8
/// the bytes are read and decoded with [`decode_config_bytes`], which leaves
/// the lines that systemd refuses for [`parse_section`] to refuse.
///
/// The byte fallback runs only for the real filesystem — the in-memory test
/// double holds valid UTF-8 and never reports invalid data — and reads with
/// `O_NOATIME`, so it leaves no access-time trail on the decoy as the normal
/// read does. `None` when the file cannot be read.
pub fn read_config_text<F: Filesystem>(fs: &F, path: &Path) -> Option<String> {
    read_listed_config(fs, path).ok().flatten()
}

/// [`read_config_text`] for a file that [`config_files`] listed: `None` when it
/// is gone, as systemd skips a file that is gone when it opens it, and
/// [`Unread`] when it is there and NAILS cannot read it.
fn read_listed_config<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<String>, Unread> {
    let unread = || Unread::new(path, UnreadCause::CannotRead);
    match fs.read_file_content(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) => match e.io_kind() {
            Some(std::io::ErrorKind::NotFound) => Ok(None),
            Some(std::io::ErrorKind::InvalidData) => read_config_bytes_noatime(path)
                .map(|bytes| Some(decode_config_bytes(&bytes)))
                .map_err(|_| unread()),
            _ => Err(unread()),
        },
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

/// What [`decode_config_bytes`] puts in place of a byte sequence that is not
/// UTF-8: U+FFFF, a noncharacter, which systemd's UTF-8 test refuses as it
/// refuses those bytes.
const NOT_UTF8: char = '\u{ffff}';

/// Decode a configuration file's bytes for [`parse_section`]: each byte
/// sequence that is not valid UTF-8 becomes one [`NOT_UTF8`], and nothing else
/// changes. Every ASCII byte stays where it was, so the lines, comments,
/// continuations and section headers are the ones systemd reads, and
/// [`parse_section`] refuses exactly the lines systemd refuses: a comment is
/// skipped whatever its bytes, and the first other line that held such a
/// sequence stops the reading.
pub fn decode_config_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            text.push(NOT_UTF8);
        }
    }
    text
}

/// Whether any file of configuration `name` exists under `root`, for a systemd
/// of major version `systemd_major`. An [`Unread`] configuration has one.
pub fn config_present<F: Filesystem>(
    fs: &F,
    root: &Path,
    name: &str,
    systemd_major: Option<u32>,
) -> bool {
    !listing(fs, root, name, systemd_major).is_ok_and(|found| {
        found.main.is_none() && found.uncertain_main.is_none() && found.dropins.is_empty()
    })
}

/// Append the assignments of `[section]` in one configuration text to `out`.
///
/// Returns the [`RefusedLine`] at which systemd would stop reading; the
/// assignments before it are kept.
pub fn parse_section(
    text: &str,
    section: &str,
    out: &mut Vec<Assignment>,
) -> Result<(), RefusedLine> {
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

/// Whether systemd's `unichar_is_valid()` refuses `c`, a character Rust's UTF-8
/// allows: one of the noncharacters U+FDD0 to U+FDEF, or the last two code
/// points of a plane (U+FFFE, U+FFFF, U+1FFFE and so on). The surrogates and
/// the code points above U+10FFFF it also refuses cannot be in a `&str`.
fn systemd_refuses(c: char) -> bool {
    let c = u32::from(c);
    (0xFDD0..=0xFDEF).contains(&c) || c & 0xFFFE == 0xFFFE
}

fn parse_line(
    line: &str,
    section: &str,
    in_section: &mut bool,
    out: &mut Vec<Assignment>,
) -> Result<(), RefusedLine> {
    // Comments went before the line was joined; a `#` here followed a byte
    // order mark and starts a key, as in systemd.
    let line = line.trim_matches(is_ws);
    if line.is_empty() {
        return Ok(());
    }
    // systemd tests every other line for UTF-8 before it looks at it, in any
    // section or none, and stops reading at one that fails.
    if line.chars().any(systemd_refuses) {
        return Err(RefusedLine::NotUtf8);
    }
    if let Some(header) = line.strip_prefix('[') {
        let name = header
            .strip_suffix(']')
            .ok_or(RefusedLine::MalformedSectionHeader)?;
        // systemd's string_is_safe() refuses these in a section name.
        if name
            .chars()
            .any(|c| c.is_ascii_control() || matches!(c, '"' | '\'' | '\\'))
        {
            return Err(RefusedLine::MalformedSectionHeader);
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
#[path = "systemd_conf_tests.rs"]
mod tests;
