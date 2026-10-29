// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A systemd unit file, read the way systemd's `config_parse()` reads it
//! (src/shared/conf-parser.c, with `read_line_full()` of src/basic/fileio.c).
//!
//! - a line ends at a newline, a carriage return or a NUL, and a run of
//!   these counts as one end as long as no kind repeats in it (`\r\n` and
//!   `\n\r` end one line, `\n\n` two, and a NUL ends a line at once);
//! - a line whose first non-blank byte is `#` or `;` is a comment, also in
//!   the middle of a continuation, whatever its bytes;
//! - a byte order mark is dropped once, from the first line that starts with
//!   one, after that line was told from a comment;
//! - a line ending in an unescaped backslash continues on the next one, the
//!   backslash replaced by a space;
//! - leading and trailing whitespace (`" \t\n\r"`) is stripped, and an empty
//!   line skipped;
//! - `[Section]` selects the section; an assignment outside any section, a
//!   line without `=` and one with nothing before it are skipped;
//! - an assignment splits at its first `=`, and key and value are stripped.
//!
//! A unit file systemd refuses does not load, and its unit never starts
//! ([`Refused`]): a line that is not valid UTF-8 by systemd's measure (which
//! also refuses the Unicode noncharacters), a section header without its
//! closing `]` or whose name holds a control character, a quote or a
//! backslash, a line longer than systemd reads (`LONG_LINE_MAX`, 1 MiB),
//! and, as some systemd releases refuse them, a header with an empty name or
//! one that holds `*`, `?` or `[`.

/// The longest line systemd reads, a continuation included.
const LONG_LINE_MAX: usize = 1024 * 1024;

/// systemd's `WHITESPACE`.
const WHITESPACE: &[u8] = b" \t\n\r";

/// The UTF-8 byte order mark.
const BYTE_ORDER_MARK: &[u8] = b"\xef\xbb\xbf";

/// Why systemd refuses a unit file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A line, not a comment, that is not valid UTF-8 by systemd's measure.
    NotUtf8,
    /// A section header without its closing `]`, or with a name systemd
    /// refuses.
    MalformedHeader,
    /// A line longer than systemd reads.
    TooLong,
}

/// The assignments of a unit file, in the order systemd applies them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitFile {
    /// `(section, key, value)`, key and value stripped.
    pub assignments: Vec<(String, String, String)>,
}

impl UnitFile {
    /// The assignments of `key` in `section`, in order.
    pub fn values<'a, 'b>(
        &'a self,
        section: &'b str,
        key: &'b str,
    ) -> impl Iterator<Item = &'a str> {
        self.assignments
            .iter()
            .filter(move |(s, k, _)| s == section && k == key)
            .map(|(_, _, value)| value.as_str())
    }

    /// The value of `key` in `section` that systemd keeps: the last one. An
    /// empty assignment resets it.
    pub fn last(&self, section: &str, key: &str) -> Option<&str> {
        self.values(section, key).last().filter(|v| !v.is_empty())
    }

    /// The assignments of `other` after these, as systemd applies a unit's
    /// drop-ins after its file.
    pub fn extend(&mut self, other: UnitFile) {
        self.assignments.extend(other.assignments);
    }
}

/// Whether `c` is in systemd's `WHITESPACE`.
fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// `unichar_is_valid()`: not a noncharacter.
fn unichar_is_valid(c: char) -> bool {
    let code = u32::from(c);
    !(0xfdd0..=0xfdef).contains(&code) && code & 0xfffe != 0xfffe
}

/// The kind of line end `byte` is: 1 for a newline, 2 for a carriage return,
/// 4 for a NUL, 0 for none.
fn end_kind(byte: u8) -> u8 {
    match byte {
        b'\n' => 1,
        b'\r' => 2,
        0 => 4,
        _ => 0,
    }
}

/// The lines `read_line()` returns (see the module docs).
fn read_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut rest = bytes;
    // A line takes its bytes and the first byte of its end off the front of
    // what is left, so the walk ends with the file whatever a step decides.
    while let [_, ..] = rest {
        let end = rest
            .iter()
            .position(|&byte| end_kind(byte) != 0)
            .unwrap_or(rest.len());
        let (line, after) = rest.split_at(end);
        lines.push(line);
        rest = after;
        if let [first, tail @ ..] = rest {
            // More of the end goes as long as no kind repeats in it and no
            // NUL came.
            let mut seen = end_kind(*first);
            rest = tail;
            while let [byte, tail @ ..] = rest {
                let kind = end_kind(*byte);
                if kind == 0 || seen & 4 != 0 || seen & kind != 0 {
                    break;
                }
                seen |= kind;
                rest = tail;
            }
        }
    }
    lines
}

/// `bytes` without the whitespace systemd strips around a line.
fn strip(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !WHITESPACE.contains(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !WHITESPACE.contains(b))
        .map_or(start, |at| at + 1);
    &bytes[start..end.max(start)]
}

/// Whether the last byte of `line` is a backslash no other one escapes.
fn ends_escaped(line: &[u8]) -> bool {
    let mut escaped = false;
    for &byte in line {
        escaped = !escaped && byte == b'\\';
    }
    escaped
}

/// Read `bytes` as systemd reads a unit file (see the module docs).
pub fn parse(bytes: &[u8]) -> Result<UnitFile, Refused> {
    let mut logical: Vec<Vec<u8>> = Vec::new();
    let mut continuation: Option<Vec<u8>> = None;
    let mut bom_seen = false;
    for buf in read_lines(bytes) {
        if buf.len() > LONG_LINE_MAX {
            return Err(Refused::TooLong);
        }
        // A comment is told by the raw line, before a byte order mark goes.
        let first = buf.iter().find(|b| !WHITESPACE.contains(b));
        if matches!(first, Some(b'#' | b';')) {
            continue;
        }
        let mut line = buf;
        if !bom_seen && let Some(rest) = buf.strip_prefix(BYTE_ORDER_MARK) {
            line = rest;
            bom_seen = true;
        }
        let mut joined = continuation.take().unwrap_or_default();
        joined.extend_from_slice(line);
        if joined.len() > LONG_LINE_MAX {
            return Err(Refused::TooLong);
        }
        if ends_escaped(&joined) {
            let last = joined.len() - 1;
            joined[last] = b' ';
            continuation = Some(joined);
            continue;
        }
        logical.push(joined);
    }
    logical.extend(continuation);

    let mut file = UnitFile::default();
    let mut section: Option<String> = None;
    for line in &logical {
        let line = strip(line);
        if line.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(line).map_err(|_| Refused::NotUtf8)?;
        if !line.chars().all(unichar_is_valid) {
            return Err(Refused::NotUtf8);
        }
        if let Some(header) = line.strip_prefix('[') {
            let name = header.strip_suffix(']').ok_or(Refused::MalformedHeader)?;
            let unsafe_char = |c: char| c < ' ' || c == '\u{7f}' || matches!(c, '"' | '\'' | '\\');
            if name.is_empty() || name.chars().any(unsafe_char) || name.contains(['*', '?', '[']) {
                return Err(Refused::MalformedHeader);
            }
            section = Some(name.to_string());
            continue;
        }
        let Some(section) = &section else {
            continue;
        };
        if let Some((key, value)) = line.split_once('=')
            && !key.is_empty()
        {
            let key = key.trim_matches(is_whitespace);
            let value = value.trim_matches(is_whitespace);
            file.assignments
                .push((section.clone(), key.to_string(), value.to_string()));
        }
    }
    Ok(file)
}

/// `value` with systemd's `%%` resolved to `%`, or `None` when it holds any
/// other specifier (`%n`, `%H` and the like), which NAILS does not resolve.
pub fn without_specifiers(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
#[path = "unit_file_tests.rs"]
mod tests;
