// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How a systemd daemon reads one section of its configuration:
//! `config_parse()` and `parse_line()` (src/shared/conf-parser.c) with
//! `read_line_full()` (src/basic/fileio.c), file by file in the order
//! `config_parse_many_files()` reads them.
//!
//! The section names of the daemons NAILS reads are plain words, so a header
//! naming any other section only has to be told apart from a header systemd
//! refuses. Two refusals differ between systemd releases (an empty name, and
//! the glob characters `*?[` in a name, refused since 2025); a text holding
//! such a header is [`Verdict::Undecided`] and compared with nothing.

/// The assignments of a section, in the order systemd applies them, and
/// whether reading went to the end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Read {
    /// `(key, value)`, both stripped.
    pub assignments: Vec<(String, String)>,
    /// A section header systemd refuses stopped the reading.
    pub stopped: bool,
}

/// Whether a text can be compared with systemd at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// What every supported systemd release reads.
    Read(Read),
    /// Releases disagree about a section header in the text.
    Undecided,
}

/// systemd's `WHITESPACE`.
fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// The lines `read_line()` returns: a line ends at `\n`, `\r` or NUL, a run
/// of these counts as one end as long as no kind repeats in it (`\r\n` and
/// `\n\r` end one line, `\n\n` two), and a NUL ends a line at once.
pub fn read_lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while at < bytes.len() && !matches!(bytes[at], b'\n' | b'\r' | 0) {
            at += 1;
        }
        let end = at;
        let mut seen = 0u8;
        while at < bytes.len() {
            let kind = match bytes[at] {
                b'\n' => 1,
                b'\r' => 2,
                0 => 4,
                _ => break,
            };
            if seen & 4 != 0 || seen & kind != 0 {
                break;
            }
            seen |= kind;
            at += 1;
        }
        lines.push(&text[start..end]);
    }
    lines
}

/// What `parse_line()` does with one logical line.
enum Line {
    /// Nothing for this section.
    Skip,
    /// A header: whether it opens `section`.
    Header(bool),
    /// A header every release refuses: reading stops.
    Refused,
    /// A header only some releases refuse.
    Undecided,
    /// An assignment.
    Assignment(String, String),
}

fn parse_line(line: &str, section: &str) -> Line {
    let line = line.trim_matches(is_whitespace);
    if line.is_empty() {
        return Line::Skip;
    }
    if let Some(header) = line.strip_prefix('[') {
        let Some(name) = header.strip_suffix(']') else {
            return Line::Refused;
        };
        // string_is_safe(): no control character (but newline, which a line
        // cannot hold), no quote, no backslash.
        if name
            .chars()
            .any(|c| (c < ' ' && c != '\n') || c == '\u{7f}' || matches!(c, '"' | '\'' | '\\'))
        {
            return Line::Refused;
        }
        if name.is_empty() || name.contains(['*', '?', '[']) {
            return Line::Undecided;
        }
        return Line::Header(name == section);
    }
    match line.split_once('=') {
        Some((key, value)) if !key.is_empty() => Line::Assignment(
            key.trim_matches(is_whitespace).to_string(),
            value.trim_matches(is_whitespace).to_string(),
        ),
        _ => Line::Skip,
    }
}

/// `config_parse()` of one file into `read`; false when reading stops.
fn parse_file(text: &str, section: &str, read: &mut Read) -> Option<bool> {
    let mut in_section = false;
    let mut bom_seen = false;
    let mut continuation: Option<String> = None;
    let mut logical: Vec<String> = Vec::new();
    for buf in read_lines(text) {
        // A comment is told by the raw line, before a byte order mark goes.
        if buf
            .trim_start_matches(is_whitespace)
            .starts_with(['#', ';'])
        {
            continue;
        }
        let mut l = buf;
        if !bom_seen && let Some(rest) = buf.strip_prefix('\u{feff}') {
            l = rest;
            bom_seen = true;
        }
        let mut p = match continuation.take() {
            Some(mut joined) => {
                joined.push_str(l);
                joined
            }
            None => l.to_string(),
        };
        let mut escaped = false;
        for c in p.chars() {
            escaped = !escaped && c == '\\';
        }
        if escaped {
            p.pop();
            p.push(' ');
            continuation = Some(p);
            continue;
        }
        logical.push(p);
    }
    logical.extend(continuation);
    for line in logical {
        match parse_line(&line, section) {
            Line::Skip => {}
            Line::Header(open) => in_section = open,
            Line::Refused => return Some(false),
            Line::Undecided => return None,
            Line::Assignment(key, value) => {
                if in_section {
                    read.assignments.push((key, value));
                }
            }
        }
    }
    Some(true)
}

/// What the daemon reads from `[section]` of the files, given in the order
/// it reads them: a malformed header stops this file and every later one.
pub fn read_files(files: &[&str], section: &str) -> Verdict {
    let mut read = Read::default();
    for text in files {
        match parse_file(text, section, &mut read) {
            Some(true) => {}
            Some(false) => {
                read.stopped = true;
                break;
            }
            None => return Verdict::Undecided,
        }
    }
    Verdict::Read(read)
}
