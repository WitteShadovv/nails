// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How GLib loads a key file and reads a value from it, which GDM and LightDM
//! rely on: `g_key_file_load_from_fd()` with `g_key_file_parse_data()`,
//! `g_key_file_flush_parse_buffer()`, `g_key_file_parse_line()` and the
//! functions it calls, then `g_key_file_get_value()` and
//! `g_key_file_parse_value_as_string()` (glib/gkeyfile.c).
//!
//! A NUL ends a C string: the functions that take a line as one stop there,
//! while the byte counts the line is passed with go on past it. A key whose
//! language tag holds a character beyond ASCII is judged by GLib's own Unicode
//! tables, so the load may go on past it or fail there; [`Load::refused`]
//! keeps what GLib holds in the second case. A translated key is always kept
//! here: GDM keeps translations, and LightDM's choice by language changes no
//! key without a tag.

/// A loaded key file: the groups in the order they were added, each with its
/// keys in the order they were added and the value each was last given.
#[derive(Debug, Clone, Default)]
pub struct KeyFile {
    pub groups: Vec<(String, Vec<(String, String)>)>,
}

/// What loading a text gives.
#[derive(Debug)]
pub struct Load {
    /// What GLib parsed taking each key whose tag goes beyond ASCII for
    /// valid, and whether the load failed on a line (GLib keeps what it
    /// parsed before).
    pub file: KeyFile,
    pub failed: bool,
    /// What GLib holds when it takes one of those keys for invalid instead:
    /// what it parsed before each, the load failed there.
    pub refused: Vec<KeyFile>,
}

struct Parser {
    file: KeyFile,
    /// `key_file->current_group`: `None` for the unnamed group a file
    /// starts in.
    current: Option<usize>,
    /// `key_file->start_group`: the first named group.
    start: Option<usize>,
    refused: Vec<KeyFile>,
}

enum Line {
    Ok,
    Error,
}

/// What `g_key_file_is_key_name()` says.
enum KeyName {
    Valid,
    Invalid,
    /// Valid if the characters of the tag beyond ASCII are letters or digits
    /// to GLib, invalid otherwise.
    Undecided,
}

/// `g_ascii_isspace()`.
fn ascii_isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `g_ascii_iscntrl()`.
fn ascii_iscntrl(c: u8) -> bool {
    c < 0x20 || c == 0x7f
}

/// `g_utf8_find_next_char()` in valid UTF-8: the index of the next character.
fn next_char(s: &[u8], at: usize) -> usize {
    let mut next = at + 1;
    while next < s.len() && s[next] & 0xc0 == 0x80 {
        next += 1;
    }
    next
}

/// `s` as a C string: up to its first NUL.
fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(nul) => &s[..nul],
        None => s,
    }
}

pub fn load(text: &str) -> Load {
    let data = text.as_bytes();
    let mut parser = Parser {
        file: KeyFile::default(),
        current: None,
        start: None,
        refused: Vec::new(),
    };
    let mut buffer: Vec<u8> = Vec::new();
    let mut i = 0;
    // g_key_file_parse_data()
    while i < data.len() {
        if data[i] == b'\n' {
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
            if !buffer.is_empty() {
                match parser.parse_line(&buffer) {
                    Line::Ok => {}
                    Line::Error => {
                        return Load {
                            file: parser.file,
                            failed: true,
                            refused: parser.refused,
                        };
                    }
                }
                buffer.clear();
            }
            i += 1;
        } else {
            let end = data[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(data.len(), |n| i + n);
            buffer.extend_from_slice(&data[i..end]);
            i = end;
        }
    }
    // g_key_file_flush_parse_buffer()
    let failed = !buffer.is_empty() && matches!(parser.parse_line(&buffer), Line::Error);
    Load {
        file: parser.file,
        failed,
        refused: parser.refused,
    }
}

impl Parser {
    fn parse_line(&mut self, line: &[u8]) -> Line {
        let mut start = 0;
        while start < line.len() && ascii_isspace(line[start]) {
            start += 1;
        }
        let line = &line[start..];
        if line_is_comment(line) {
            Line::Ok
        } else if line_is_group(line) {
            self.parse_group(line)
        } else if line_is_key_value_pair(line) {
            self.parse_key_value_pair(line)
        } else {
            Line::Error
        }
    }

    fn parse_group(&mut self, line: &[u8]) -> Line {
        let name_start = 1;
        let mut name_end = line.len() - 1;
        while line[name_end] != b']' {
            name_end -= 1;
        }
        // g_strndup()
        let name = c_str(&line[name_start..name_end]);
        if !is_group_name(name) {
            return Line::Error;
        }
        self.add_group(std::str::from_utf8(name).expect("cut at ASCII bytes"));
        Line::Ok
    }

    fn add_group(&mut self, name: &str) {
        if let Some(index) = self.file.groups.iter().position(|(g, _)| g == name) {
            self.current = Some(index);
            return;
        }
        self.file.groups.push((name.to_string(), Vec::new()));
        self.current = Some(self.file.groups.len() - 1);
        if self.start.is_none() {
            self.start = self.current;
        }
    }

    fn parse_key_value_pair(&mut self, line: &[u8]) -> Line {
        let Some(group) = self.current else {
            // "Key file does not start with a group"
            return Line::Error;
        };
        let eq = line
            .iter()
            .position(|&b| b == b'=')
            .expect("a key-value line");
        // key_end, chomping the whitespace before the `=`.
        let mut key_end = eq - 1;
        while ascii_isspace(line[key_end]) {
            key_end -= 1;
        }
        let key = &line[..=key_end];
        match is_key_name(key) {
            KeyName::Valid => {}
            KeyName::Invalid => return Line::Error,
            KeyName::Undecided => self.refused.push(self.file.clone()),
        }
        let mut value_start = eq + 1;
        while value_start < line.len() && ascii_isspace(line[value_start]) {
            value_start += 1;
        }
        let value = &line[value_start..];
        if self.start == Some(group)
            && key == b"Encoding"
            && !(value.len() == 5 && value.eq_ignore_ascii_case(b"UTF-8"))
        {
            return Line::Error;
        }
        let key = std::str::from_utf8(key).expect("cut at ASCII bytes");
        // g_strndup()
        let value = std::str::from_utf8(c_str(value)).expect("cut at ASCII bytes");
        // g_key_file_add_key_value_pair(): the lookup map takes the new pair.
        let keys = &mut self.file.groups[group].1;
        match keys.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v = value.to_string(),
            None => keys.push((key.to_string(), value.to_string())),
        }
        Line::Ok
    }
}

/// `g_key_file_line_is_comment()`, the line's leading whitespace skipped.
fn line_is_comment(line: &[u8]) -> bool {
    line.is_empty() || line[0] == b'#' || line[0] == 0
}

/// `g_key_file_line_is_group()`.
fn line_is_group(line: &[u8]) -> bool {
    if line.first() != Some(&b'[') {
        return false;
    }
    let mut p = 1;
    while p < line.len() && line[p] != 0 && line[p] != b']' {
        p = next_char(line, p);
    }
    if p >= line.len() || line[p] != b']' {
        return false;
    }
    p = next_char(line, p);
    while p < line.len() && (line[p] == b' ' || line[p] == b'\t') {
        p = next_char(line, p);
    }
    p == line.len() || line[p] == 0
}

/// `g_key_file_line_is_key_value_pair()`.
fn line_is_key_value_pair(line: &[u8]) -> bool {
    match c_str(line).iter().position(|&b| b == b'=') {
        None => false,
        // "Key must be non-empty": the `=` is not the first character.
        Some(p) => line[p] != line[0],
    }
}

/// `g_key_file_is_group_name()`.
fn is_group_name(name: &[u8]) -> bool {
    let mut q = 0;
    while q < name.len() && name[q] != b']' && name[q] != b'[' && !ascii_iscntrl(name[q]) {
        q = next_char(name, q);
    }
    !(q < name.len() || q == 0)
}

/// `g_key_file_is_key_name()`, which `g_unichar_isalnum()` decides for a
/// character beyond ASCII.
fn is_key_name(name: &[u8]) -> KeyName {
    let end = name.len();
    let mut q = 0;
    while q < end && name[q] != b'=' && name[q] != b'[' && name[q] != b']' {
        q = next_char(name, q);
    }
    if q == 0 {
        return KeyName::Invalid;
    }
    if name[0] == b' ' || name[q - 1] == b' ' {
        return KeyName::Invalid;
    }
    let mut beyond_ascii = false;
    if q < end && name[q] == b'[' {
        q += 1;
        while q < end
            && (name[q].is_ascii_alphanumeric()
                || matches!(name[q], b'-' | b'_' | b'.' | b'@')
                || !name[q].is_ascii())
        {
            beyond_ascii |= !name[q].is_ascii();
            q = next_char(name, q);
        }
        if q >= end || name[q] != b']' {
            return KeyName::Invalid;
        }
        q += 1;
    }
    match (q >= end, beyond_ascii) {
        (false, _) => KeyName::Invalid,
        (true, false) => KeyName::Valid,
        (true, true) => KeyName::Undecided,
    }
}

impl KeyFile {
    /// `g_key_file_get_value()`.
    pub fn value(&self, group: &str, key: &str) -> Option<&str> {
        let (_, keys) = self.groups.iter().find(|(g, _)| g == group)?;
        keys.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// `g_key_file_set_value()`.
    pub fn set_value(&mut self, group: &str, key: &str, value: &str) {
        let index = match self.groups.iter().position(|(g, _)| g == group) {
            Some(index) => index,
            None => {
                self.groups.push((group.to_string(), Vec::new()));
                self.groups.len() - 1
            }
        };
        let keys = &mut self.groups[index].1;
        match keys.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v = value.to_string(),
            None => keys.push((key.to_string(), value.to_string())),
        }
    }
}

/// `g_key_file_parse_value_as_string()` without list pieces, as
/// `g_key_file_get_string()` calls it: `None` where it sets an error.
pub fn parse_value_as_string(value: &str) -> Option<String> {
    let p = value.as_bytes();
    let mut out = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        if p[i] == b'\\' {
            i += 1;
            match p.get(i) {
                Some(b's') => out.push(b' '),
                Some(b'n') => out.push(b'\n'),
                Some(b't') => out.push(b'\t'),
                Some(b'r') => out.push(b'\r'),
                Some(b'\\') => out.push(b'\\'),
                // "escape character at end of line", "invalid escape
                // sequence"
                None | Some(_) => return None,
            }
        } else {
            out.push(p[i]);
        }
        i += 1;
    }
    Some(String::from_utf8(out).expect("escapes replace ASCII with ASCII"))
}
