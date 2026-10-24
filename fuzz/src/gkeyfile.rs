// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How GLib loads a key file and reads a value from it, which GDM and LightDM
//! rely on: `g_key_file_load_from_fd()` with `g_key_file_parse_data()`,
//! `g_key_file_flush_parse_buffer()`, `g_key_file_parse_line()` and the
//! functions it calls, then `g_key_file_get_value()` and
//! `g_key_file_parse_value_as_string()` (glib/gkeyfile.c).
//!
//! A NUL ends a C string, so GLib's line functions stop at one where its
//! byte counts go on; a text that holds one is [`Load::Undecided`]. So is a
//! key whose language tag holds a character beyond ASCII, which GLib judges
//! with its own Unicode tables. A translated key is always kept here: GDM
//! keeps translations, and LightDM's choice by language changes no key
//! without a tag.

/// A loaded key file: the groups in the order they were added, each with its
/// keys in the order they were added and the value each was last given.
#[derive(Debug, Default)]
pub struct KeyFile {
    pub groups: Vec<(String, Vec<(String, String)>)>,
}

/// What loading a text gives.
#[derive(Debug)]
pub enum Load {
    /// What GLib parsed, and whether the load failed on a line (GLib keeps
    /// what it parsed before).
    Loaded { file: KeyFile, failed: bool },
    /// GLib's outcome is not modelled for this text.
    Undecided,
}

struct Parser {
    file: KeyFile,
    /// `key_file->current_group`: `None` for the unnamed group a file
    /// starts in.
    current: Option<usize>,
    /// `key_file->start_group`: the first named group.
    start: Option<usize>,
}

enum Line {
    Ok,
    Error,
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

pub fn load(text: &str) -> Load {
    if text.contains('\0') {
        return Load::Undecided;
    }
    let data = text.as_bytes();
    let mut parser = Parser {
        file: KeyFile::default(),
        current: None,
        start: None,
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
                        return Load::Loaded {
                            file: parser.file,
                            failed: true,
                        };
                    }
                    Line::Undecided => return Load::Undecided,
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
    let failed = if buffer.is_empty() {
        false
    } else {
        match parser.parse_line(&buffer) {
            Line::Ok => false,
            Line::Error => true,
            Line::Undecided => return Load::Undecided,
        }
    };
    Load::Loaded {
        file: parser.file,
        failed,
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
        let name = &line[name_start..name_end];
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
            Some(true) => {}
            Some(false) => return Line::Error,
            None => return Line::Undecided,
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
        let value = std::str::from_utf8(value).expect("cut at ASCII bytes");
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
    line.is_empty() || line[0] == b'#'
}

/// `g_key_file_line_is_group()`.
fn line_is_group(line: &[u8]) -> bool {
    if line.first() != Some(&b'[') {
        return false;
    }
    let mut p = 1;
    while p < line.len() && line[p] != b']' {
        p = next_char(line, p);
    }
    if p >= line.len() {
        return false;
    }
    p = next_char(line, p);
    while p < line.len() && (line[p] == b' ' || line[p] == b'\t') {
        p = next_char(line, p);
    }
    p == line.len()
}

/// `g_key_file_line_is_key_value_pair()`.
fn line_is_key_value_pair(line: &[u8]) -> bool {
    match line.iter().position(|&b| b == b'=') {
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

/// `g_key_file_is_key_name()`; `None` for a language tag beyond ASCII.
fn is_key_name(name: &[u8]) -> Option<bool> {
    let end = name.len();
    let mut q = 0;
    while q < end && name[q] != b'=' && name[q] != b'[' && name[q] != b']' {
        q = next_char(name, q);
    }
    if q == 0 {
        return Some(false);
    }
    if name[0] == b' ' || name[q - 1] == b' ' {
        return Some(false);
    }
    if q < end && name[q] == b'[' {
        q += 1;
        while q < end
            && (name[q].is_ascii_alphanumeric()
                || matches!(name[q], b'-' | b'_' | b'.' | b'@')
                || !name[q].is_ascii())
        {
            if !name[q].is_ascii() {
                return None;
            }
            q = next_char(name, q);
        }
        if q >= end || name[q] != b']' {
            return Some(false);
        }
        q += 1;
    }
    Some(q >= end)
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
