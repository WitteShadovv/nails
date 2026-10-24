// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! GLib's key-file reader, which GDM and LightDM read their configuration
//! with: `g_key_file_load_from_file()`, `g_key_file_get_value()` and
//! `g_key_file_get_string()` of glib/gkeyfile.c.
//!
//! GLib reads a file line by line and refuses a line that is no comment, no
//! group header and no `key=value`, or names an invalid group or key: the load
//! fails there, and what it read before stays in the key file. Only a line
//! that starts with `#`, or ends at a NUL before anything else, is a comment;
//! a `#` later in a line is part of the value. A key set again in its group
//! replaces the value, and a group named again continues the earlier one.
//!
//! GLib takes most of a line as a C string, which ends at a NUL, but counts
//! bytes past it in two places: a group's name runs to the line's last `]`,
//! and the encoding a file declares is compared whole. A key may carry a
//! language tag (`key[de]`) of letters, digits and `-_.@`; which characters
//! beyond ASCII count as letters or digits GLib decides with Unicode tables of
//! its own version. Such a key may load or be refused, and both outcomes are
//! kept.

/// What GLib may load from one file.
pub(super) struct Parsed {
    /// What it loads when it takes every key it may refuse for valid: the
    /// groups and keys read before the first line it refuses.
    pub(super) file: KeyFile,
    /// Whether that load refuses no line: GLib then reports it as done.
    pub(super) complete: bool,
    /// What it holds instead when it refuses one of those keys: the groups
    /// and keys read before each, once for those that only translations
    /// keep apart, which no reader here looks up.
    pub(super) refused: Vec<KeyFile>,
    /// Whether a key without a language tag was set since the last entry of
    /// `refused`.
    changed: bool,
}

impl Parsed {
    /// Each key file GLib may end up with.
    pub(super) fn outcomes(&self) -> impl Iterator<Item = &KeyFile> {
        self.refused.iter().chain(std::iter::once(&self.file))
    }

    /// Whether GLib may report the load as done.
    pub(super) fn may_load(&self) -> bool {
        self.complete
    }

    /// Whether GLib may report the load as failed.
    pub(super) fn may_fail(&self) -> bool {
        !self.complete || !self.refused.is_empty()
    }
}

/// The groups of a key file, in the order they first appear, each with its
/// keys in the order they were first set.
#[derive(Debug, Clone, Default)]
pub(super) struct KeyFile {
    groups: Vec<Group>,
}

#[derive(Debug, Clone)]
struct Group {
    name: String,
    keys: Vec<(String, String)>,
}

impl KeyFile {
    /// The raw value of `key` in `group`, as `g_key_file_get_value()` returns
    /// it: what follows the `=`, leading whitespace removed, trailing
    /// whitespace and escapes kept.
    pub(super) fn value(&self, group: &str, key: &str) -> Option<&str> {
        let group = self.groups.iter().find(|g| g.name == group)?;
        group
            .keys
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// Set `key` in `group`, adding the group after the others when it is new.
    pub(super) fn set(&mut self, group: &str, key: &str, value: &str) {
        let index = self.group_index(group);
        self.set_at(index, key, value);
    }

    fn set_at(&mut self, group: usize, key: &str, value: &str) {
        let keys = &mut self.groups[group].keys;
        match keys.iter_mut().find(|(name, _)| name == key) {
            Some((_, old)) => value.clone_into(old),
            None => keys.push((key.to_string(), value.to_string())),
        }
    }

    /// The groups' names, in order.
    pub(super) fn group_names(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(|group| group.name.as_str())
    }

    /// Each group's name with its keys and raw values, in order.
    pub(super) fn entries(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.groups.iter().flat_map(|group| {
            group
                .keys
                .iter()
                .map(|(key, value)| (group.name.as_str(), key.as_str(), value.as_str()))
        })
    }

    fn group_index(&mut self, name: &str) -> usize {
        match self.groups.iter().position(|group| group.name == name) {
            Some(index) => index,
            None => {
                self.groups.push(Group {
                    name: name.to_string(),
                    keys: Vec::new(),
                });
                self.groups.len() - 1
            }
        }
    }
}

/// GLib's `g_ascii_isspace()`: space, tab, newline, vertical tab, form feed
/// and carriage return.
fn is_space(c: char) -> bool {
    c == ' ' || ('\t'..='\r').contains(&c)
}

/// `text` up to its first NUL, where a C string ends.
fn c_string(text: &str) -> &str {
    text.split('\0').next().unwrap_or_default()
}

/// Load `text` as `g_key_file_load_from_file()` does.
pub(super) fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed {
        file: KeyFile::default(),
        complete: true,
        refused: Vec::new(),
        changed: true,
    };
    let mut current = None;
    for line in lines(text) {
        if !parse_line(&mut parsed, &mut current, line) {
            parsed.complete = false;
            break;
        }
    }
    parsed
}

/// The lines GLib parses: the text split at each `\n`, with one `\r` before
/// the `\n` dropped. A last line without a `\n` keeps its `\r`.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
        .map(|line| match line.strip_suffix('\n') {
            Some(line) => line.strip_suffix('\r').unwrap_or(line),
            None => line,
        })
}

/// One line into `parsed`; false when GLib refuses it. `current` is the
/// index of the group the line is in, `None` before the first header.
fn parse_line(parsed: &mut Parsed, current: &mut Option<usize>, line: &str) -> bool {
    let line = line.trim_start_matches(is_space);
    // A line that starts with a NUL is empty to GLib, so a comment.
    let text = c_string(line);
    if text.is_empty() || text.starts_with('#') {
        return true;
    }
    if let Some(name) = group_name(line) {
        if !is_group_name(name) {
            return false;
        }
        *current = Some(parsed.file.group_index(name));
        return true;
    }
    // A key-value line: a `=` with a key before it.
    let Some(eq) = text.find('=').filter(|&eq| eq > 0) else {
        return false;
    };
    let Some(group) = *current else {
        // "Key file does not start with a group".
        return false;
    };
    let key = text[..eq].trim_end_matches(is_space);
    match key_name(key) {
        KeyName::Valid => {}
        KeyName::Invalid => return false,
        KeyName::Undecided if parsed.changed => {
            parsed.refused.push(parsed.file.clone());
            parsed.changed = false;
        }
        KeyName::Undecided => {}
    }
    let value = text[eq + 1..].trim_start_matches(is_space);
    // The first group may declare the encoding, which must be UTF-8; GLib
    // compares every byte of the line here, past a NUL too.
    let declared = line[eq + 1..].trim_start_matches(is_space);
    if group == 0 && key == "Encoding" && !declared.eq_ignore_ascii_case("UTF-8") {
        return false;
    }
    parsed.changed |= !key.contains('[');
    parsed.file.set_at(group, key, value);
    true
}

/// The name a group header line gives, GLib's way: the line, read up to a
/// NUL, is `[`, a name up to the first `]`, then nothing but spaces and tabs;
/// the name `g_key_file_parse_group()` takes runs from the `[` to the last
/// `]` of the whole line and ends at a NUL.
fn group_name(line: &str) -> Option<&str> {
    let rest = c_string(line).strip_prefix('[')?;
    let close = rest.find(']')?;
    if !rest[close + 1..].chars().all(|c| c == ' ' || c == '\t') {
        return None;
    }
    let last = line.rfind(']')?;
    Some(c_string(&line[1..last]))
}

/// `g_key_file_is_group_name()`: not empty, no bracket, no ASCII control
/// character.
fn is_group_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c == '[' || c == ']' || c.is_ascii_control())
}

/// How `g_key_file_is_key_name()` judges a key.
enum KeyName {
    Valid,
    Invalid,
    /// Valid if GLib's tables take each character beyond ASCII of its
    /// language tag for a letter or a digit, invalid otherwise.
    Undecided,
}

/// `g_key_file_is_key_name()`: a name without brackets that does not end in
/// a space, optionally followed by one `[locale]` of letters, digits and
/// `-_.@`, and nothing after it.
fn key_name(key: &str) -> KeyName {
    let end = key.find(['[', ']']).unwrap_or(key.len());
    if end == 0 || key[..end].ends_with(' ') {
        return KeyName::Invalid;
    }
    let rest = &key[end..];
    if rest.is_empty() {
        return KeyName::Valid;
    }
    let Some(locale) = rest
        .strip_prefix('[')
        .and_then(|locale| locale.strip_suffix(']'))
    else {
        return KeyName::Invalid;
    };
    let mut beyond_ascii = false;
    for c in locale.chars() {
        if !c.is_ascii() {
            beyond_ascii = true;
        } else if !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@')) {
            return KeyName::Invalid;
        }
    }
    if beyond_ascii {
        KeyName::Undecided
    } else {
        KeyName::Valid
    }
}

/// `g_key_file_get_string()`'s reading of a raw value: `\s`, `\n`, `\t`,
/// `\r` and `\\` stand for a space, a newline, a tab, a carriage return and a
/// backslash. Any other escape, or a `\` at the end, makes GLib refuse the
/// value: `None`.
pub(super) fn unescape(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            _ => return None,
        });
    }
    Some(out)
}
