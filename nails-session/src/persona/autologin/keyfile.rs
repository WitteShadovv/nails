// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! GLib's key-file reader, which GDM and LightDM read their configuration
//! with: `g_key_file_load_from_file()`, `g_key_file_get_value()` and
//! `g_key_file_get_string()` of glib/gkeyfile.c.
//!
//! GLib reads a file line by line and refuses a line that is no comment, no
//! group header and no `key=value`, or names an invalid group or key: the load
//! fails there, and what it read before stays in the key file. Only a line
//! that starts with `#` is a comment; a `#` later in a line is part of the
//! value. A key set again in its group replaces the value, and a group named
//! again continues the earlier one.

/// What GLib loads from one file.
pub(super) struct Parsed {
    /// The groups and keys read before the first line GLib refuses.
    pub(super) file: KeyFile,
    /// Whether no line was refused: GLib then reports the load as done.
    pub(super) complete: bool,
}

/// The groups of a key file, in the order they first appear, each with its
/// keys in the order they were first set.
#[derive(Debug, Default)]
pub(super) struct KeyFile {
    groups: Vec<Group>,
}

#[derive(Debug)]
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

/// Load `text` as `g_key_file_load_from_file()` does.
pub(super) fn parse(text: &str) -> Parsed {
    let mut file = KeyFile::default();
    let mut current = None;
    for line in lines(text) {
        if !parse_line(&mut file, &mut current, line) {
            return Parsed {
                file,
                complete: false,
            };
        }
    }
    Parsed {
        file,
        complete: true,
    }
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

/// One line into `file`; false when GLib refuses it. `current` is the index
/// of the group the line is in, `None` before the first header.
fn parse_line(file: &mut KeyFile, current: &mut Option<usize>, line: &str) -> bool {
    let line = line.trim_start_matches(is_space);
    if line.is_empty() || line.starts_with('#') {
        return true;
    }
    if let Some(name) = group_header(line) {
        if !is_group_name(name) {
            return false;
        }
        *current = Some(file.group_index(name));
        return true;
    }
    // A key-value line: a `=` with a key before it.
    let Some(eq) = line.find('=').filter(|&eq| eq > 0) else {
        return false;
    };
    let Some(group) = *current else {
        // "Key file does not start with a group".
        return false;
    };
    let key = line[..eq].trim_end_matches(is_space);
    if !is_key_name(key) {
        return false;
    }
    let value = line[eq + 1..].trim_start_matches(is_space);
    // The first group may declare the encoding, which must be UTF-8.
    if group == 0 && key == "Encoding" && !value.eq_ignore_ascii_case("UTF-8") {
        return false;
    }
    file.set_at(group, key, value);
    true
}

/// The name of a group header line: `[`, the name up to the first `]`, then
/// nothing but spaces and tabs.
fn group_header(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let close = rest.find(']')?;
    rest[close + 1..]
        .chars()
        .all(|c| c == ' ' || c == '\t')
        .then(|| &rest[..close])
}

/// `g_key_file_is_group_name()`: not empty, no bracket, no ASCII control
/// character.
fn is_group_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c == '[' || c == ']' || c.is_ascii_control())
}

/// `g_key_file_is_key_name()`: a name without brackets that does not end in
/// a space, optionally followed by one `[locale]` of letters, digits and
/// `-_.@`, and nothing after it.
fn is_key_name(key: &str) -> bool {
    let end = key.find(['[', ']']).unwrap_or(key.len());
    if end == 0 || key[..end].ends_with(' ') {
        return false;
    }
    let rest = &key[end..];
    if rest.is_empty() {
        return true;
    }
    rest.strip_prefix('[')
        .and_then(|locale| locale.strip_suffix(']'))
        .is_some_and(|locale| {
            locale
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
        })
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
