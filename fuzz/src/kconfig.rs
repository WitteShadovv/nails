// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How KConfig reads a configuration and an entry of it, which Plasma Login
//! Manager relies on since 6.7: `KConfigPrivate::parseUserConfigFiles()`
//! (src/core/kconfig.cpp), `KConfigIniBackend::parseConfig()`,
//! `printableToString()` and `charFromHex()` (src/core/kconfigini.cpp),
//! `KEntryMap::setEntry()` and `getEntry()` (src/core/kconfigdata.cpp) and
//! `KConfigGroup::readEntry()` (src/core/kconfiggroup.cpp), for a display
//! manager running in the language `locale`.
//!
//! The entry map keeps a key apart by its group, its name, whether it is a
//! translation and whether it was read from a file of defaults, as KConfig
//! does. A value marked `[$e]` is returned as written, unexpanded, which is
//! what NAILS reports. A translation counts only in its own language: a bad
//! escape in its value counts towards the file's hundred broken lines there,
//! and one whose name decodes to nothing sets its group's marker there.

use std::collections::BTreeMap;

/// What reading gives.
#[derive(Debug)]
pub struct Read {
    /// The value `readEntry("User")` returns in each group asked for.
    pub users: Vec<Option<String>>,
    /// Whether a translated `User` was read in one of them.
    pub translated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    group: String,
    /// `None` for the group's marker.
    key: Option<Vec<u8>>,
    local: bool,
    default: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Entry {
    value: Option<Vec<u8>>,
    immutable: bool,
    deleted: bool,
    expand: bool,
    localized_country: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Options {
    immutable: bool,
    deleted: bool,
    expand: bool,
    default: bool,
    localized: bool,
    localized_country: bool,
}

#[derive(Debug, Default)]
struct EntryMap {
    map: BTreeMap<Key, Entry>,
}

fn key(group: &str, name: Option<&[u8]>, local: bool, default: bool) -> Key {
    Key {
        group: group.to_string(),
        key: name.map(<[u8]>::to_vec),
        local,
        default,
    }
}

impl EntryMap {
    /// `KEntryMap::setEntry()`; a `name` that is empty sets the group's
    /// marker, as an empty key does in KConfig.
    fn set_entry(&mut self, group: &str, name: &[u8], value: Option<Vec<u8>>, o: Options) -> bool {
        let found = key(group, Some(name), o.localized, o.default);
        let found = if name.is_empty() {
            // An empty name compares equal to the marker's null one.
            Key { key: None, ..found }
        } else {
            found
        };
        let existing = self.map.get(&found).cloned();

        if name.is_empty() {
            let marker = key(group, None, false, false);
            let e = Entry {
                immutable: o.immutable,
                ..Entry::default()
            };
            match self.map.get_mut(&found) {
                None => {
                    self.map.insert(marker, e);
                    return true;
                }
                Some(current) if *current == e => return false,
                Some(current) => *current = e,
            }
            return true;
        }

        let (mut e, new_key) = match existing {
            Some(entry) => {
                if entry.immutable {
                    return false;
                }
                (entry, false)
            }
            None => {
                let marker = key(group, None, false, false);
                match self.map.get(&marker) {
                    None => {
                        self.map.insert(marker, Entry::default());
                    }
                    Some(m) if m.immutable => return false,
                    Some(_) => {}
                }
                (Entry::default(), true)
            }
        };
        let k = key(group, Some(name), o.localized, o.default);
        let value_is_null = value.is_none();
        e.value = value.clone();
        e.immutable = e.immutable || o.immutable;
        if value_is_null {
            e.deleted = e.deleted || o.deleted;
        } else {
            e.deleted = false;
        }
        e.expand = o.expand;
        e.localized_country = o.localized && o.localized_country;

        let without_default = Options {
            default: false,
            ..o
        };
        if new_key {
            if e.deleted {
                self.map.insert(k, e);
                return false;
            }
            self.map.insert(k.clone(), e);
            if k.default {
                self.set_entry(group, name, value, without_default);
            }
            return true;
        }

        let current = self.map.get(&found).cloned().expect("found above");
        if o.localized && current.localized_country && !e.localized_country {
            return false;
        }
        if current != e {
            self.map.insert(found, e);
            if k.default {
                self.set_entry(group, name, value, without_default);
            }
            if !o.localized {
                self.map.remove(&key(group, Some(name), true, false));
                if k.default {
                    self.map.remove(&key(group, Some(name), true, true));
                }
            }
            return true;
        }
        if !o.localized {
            let mut changed = self
                .map
                .remove(&key(group, Some(name), true, false))
                .is_some();
            if k.default
                && self
                    .map
                    .remove(&key(group, Some(name), true, true))
                    .is_some()
            {
                changed = true;
            }
            return changed;
        }
        false
    }

    /// `getEntryOption(group, {}, {}, EntryImmutable)`: the group's marker.
    fn group_immutable(&self, group: &str) -> bool {
        self.map
            .get(&key(group, None, false, false))
            .is_some_and(|e| e.immutable)
    }

    /// `KEntryMap::getEntry()` searching translations first, without
    /// defaults: `None` for the default value.
    fn get_entry(&self, group: &str, name: &[u8]) -> Option<Vec<u8>> {
        let entry = self
            .map
            .get(&key(group, Some(name), true, false))
            .or_else(|| self.map.get(&key(group, Some(name), false, false)))?;
        if entry.deleted {
            return None;
        }
        entry.value.clone()
    }
}

/// `QByteArrayView::trimmed()`.
fn trimmed(s: &[u8]) -> &[u8] {
    let space = |c: &u8| *c == b' ' || (b'\t'..=b'\r').contains(c);
    let mut start = 0;
    let mut end = s.len();
    while start < end && space(&s[start]) {
        start += 1;
    }
    while end > start && space(&s[end - 1]) {
        end -= 1;
    }
    &s[start..end]
}

/// `KConfigIniBackend::charFromHex()`.
fn char_from_hex(s: &[u8]) -> u8 {
    let mut ret: u8 = 0;
    for &c in &s[..2] {
        ret <<= 4;
        if c.is_ascii_digit() {
            ret |= c - b'0';
        } else if (b'a'..=b'f').contains(&c) {
            ret |= c - b'a' + 0x0a;
        } else if (b'A'..=b'F').contains(&c) {
            ret |= c - b'A' + 0x0a;
        } else {
            return b'x';
        }
    }
    ret
}

/// `KConfigIniBackend::printableToString()`, decoding in place as KConfig
/// does: the decoded view, and whether no escape was invalid.
fn printable_to_string(s: &[u8]) -> (Vec<u8>, bool) {
    if s.is_empty() || !s.contains(&b'\\') {
        return (s.to_vec(), true);
    }
    let mut str = trimmed(s).to_vec();
    let l = str.len();
    let mut r = 0;
    let mut i = 0;
    while i < l {
        if str[i] != b'\\' {
            str[r] = str[i];
        } else {
            i += 1;
            if i >= l {
                str[r] = b'\\';
                break;
            }
            match str[i] {
                b's' => str[r] = b' ',
                b't' => str[r] = b'\t',
                b'n' => str[r] = b'\n',
                b'r' => str[r] = b'\r',
                b'\\' => str[r] = b'\\',
                c @ (b';' | b',') => {
                    str[r] = b'\\';
                    r += 1;
                    str[r] = c;
                }
                b'x' => {
                    if i + 2 < l {
                        str[r] = char_from_hex(&str[i + 1..]);
                        i += 2;
                    } else {
                        str[r] = b'x';
                        i = l - 1;
                    }
                }
                _ => {
                    str[r] = b'\\';
                    return (str, false);
                }
            }
        }
        i += 1;
        r += 1;
    }
    str.truncate(r);
    (str, true)
}

/// `QString::fromUtf8()`, with the count of replacement characters not
/// modelled.
fn from_utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// The reading of the files, `mains` telling which is the main file.
struct Reader<'a> {
    map: EntryMap,
    locale: &'a [u8],
    language: &'a [u8],
    wanted: &'a [&'a str],
    translated: bool,
}

/// `KConfigPrivate::parseUserConfigFiles()` over `files` (text, whether it
/// is the main file), then `readEntry("User")` in each of `groups`.
pub fn read(files: &[(&str, bool)], groups: &[&str], locale: &str) -> Read {
    let locale = locale.as_bytes();
    let language = match locale.iter().position(|&c| c == b'_') {
        Some(i) => &locale[..i],
        None => locale,
    };
    let mut reader = Reader {
        map: EntryMap::default(),
        locale,
        language,
        wanted: groups,
        translated: false,
    };
    let mut file_immutable = false;
    for &(text, main) in files {
        if file_immutable {
            break;
        }
        file_immutable = reader.parse_config(text.as_bytes(), !main);
    }
    Read {
        users: groups
            .iter()
            .map(|g| reader.map.get_entry(g, b"User").map(|v| from_utf8(&v)))
            .collect(),
        translated: reader.translated,
    }
}

impl Reader<'_> {
    /// `KConfigIniBackend::parseConfig()`, `default` for `ParseDefaults`:
    /// whether the file is immutable (`ParseImmutable`).
    fn parse_config(&mut self, text: &[u8], default: bool) -> bool {
        const MAX_ERRORS: usize = 100;
        let mut immutable_groups: Vec<String> = Vec::new();
        let mut file_option_immutable = false;
        let mut group_option_immutable = false;
        let mut group_skip = false;
        let mut current_group = "<default>".to_string();
        let mut error_count = 0;

        let mut rest = text;
        while !rest.is_empty() && error_count < MAX_ERRORS {
            let end = rest
                .iter()
                .position(|&c| c == b'\n')
                .map_or(rest.len(), |n| n + 1);
            let buffer = &rest[..end];
            rest = &rest[end..];
            let line = trimmed(buffer);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            if line[0] == b'[' {
                group_option_immutable = file_option_immutable;
                let mut group_name: Vec<u8> = Vec::new();
                let mut start = 1;
                let mut valid = true;
                loop {
                    let mut end = start;
                    loop {
                        if end == line.len() {
                            valid = false;
                            break;
                        }
                        if line[end] == b']' {
                            break;
                        }
                        end += 1;
                    }
                    if !valid {
                        break;
                    }
                    if end + 1 == line.len()
                        && start + 2 == end
                        && line[start] == b'$'
                        && line[start + 1] == b'i'
                    {
                        if group_name.is_empty() {
                            file_option_immutable = true;
                        } else {
                            group_option_immutable = true;
                        }
                    } else {
                        if !group_name.is_empty() {
                            group_name.push(0x1d);
                        }
                        let (part, _) = printable_to_string(&line[start..end]);
                        group_name.extend_from_slice(&part);
                    }
                    start = end + 2;
                    if !(start <= line.len() && line[end + 1] == b'[') {
                        break;
                    }
                }
                if !valid {
                    // "Invalid group header."
                    continue;
                }
                current_group = from_utf8(&group_name);
                group_skip = self.map.group_immutable(&current_group);
                if group_skip && !default {
                    continue;
                }
                if group_option_immutable {
                    immutable_groups.push(current_group.clone());
                }
            } else {
                if group_skip && !default {
                    continue;
                }
                match self.entry(line, &current_group, group_option_immutable, default) {
                    Ok(()) => {}
                    Err(()) => error_count += 1,
                }
            }
        }
        for group in &immutable_groups {
            let o = Options {
                immutable: true,
                ..Options::default()
            };
            self.map.set_entry(group, b"", None, o);
        }
        file_option_immutable
    }

    /// The entry branch of `parseConfig()`; `Err` where it counts an error.
    fn entry(
        &mut self,
        line: &[u8],
        group: &str,
        group_immutable: bool,
        default: bool,
    ) -> Result<(), ()> {
        let eqpos = line.iter().position(|&c| c == b'=');
        let (mut a_key, value): (&[u8], &[u8]) = match eqpos {
            None => (line, &[]),
            Some(eq) => (trimmed(&line[..eq]), trimmed(&line[eq + 1..])),
        };
        if a_key.is_empty() {
            // "Invalid entry (empty key)", not counted.
            return Ok(());
        }
        let mut o = Options {
            immutable: group_immutable,
            ..Options::default()
        };
        let mut locale: Option<&[u8]> = None;
        while let Some(start) = a_key.iter().rposition(|&c| c == b'[') {
            let Some(end) = a_key[start..].iter().position(|&c| c == b']') else {
                // "Invalid entry (missing ']')"
                return Err(());
            };
            let end = start + end;
            if end > start + 1 && a_key[start + 1] == b'$' {
                for &c in &a_key[start + 2..end] {
                    match c {
                        b'i' => o.immutable = true,
                        b'e' => o.expand = true,
                        b'd' => {
                            o.deleted = true;
                            o.default = default;
                            let (name, _) = printable_to_string(&a_key[..start]);
                            self.map.set_entry(group, &name, None, o);
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            } else {
                if locale.is_some() {
                    // "Invalid entry (second locale!?)"
                    return Err(());
                }
                locale = Some(&a_key[start + 1..end]);
            }
            a_key = &a_key[..start];
        }
        if eqpos.is_none() {
            // "Invalid entry (missing '=')"
            return Err(());
        }
        let (name, _) = printable_to_string(a_key);
        if let Some(locale) = locale {
            if name == b"User" && self.wanted.contains(&group) {
                self.translated = true;
            }
            if !locale.is_empty()
                && locale != self.locale
                && locale != self.language
                && (locale[0] != b'C' || self.locale != b"en_US")
            {
                return Ok(());
            }
        }
        o.default = default;
        if let Some(locale) = locale {
            o.localized = true;
            o.localized_country = locale.contains(&b'_');
        }
        let (value, ok) = printable_to_string(value);
        self.map.set_entry(group, &name, Some(value), o);
        if ok { Ok(()) } else { Err(()) }
    }
}
