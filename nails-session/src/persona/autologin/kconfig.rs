// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! KConfig's INI reader, which Plasma Login Manager reads its configuration
//! with since 6.7: `KConfigIniBackend::parseConfig()` of
//! src/core/kconfigini.cpp, with the entry map of kconfigdata.cpp, over the
//! files in the order `KConfig` reads them.
//!
//! A line is trimmed; one that starts with `#` is a comment. A header names
//! a group, `[Autologin][seat0]` a group within a group. A key may carry
//! options in brackets: `[$i]` makes it immutable, `[$d]` deletes it, `[$e]`
//! expands environment variables in its value when it is read; other
//! brackets name the language a translation is for. Values, keys and group
//! names take the escapes `\s`, `\t`, `\n`, `\r`, `\\` and `\xNN`. A key
//! that decodes to nothing (a lone `\`) is no key: it sets whether its group
//! is immutable, as the line's options say.
//!
//! A later file overrides an earlier one, but never an immutable key, nor
//! add a key to a group an earlier file marked immutable (`[group][$i]`). A
//! file with a header that is only `[$i]` marks itself immutable and is the
//! last one read. A file is read no further than its hundredth broken line.
//!
//! Every file but the main one is read as defaults: a key such a file sets
//! has an entry of the defaults beside the one `readEntry()` reads, and a
//! change to the first goes on to the second through the same checks. The
//! main file sets only the second. So the two can differ: deleting a key
//! that had no entry makes only the first, and an immutable group refuses a
//! new second entry where it lets the first one change.
//!
//! That is the entry map of KDE Frameworks 6.29 and later. Plasma Login
//! Manager 6.7 also runs on 6.26 to 6.28, whose map differs in three ways
//! ([`Frameworks::Before6_29`]): a drop-in's `[$d]` deletes the entry
//! `readEntry()` reads, deleting a key that had no entry makes nothing, and a
//! change to the defaults' entry is copied over the other one unchecked. So
//! there a later drop-in's value wins over a deletion marked immutable.
//!
//! A translation is read only in its language, and the language the display
//! manager runs in is not in the files. So the files are read once in each
//! language that matters: every one a translation names, `en_US` (which reads
//! a `C` translation as its own), and one none names.

use std::collections::{BTreeMap, BTreeSet};

/// What KConfig names the group nested in another: the names joined with
/// this byte.
const GROUP_SEPARATOR: u8 = 0x1d;

/// The broken lines after which KConfig stops reading a file.
const MAX_ERRORS: usize = 100;

/// One file to read.
pub(super) struct Source<'a> {
    /// The file's text.
    pub(super) text: &'a str,
    /// Whether this is the file KConfig was opened on, read last; the
    /// others are read as its defaults.
    pub(super) main: bool,
}

/// The KDE Frameworks release KConfig comes with, as far as its entry map
/// goes: Plasma Login Manager 6.7 runs on 6.26 and later, 6.8 on 6.30 and
/// later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Frameworks {
    /// 6.26 to 6.28.
    Before6_29,
    /// 6.29 and later.
    Since6_29,
}

/// The values of `User` in the groups `groups` after reading `sources` in
/// order with the entry map of `frameworks`, in each language that reads
/// them differently. A translated `User` in one of them counts as well,
/// whatever comes after it: which value `readEntry()` then returns depends
/// on more than the files tell. A value KConfig would expand (`[$e]`) counts
/// as written.
pub(super) fn users(
    sources: &[Source<'_>],
    groups: &[&str],
    frameworks: Frameworks,
) -> Vec<String> {
    let mut users = Vec::new();
    for locale in locales(sources) {
        let mut reader = Reader {
            map: Map::new(frameworks),
            wanted: groups,
            locale: &locale,
            translated: Vec::new(),
        };
        for source in sources {
            if reader.read(source.text, source.main) {
                break;
            }
        }
        users.append(&mut reader.translated);
        users.extend(
            groups
                .iter()
                .filter_map(|group| reader.map.value(group, b"User")),
        );
    }
    users
}

/// Every value `sources` give `User` in the groups `groups`, translations
/// too, whatever reads them or comes after them.
pub(super) fn every_user(sources: &[Source<'_>], groups: &[&str]) -> Vec<String> {
    let mut users = Vec::new();
    for source in sources {
        let mut group = "<default>".to_string();
        for line in lines(source.text) {
            match line.first() {
                None | Some(b'#') => {}
                Some(b'[') => {
                    if let Some((name, _)) = group_header(line) {
                        group = qt_string(&name);
                    }
                }
                Some(_) => {
                    if let Key::Set { name, value, .. } = parse_key(line)
                        && decode(name).0 == b"User"
                        && groups.contains(&group.as_str())
                    {
                        users.push(qt_string(&decode(value).0));
                    }
                }
            }
        }
    }
    users
}

/// The languages to read `sources` in: the language each translation names,
/// `en_US` and one that names none. Without a translation every language
/// reads them alike, and one is enough.
fn locales(sources: &[Source<'_>]) -> Vec<Vec<u8>> {
    let mut locales: BTreeSet<Vec<u8>> = sources
        .iter()
        .flat_map(|source| lines(source.text))
        .filter(|line| !matches!(line.first(), None | Some(b'#' | b'[')))
        .filter_map(|line| match parse_key(line) {
            Key::Set {
                locale: Some(tag), ..
            } if !tag.is_empty() => Some(tag.to_vec()),
            _ => None,
        })
        .collect();
    if !locales.is_empty() {
        locales.insert(b"en_US".to_vec());
    }
    // No tag is empty: the empty locale stands for a language none names.
    locales.insert(Vec::new());
    locales.into_iter().collect()
}

/// The lines of `text` as `parseConfig()` reads them: split at `\n` and
/// trimmed.
fn lines(text: &str) -> impl Iterator<Item = &[u8]> {
    text.as_bytes().split(|&byte| byte == b'\n').map(trim)
}

/// An entry, with what `KEntry` compares of it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// `None` once deleted.
    value: Option<Vec<u8>>,
    immutable: bool,
    /// `[$e]`, which changes nothing read here but whether two entries are
    /// the same.
    expand: bool,
}

/// KConfig's entry map, as far as reading entries goes. A key read from a
/// drop-in has an entry of the defaults beside the one `readEntry()` reads.
#[derive(Debug)]
struct Map {
    /// By group, key and whether the entry is the defaults' one.
    entries: BTreeMap<(String, Vec<u8>, bool), Entry>,
    /// The markers of the groups that have one, and whether each group is
    /// immutable.
    groups: BTreeMap<String, bool>,
    frameworks: Frameworks,
}

impl Map {
    fn new(frameworks: Frameworks) -> Self {
        Self {
            entries: BTreeMap::new(),
            groups: BTreeMap::new(),
            frameworks,
        }
    }

    /// `KEntryMap::setEntry()`, into the defaults' entry when `default`:
    /// nothing changes an immutable entry, and an immutable group takes no
    /// new one. A change to the defaults' entry goes on to the other one,
    /// through the same checks, unless it deletes a key that had no entry.
    /// Before 6.29 such a deletion makes no entry at all, and a change to the
    /// defaults' entry is copied over the other one unchecked. A key that is
    /// empty sets the group's marker instead, and so whether the group is
    /// immutable.
    fn set(&mut self, group: &str, key: &[u8], entry: Entry, default: bool) {
        if key.is_empty() {
            self.groups.insert(group.to_string(), entry.immutable);
            return;
        }
        let id = (group.to_string(), key.to_vec(), default);
        match self.entries.get(&id) {
            Some(current) if current.immutable || *current == entry => return,
            Some(_) => {}
            None if self.group_immutable(group) => return,
            None => {
                self.groups.entry(group.to_string()).or_insert(false);
                if entry.value.is_none() {
                    if self.frameworks == Frameworks::Since6_29 {
                        self.entries.insert(id, entry);
                    }
                    return;
                }
            }
        }
        self.entries.insert(id, entry.clone());
        if default {
            match self.frameworks {
                Frameworks::Since6_29 => self.set(group, key, entry, false),
                Frameworks::Before6_29 => {
                    let other = (group.to_string(), key.to_vec(), false);
                    self.entries.insert(other, entry);
                }
            }
        }
    }

    fn group_immutable(&self, group: &str) -> bool {
        self.groups.get(group).copied().unwrap_or(false)
    }

    /// The value `KConfigGroup::readEntry()` returns, unexpanded: never the
    /// defaults' one.
    fn value(&self, group: &str, key: &[u8]) -> Option<String> {
        let entry = self
            .entries
            .get(&(group.to_string(), key.to_vec(), false))?;
        entry.value.as_deref().map(qt_string)
    }
}

/// Where the reading of one file stands.
struct FileState {
    /// Whether this is the main file; the others are read as defaults.
    main: bool,
    group: String,
    /// Every key of the current group is immutable.
    group_immutable: bool,
    file_immutable: bool,
    /// An earlier file made the current group immutable.
    skip: bool,
    /// The groups this file marks immutable once it has been read.
    immutable_groups: Vec<String>,
    errors: usize,
}

struct Reader<'g> {
    map: Map,
    /// The groups whose `User` is wanted.
    wanted: &'g [&'g str],
    /// The language KConfig runs in, `de_DE` say.
    locale: &'g [u8],
    /// The values of translated `User` keys in those groups.
    translated: Vec<String>,
}

impl Reader<'_> {
    /// One file into the map; whether it marks itself immutable, which ends
    /// the reading.
    fn read(&mut self, text: &str, main: bool) -> bool {
        let mut state = FileState {
            main,
            group: "<default>".to_string(),
            group_immutable: false,
            file_immutable: false,
            skip: false,
            immutable_groups: Vec::new(),
            errors: 0,
        };
        for line in lines(text) {
            if state.errors >= MAX_ERRORS {
                break;
            }
            match line.first() {
                None | Some(b'#') => {}
                Some(b'[') => self.header(line, &mut state),
                // The main file skips the keys of a group an earlier file
                // made immutable; for the others the map refuses them.
                Some(_) if state.skip && main => {}
                Some(_) => self.entry(line, &mut state),
            }
        }
        for group in state.immutable_groups {
            self.map.groups.insert(group, true);
        }
        state.file_immutable
    }

    fn header(&mut self, line: &[u8], state: &mut FileState) {
        state.group_immutable = state.file_immutable;
        // A header KConfig cannot read leaves the group as it was.
        let Some((name, mark)) = group_header(line) else {
            return;
        };
        match mark {
            Mark::File => state.file_immutable = true,
            Mark::Group => state.group_immutable = true,
            Mark::None => {}
        }
        state.group = qt_string(&name);
        state.skip = self.map.group_immutable(&state.group);
        if state.group_immutable && !(state.skip && state.main) {
            state.immutable_groups.push(state.group.clone());
        }
    }

    fn entry(&mut self, line: &[u8], state: &mut FileState) {
        match parse_key(line) {
            Key::Empty => {}
            Key::Broken => state.errors += 1,
            Key::Delete {
                name,
                immutable,
                expand,
            } => {
                let name = decode(name).0;
                let entry = Entry {
                    value: None,
                    immutable: immutable || state.group_immutable,
                    expand,
                };
                // Before 6.29 a drop-in deletes the entry `readEntry()`
                // reads, not the defaults' one.
                let default = !state.main && self.map.frameworks == Frameworks::Since6_29;
                self.map.set(&state.group, &name, entry, default);
            }
            Key::Set {
                name,
                locale,
                immutable,
                expand,
                value,
            } => {
                let name = decode(name).0;
                if locale.is_some_and(|tag| !self.reads(tag)) {
                    // A translation for another language: skipped whole.
                    return;
                }
                let (value, decoded) = decode(value);
                if !decoded {
                    state.errors += 1;
                }
                if locale.is_some() && !name.is_empty() {
                    if name == b"User" && self.wanted.contains(&state.group.as_str()) {
                        self.translated.push(qt_string(&value));
                    }
                    return;
                }
                let entry = Entry {
                    value: Some(value),
                    immutable: immutable || state.group_immutable,
                    expand,
                };
                self.map.set(&state.group, &name, entry, !state.main);
            }
        }
    }

    /// Whether KConfig reads a translation for `tag` in its language: one
    /// without a tag, or for the language with or without its country, in
    /// every language; in `en_US` also every tag that starts with `C`.
    fn reads(&self, tag: &[u8]) -> bool {
        let language = match self.locale.iter().position(|&byte| byte == b'_') {
            Some(underscore) => &self.locale[..underscore],
            None => self.locale,
        };
        tag.is_empty()
            || tag == self.locale
            || tag == language
            || (tag[0] == b'C' && self.locale == b"en_US")
    }
}

/// A key line, as `parseConfig()` takes it apart: the name and the options
/// still raw, as written.
enum Key<'a> {
    /// No key before the `=`: skipped, and not counted as broken.
    Empty,
    /// A line KConfig counts as broken.
    Broken,
    /// `name[$d]`: the key deleted.
    Delete {
        name: &'a [u8],
        immutable: bool,
        expand: bool,
    },
    /// `name=value`, or `name[locale]=value` for a translation.
    Set {
        name: &'a [u8],
        locale: Option<&'a [u8]>,
        immutable: bool,
        expand: bool,
        value: &'a [u8],
    },
}

/// Take the trimmed line `line`, which opens no group, apart as
/// `parseConfig()` does: the brackets at the end of its key, the last first.
fn parse_key(line: &[u8]) -> Key<'_> {
    let (mut key, value) = match line.iter().position(|&byte| byte == b'=') {
        Some(eq) => (trim(&line[..eq]), Some(trim(&line[eq + 1..]))),
        None => (line, None),
    };
    if key.is_empty() {
        return Key::Empty;
    }
    let (mut immutable, mut expand) = (false, false);
    let mut locale = None;
    while let Some(open) = key.iter().rposition(|&byte| byte == b'[') {
        let Some(close) = key[open..].iter().position(|&byte| byte == b']') else {
            return Key::Broken;
        };
        let close = open + close;
        if close > open + 1 && key[open + 1] == b'$' {
            for &option in &key[open + 2..close] {
                match option {
                    b'i' => immutable = true,
                    // `$e` changes the value only when it is read.
                    b'e' => expand = true,
                    b'd' => {
                        return Key::Delete {
                            name: &key[..open],
                            immutable,
                            expand,
                        };
                    }
                    _ => {}
                }
            }
        } else if locale.is_some() {
            // A second language.
            return Key::Broken;
        } else {
            locale = Some(&key[open + 1..close]);
        }
        key = &key[..open];
    }
    match value {
        Some(value) => Key::Set {
            name: key,
            locale,
            immutable,
            expand,
            value,
        },
        None => Key::Broken,
    }
}

/// An `[$i]` closing a header: of the file when it is all the header holds,
/// of the group otherwise.
enum Mark {
    None,
    File,
    Group,
}

/// The group a header line names, its parts each decoded and joined with
/// [`GROUP_SEPARATOR`]; `None` for a part without its `]`. What follows the
/// `]` of the last part is ignored.
fn group_header(line: &[u8]) -> Option<(Vec<u8>, Mark)> {
    let mut name = Vec::new();
    let mut mark = Mark::None;
    let mut start = 1;
    loop {
        let end = start + line.get(start..)?.iter().position(|&byte| byte == b']')?;
        let part = &line[start..end];
        if end + 1 == line.len() && part == b"$i" {
            mark = if name.is_empty() {
                Mark::File
            } else {
                Mark::Group
            };
        } else {
            if !name.is_empty() {
                name.push(GROUP_SEPARATOR);
            }
            name.extend_from_slice(&decode(part).0);
        }
        start = end + 2;
        if start > line.len() || line[end + 1] != b'[' {
            return Some((name, mark));
        }
    }
}

/// `QByteArrayView::trimmed()`: ASCII whitespace off both ends, the vertical
/// tab included.
fn trim(bytes: &[u8]) -> &[u8] {
    let is_space = |byte: &u8| *byte == b' ' || (b'\t'..=b'\r').contains(byte);
    let Some(start) = bytes.iter().position(|byte| !is_space(byte)) else {
        return &[];
    };
    let end = bytes
        .iter()
        .rposition(|byte| !is_space(byte))
        .map_or(start, |end| end + 1);
    &bytes[start..end]
}

/// `KConfigIniBackend::printableToString()`: the text with its escapes
/// decoded, and whether they all were. An unknown escape stops the decoding
/// where it stands and leaves the rest as it was; a `\` at the very end is
/// dropped.
fn decode(raw: &[u8]) -> (Vec<u8>, bool) {
    if !raw.contains(&b'\\') {
        return (raw.to_vec(), true);
    }
    let text = trim(raw);
    let mut out = text.to_vec();
    let (mut i, mut r) = (0, 0);
    while i < text.len() {
        if text[i] == b'\\' {
            i += 1;
            let Some(&escape) = text.get(i) else {
                break;
            };
            match escape {
                b's' => out[r] = b' ',
                b't' => out[r] = b'\t',
                b'n' => out[r] = b'\n',
                b'r' => out[r] = b'\r',
                b'\\' => out[r] = b'\\',
                // Kept as written, for desktop files.
                b';' | b',' => {
                    out[r] = b'\\';
                    r += 1;
                    out[r] = escape;
                }
                b'x' if i + 2 < text.len() => {
                    out[r] = hex(text[i + 1], text[i + 2]);
                    i += 2;
                }
                b'x' => {
                    out[r] = b'x';
                    i = text.len() - 1;
                }
                _ => {
                    out[r] = b'\\';
                    return (out, false);
                }
            }
        } else {
            out[r] = text[i];
        }
        i += 1;
        r += 1;
    }
    out.truncate(r);
    (out, true)
}

/// `KConfigIniBackend::charFromHex()`: the byte two hex digits spell, or
/// `x` when either is no hex digit.
fn hex(high: u8, low: u8) -> u8 {
    let digit = |byte: u8| char::from(byte).to_digit(16);
    match (digit(high), digit(low)) {
        (Some(high), Some(low)) => u8::try_from(high * 16 + low).unwrap_or(b'x'),
        _ => b'x',
    }
}

/// `QString::fromUtf8()`: a byte order mark at the start dropped, invalid
/// UTF-8 replaced.
fn qt_string(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}
