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
//! names take the escapes `\s`, `\t`, `\n`, `\r`, `\\` and `\xNN`.
//!
//! A later file overrides an earlier one, but never an immutable key, nor
//! add a key to a group an earlier file marked immutable (`[group][$i]`). A
//! file that marks itself immutable (`[$i]` before any group) is the last one
//! read. A file is read no further than its hundredth broken line.

use std::collections::BTreeMap;

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

/// The values of `User` in the groups `groups` after reading `sources` in
/// order. A translated `User` in one of them counts as well, whatever comes
/// after it: which translation KConfig takes depends on the language the
/// display manager runs in, which the files do not tell. A value KConfig
/// would expand (`[$e]`) counts as written.
pub(super) fn users(sources: &[Source<'_>], groups: &[&str]) -> Vec<String> {
    let mut reader = Reader {
        map: Map::default(),
        wanted: groups,
        translated: Vec::new(),
    };
    for source in sources {
        if reader.read(source.text, source.main) {
            break;
        }
    }
    let mut users = std::mem::take(&mut reader.translated);
    users.extend(
        groups
            .iter()
            .filter_map(|group| reader.map.value(group, b"User")),
    );
    users
}

#[derive(Debug, Default)]
struct Entry {
    /// `None` once deleted.
    value: Option<Vec<u8>>,
    immutable: bool,
}

/// KConfig's entry map, as far as reading entries goes.
#[derive(Debug, Default)]
struct Map {
    entries: BTreeMap<(String, Vec<u8>), Entry>,
    /// The groups that have entries, and whether each is immutable.
    groups: BTreeMap<String, bool>,
}

impl Map {
    /// `KEntryMap::setEntry()`: nothing changes an immutable key, and an
    /// immutable group takes no new key.
    fn set(&mut self, group: &str, key: &[u8], value: Option<Vec<u8>>, immutable: bool) {
        let id = (group.to_string(), key.to_vec());
        match self.entries.get(&id) {
            Some(entry) if entry.immutable => return,
            Some(_) => {}
            None => match self.groups.get(group) {
                Some(true) => return,
                Some(false) => {}
                None => {
                    self.groups.insert(group.to_string(), false);
                }
            },
        }
        let entry = self.entries.entry(id).or_default();
        entry.value = value;
        entry.immutable = immutable;
    }

    fn group_immutable(&self, group: &str) -> bool {
        self.groups.get(group).copied().unwrap_or(false)
    }

    /// The value `KConfigGroup::readEntry()` returns, unexpanded.
    fn value(&self, group: &str, key: &[u8]) -> Option<String> {
        let entry = self.entries.get(&(group.to_string(), key.to_vec()))?;
        entry.value.as_deref().map(qt_string)
    }
}

/// Where the reading of one file stands.
struct FileState {
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
    /// The values of translated `User` keys in those groups.
    translated: Vec<String>,
}

impl Reader<'_> {
    /// One file into the map; whether it marks itself immutable, which ends
    /// the reading.
    fn read(&mut self, text: &str, main: bool) -> bool {
        let mut state = FileState {
            group: "<default>".to_string(),
            group_immutable: false,
            file_immutable: false,
            skip: false,
            immutable_groups: Vec::new(),
            errors: 0,
        };
        for line in text.as_bytes().split(|&byte| byte == b'\n') {
            if state.errors >= MAX_ERRORS {
                break;
            }
            let line = trim(line);
            match line.first() {
                None | Some(b'#') => {}
                Some(b'[') => self.header(line, main, &mut state),
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

    fn header(&mut self, line: &[u8], main: bool, state: &mut FileState) {
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
        if state.group_immutable && !(state.skip && main) {
            state.immutable_groups.push(state.group.clone());
        }
    }

    fn entry(&mut self, line: &[u8], state: &mut FileState) {
        let (mut key, value) = match line.iter().position(|&byte| byte == b'=') {
            Some(eq) => (trim(&line[..eq]), Some(trim(&line[eq + 1..]))),
            None => (line, None),
        };
        if key.is_empty() {
            return;
        }
        let mut immutable = state.group_immutable;
        let mut translated = false;
        // The brackets at the end of the key, the last first.
        while let Some(open) = key.iter().rposition(|&byte| byte == b'[') {
            let Some(close) = key[open..].iter().position(|&byte| byte == b']') else {
                state.errors += 1;
                return;
            };
            let close = open + close;
            if close > open + 1 && key[open + 1] == b'$' {
                for &option in &key[open + 2..close] {
                    match option {
                        b'i' => immutable = true,
                        b'd' => {
                            let name = decode(&key[..open]).0;
                            self.map.set(&state.group, &name, None, immutable);
                            return;
                        }
                        // `$e` changes the value only when it is read.
                        _ => {}
                    }
                }
            } else if translated {
                // A second language.
                state.errors += 1;
                return;
            } else {
                translated = true;
            }
            key = &key[..open];
        }
        let Some(value) = value else {
            state.errors += 1;
            return;
        };
        let key = decode(key).0;
        let (value, decoded) = decode(value);
        if translated {
            if key == b"User" && self.wanted.contains(&state.group.as_str()) {
                self.translated.push(qt_string(&value));
            }
            return;
        }
        if !decoded {
            state.errors += 1;
        }
        self.map.set(&state.group, &key, Some(value), immutable);
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
