// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Matching hidden-environment markers in the text of a `.nix` file.
//!
//! The scan works on bytes of ASCII-lowercased text, one line at a time, so a
//! match maps back to a line and to the original spelling by offset. Every
//! marker counts in comments as well: an examiner reads them, and a
//! commented-out line that names the hidden volume points at it as plainly as
//! a live one. The device-mapper name, often an ordinary word such as `data`,
//! counts only where it names the mapping ([`Pattern::Name`]).

use std::ops::Range;

/// How a marker is matched in a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pattern {
    /// Plain text anywhere.
    Text(String),
    /// A path, or the name of a systemd unit made from one. It must begin a
    /// path (the byte before it cannot continue a file name; a `/` may
    /// precede it, as in `file:///mnt/data`) and end at the end of a path
    /// component (the byte after it cannot continue a file name). So
    /// `/mnt/data` matches `/mnt/data/nixos` but not `/mnt/data2` or
    /// `/srv/mnt/data`, and `mnt-data.mount` does not match
    /// `srv-mnt-data.mount`.
    Path(String),
    /// A word between bytes that cannot be part of a Nix identifier: `nails`
    /// matches `config.nails.enable` but not `snails`.
    Word(String),
    /// A device-mapper name where it names the mapping (see [`mapping_name`]),
    /// never as an ordinary word (`description = "Back up user data"`) or a
    /// directory (`/var/lib/postgresql/data`). `escaped` holds each spelling
    /// of the name as a systemd instance (`vg-root` is `vg\x2droot`, which a
    /// double-quoted Nix string writes `vg\\x2droot`).
    Name { name: String, escaped: Vec<String> },
    /// The `/dev/disk/by-id/dm-uuid-…` link of the mapping `name`, whatever
    /// its uuid: the link's name ends with `-<name>`.
    DmUuid(String),
}

impl Pattern {
    /// The byte range of the first match in `line`. `luks` holds the ranges
    /// of the `boot.initrd.luks.devices` entry names that `line` defines, as
    /// [`AttrPaths::luks_names`] returns them.
    pub(super) fn find(&self, line: &[u8], luks: &[Range<usize>]) -> Option<Range<usize>> {
        match self {
            Pattern::Text(text) => find_where(line, text, |_, _| true),
            Pattern::Path(path) => find_where(line, path, |before, after| {
                !continues_file_name(before) && !continues_file_name(after)
            }),
            Pattern::Word(word) => find_where(line, word, bounded),
            Pattern::Name { name, escaped } => mapping_name(line, name, escaped, luks),
            Pattern::DmUuid(name) => dm_uuid_link(line, name),
        }
    }
}

/// Where `line` names the mapping `name`, in comments as well as in code:
///
/// - a `luks.devices` entry: `luks.devices.data`, `luks.devices."data"`, or
///   an entry [`AttrPaths`] found in a block (`luks`);
/// - on a line that mentions `crypttab` or `cryptsetup`, as a word that is
///   not part of a path: crypttab text, `cryptsetup open /dev/sdb2 data`,
///   `systemd-cryptsetup@data.service` (with `escaped`, the instance name
///   systemd writes for a name with a `-` in it, in either spelling);
/// - at the start of a crypttab line: the name, then the device as a `/dev/`
///   path, a `UUID=`, `PARTUUID=`, `LABEL=`, `PARTLABEL=` or `ID=` tag, or
///   another absolute path (a container file) followed by a key file field.
fn mapping_name(
    line: &[u8],
    name: &str,
    escaped: &[String],
    luks: &[Range<usize>],
) -> Option<Range<usize>> {
    if let Some(range) = luks_entry(line, name.as_bytes()) {
        return Some(range);
    }
    if let Some(range) = luks.iter().find(|r| line[(*r).clone()] == *name.as_bytes()) {
        return Some(range.clone());
    }
    if contains(line, b"crypttab") || contains(line, b"cryptsetup") {
        let word = find_where(line, name, |before, after| {
            bounded(before, after) && before != Some(b'/') && after != Some(b'/')
        });
        let instance = || {
            escaped.iter().find_map(|escaped| {
                find_where(line, &format!("cryptsetup@{escaped}"), |_, after| {
                    !after.is_some_and(is_identifier_byte)
                })
                .map(|range| range.end - escaped.len()..range.end)
            })
        };
        if let Some(range) = word.or_else(instance) {
            return Some(range);
        }
    }
    crypttab_line(line, name.as_bytes())
}

/// `luks.devices.<name>` or `luks.devices."<name>"`: the range of the name.
fn luks_entry(line: &[u8], name: &[u8]) -> Option<Range<usize>> {
    const PREFIX: &[u8] = b"luks.devices.";
    (0..line.len()).find_map(|at| {
        let rest = line[at..].strip_prefix(PREFIX)?;
        let start = at + PREFIX.len();
        if let Some(quoted) = rest.strip_prefix(b"\"") {
            (quoted.strip_prefix(name)?.first() == Some(&b'"'))
                .then_some(start + 1..start + 1 + name.len())
        } else {
            let after = rest.strip_prefix(name)?.first().copied();
            (!after.is_some_and(is_identifier_byte)).then_some(start..start + name.len())
        }
    })
}

/// A crypttab line that opens `name`: the name first (after any indentation,
/// comment marker or opening quote), then the device. A device that is
/// neither a `/dev/` path nor a tag counts as an absolute path followed by a
/// key file field (`none`, `-` or a path), so prose such as `# data /home is
/// backed up` is no crypttab line.
fn crypttab_line(line: &[u8], name: &[u8]) -> Option<Range<usize>> {
    const DEVICE: &[&[u8]] = &[
        b"/dev/",
        b"uuid=",
        b"partuuid=",
        b"label=",
        b"partlabel=",
        b"id=",
    ];
    let mut start = 0;
    loop {
        let rest = &line[start..];
        start += if rest.starts_with(b"/*") {
            2
        } else if matches!(
            rest.first(),
            Some(b' ' | b'\t' | b'#' | b'*' | b'"' | b'\'')
        ) {
            1
        } else {
            break;
        };
    }
    let rest = line[start..].strip_prefix(name)?;
    let gap = rest
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    let device = &rest[gap..];
    let opens =
        gap > 0 && (DEVICE.iter().any(|tag| device.starts_with(tag)) || file_device(device));
    opens.then_some(start..start + name.len())
}

/// An absolute path, then a key file field: `none`, `-` or another path.
fn file_device(fields: &[u8]) -> bool {
    if fields.first() != Some(&b'/') {
        return false;
    }
    let mut words = fields
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|word| !word.is_empty());
    let _device = words.next();
    words.next().is_some_and(|key| {
        let key = key.strip_suffix(b"\"").unwrap_or(key);
        key == b"none" || key == b"-" || key.first() == Some(&b'/')
    })
}

/// A `/dev/disk/by-id/dm-uuid-…` path whose last component ends with
/// `-<name>`: the range of the whole path.
fn dm_uuid_link(line: &[u8], name: &str) -> Option<Range<usize>> {
    const PREFIX: &str = "/dev/disk/by-id/dm-uuid-";
    let suffix = format!("-{name}");
    let mut from = 0;
    while let Some(found) = find_where(&line[from..], PREFIX, |before, _| {
        !continues_file_name(before)
    }) {
        let start = from + found.start;
        let tail = from + found.end;
        let end = tail
            + line[tail..]
                .iter()
                .take_while(|&&b| continues_file_name(Some(b)))
                .count();
        if line[tail..end].ends_with(suffix.as_bytes()) {
            return Some(start..end);
        }
        from = tail;
    }
    None
}

/// One open bracket, as [`AttrPaths`] tracks it.
#[derive(Debug)]
enum Frame {
    /// An attribute set whose attributes are defined below `path`. `value` is
    /// the full path of the definition whose value is being read, from its
    /// `=` to its `;`: a `{` or `[` in that value opens a block of it.
    Attrs {
        path: Vec<String>,
        value: Option<Vec<String>>,
    },
    /// A list in the value of `path` (`lib.mkMerge [ { … } { … } ]`): each
    /// attribute set in it is a value of `path` too.
    List { path: Vec<String> },
    /// An interpolation, `${ … }`.
    Interpolation,
}

/// Tracks the attribute paths a file defines, line by line, so the name of a
/// `boot.initrd.luks.devices` entry can be told from the same word anywhere
/// else however the entry is written: in a `luks.devices = { … }` block, as
/// `devices.data` in a `luks = { … }` block, in fully nested blocks, in a
/// `lib.mkForce { … }` or `lib.mkMerge [ { … } ]` value, or by `inherit`.
///
/// Braces and brackets are counted on the whole line, comments included, so
/// a block that was commented out line by line is followed too. Parentheses
/// are not counted: a `case` in a shell script string leaves them unbalanced.
#[derive(Debug)]
pub(super) struct AttrPaths {
    /// The open brackets, the file's top level first.
    frames: Vec<Frame>,
}

impl Default for AttrPaths {
    fn default() -> Self {
        Self {
            frames: vec![Frame::Attrs {
                path: Vec::new(),
                value: None,
            }],
        }
    }
}

/// One component of an attribute path being read: its text and its range.
type Component = (Vec<u8>, Range<usize>);

impl AttrPaths {
    /// The ranges in `line` of the `boot.initrd.luks.devices` entry names it
    /// defines (`data` in `data = { … };`, `data.device = …;` or
    /// `devices.data = …;` in the right block, or `inherit data;`).
    pub(super) fn luks_names(&mut self, line: &[u8]) -> Vec<Range<usize>> {
        let mut names = Vec::new();
        // An attribute may start here: at the start of a line inside a block
        // that waits for one, and after its `{` or a `;` at its own level.
        let mut attribute = self.expects_attribute();
        let mut i = 0;
        while i < line.len() {
            if attribute {
                // Blanks and comment markers keep the position.
                if matches!(line[i], b' ' | b'\t' | b'#' | b'*' | b'/') {
                    i += 1;
                    continue;
                }
                attribute = false;
                if let Some(next) = self.definition(line, i, &mut names) {
                    i = next;
                    continue;
                }
            }
            match line[i] {
                b'$' if line.get(i + 1) == Some(&b'{') => {
                    self.frames.push(Frame::Interpolation);
                    i += 1;
                }
                b'{' => {
                    let path = self.block_path();
                    self.frames.push(Frame::Attrs { path, value: None });
                    attribute = true;
                }
                b'[' => {
                    let path = self.block_path();
                    self.frames.push(Frame::List { path });
                }
                b']' => {
                    if matches!(self.frames.last(), Some(Frame::List { .. })) {
                        self.frames.pop();
                    }
                }
                b'}' => {
                    if self.frames.len() > 1 {
                        self.frames.pop();
                    }
                }
                b';' => {
                    if let Some(Frame::Attrs { value, .. }) = self.frames.last_mut() {
                        *value = None;
                    }
                    attribute = self.expects_attribute();
                }
                _ => {}
            }
            i += 1;
        }
        names
    }

    /// Whether the innermost block waits for an attribute.
    fn expects_attribute(&self) -> bool {
        matches!(self.frames.last(), Some(Frame::Attrs { value: None, .. }))
    }

    /// The path a block opened here defines below: the definition whose value
    /// is being read, or the list's path; none elsewhere.
    fn block_path(&self) -> Vec<String> {
        match self.frames.last() {
            Some(Frame::Attrs {
                value: Some(path), ..
            })
            | Some(Frame::List { path }) => path.clone(),
            _ => Vec::new(),
        }
    }

    /// The path of the innermost attribute set.
    fn attrs_path(&self) -> &[String] {
        match self.frames.last() {
            Some(Frame::Attrs { path, .. }) => path,
            _ => &[],
        }
    }

    /// Read the definition that may start at `start`: `inherit …;` or an
    /// attribute path and its `=`. Pushes the entry names it defines to
    /// `names` and returns where to go on, or `None` when no definition
    /// starts there.
    fn definition(
        &mut self,
        line: &[u8],
        start: usize,
        names: &mut Vec<Range<usize>>,
    ) -> Option<usize> {
        if let Some(rest) = line[start..].strip_prefix(b"inherit")
            && !rest.first().copied().is_some_and(is_identifier_byte)
        {
            return Some(self.inherit(line, start + b"inherit".len(), names));
        }
        let (components, end) = attribute_path(line, start)?;
        let next = skip_blanks(line, end);
        if line.get(next) != Some(&b'=') || line.get(next + 1) == Some(&b'=') {
            return None;
        }
        let mut full: Vec<String> = self.attrs_path().to_vec();
        let offset = full.len();
        full.extend(
            components
                .iter()
                .map(|(text, _)| String::from_utf8_lossy(text).into_owned()),
        );
        for (index, (_, range)) in components.into_iter().enumerate() {
            if names_luks_entry(&full, offset + index) {
                names.push(range);
            }
        }
        if let Some(Frame::Attrs { value, .. }) = self.frames.last_mut() {
            *value = Some(full);
        }
        Some(next + 1)
    }

    /// The names an `inherit` (`inherit data;`, `inherit (cfg) data;`)
    /// defines from `from` to its `;`, which is left for the caller.
    fn inherit(&self, line: &[u8], from: usize, names: &mut Vec<Range<usize>>) -> usize {
        let in_devices = self
            .attrs_path()
            .ends_with(&["luks".into(), "devices".into()]);
        let mut i = from;
        let mut depth = 0usize;
        while i < line.len() && line[i] != b';' {
            match line[i] {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                _ if depth == 0 => {
                    if let Some(((_, range), end)) = component(line, i) {
                        if in_devices {
                            names.push(range);
                        }
                        i = end;
                        continue;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        i
    }
}

/// Whether the component at `index` of `path` names a `luks.devices` entry:
/// the two before it are `luks` and `devices`.
fn names_luks_entry(path: &[String], index: usize) -> bool {
    index >= 2 && path[index - 2] == "luks" && path[index - 1] == "devices"
}

/// The attribute path at `start` (`a.b."c"`, blanks allowed around each
/// dot): its components and where it ends.
fn attribute_path(line: &[u8], start: usize) -> Option<(Vec<Component>, usize)> {
    let mut components = Vec::new();
    let (first, mut end) = component(line, start)?;
    components.push(first);
    loop {
        let dot = skip_blanks(line, end);
        if line.get(dot) != Some(&b'.') {
            break;
        }
        let Some((next, after)) = component(line, skip_blanks(line, dot + 1)) else {
            break;
        };
        components.push(next);
        end = after;
    }
    Some((components, end))
}

/// One attribute name at `start` (`data` or `"data"`): its text and range
/// without quotes, and where it ends.
fn component(line: &[u8], start: usize) -> Option<(Component, usize)> {
    if line.get(start) == Some(&b'"') {
        let close = start + 1 + line[start + 1..].iter().position(|&b| b == b'"')?;
        let range = start + 1..close;
        return Some(((line[range.clone()].to_vec(), range), close + 1));
    }
    let len = line
        .get(start..)?
        .iter()
        .take_while(|&&b| is_identifier_byte(b) || b == b'\'')
        .count();
    if len == 0 {
        return None;
    }
    let range = start..start + len;
    Some(((line[range.clone()].to_vec(), range), start + len))
}

fn skip_blanks(line: &[u8], from: usize) -> usize {
    from + line.get(from..).map_or(0, |rest| {
        rest.iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count()
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The first occurrence of `needle` in `haystack` that `accept` takes, given
/// the bytes just before and just after it.
fn find_where(
    haystack: &[u8],
    needle: &str,
    accept: impl Fn(Option<u8>, Option<u8>) -> bool,
) -> Option<Range<usize>> {
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find_map(|start| {
        let end = start + needle.len();
        let before = start.checked_sub(1).map(|i| haystack[i]);
        let after = haystack.get(end).copied();
        (haystack[start..end] == *needle && accept(before, after)).then_some(start..end)
    })
}

/// Neither neighbour can be part of a Nix identifier. `-` and `_` join words,
/// so `evolution-data-server` holds no word `data`.
fn bounded(before: Option<u8>, after: Option<u8>) -> bool {
    !before.is_some_and(is_identifier_byte) && !after.is_some_and(is_identifier_byte)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// Whether `byte` continues a file name. Separators, quotes, spaces and Nix
/// punctuation do not; non-ASCII bytes do.
fn continues_file_name(byte: Option<u8>) -> bool {
    byte.is_some_and(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'.' | b'_' | b'-' | b'+' | b'@' | b'~' | b'%')
            || !b.is_ascii()
    })
}

#[cfg(test)]
#[path = "nix_text_tests.rs"]
mod tests;
