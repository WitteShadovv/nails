// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Matching hidden-environment markers in the text of a `.nix` file.
//!
//! The scan works on bytes of ASCII-lowercased text, one line at a time, so a
//! match maps back to a line and to the original spelling by offset. Every
//! marker counts in comments as well: an examiner reads them, and a
//! commented-out line that names the hidden volume points at it as plainly as
//! a live one. The device-mapper name and a filesystem label, often ordinary
//! words such as `data`, count only where they name the mapping or the
//! filesystem ([`Pattern::Name`], [`Pattern::Tag`]).

use super::scan::{Named, is_identifier_byte};
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
    /// The `/dev/disk/by-id/dm-uuid-…` link of the cryptsetup mapping
    /// `name`, whatever its uuid: `dm-uuid-CRYPT-<TYPE>-<name>` or
    /// `dm-uuid-CRYPT-<TYPE>-<32 hex digits>-<name>`.
    DmUuid(String),
    /// An identifier written as a tag, `<tag>=<value>` (`LABEL=data`,
    /// `PARTLABEL="vault"`), the value ending where a file name would. A
    /// filesystem label (`label`) counts as the `label` of a `fileSystems` or
    /// `swapDevices` entry too ([`Named::Label`]).
    Tag { tag: String, value: String },
}

/// What a line holds beyond its text, from the lines before it.
#[derive(Debug, Default)]
pub(super) struct Context {
    /// The ranges that name something ([`super::scan::Scanner`]).
    pub(super) names: Vec<(Range<usize>, Named)>,
    /// The arguments of a `cryptsetup` or `systemd-cryptsetup` command that
    /// opens, closes or asks about a mapping ([`Shell`]).
    pub(super) arguments: Vec<Range<usize>>,
}

impl Pattern {
    /// The byte range of the first match in `line`.
    pub(super) fn find(&self, line: &[u8], context: &Context) -> Option<Range<usize>> {
        match self {
            Pattern::Text(text) => find_where(line, text, |_, _| true),
            Pattern::Path(path) => find_where(line, path, |before, after| {
                !continues_file_name(before) && !continues_file_name(after)
            }),
            Pattern::Word(word) => find_where(line, word, bounded),
            Pattern::Name { name, escaped } => mapping_name(line, name, escaped, context),
            Pattern::DmUuid(name) => dm_uuid_link(line, name),
            Pattern::Tag { tag, value } => tag_value(line, tag, value).or_else(|| {
                if tag == "label" {
                    named(line, value, Named::Label, context)
                } else {
                    None
                }
            }),
        }
    }
}

/// Where `line` names the mapping `name`, in comments as well as in code:
///
/// - a `luks.devices` or `clevis.devices` entry: `luks.devices.data`,
///   `luks.devices."data"`, or a name [`super::scan::Scanner`] found;
/// - an argument of a `cryptsetup` command that opens, closes or asks about a
///   mapping (`cryptsetup open /dev/sdb2 data`, continued lines included), as
///   a word that is not part of a path, or the instance of
///   `systemd-cryptsetup@data.service` (with `escaped`, the instance name
///   systemd writes for a name with a `-` in it, in either spelling);
/// - at the start of a crypttab line, at the start of the line or of a
///   string: the name, then the device as a `/dev/` path, a `UUID=`,
///   `PARTUUID=`, `LABEL=`, `PARTLABEL=` or `ID=` tag, or another absolute
///   path (a container file) followed by a key file field.
fn mapping_name(
    line: &[u8],
    name: &str,
    escaped: &[String],
    context: &Context,
) -> Option<Range<usize>> {
    if let Some(range) = luks_entry(line, name.as_bytes()) {
        return Some(range);
    }
    if let Some(range) = named(line, name, Named::Mapping, context) {
        return Some(range);
    }
    for span in &context.arguments {
        let argument = find_where(&line[span.clone()], name, |before, after| {
            bounded(before, after) && before != Some(b'/') && after != Some(b'/')
        });
        if let Some(range) = argument {
            return Some(span.start + range.start..span.start + range.end);
        }
    }
    let instance = escaped.iter().find_map(|escaped| {
        find_where(line, &format!("cryptsetup@{escaped}"), |_, after| {
            !after.is_some_and(is_identifier_byte)
        })
        .map(|range| range.end - escaped.len()..range.end)
    });
    if instance.is_some() {
        return instance;
    }
    crypttab_starts(line).find_map(|from| crypttab_line(line, from, name.as_bytes()))
}

/// A range of `line` the scanner found naming `what`, whose text is `text`.
fn named(line: &[u8], text: &str, what: Named, context: &Context) -> Option<Range<usize>> {
    context
        .names
        .iter()
        .find(|(range, named)| *named == what && line[range.clone()] == *text.as_bytes())
        .map(|(range, _)| range.clone())
}

/// `luks.devices.<name>`, `clevis.devices.<name>`, or either with the name
/// quoted: the range of the name.
fn luks_entry(line: &[u8], name: &[u8]) -> Option<Range<usize>> {
    const PREFIXES: [&[u8]; 2] = [b"luks.devices.", b"clevis.devices."];
    (0..line.len()).find_map(|at| {
        PREFIXES.iter().find_map(|prefix| {
            let rest = line[at..].strip_prefix(*prefix)?;
            let start = at + prefix.len();
            if let Some(quoted) = rest.strip_prefix(b"\"") {
                (quoted.strip_prefix(name)?.first() == Some(&b'"'))
                    .then_some(start + 1..start + 1 + name.len())
            } else {
                let after = rest.strip_prefix(name)?.first().copied();
                (!after.is_some_and(is_identifier_byte)).then_some(start..start + name.len())
            }
        })
    })
}

/// Where a crypttab line can start: at the start of the line and right
/// after every `"` and `''`, where a string's text may begin.
fn crypttab_starts(line: &[u8]) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(
        (0..line.len())
            .filter(|&at| line[at] == b'"' || line[at..].starts_with(b"''"))
            .map(move |at| at + if line[at] == b'"' { 1 } else { 2 }),
    )
}

/// A crypttab line from `from` that opens `name`: the name first (after any
/// indentation, comment marker or opening quote), then the device. A device
/// that is neither a `/dev/` path nor a tag counts as an absolute path
/// followed by a key file field (`none`, `-` or a path), so prose such as
/// `# data /home is backed up` is no crypttab line. Fields may be separated
/// by blanks or by `\t`, as a Nix string writes a tab.
fn crypttab_line(line: &[u8], from: usize, name: &[u8]) -> Option<Range<usize>> {
    const DEVICE: &[&[u8]] = &[
        b"/dev/",
        b"uuid=",
        b"partuuid=",
        b"label=",
        b"partlabel=",
        b"id=",
    ];
    let mut start = from;
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
    let gap = field_gap(rest);
    let device = &rest[gap..];
    let opens =
        gap > 0 && (DEVICE.iter().any(|tag| device.starts_with(tag)) || file_device(device));
    opens.then_some(start..start + name.len())
}

/// The length of the field separator at the start of `text`: blanks and
/// `\t` escapes.
fn field_gap(text: &[u8]) -> usize {
    let mut at = 0;
    loop {
        if matches!(text.get(at), Some(b' ' | b'\t')) {
            at += 1;
        } else if text[at..].starts_with(b"\\t") {
            at += 2;
        } else {
            return at;
        }
    }
}

/// An absolute path, then a key file field: `none`, `-` or another path.
fn file_device(fields: &[u8]) -> bool {
    if fields.first() != Some(&b'/') {
        return false;
    }
    let device = fields
        .iter()
        .take_while(|&&b| b != b' ' && b != b'\t' && b != b'\\')
        .count();
    let rest = &fields[device..];
    let key = &rest[field_gap(rest)..];
    let key = &key[..key
        .iter()
        .take_while(|&&b| !matches!(b, b' ' | b'\t' | b'\\' | b'"' | b'\''))
        .count()];
    !rest.is_empty() && (key == b"none" || key == b"-" || key.first() == Some(&b'/'))
}

/// A `/dev/disk/by-id/dm-uuid-crypt-<type>-…` path whose last component is
/// cryptsetup's whole name for the mapping `name`: `<type>-<name>` or
/// `<type>-<32 hex digits>-<name>`, the type without a dash. The range of
/// the whole path.
fn dm_uuid_link(line: &[u8], name: &str) -> Option<Range<usize>> {
    const PREFIX: &str = "/dev/disk/by-id/dm-uuid-crypt-";
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
        let last = &line[tail..end];
        let kind = last
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        if kind > 0
            && let Some(rest) = last[kind..].strip_prefix(b"-")
        {
            let after_uuid = rest.get(32) == Some(&b'-')
                && rest[..32].iter().all(u8::is_ascii_hexdigit)
                && rest[33..] == *name.as_bytes();
            if rest == name.as_bytes() || after_uuid {
                return Some(start..end);
            }
        }
        from = tail;
    }
    None
}

/// `<tag>=<value>`, the value quoted or not: the range of the value. The
/// tag must not end another word (`partlabel=` holds no `label=` tag), and
/// the value must end where a file name would.
fn tag_value(line: &[u8], tag: &str, value: &str) -> Option<Range<usize>> {
    let lead = format!("{tag}=");
    let mut from = 0;
    while let Some(found) = find_where(&line[from..], &lead, |before, _| {
        !before.is_some_and(is_identifier_byte)
    }) {
        let mut at = from + found.end;
        if line.get(at) == Some(&b'"') {
            at += 1;
        }
        if line[at..].starts_with(value.as_bytes())
            && !continues_file_name(line.get(at + value.len()).copied())
        {
            return Some(at..at + value.len());
        }
        from += found.end;
    }
    None
}

/// The commands of a `cryptsetup` family that name a mapping in their
/// arguments: they open, close or ask about one.
const MAPPING_VERBS: &[&[u8]] = &[
    b"open",
    b"luksopen",
    b"tcryptopen",
    b"plainopen",
    b"loopaesopen",
    b"bitlkopen",
    b"fvault2open",
    b"close",
    b"luksclose",
    b"remove",
    b"status",
    b"resize",
    b"refresh",
    b"lukssuspend",
    b"luksresume",
    b"attach",
    b"detach",
];

/// How far a `cryptsetup` command reaches past the end of a line, when the
/// line ends in `\`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Command {
    #[default]
    None,
    /// `cryptsetup` without its verb yet.
    Cryptsetup,
    /// After a verb from [`MAPPING_VERBS`]: every word is an argument.
    Arguments,
}

/// Follows `cryptsetup` commands across lines continued with `\`.
#[derive(Debug, Default)]
pub(super) struct Shell {
    carried: Command,
}

impl Shell {
    /// The ranges of `line` that are arguments of a `cryptsetup` or
    /// `systemd-cryptsetup` command whose verb names a mapping. A command
    /// ends at `;`, `|`, `&` or `#`, or at the end of a line that does not
    /// end in `\`. Without such a verb, the command names nothing: a package
    /// list or prose that mentions `cryptsetup` passes.
    pub(super) fn line(&mut self, line: &[u8]) -> Vec<Range<usize>> {
        let mut spans = Vec::new();
        let mut command = std::mem::take(&mut self.carried);
        let mut from = (command == Command::Arguments).then_some(0);
        let mut i = 0;
        while i < line.len() {
            if matches!(line[i], b';' | b'|' | b'&' | b'#') {
                if let Some(start) = from.take() {
                    spans.push(start..i);
                }
                command = Command::None;
                i += 1;
                continue;
            }
            if !is_identifier_byte(line[i]) || (i > 0 && is_identifier_byte(line[i - 1])) {
                i += 1;
                continue;
            }
            let end = i + line[i..]
                .iter()
                .take_while(|&&b| is_identifier_byte(b))
                .count();
            let word = &line[i..end];
            if word.ends_with(b"cryptsetup") && line.get(end) != Some(&b'@') {
                command = Command::Cryptsetup;
            } else if command == Command::Cryptsetup && MAPPING_VERBS.contains(&word) {
                command = Command::Arguments;
                from = Some(end);
            }
            i = end;
        }
        if let Some(start) = from {
            spans.push(start..line.len());
        }
        let continued = line
            .iter()
            .rev()
            .find(|&&b| b != b' ' && b != b'\t' && b != b'\r')
            == Some(&b'\\');
        if continued {
            self.carried = command;
        }
        spans
    }
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
