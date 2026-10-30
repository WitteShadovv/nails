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
    /// path and end at the end of a path component (the byte after it cannot
    /// continue a file name), and each `/` after its first byte may be
    /// written as several, as the kernel reads a path. A path begins where
    /// the byte before it, past the slashes in front of it, cannot continue
    /// a file name (`file:///mnt/data`, `//mnt/data`), or after the prefixes
    /// systemd allows before a path where they start a value
    /// (`EnvironmentFile=-/mnt/data/app.env`); a unit name begins where the
    /// byte before it cannot continue a file name. So `/mnt/data` matches
    /// `/mnt//data` and `/mnt/data/nixos` but not `/mnt/data2`,
    /// `/srv/mnt/data`, `/srv//mnt/data` or `x-/mnt/data`, and
    /// `mnt-data.mount` does not match `srv-mnt-data.mount`.
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
            Pattern::Path(path) => find_path(line, path.as_bytes()),
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
/// `<type>-<32 hex digits>-<name>`, the type without a dash. Its slashes may
/// be doubled, as in a [`Pattern::Path`]. The range of the whole path.
fn dm_uuid_link(line: &[u8], name: &str) -> Option<Range<usize>> {
    const PREFIX: &[u8] = b"/dev/disk/by-id/dm-uuid-crypt-";
    (0..line.len()).find_map(|start| {
        let tail = path_end(line, start, PREFIX)?;
        if !begins_path(line, start) {
            return None;
        }
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
        let rest = last[kind..].strip_prefix(b"-").filter(|_| kind > 0)?;
        let after_uuid = rest.get(32) == Some(&b'-')
            && rest[..32].iter().all(u8::is_ascii_hexdigit)
            && rest[33..] == *name.as_bytes();
        (rest == name.as_bytes() || after_uuid).then_some(start..end)
    })
}

/// The first place in `line` where the path or unit name `path` stands, as
/// [`Pattern::Path`] describes.
fn find_path(line: &[u8], path: &[u8]) -> Option<Range<usize>> {
    // A run of slashes in the marker itself counts once, as one in the text.
    let mut path = path.to_vec();
    path.dedup_by(|byte, previous| *byte == b'/' && *previous == b'/');
    let rooted = path.first() == Some(&b'/');
    (0..line.len()).find_map(|start| {
        let end = path_end(line, start, &path)?;
        let begins = if rooted {
            begins_path(line, start)
        } else {
            !continues_file_name(start.checked_sub(1).map(|i| line[i]))
        };
        (begins && !continues_file_name(line.get(end).copied())).then_some(start..end)
    })
}

/// Where `path`, read in `line` from `start`, ends: each `/` after its first
/// byte stands for a run of slashes, as the kernel reads a path
/// (`/mnt//data` is `/mnt/data`). `path` holds no run of its own. `None`
/// when `path` is not there.
fn path_end(line: &[u8], start: usize, path: &[u8]) -> Option<usize> {
    let mut at = start;
    for (index, &byte) in path.iter().enumerate() {
        if line.get(at) != Some(&byte) {
            return None;
        }
        at += 1;
        if index > 0 && byte == b'/' {
            at += line[at..].iter().take_while(|&&b| b == b'/').count();
        }
    }
    (!path.is_empty()).then_some(at)
}

/// The prefixes systemd allows before a path in a setting: `-` for a file
/// that may be missing (`EnvironmentFile=-/mnt/data/app.env`), `+`, `!` and
/// `!!` for privileges, `@` for the program's own name, `:` for no
/// environment expansion.
const SYSTEMD_PREFIXES: &[u8] = b"-+@!:";

/// Whether a path that starts at `start` in `line` begins there: the byte
/// before it, past the slashes in front of it, cannot continue a file name,
/// or ends a run of systemd's prefixes that itself starts a value, at the
/// start of the line or after `=`, a quote or a blank. `file:///mnt/data`,
/// `//mnt/data` and `"-/mnt/data/app.env"` name `/mnt/data`;
/// `/srv//mnt/data` and `/srv/-/mnt/data` do not.
fn begins_path(line: &[u8], start: usize) -> bool {
    let Some(at) = line[..start].iter().rposition(|&b| b != b'/') else {
        return true;
    };
    if !continues_file_name(Some(line[at])) {
        return true;
    }
    // No prefix leaves `at` itself, a byte of a file name, as the one
    // before the value: no value starts there.
    let prefixes = line[..=at]
        .iter()
        .rev()
        .take_while(|b| SYSTEMD_PREFIXES.contains(b))
        .count();
    starts_value(line, at + 1 - prefixes)
}

/// Whether a value starts at `at` in `line`: at the start of the line, or
/// after `=`, a quote or a blank.
fn starts_value(line: &[u8], at: usize) -> bool {
    at.checked_sub(1)
        .map(|before| line[before])
        .is_none_or(|b| matches!(b, b'=' | b'"' | b'\'' | b' ' | b'\t'))
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
/// arguments: they open, close or ask about one. Each open and close has the
/// aliases cryptsetup accepts for it (`create` is the obsolete plain open,
/// which takes the name first); `attach` and `detach` are
/// `systemd-cryptsetup`'s.
const MAPPING_VERBS: &[&[u8]] = &[
    b"open",
    b"create",
    b"luksopen",
    b"tcryptopen",
    b"plainopen",
    b"loopaesopen",
    b"bitlkopen",
    b"fvault2open",
    b"close",
    b"remove",
    b"luksclose",
    b"tcryptclose",
    b"plainclose",
    b"loopaesclose",
    b"bitlkclose",
    b"fvault2close",
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
    /// list passes, and so does prose that mentions `cryptsetup` without one
    /// of these verbs after it. Prose that has one reads as the command
    /// (`# use cryptsetup open for the data volume`).
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
