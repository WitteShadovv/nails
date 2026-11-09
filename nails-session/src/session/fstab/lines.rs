// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines of an fstab that systemd's fstab generator reads as entries,
//! and those it may read otherwise than [`parse_fstab`](super::parse_fstab).
//!
//! The generator reads `/etc/fstab` with glibc's `getmntent()` up to systemd
//! 258 and with libmount from 259 on. Both split a line at spaces and tabs
//! alone, where [`parse_fstab`](super::parse_fstab) splits and trims it at
//! any whitespace. glibc undoes the escapes `\040`, `\011`, `\012`, `\134`
//! and `\\` in each field, libmount every three-digit octal escape, and
//! [`parse_fstab`](super::parse_fstab) every one up to `\377` in the device
//! and the mount point and none in the type and the options. glibc reads
//! 4095 bytes of a line at most and ends one at a NUL, and libmount reads the
//! whole file as a mount table or as the list of swaps when its first line
//! begins as a line of one does. systemd splits the options at a comma that
//! no backslash escapes, [`parse_fstab`](super::parse_fstab) at every comma.
//!
//! [`entry_lines`] gives the lines that glibc reads, and libmount where it
//! reads them at all, as [`parse_fstab`](super::parse_fstab) does, in the
//! four fields the session policy decides by, the device, the mount point,
//! the type and the options, or the first line they may not, which an entry
//! that reads the file refuses: NAILS cannot tell what the hidden systemd
//! mounts from it. libmount skips some lines that NAILS still decides, such
//! as one of two fields or one whose pass number is no number.

/// One of the fields of an fstab line that the session policy decides by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The device, or what else the line mounts.
    Device,
    /// The mount point.
    MountPoint,
    /// The filesystem type.
    Type,
    /// The mount options.
    Options,
}

impl Field {
    /// The four, in the order a line has them.
    const ALL: [Field; 4] = [
        Field::Device,
        Field::MountPoint,
        Field::Type,
        Field::Options,
    ];

    /// The field's name in a message.
    fn name(self) -> &'static str {
        match self {
            Field::Device => "device",
            Field::MountPoint => "mount point",
            Field::Type => "type",
            Field::Options => "options",
        }
    }

    /// The escapes that glibc and libmount undo alike in this field, and
    /// that leave it read as [`parse_fstab`](super::parse_fstab) reads it:
    /// those of a space, a tab and a newline, and in the device and the mount
    /// point the one of a backslash, which
    /// [`parse_fstab`](super::parse_fstab) undoes there too. In the options a
    /// backslash would escape the next comma for systemd; no type has an
    /// escape.
    fn alike_escapes(self) -> &'static [&'static [u8]] {
        match self {
            Field::Device | Field::MountPoint => &[b"\\040", b"\\011", b"\\012", b"\\134"],
            Field::Options => &[b"\\040", b"\\011", b"\\012"],
            Field::Type => &[],
        }
    }
}

/// Why systemd's fstab generator may read a line otherwise than
/// [`parse_fstab`](super::parse_fstab) does ([`entry_lines`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlike {
    /// The line begins as one of a mount table or of the list of swaps does:
    /// as the first line, it makes libmount read the whole file as that.
    OtherTable,
    /// The line is longer than the 4095 bytes glibc reads of it.
    TooLong,
    /// The field is not UTF-8 text.
    NotText(Field),
    /// The field holds this character: whitespace other than a space or a
    /// tab, at which [`parse_fstab`](super::parse_fstab) splits or trims the
    /// line and systemd does not, or a NUL, at which glibc ends it.
    Holds(Field, char),
    /// The field holds this escape, as written: one that glibc and libmount
    /// undo differently, or a backslash that keeps systemd from splitting the
    /// options at the comma after it, or any backslash in the type.
    Escape(Field, String),
}

impl std::fmt::Display for Unlike {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unlike::OtherTable => write!(
                f,
                "begins as a line of a mount table or of the list of swaps does, and systemd \
                 from 259 on reads a file that begins with such a line as that table"
            ),
            Unlike::TooLong => write!(
                f,
                "is longer than the 4095 bytes of a line that systemd up to 258 reads"
            ),
            Unlike::NotText(field) => write!(f, "has a {} that is not UTF-8 text", field.name()),
            Unlike::Holds(field, '\0') => write!(
                f,
                "has a NUL in its {}, where systemd up to 258 ends the line",
                field.name()
            ),
            Unlike::Holds(field, c) => write!(
                f,
                "has U+{:04X} in its {}, which NAILS takes for a separator and systemd does not",
                u32::from(*c),
                field.name()
            ),
            Unlike::Escape(field, escape) => write!(
                f,
                "has `{escape}` in its {}, which systemd may read otherwise than NAILS",
                field.name()
            ),
        }
    }
}

/// The longest line glibc's `getmntent()` reads whole: it cuts a longer one
/// short.
const LONGEST_LINE: usize = 4095;

/// The lines of the fstab `text` that systemd's fstab generator reads as
/// entries, each as the file has it, without its newline, for
/// [`parse_in_root`](super::parse_in_root): neither a blank line, a comment
/// nor a line of one field is, which glibc gives no mount point and libmount
/// does not read. Or the first line, counted from 1, that the generator may
/// read otherwise than [`parse_fstab`](super::parse_fstab) does (see the
/// module docs), and why.
pub fn entry_lines(text: &[u8]) -> Result<Vec<&[u8]>, (usize, Unlike)> {
    let mut lines = Vec::new();
    for (index, line) in text.split(|byte| *byte == b'\n').enumerate() {
        let unlike = |why| Err((index + 1, why));
        if begins_other_table(line) {
            return unlike(Unlike::OtherTable);
        }
        let fields: Vec<&[u8]> = line
            .split(|byte| matches!(byte, b' ' | b'\t'))
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() < 2 || fields[0].starts_with(b"#") {
            continue;
        }
        if line.len() > LONGEST_LINE {
            return unlike(Unlike::TooLong);
        }
        for (bytes, field) in fields.into_iter().zip(Field::ALL) {
            if let Some(why) = read_otherwise(bytes, field) {
                return unlike(why);
            }
        }
        lines.push(line);
    }
    Ok(lines)
}

/// Whether libmount takes the fstab line `line`, as the first line it reads,
/// for one of a mount table or of `/proc/swaps`, and so reads the whole file
/// as that table (`guess_table_format()`): one that begins, after spaces and
/// tabs, with the header of `/proc/swaps`, or with two numbers as
/// `sscanf("%u %u")` reads them, each after any whitespace and with a sign
/// or none.
fn begins_other_table(line: &[u8]) -> bool {
    let line = skip(line, b" \t");
    if line.starts_with(b"Filename\t") {
        return true;
    }
    let mut rest = line;
    for _ in 0..2 {
        // C's isspace(), the vertical tab among them.
        rest = skip(rest, b" \t\n\x0b\x0c\r");
        rest = rest
            .strip_prefix(b"+")
            .or(rest.strip_prefix(b"-"))
            .unwrap_or(rest);
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits == 0 {
            return false;
        }
        rest = &rest[digits..];
    }
    true
}

/// `bytes` without the bytes of `set` it begins with.
fn skip<'a>(bytes: &'a [u8], set: &[u8]) -> &'a [u8] {
    let start = bytes
        .iter()
        .position(|byte| !set.contains(byte))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Why systemd may read `bytes`, the `field` of an fstab line, otherwise than
/// [`parse_fstab`](super::parse_fstab) does, if it may.
fn read_otherwise(bytes: &[u8], field: Field) -> Option<Unlike> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Some(Unlike::NotText(field));
    };
    if let Some(c) = text.chars().find(|c| c.is_whitespace() || *c == '\0') {
        return Some(Unlike::Holds(field, c));
    }
    let mut rest = bytes;
    while let Some(found) = rest.iter().position(|byte| *byte == b'\\') {
        rest = &rest[found..];
        if let Some(escape) = field.alike_escapes().iter().find(|e| rest.starts_with(e)) {
            rest = &rest[escape.len()..];
            continue;
        }
        // Three octal digits make an escape for libmount, which glibc leaves
        // as it is but for the ones above; a backslash before another undoes
        // it for glibc alone, and one before a comma keeps systemd from
        // splitting the options there. Any other backslash all three keep.
        let octal = rest.len() >= 4 && rest[1..4].iter().all(|digit| (b'0'..=b'7').contains(digit));
        let next = rest.get(1).copied();
        if octal
            || next == Some(b'\\')
            || (field == Field::Options && next == Some(b','))
            || field == Field::Type
        {
            let shown = if octal { 4 } else { rest.len().min(2) };
            return Some(Unlike::Escape(
                field,
                String::from_utf8_lossy(&rest[..shown]).into_owned(),
            ));
        }
        rest = &rest[1..];
    }
    None
}

#[cfg(test)]
#[path = "lines_tests.rs"]
mod tests;
