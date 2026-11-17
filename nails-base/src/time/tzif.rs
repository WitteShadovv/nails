// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a TZif file (RFC 8536) says beyond the offsets jiff reads from it.
//!
//! jiff reads a zone file's local time types, transitions and footer. Two
//! more things decide which offset NAILS shows, as they always have:
//!
//! - The leap-second table of a `right/` zone. Such a file counts its
//!   transitions in "leap time", Unix time plus the leap seconds so far, and
//!   jiff leaves the table out. An instant is compared with the transitions
//!   in leap time, so a change of offset falls on its Unix second rather than
//!   27 seconds after it.
//! - The footer's rule on its own, for a time after the last transition and
//!   outside the years jiff reaches (-9999 to 9999).
//!
//! A leap-second table must start at or after 1970 with a correction of one
//! second, step by one second at a time, and keep 28 days between its
//! entries; a file with any other table is no zone.
//!
//! The footer is taken as NAILS has always taken it before jiff reads the
//! file (see [`framed`]).

use std::borrow::Cow;

/// The parts of a TZif file read here.
#[derive(Debug, Clone, Default)]
pub(super) struct Extras {
    /// The leap-second table: (leap time, correction in seconds) in order.
    pub(super) leap_seconds: Vec<(i64, i32)>,
    /// The time of the last transition, in leap time.
    pub(super) last_transition: Option<i64>,
    /// The footer's POSIX TZ string, when it holds one.
    pub(super) footer: Option<String>,
}

impl Extras {
    /// Unix time `unix` in the leap time the file's transitions are counted
    /// in: plus the correction of the last leap second before it.
    pub(super) fn leap_time(&self, unix: i64) -> i64 {
        let mut leap = unix;
        for &(at, correction) in &self.leap_seconds {
            if leap < at {
                break;
            }
            leap = unix.saturating_add(i64::from(correction));
        }
        leap
    }
}

/// The header's counts, in the order RFC 8536 lists them.
struct Counts {
    ut_local: usize,
    std_wall: usize,
    leap: usize,
    transitions: usize,
    types: usize,
    chars: usize,
}

/// The TZif file `bytes` as jiff is given it.
///
/// A footer, all that follows the version 2 data block, that starts and ends
/// with a newline holds the rule between them with the blanks around it
/// trimmed, as NAILS has always read it: it is given to jiff as that rule on
/// a line of its own. So a footer that ends in `\r\n`, or is a single newline
/// (no rule), reads as it did, where jiff alone would refuse the file. A rule
/// that holds a newline, a footer that is not UTF-8 or does not start and end
/// with a newline, and a version 1 file are left as they stand, for jiff to
/// read or refuse.
pub(super) fn framed(bytes: &[u8]) -> Cow<'_, [u8]> {
    let Some(start) = footer_start(bytes) else {
        return Cow::Borrowed(bytes);
    };
    let Ok(footer) = std::str::from_utf8(&bytes[start..]) else {
        return Cow::Borrowed(bytes);
    };
    if !(footer.starts_with('\n') && footer.ends_with('\n')) {
        return Cow::Borrowed(bytes);
    }
    let rule = footer.trim_matches(|c: char| c.is_ascii_whitespace());
    if rule.contains('\n') {
        return Cow::Borrowed(bytes);
    }
    let mut out = Vec::with_capacity(start + rule.len() + 2);
    out.extend_from_slice(&bytes[..start]);
    out.push(b'\n');
    out.extend_from_slice(rule.as_bytes());
    out.push(b'\n');
    Cow::Owned(out)
}

/// Where the footer of a version 2 or later TZif file starts: after the
/// version 1 data block, the second header and the 64-bit data block. `None`
/// for a version 1 file, or one too short to hold those.
fn footer_start(bytes: &[u8]) -> Option<usize> {
    let (version, counts, _) = header(bytes)?;
    if version == 0 {
        return None;
    }
    let second = block_len(&counts, 4)?.checked_add(44)?;
    let (_, counts, _) = header(bytes.get(second..)?)?;
    let start = block_len(&counts, 8)?
        .checked_add(second)?
        .checked_add(44)?;
    (start <= bytes.len()).then_some(start)
}

/// Read the extras of the TZif file `bytes`, or `None` when they are not
/// there to read or the leap-second table is no valid one.
pub(super) fn read(bytes: &[u8]) -> Option<Extras> {
    let (version, counts, rest) = header(bytes)?;
    if version == 0 {
        // Version 1: 32-bit times and no footer.
        return extras(&counts, rest, 4, None);
    }
    // Version 2 and later: skip the version 1 block for the 64-bit one.
    let rest = rest.get(block_len(&counts, 4)?..)?;
    let (_, counts, rest) = header(rest)?;
    let len = block_len(&counts, 8)?;
    let footer = std::str::from_utf8(rest.get(len..)?).ok()?;
    let footer = footer.trim_matches(|c: char| c.is_ascii_whitespace());
    let footer = (!footer.is_empty()).then(|| footer.to_string());
    extras(&counts, rest, 8, footer)
}

/// The version byte (0 for version 1), the counts and the bytes after the
/// 44-byte header.
fn header(bytes: &[u8]) -> Option<(u8, Counts, &[u8])> {
    let head = bytes.get(..44)?;
    if &head[..4] != b"TZif" {
        return None;
    }
    let count = |at: usize| -> Option<usize> {
        let field: [u8; 4] = head.get(at..at + 4)?.try_into().ok()?;
        usize::try_from(u32::from_be_bytes(field)).ok()
    };
    let counts = Counts {
        ut_local: count(20)?,
        std_wall: count(24)?,
        leap: count(28)?,
        transitions: count(32)?,
        types: count(36)?,
        chars: count(40)?,
    };
    Some((head[4], counts, &bytes[44..]))
}

/// The length of a data block whose times take `time_size` bytes.
fn block_len(counts: &Counts, time_size: usize) -> Option<usize> {
    let transitions = counts.transitions.checked_mul(time_size + 1)?;
    let types = counts.types.checked_mul(6)?;
    let leap = counts.leap.checked_mul(time_size + 4)?;
    transitions
        .checked_add(types)?
        .checked_add(counts.chars)?
        .checked_add(leap)?
        .checked_add(counts.std_wall)?
        .checked_add(counts.ut_local)
}

fn extras(
    counts: &Counts,
    block: &[u8],
    time_size: usize,
    footer: Option<String>,
) -> Option<Extras> {
    // Every offset below is within the block's length, which does not
    // overflow.
    let block = block.get(..block_len(counts, time_size)?)?;
    let time = |bytes: &[u8]| -> Option<i64> {
        Some(match time_size {
            4 => i64::from(i32::from_be_bytes(bytes.try_into().ok()?)),
            _ => i64::from_be_bytes(bytes.try_into().ok()?),
        })
    };
    let last_transition = match counts.transitions.checked_sub(1) {
        Some(last) => Some(time(
            block.get(last * time_size..counts.transitions * time_size)?,
        )?),
        None => None,
    };
    let start = counts.transitions * (time_size + 1) + counts.types * 6 + counts.chars;
    let table = block.get(start..start + counts.leap * (time_size + 4))?;
    let leap_seconds = table
        .chunks_exact(time_size + 4)
        .map(|record| {
            let (at, correction) = record.split_at(time_size);
            Some((time(at)?, i32::from_be_bytes(correction.try_into().ok()?)))
        })
        .collect::<Option<Vec<_>>>()?;
    valid_leap_seconds(&leap_seconds).then_some(Extras {
        leap_seconds,
        last_transition,
        footer,
    })
}

/// Whether a leap-second table starts at or after 1970 with a correction of
/// one second, and steps by one second at least 28 days apart.
fn valid_leap_seconds(table: &[(i64, i32)]) -> bool {
    const MIN_INTERVAL: i64 = 28 * 86_400 - 1;
    let starts = table
        .first()
        .is_none_or(|&(at, correction)| at >= 0 && correction.saturating_abs() == 1);
    starts
        && table.windows(2).all(|pair| {
            let ((at0, correction0), (at1, correction1)) = (pair[0], pair[1]);
            at1.saturating_sub(at0) >= MIN_INTERVAL
                && correction1.saturating_sub(correction0).saturating_abs() == 1
        })
}
