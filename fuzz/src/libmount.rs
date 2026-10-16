// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How libmount reads one line of `/run/mount/utab`: `mnt_table_parse_next`
//! and `mnt_parse_utab_line` (libmount/src/tab_parse.c) with `next_s32`,
//! `next_u64` and `unmangle` (lib/mangle.c), as in util-linux 2.39 to 2.42.
//!
//! One deliberate difference, documented by NAILS: an `ID=` beyond `int`
//! skips the line here, where libmount would cut it short to another number.

/// The fields of a utab line, values decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UtabLine {
    /// The mount ID; 0 for none.
    pub id: i32,
    pub source: Option<String>,
    pub target: Option<String>,
    pub root: Option<String>,
}

/// Whether libmount can have written `line`. Its `mangle()` writes a space, a
/// tab, a newline and the backslash as three-digit octal escapes and every
/// other byte as it is, so a backslash in a line it wrote always starts one
/// of those escapes. A line with any other backslash comes from no libmount,
/// and the two decoders need not agree on it. This takes the escape of any
/// byte up to a space, of DEL and of the backslash for one: a superset of
/// what `mangle()` writes, which only compares the decoders on more lines.
pub fn producible(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'\\' {
            at += 1;
            continue;
        }
        let escape = bytes.get(at + 1..at + 4);
        let value = escape.and_then(|digits| {
            digits
                .iter()
                .all(|digit| (b'0'..=b'7').contains(digit))
                .then(|| digits.iter().fold(0u32, |v, d| v * 8 + u32::from(d - b'0')))
        });
        if !value.is_some_and(|v| (1..=0x20).contains(&v) || v == 0x5c || v == 0x7f) {
            return false;
        }
        at += 4;
    }
    true
}

/// A number field as `next_s32` and `next_u64` read it with `strtol` and
/// `strtoumax`.
enum Number {
    /// The value is empty at the end of the line: no number, and libmount
    /// reads on.
    AtEnd,
    /// libmount gives up on the line.
    Bad,
    /// A negative sign, the magnitude and where the number ends.
    Read(bool, u128, usize),
}

fn number(s: &[u8], start: usize) -> Number {
    if start >= s.len() {
        return Number::AtEnd;
    }
    let mut at = start;
    while s
        .get(at)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
    {
        at += 1;
    }
    let negative = s.get(at) == Some(&b'-');
    if matches!(s.get(at), Some(b'+' | b'-')) {
        at += 1;
    }
    let digits = s[at..].iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return Number::Bad;
    }
    let end = at + digits;
    // Wider than both `long` and `uintmax_t`, so an overflow of either is
    // still seen below; longer runs of digits overflow both anyway.
    let Ok(magnitude) = std::str::from_utf8(&s[at..end])
        .unwrap_or("x")
        .parse::<u128>()
    else {
        return Number::Bad;
    };
    if !matches!(s.get(end), None | Some(b' ' | b'\t')) {
        return Number::Bad;
    }
    Number::Read(negative, magnitude, end)
}

/// `unmangle()`: the value from `start` to the next space or tab, octal
/// escapes decoded; `None` for an empty value, which libmount takes for an
/// allocation failure and so skips the line.
fn unmangle(s: &[u8], start: usize) -> Option<(String, usize)> {
    let len = s[start..]
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(s.len() - start);
    if len == 0 {
        return None;
    }
    let raw = &s[start..start + len];
    let mut out = Vec::with_capacity(len);
    let mut at = 0;
    while at < raw.len() {
        // Three octal digits must follow within the value.
        let octal = |i: usize| raw.get(i).is_some_and(|b| (b'0'..=b'7').contains(b));
        if raw[at] == b'\\' && octal(at + 1) && octal(at + 2) && octal(at + 3) {
            let value = 64 * u32::from(raw[at + 1] & 7)
                + 8 * u32::from(raw[at + 2] & 7)
                + u32::from(raw[at + 3] & 7);
            out.push((value & 0xff) as u8);
            at += 4;
        } else {
            out.push(raw[at]);
            at += 1;
        }
    }
    Some((String::from_utf8_lossy(&out).into_owned(), start + len))
}

/// The line as libmount reads it, or `None` for one it skips: a blank line,
/// a comment, or a line `mnt_parse_utab_line` fails on.
pub fn parse_utab_line(line: &str) -> Option<UtabLine> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let first = line.bytes().position(|b| b != b' ' && b != b'\t')?;
    let s = &line.as_bytes()[first..];
    if s[0] == b'#' {
        return None;
    }
    let mut fields = UtabLine::default();
    let (mut uniq_id, mut bindsrc, mut options, mut attrs) = (false, false, false, false);
    let mut p = 0;
    loop {
        while s.get(p) == Some(&b' ') {
            p += 1;
        }
        if p >= s.len() {
            return Some(fields);
        }
        let rest = &s[p..];
        let string = |key: &[u8], set: bool| !set && rest.starts_with(key);
        if !uniq_id && rest.starts_with(b"UNIQID=") {
            match number(s, p + 7) {
                Number::AtEnd => p = s.len(),
                Number::Bad => return None,
                Number::Read(_, magnitude, end) => {
                    // strtoumax: beyond 64 bits is ERANGE.
                    u64::try_from(magnitude).ok()?;
                    uniq_id = magnitude != 0;
                    p = end;
                }
            }
        } else if fields.id == 0 && rest.starts_with(b"ID=") {
            match number(s, p + 3) {
                Number::AtEnd => p = s.len(),
                Number::Bad => return None,
                Number::Read(negative, magnitude, end) => {
                    let magnitude = i64::try_from(magnitude).ok()?;
                    fields.id =
                        i32::try_from(if negative { -magnitude } else { magnitude }).ok()?;
                    p = end;
                }
            }
        } else if string(b"SRC=", fields.source.is_some()) {
            let (value, end) = unmangle(s, p + 4)?;
            (fields.source, p) = (Some(value), end);
        } else if string(b"TARGET=", fields.target.is_some()) {
            let (value, end) = unmangle(s, p + 7)?;
            (fields.target, p) = (Some(value), end);
        } else if string(b"ROOT=", fields.root.is_some()) {
            let (value, end) = unmangle(s, p + 5)?;
            (fields.root, p) = (Some(value), end);
        } else if string(b"BINDSRC=", bindsrc) {
            (bindsrc, p) = (true, unmangle(s, p + 8)?.1);
        } else if string(b"OPTS=", options) {
            (options, p) = (true, unmangle(s, p + 5)?.1);
        } else if string(b"ATTRS=", attrs) {
            (attrs, p) = (true, unmangle(s, p + 6)?.1);
        } else {
            // An unknown field: skipped to the next space.
            p += rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
        }
    }
}
