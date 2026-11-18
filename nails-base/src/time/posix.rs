// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which POSIX TZ strings `TZ` may hold.
//!
//! NAILS takes a `TZ` rule in the POSIX form without the extensions RFC 8536
//! allows only in a zone file's footer: the names three to seven characters
//! long, an offset of less than 24 hours, and a change at an hour from 0 to 24
//! without a sign. A rule outside that is no zone of its own, and the local
//! zone is then looked for as for a `TZ` that names nothing (see
//! [`super::zone`]). The rule's meaning is read by jiff once this check passes.
//!
//! A zone file's footer is read by jiff, extensions and all, but an offset of
//! 24 hours or more is refused there as in `TZ`: a zone file whose footer
//! gives one is no zone (see [`offset_of_a_day`]).

/// Whether `rule` is a POSIX TZ string `TZ` may hold.
pub(super) fn accepted(rule: &str) -> bool {
    let mut cursor = Cursor(rule.as_bytes());
    accepted_from(&mut cursor).is_some()
}

fn accepted_from(cursor: &mut Cursor<'_>) -> Option<()> {
    name(cursor)?;
    offset(cursor)?;
    if cursor.is_empty() {
        return Some(());
    }
    name(cursor)?;
    match cursor.peek()? {
        b',' => {}
        _ => offset(cursor)?,
    }
    cursor.tag(b",")?;
    rule_day(cursor)?;
    cursor.tag(b",")?;
    rule_day(cursor)?;
    cursor.is_empty().then_some(())
}

/// Whether the footer rule `rule` of a zone file gives its standard offset,
/// or its daylight saving offset where it names one, an hour of 24 or more.
/// jiff reads an offset of 24 hours there, which POSIX allows, but NAILS has
/// never taken one. Only the names and offsets at the start of the rule are
/// looked at: jiff has read the rule already.
pub(super) fn offset_of_a_day(rule: &str) -> bool {
    let mut cursor = Cursor(rule.as_bytes());
    offsets_of_a_day(&mut cursor).unwrap_or(false)
}

/// The same, `None` where an offset is not there to read: after the
/// standard offset, a daylight saving name with no offset is followed by `,`
/// or nothing.
fn offsets_of_a_day(cursor: &mut Cursor<'_>) -> Option<bool> {
    letters(cursor)?;
    if signed_hhmmss(cursor)?.0 > 23 {
        return Some(true);
    }
    letters(cursor)?;
    Some(signed_hhmmss(cursor)?.0 > 23)
}

/// A zone name: letters, or `<…>` around letters, digits, `+` and `-`; three
/// to seven of them.
fn name(cursor: &mut Cursor<'_>) -> Option<()> {
    let name = letters(cursor)?;
    let allowed = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-');
    ((3..=7).contains(&name.len()) && name.iter().all(allowed)).then_some(())
}

/// The characters of a zone name: letters, or what `<…>` holds.
fn letters<'a>(cursor: &mut Cursor<'a>) -> Option<&'a [u8]> {
    if cursor.peek() == Some(b'<') {
        cursor.take(1)?;
        let name = cursor.take_while(|b| b != b'>');
        cursor.tag(b">")?;
        Some(name)
    } else {
        Some(cursor.take_while(|b| b.is_ascii_alphabetic()))
    }
}

/// An offset: an optional sign, then hours below 24, optional minutes and
/// seconds below 60.
fn offset(cursor: &mut Cursor<'_>) -> Option<()> {
    let (hours, minutes, seconds) = signed_hhmmss(cursor)?;
    (hours <= 23 && minutes <= 59 && seconds <= 59).then_some(())
}

/// An optional sign, then `hh[:mm[:ss]]`.
fn signed_hhmmss(cursor: &mut Cursor<'_>) -> Option<(i32, i32, i32)> {
    if matches!(cursor.peek(), Some(b'+' | b'-')) {
        cursor.take(1)?;
    }
    hhmmss(cursor)
}

/// The day of a change (`Mm.w.d`, `Jn` or `n`), with an optional `/time` at
/// an hour from 0 to 24.
fn rule_day(cursor: &mut Cursor<'_>) -> Option<()> {
    let day_ok = match cursor.peek()? {
        b'M' => {
            cursor.take(1)?;
            let month = cursor.int::<u8>()?;
            cursor.tag(b".")?;
            let week = cursor.int::<u8>()?;
            cursor.tag(b".")?;
            let weekday = cursor.int::<u8>()?;
            (1..=12).contains(&month) && (1..=5).contains(&week) && weekday <= 6
        }
        b'J' => {
            cursor.take(1)?;
            (1..=365).contains(&cursor.int::<u16>()?)
        }
        _ => cursor.int::<u16>()? <= 365,
    };
    if !day_ok {
        return None;
    }
    if cursor.peek() == Some(b'/') {
        cursor.take(1)?;
        let (hours, minutes, seconds) = hhmmss(cursor)?;
        if !(hours <= 24 && minutes <= 59 && seconds <= 59) {
            return None;
        }
    }
    Some(())
}

/// `hh[:mm[:ss]]`, each an unsigned decimal number.
fn hhmmss(cursor: &mut Cursor<'_>) -> Option<(i32, i32, i32)> {
    let hours = cursor.int::<i32>()?;
    let mut minutes = 0;
    let mut seconds = 0;
    if cursor.peek() == Some(b':') {
        cursor.take(1)?;
        minutes = cursor.int::<i32>()?;
        if cursor.peek() == Some(b':') {
            cursor.take(1)?;
            seconds = cursor.int::<i32>()?;
        }
    }
    Some((hours, minutes, seconds))
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn take_while(&mut self, keep: impl Fn(u8) -> bool) -> &'a [u8] {
        let n = self
            .0
            .iter()
            .position(|&b| !keep(b))
            .unwrap_or(self.0.len());
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }

    fn tag(&mut self, tag: &[u8]) -> Option<()> {
        (self.take(tag.len())? == tag).then_some(())
    }

    /// A decimal number of one or more digits that fits `T`.
    fn int<T: std::str::FromStr>(&mut self) -> Option<T> {
        let digits = self.take_while(|b| b.is_ascii_digit());
        std::str::from_utf8(digits).ok()?.parse().ok()
    }
}
