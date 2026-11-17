// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading an RFC 3339 date and time.
//!
//! The grammar is RFC 3339's `date-time` with a four-digit year, read as
//! NAILS has always read the state file's fields and the log's lines:
//!
//! - the date and the time may be split by `T`, `t` or a space;
//! - the seconds may carry a fraction of any length, of which nine digits are
//!   kept and the rest dropped, never rounded;
//! - the offset is `Z`, `z` or a sign (`+`, `-` or U+2212) with `HH:MM`, both
//!   parts required, of less than 24 hours;
//! - nothing may come before or after.
//!
//! A leap second (`:60`) is refused: no clock NAILS reads gives one, so it
//! only stands in a file NAILS did not write.

use super::civil::{DAY, days_from_civil};

/// Why a text is no RFC 3339 date and time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// It ends before the date, the time or the offset is complete.
    TooShort,
    /// A character stands where the grammar has no place for it.
    Invalid,
    /// A field is outside its range: a day the month does not have, an hour
    /// of 24, a minute or second of 60 or more, an offset of a day or more.
    OutOfRange,
    /// Something follows the offset.
    TrailingInput,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooShort => "premature end of input",
            Self::Invalid => "input contains invalid characters",
            Self::OutOfRange => "input is out of range",
            Self::TrailingInput => "trailing input",
        })
    }
}

impl std::error::Error for ParseError {}

/// The Unix seconds and nanoseconds `text` names.
pub(super) fn parse(text: &str) -> Result<(i64, u32), ParseError> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return Err(ParseError::TooShort);
    }
    let number = |at: usize, len: usize| -> Result<u32, ParseError> {
        bytes[at..at + len].iter().try_fold(0u32, |value, &b| {
            if b.is_ascii_digit() {
                Ok(value * 10 + u32::from(b - b'0'))
            } else {
                Err(ParseError::Invalid)
            }
        })
    };
    let expect = |at: usize, wanted: &[u8]| {
        if wanted.contains(&bytes[at]) {
            Ok(())
        } else {
            Err(ParseError::Invalid)
        }
    };
    let year = number(0, 4)?;
    expect(4, b"-")?;
    let month = number(5, 2)?;
    expect(7, b"-")?;
    let day = number(8, 2)?;
    expect(10, b"Tt ")?;
    let hour = number(11, 2)?;
    expect(13, b":")?;
    let minute = number(14, 2)?;
    expect(16, b":")?;
    let second = number(17, 2)?;

    let days = days_from_civil(i64::from(year), month, day).ok_or(ParseError::OutOfRange)?;
    if hour >= 24 || minute >= 60 || second >= 60 {
        return Err(ParseError::OutOfRange);
    }

    let mut rest = &text[19..];
    let mut nanos = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(ParseError::Invalid);
        }
        for (place, b) in fraction
            .bytes()
            .take(9)
            .take_while(u8::is_ascii_digit)
            .enumerate()
        {
            nanos += u32::from(b - b'0') * 10u32.pow(8 - place as u32);
        }
        rest = &fraction[digits..];
    }

    let (offset, rest) = offset(rest)?;
    if !rest.is_empty() {
        return Err(ParseError::TrailingInput);
    }

    let local = days * DAY + i64::from(hour * 3600 + minute * 60 + second);
    Ok((local - i64::from(offset), nanos))
}

/// The offset at the start of `text` in seconds, and what follows it.
fn offset(text: &str) -> Result<(i32, &str), ParseError> {
    if let Some(rest) = text.strip_prefix(['Z', 'z']) {
        return Ok((0, rest));
    }
    let (negative, rest) = if let Some(rest) = text.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = text.strip_prefix(['-', '\u{2212}']) {
        (true, rest)
    } else if text.is_empty() {
        return Err(ParseError::TooShort);
    } else {
        return Err(ParseError::Invalid);
    };
    let bytes = rest.as_bytes();
    if bytes.len() < 2 {
        return Err(ParseError::TooShort);
    }
    let digit = |b: u8| {
        if b.is_ascii_digit() {
            Ok(i32::from(b - b'0'))
        } else {
            Err(ParseError::Invalid)
        }
    };
    let hours = digit(bytes[0])? * 10 + digit(bytes[1])?;
    match bytes.get(2) {
        Some(b':') => {}
        Some(_) => return Err(ParseError::Invalid),
        None => return Err(ParseError::TooShort),
    }
    if bytes.len() < 5 {
        return Err(ParseError::TooShort);
    }
    let minutes = match (bytes[3], bytes[4]) {
        (tens @ b'0'..=b'5', ones) => digit(tens)? * 10 + digit(ones)?,
        (b'6'..=b'9', ones) if ones.is_ascii_digit() => return Err(ParseError::OutOfRange),
        _ => return Err(ParseError::Invalid),
    };
    let seconds = hours * 3600 + minutes * 60;
    if seconds >= DAY as i32 {
        return Err(ParseError::OutOfRange);
    }
    Ok((if negative { -seconds } else { seconds }, &rest[5..]))
}
