// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unix seconds to and from the proleptic Gregorian calendar, and the text
//! forms NAILS writes a date and a time of day in.
//!
//! The conversions are exact for every `i64` day count (Howard Hinnant's
//! `days_from_civil` and `civil_from_days`), so a date far outside the range
//! [`Timestamp`](super::Timestamp) keeps is still written right, as a local
//! time just past its last day is.

use std::fmt::Write as _;

/// Seconds in a day.
pub(super) const DAY: i64 = 86_400;

/// A calendar date and a time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Civil {
    /// The date and time of day `secs` seconds after 1970-01-01T00:00:00.
    pub fn from_unix(secs: i64) -> Self {
        let days = secs.div_euclid(DAY);
        let of_day = secs.rem_euclid(DAY);
        let (year, month, day) = civil_from_days(days);
        // `of_day` is below 86 400, so each part fits a `u32`.
        let of_day = of_day as u32;
        Self {
            year,
            month,
            day,
            hour: of_day / 3600,
            minute: of_day / 60 % 60,
            second: of_day % 60,
        }
    }

    /// `YYYY-MM-DD`: four digits for the years 0 to 9999, and a sign with at
    /// least four digits for any other.
    pub fn write_date(&self, out: &mut String) {
        if (0..=9999).contains(&self.year) {
            let _ = write!(out, "{:04}", self.year);
        } else {
            let _ = write!(out, "{:+05}", self.year);
        }
        let _ = write!(out, "-{:02}-{:02}", self.month, self.day);
    }

    /// `HH:MM:SS`.
    pub fn write_time(&self, out: &mut String) {
        let _ = write!(
            out,
            "{:02}:{:02}:{:02}",
            self.hour, self.minute, self.second
        );
    }
}

/// A fraction of a second as `.` and 3, 6 or 9 digits, the fewest that hold
/// it, or nothing for none.
pub(super) fn write_fraction(out: &mut String, nanos: u32) {
    let _ = match nanos {
        0 => Ok(()),
        n if n % 1_000_000 == 0 => write!(out, ".{:03}", n / 1_000_000),
        n if n % 1_000 == 0 => write!(out, ".{:06}", n / 1_000),
        n => write!(out, ".{n:09}"),
    };
}

/// An offset from UTC in seconds as `+HH:MM`, rounded to the nearest minute
/// (half a minute up). A negative offset keeps its sign when it rounds to
/// zero minutes.
pub(super) fn write_offset(out: &mut String, offset: i32) {
    let sign = if offset < 0 { '-' } else { '+' };
    let minutes = (offset.unsigned_abs() + 30) / 60;
    let _ = write!(out, "{sign}{:02}:{:02}", minutes / 60, minutes % 60);
}

/// The days since 1970-01-01 of a proleptic Gregorian date, or `None` when the
/// date does not exist.
pub(super) fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// The proleptic Gregorian date `days` days after 1970-01-01.
pub(super) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01, so a leap day ends its year.
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    // Both stay small: a day of the month and a month, so the casts are exact.
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
