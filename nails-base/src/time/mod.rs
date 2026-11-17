// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Instants as NAILS keeps, writes and shows them.
//!
//! A [`Timestamp`] is an instant in UTC to the nanosecond. Its text forms are
//! the ones NAILS has always written, byte for byte:
//!
//! - the state file's fields (serde) and [`Timestamp::to_rfc3339_z`]: RFC 3339
//!   in UTC with `Z`, the seconds' fraction cut to the fewest of 0, 3, 6 or 9
//!   digits that hold it, `2026-10-23T18:36:54.578963021Z`;
//! - [`Timestamp::to_rfc3339`]: the same with `+00:00` in place of `Z`, as the
//!   JSON report and the alerts carry it;
//! - [`Timestamp::to_utc_seconds`] and [`utc_seconds`]: to the second with `Z`,
//!   `2026-10-23T18:36:54Z`;
//! - [`Zone::stamp`] and [`Zone::clock`]: the time `status` shows in the local
//!   zone, `2026-10-23 20:36:54 +02:00` and `20:36:54`.
//!
//! A year from 0 to 9999 is written with four digits; any other with its sign
//! and at least four digits (`+10000`, `-0001`). A timestamp covers the years
//! -262143 to 262142, and a time outside them is no timestamp: reading one
//! fails rather than lands on another day.
//!
//! The calendar arithmetic and the RFC 3339 reading are NAILS's own, small
//! enough to check by hand and pinned by tests; the time zone rules (TZif files
//! and POSIX TZ strings) are read with jiff, which reads no file itself, and a
//! zone file's leap seconds and footer rule here (see [`tzif`]).

mod civil;
mod posix;
mod rfc3339;
mod tzif;
mod zone;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod zone_tests;

use std::time::{SystemTime, UNIX_EPOCH};

use civil::{Civil, write_fraction};
pub use jiff::SignedDuration;
pub use rfc3339::ParseError;
pub use zone::Zone;

/// An instant in UTC, to the nanosecond, in the years -262143 to 262142.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Whole seconds since 1970-01-01T00:00:00Z, rounded down.
    secs: i64,
    /// Nanoseconds past `secs`, below one second.
    nanos: u32,
}

impl Timestamp {
    /// The first instant: -262143-01-01T00:00:00Z.
    pub const MIN: Self = Self {
        secs: -8_334_601_228_800,
        nanos: 0,
    };

    /// The last instant: +262142-12-31T23:59:59.999999999Z.
    pub const MAX: Self = Self {
        secs: 8_210_266_876_799,
        nanos: 999_999_999,
    };

    /// The instant `secs` seconds and `nanos` nanoseconds after 1970-01-01T00:00:00Z,
    /// or `None` outside the years a timestamp covers or for a `nanos` of a
    /// second or more.
    pub fn from_unix(secs: i64, nanos: u32) -> Option<Self> {
        let instant = Self { secs, nanos };
        (nanos < 1_000_000_000 && (Self::MIN..=Self::MAX).contains(&instant)).then_some(instant)
    }

    /// The instant `secs` whole seconds after 1970-01-01T00:00:00Z, or `None`
    /// outside the years a timestamp covers.
    pub fn from_unix_seconds(secs: i64) -> Option<Self> {
        Self::from_unix(secs, 0)
    }

    /// The instant of a system time, or `None` outside the years a timestamp
    /// covers.
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => {
                Self::from_unix(i64::try_from(after.as_secs()).ok()?, after.subsec_nanos())
            }
            Err(before) => {
                let before = before.duration();
                let secs = i64::try_from(before.as_secs()).ok()?;
                match before.subsec_nanos() {
                    0 => Self::from_unix(secs.checked_neg()?, 0),
                    nanos => {
                        Self::from_unix(secs.checked_neg()?.checked_sub(1)?, 1_000_000_000 - nanos)
                    }
                }
            }
        }
    }

    /// Now, by the system clock.
    ///
    /// Linux keeps its clock between 1970 and 2262, inside the years a
    /// timestamp covers; a clock outside them is taken as the nearest end of
    /// that range, and a warning says so, rather than stopping the program.
    pub fn now() -> Self {
        let now = SystemTime::now();
        Self::from_system_time(now).unwrap_or_else(|| {
            let ahead = now >= UNIX_EPOCH;
            tracing::warn!(
                ahead,
                "the system clock is outside the years -262143 to 262142; the time is taken as \
                 the nearest end of that range"
            );
            if ahead { Self::MAX } else { Self::MIN }
        })
    }

    /// The whole seconds since 1970-01-01T00:00:00Z, rounded down.
    pub fn unix_seconds(self) -> i64 {
        self.secs
    }

    /// The nanoseconds past [`unix_seconds`](Self::unix_seconds).
    pub fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    /// The time from `earlier` to this instant, negative when `earlier` is
    /// later.
    pub fn duration_since(self, earlier: Self) -> SignedDuration {
        // Both are within the range, so neither difference overflows, and the
        // nanoseconds stay below a second either way.
        let secs = self.secs - earlier.secs;
        let nanos = i64::from(self.nanos) - i64::from(earlier.nanos);
        SignedDuration::new(secs, nanos as i32)
    }

    /// Read an RFC 3339 date and time with a four-digit year (see
    /// [`ParseError`] for what is refused).
    pub fn parse_rfc3339(text: &str) -> Result<Self, ParseError> {
        let (secs, nanos) = rfc3339::parse(text)?;
        // A four-digit year with an offset below a day is always in range.
        Self::from_unix(secs, nanos).ok_or(ParseError::OutOfRange)
    }

    /// RFC 3339 in UTC with `Z`, as the state file keeps a time:
    /// `2026-10-23T18:36:54.578963021Z`.
    pub fn to_rfc3339_z(self) -> String {
        self.rfc3339("Z")
    }

    /// RFC 3339 in UTC with `+00:00`: `2026-10-23T18:36:54.578963021+00:00`.
    pub fn to_rfc3339(self) -> String {
        self.rfc3339("+00:00")
    }

    /// RFC 3339 in UTC to the second with `Z`: `2026-10-23T18:36:54Z`.
    pub fn to_utc_seconds(self) -> String {
        let mut out = String::with_capacity(20);
        let civil = Civil::from_unix(self.secs);
        civil.write_date(&mut out);
        out.push('T');
        civil.write_time(&mut out);
        out.push('Z');
        out
    }

    fn rfc3339(self, utc: &str) -> String {
        let mut out = String::with_capacity(35);
        let civil = Civil::from_unix(self.secs);
        civil.write_date(&mut out);
        out.push('T');
        civil.write_time(&mut out);
        write_fraction(&mut out, self.nanos);
        out.push_str(utc);
        out
    }
}

/// `secs` seconds after 1970-01-01T00:00:00Z in UTC to the second with `Z`,
/// or `None` outside the years a timestamp covers.
pub fn utc_seconds(secs: i64) -> Option<String> {
    Timestamp::from_unix_seconds(secs).map(Timestamp::to_utc_seconds)
}

impl std::fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_rfc3339_z())
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339_z())
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Timestamp;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an RFC 3339 date and time")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Timestamp, E> {
                Timestamp::parse_rfc3339(text).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}
