// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Timestamps: the calendar, the text forms and the RFC 3339 reading.

use super::civil::{Civil, civil_from_days, days_from_civil};
use super::*;
use std::time::Duration;

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::from_unix(secs, nanos).unwrap()
}

#[test]
fn the_calendar_agrees_with_jiff_day_by_day_over_its_years() {
    // jiff covers the years -9999 to 9999: step through them a prime number of
    // days at a time, and check each end.
    let first = days_from_civil(-9999, 1, 1).unwrap();
    let last = days_from_civil(9999, 12, 31).unwrap();
    let mut days = first;
    while days <= last {
        let (year, month, day) = civil_from_days(days);
        let date = jiff::civil::date(year as i16, month as i8, day as i8);
        let epoch = jiff::civil::date(1970, 1, 1);
        assert_eq!(
            i64::from((date - epoch).get_days()),
            days,
            "{year}-{month}-{day}"
        );
        assert_eq!(days_from_civil(year, month, day), Some(days));
        days += 997;
    }
    assert_eq!(civil_from_days(first), (-9999, 1, 1));
    assert_eq!(civil_from_days(last), (9999, 12, 31));
}

#[test]
fn the_calendar_knows_leap_years_and_month_lengths() {
    assert!(days_from_civil(2024, 2, 29).is_some());
    assert!(days_from_civil(2000, 2, 29).is_some());
    assert!(days_from_civil(1900, 2, 29).is_none());
    assert!(days_from_civil(2023, 2, 29).is_none());
    assert!(days_from_civil(2026, 4, 31).is_none());
    assert!(days_from_civil(2026, 0, 1).is_none());
    assert!(days_from_civil(2026, 13, 1).is_none());
    assert!(days_from_civil(2026, 1, 0).is_none());
    assert_eq!(days_from_civil(1970, 1, 1), Some(0));
    assert_eq!(days_from_civil(1969, 12, 31), Some(-1));
    assert_eq!(days_from_civil(0, 3, 1), Some(-719_468));
}

#[test]
fn the_calendar_holds_at_the_ends_of_i64_seconds() {
    for secs in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
        let civil = Civil::from_unix(secs);
        let days = days_from_civil(civil.year, civil.month, civil.day).unwrap();
        let back = i128::from(days) * 86_400
            + i128::from(civil.hour * 3600 + civil.minute * 60 + civil.second);
        assert_eq!(back, i128::from(secs), "{secs}");
    }
}

#[test]
fn a_timestamp_is_written_with_zero_three_six_or_nine_fraction_digits() {
    let cases = [
        (at(0, 0), "1970-01-01T00:00:00Z"),
        (at(0, 1), "1970-01-01T00:00:00.000000001Z"),
        (at(0, 1_000), "1970-01-01T00:00:00.000001Z"),
        (at(0, 1_000_000), "1970-01-01T00:00:00.001Z"),
        (at(0, 120_000_000), "1970-01-01T00:00:00.120Z"),
        (at(0, 123_456_000), "1970-01-01T00:00:00.123456Z"),
        (at(-1, 500_000_000), "1969-12-31T23:59:59.500Z"),
        (
            at(1_700_000_000, 123_456_789),
            "2023-11-14T22:13:20.123456789Z",
        ),
    ];
    for (instant, z) in cases {
        assert_eq!(instant.to_rfc3339_z(), z);
        assert_eq!(format!("{instant:?}"), z);
        assert_eq!(serde_json::to_string(&instant).unwrap(), format!("\"{z}\""));
        assert_eq!(
            instant.to_rfc3339(),
            z.replace('Z', "+00:00"),
            "the +00:00 form"
        );
    }
}

#[test]
fn a_year_outside_four_digits_is_written_with_its_sign() {
    let cases = [
        (253_402_300_799, "9999-12-31T23:59:59Z"),
        (253_402_300_800, "+10000-01-01T00:00:00Z"),
        (-62_167_219_200, "0000-01-01T00:00:00Z"),
        (-62_167_219_201, "-0001-12-31T23:59:59Z"),
        (Timestamp::MAX.unix_seconds(), "+262142-12-31T23:59:59Z"),
        (Timestamp::MIN.unix_seconds(), "-262143-01-01T00:00:00Z"),
    ];
    for (secs, text) in cases {
        assert_eq!(utc_seconds(secs).as_deref(), Some(text));
        assert_eq!(at(secs, 0).to_rfc3339_z(), text);
    }
    assert_eq!(
        Timestamp::MAX.to_rfc3339(),
        "+262142-12-31T23:59:59.999999999+00:00"
    );
}

#[test]
fn a_time_outside_the_years_is_no_timestamp() {
    for secs in [
        Timestamp::MAX.unix_seconds() + 1,
        Timestamp::MIN.unix_seconds() - 1,
        i64::MAX,
        i64::MIN,
    ] {
        assert_eq!(Timestamp::from_unix_seconds(secs), None, "{secs}");
        assert_eq!(utc_seconds(secs), None, "{secs}");
    }
    assert_eq!(Timestamp::from_unix(0, 1_000_000_000), None);
    assert!(Timestamp::from_unix(0, 999_999_999).is_some());
}

#[test]
fn a_system_time_before_1970_counts_down_to_the_second_it_falls_in() {
    let cases = [
        (UNIX_EPOCH, (0, 0)),
        (UNIX_EPOCH - Duration::from_millis(500), (-1, 500_000_000)),
        (UNIX_EPOCH - Duration::from_secs(1), (-1, 0)),
        (UNIX_EPOCH - Duration::from_millis(1500), (-2, 500_000_000)),
        (
            UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999),
            (1_700_000_000, 999_999_999),
        ),
    ];
    for (time, (secs, nanos)) in cases {
        let instant = Timestamp::from_system_time(time).unwrap();
        assert_eq!(
            (instant.unix_seconds(), instant.subsec_nanos()),
            (secs, nanos)
        );
    }
    let far = UNIX_EPOCH + Duration::from_secs(9_000_000_000_000);
    assert_eq!(Timestamp::from_system_time(far), None);
    let before = UNIX_EPOCH - Duration::from_secs(9_000_000_000_000);
    assert_eq!(Timestamp::from_system_time(before), None);
    let before = UNIX_EPOCH - Duration::new(9_000_000_000_000, 1);
    assert_eq!(Timestamp::from_system_time(before), None);
}

#[test]
fn now_is_the_system_clock() {
    let before = Timestamp::from_system_time(SystemTime::now()).unwrap();
    let now = Timestamp::now();
    let after = Timestamp::from_system_time(SystemTime::now()).unwrap();
    assert!(before <= now && now <= after);
}

#[test]
fn a_duration_is_signed_and_keeps_the_nanoseconds() {
    let earlier = at(100, 900_000_000);
    let later = at(103, 100_000_000);
    assert_eq!(
        later.duration_since(earlier),
        SignedDuration::new(2, 200_000_000)
    );
    assert_eq!(
        earlier.duration_since(later),
        SignedDuration::new(-2, -200_000_000)
    );
    assert_eq!(
        Timestamp::MAX.duration_since(Timestamp::MIN).as_secs(),
        Timestamp::MAX.unix_seconds() - Timestamp::MIN.unix_seconds()
    );
    assert_eq!(later.duration_since(later), SignedDuration::ZERO);
}

#[test]
fn rfc_3339_is_read_strictly() {
    let read = |text: &str| Timestamp::parse_rfc3339(text).map(Timestamp::to_rfc3339_z);
    assert_eq!(
        read("2026-10-23T18:36:54.5\u{2212}01:00").as_deref(),
        Ok("2026-10-23T19:36:54.500Z"),
        "U+2212 is a minus sign"
    );
    assert_eq!(
        read("2026-10-23T18:36:54Z").as_deref(),
        Ok("2026-10-23T18:36:54Z")
    );
    let refused = [
        ("2026-10-23T18:36:54", ParseError::TooShort),
        ("2026-10-23T18:36:54+0", ParseError::TooShort),
        ("2026-10-23T18:36:54+02", ParseError::TooShort),
        ("2026-10-23T18:36:54+02:0", ParseError::TooShort),
        ("2026-10-23T18:36:54+02:60", ParseError::OutOfRange),
        ("2026-10-23T18:36:54+02:6x", ParseError::Invalid),
        ("2026-10-23T18:36:54+0x:00", ParseError::Invalid),
        ("2026-10-23T18:36:54+0200", ParseError::Invalid),
        ("2026-10-23T18:36:54+24:00", ParseError::OutOfRange),
        ("2026-10-23T18:36:54+99:00", ParseError::OutOfRange),
        ("2026-10-23T18:36:54 Z", ParseError::Invalid),
        ("2026-10-23T18:36:54UTC", ParseError::Invalid),
        ("2026-10-23T18:36:54Z ", ParseError::TrailingInput),
        ("2026-10-23T18:36:54.Z", ParseError::Invalid),
        ("2026-10-23T18:36:60Z", ParseError::OutOfRange),
        ("2026-10-23T24:00:00Z", ParseError::OutOfRange),
        ("2026-10-32T00:00:00Z", ParseError::OutOfRange),
        ("2026-10-23X18:36:54Z", ParseError::Invalid),
        ("2026/10/23T18:36:54Z", ParseError::Invalid),
        (" 2026-10-23T18:36:54Z", ParseError::Invalid),
        ("+10000-01-01T00:00:00Z", ParseError::Invalid),
        ("-0001-12-31T23:59:59Z", ParseError::Invalid),
        ("2026-1-23T18:36:54Z", ParseError::Invalid),
        ("2026-10-23T18:36:54\u{e9}", ParseError::Invalid),
    ];
    for (text, error) in refused {
        assert_eq!(read(text), Err(error), "{text:?}");
    }
    assert_eq!(ParseError::TooShort.to_string(), "premature end of input");
    assert_eq!(
        ParseError::Invalid.to_string(),
        "input contains invalid characters"
    );
    assert_eq!(ParseError::OutOfRange.to_string(), "input is out of range");
    assert_eq!(ParseError::TrailingInput.to_string(), "trailing input");
}

#[test]
fn a_refused_field_names_why_in_the_serde_error() {
    let error = serde_json::from_str::<Timestamp>("\"2026-02-30T00:00:00Z\"").unwrap_err();
    assert!(
        error.to_string().contains("input is out of range"),
        "{error}"
    );
    let error = serde_json::from_str::<Timestamp>("17").unwrap_err();
    assert!(
        error.to_string().contains("an RFC 3339 date and time"),
        "{error}"
    );
}

proptest::proptest! {
    #[test]
    fn every_timestamp_reads_back_from_its_text(
        secs in Timestamp::MIN.unix_seconds()..=Timestamp::MAX.unix_seconds(),
        nanos in 0u32..1_000_000_000,
    ) {
        let instant = at(secs, nanos);
        let text = instant.to_rfc3339_z();
        if (0..=9999).contains(&Civil::from_unix(secs).year) {
            proptest::prop_assert_eq!(Timestamp::parse_rfc3339(&text), Ok(instant));
            proptest::prop_assert_eq!(
                Timestamp::parse_rfc3339(&instant.to_rfc3339()),
                Ok(instant)
            );
        }
        let json = serde_json::to_string(&instant).unwrap();
        proptest::prop_assert_eq!(json, format!("\"{text}\""));
    }

    #[test]
    fn the_text_agrees_with_jiff_from_year_0_to_where_jiff_reaches(
        secs in -62_167_219_200i64..=jiff::Timestamp::MAX.as_second(),
    ) {
        // jiff writes a negative year with three digits (`-001`); from year 0
        // on, both write four.
        let ours = at(secs, 0).to_utc_seconds();
        let theirs = jiff::Timestamp::from_second(secs).unwrap();
        let theirs = theirs.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
        proptest::prop_assert_eq!(ours, theirs);
    }

    #[test]
    fn reading_any_text_never_panics(text in ".{0,40}") {
        let _ = Timestamp::parse_rfc3339(&text);
    }
}
