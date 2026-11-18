// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The time text NAILS reads: an RFC 3339 timestamp from the state file or a
//! log line, and a local zone from a TZif file (`/etc/localtime`, the decoy's)
//! or a POSIX rule in `TZ`.
//!
//! The first byte picks the reader, the rest is its input. A timestamp that is
//! read is written back in both of NAILS's forms, and each reads again as the
//! same instant unless the offset carried it outside the years 0 to 9999; the
//! state file's serde form matches. A zone that is read shows a time at six
//! fixed instants across the range a timestamp covers, its two ends included,
//! without a panic, with an offset under 26 hours and the time of day its
//! stamp holds; the instants do not come from the input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::time::{Timestamp, Zone};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => timestamp(&String::from_utf8_lossy(rest)),
        1 => {
            if let Some(zone) = Zone::tzif(rest) {
                shows(&zone);
            }
        }
        _ => {
            if let Some(zone) = Zone::posix(&String::from_utf8_lossy(rest)) {
                shows(&zone);
            }
        }
    }
});

fn timestamp(text: &str) {
    let Ok(instant) = Timestamp::parse_rfc3339(text) else {
        return;
    };
    let z = instant.to_rfc3339_z();
    assert_eq!(serde_json::to_string(&instant).unwrap(), format!("\"{z}\""));
    // An offset can carry a time read in year 9999 into year 10000, or one
    // read in year 0 into year -1, whose forms have a sign (`+10000`,
    // `-0001`), which the reading refuses, as it refuses any year that is not
    // four digits.
    if z.starts_with(['+', '-']) {
        assert!(Timestamp::parse_rfc3339(&z).is_err(), "{text:?}");
        return;
    }
    assert_eq!(Timestamp::parse_rfc3339(&z), Ok(instant), "{text:?}");
    assert_eq!(
        Timestamp::parse_rfc3339(&instant.to_rfc3339()),
        Ok(instant),
        "{text:?}"
    );
}

fn shows(zone: &Zone) {
    let instants = [
        Timestamp::MIN,
        Timestamp::from_unix_seconds(-1).unwrap(),
        Timestamp::from_unix_seconds(0).unwrap(),
        Timestamp::from_unix_seconds(1_774_746_000).unwrap(),
        Timestamp::from_unix_seconds(253_402_300_800).unwrap(),
        Timestamp::MAX,
    ];
    for instant in instants {
        let offset = zone.offset_at(instant);
        assert!(offset.unsigned_abs() < 26 * 3600, "{offset}");
        let stamp = zone.stamp(instant);
        assert!(stamp.contains(&zone.clock(instant)), "{stamp}");
    }
}
