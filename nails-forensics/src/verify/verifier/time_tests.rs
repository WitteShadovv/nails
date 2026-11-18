// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The modification time a catalog finding names, pinned as it is written:
//! RFC 3339 in UTC, cut to the second it falls in.

use super::catalog::format_time;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn a_file_time_is_named_in_utc_to_the_second_it_falls_in() {
    let cases = [
        (UNIX_EPOCH, "1970-01-01T00:00:00Z"),
        (
            UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999),
            "2023-11-14T22:13:20Z",
        ),
        (
            UNIX_EPOCH - Duration::from_millis(500),
            "1969-12-31T23:59:59Z",
        ),
        (UNIX_EPOCH - Duration::from_secs(1), "1969-12-31T23:59:59Z"),
        (
            UNIX_EPOCH - Duration::from_millis(1500),
            "1969-12-31T23:59:58Z",
        ),
        (
            UNIX_EPOCH + Duration::from_secs(253_402_300_800),
            "+10000-01-01T00:00:00Z",
        ),
        (
            UNIX_EPOCH - Duration::from_secs(62_167_219_201),
            "-0001-12-31T23:59:59Z",
        ),
    ];
    for (time, shown) in cases {
        assert_eq!(format_time(time), shown, "{time:?}");
    }
}
