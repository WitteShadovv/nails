// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The time strings of the state file, pinned as NAILS writes and reads them.
//!
//! Every timestamp field of the state file is written as RFC 3339 in UTC with
//! `Z`, the seconds' fraction cut to the fewest of 0, 3, 6 or 9 digits that hold
//! it. The load re-serialises the file to check its integrity digest, so a
//! field that came back in any other form would turn a good state file corrupt.
//! These tests name no time library: they hold for any code behind the fields.
//!
//! `src/state/golden/time/` holds state files written by the serialiser of the
//! 0.3.0 release candidates, with sub-second parts of every length it writes and
//! the edges of the four-digit year. They are never regenerated, and their
//! SHA-256 is pinned below.

use nails_base::{LastActivation, LoadOutcome, StateFile, SystemState};
use std::path::{Path, PathBuf};

/// `text` read as the `finished_at` of a last activation and written back, or
/// `None` when the read refuses it.
fn finished_at(text: &str) -> Option<String> {
    let json = format!(r#"{{"duration_ms":1,"finished_at":{}}}"#, quoted(text));
    let read: LastActivation = serde_json::from_str(&json).ok()?;
    let value = serde_json::to_value(&read).unwrap();
    Some(value["finished_at"].as_str().unwrap().to_string())
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap()
}

#[test]
fn a_timestamp_is_written_in_utc_with_zero_three_six_or_nine_fraction_digits() {
    let cases = [
        ("2026-10-23T18:36:54Z", "2026-10-23T18:36:54Z"),
        ("2026-10-23T18:36:54.000Z", "2026-10-23T18:36:54Z"),
        ("2026-10-23T18:36:54.000000000Z", "2026-10-23T18:36:54Z"),
        ("2026-10-23T18:36:54.5Z", "2026-10-23T18:36:54.500Z"),
        ("2026-10-23T18:36:54.12Z", "2026-10-23T18:36:54.120Z"),
        ("2026-10-23T18:36:54.123Z", "2026-10-23T18:36:54.123Z"),
        ("2026-10-23T18:36:54.001Z", "2026-10-23T18:36:54.001Z"),
        ("2026-10-23T18:36:54.100000Z", "2026-10-23T18:36:54.100Z"),
        ("2026-10-23T18:36:54.1234Z", "2026-10-23T18:36:54.123400Z"),
        ("2026-10-23T18:36:54.12345Z", "2026-10-23T18:36:54.123450Z"),
        ("2026-10-23T18:36:54.123456Z", "2026-10-23T18:36:54.123456Z"),
        ("2026-10-23T18:36:54.000001Z", "2026-10-23T18:36:54.000001Z"),
        (
            "2026-10-23T18:36:54.123456000Z",
            "2026-10-23T18:36:54.123456Z",
        ),
        (
            "2026-10-23T18:36:54.1234567Z",
            "2026-10-23T18:36:54.123456700Z",
        ),
        (
            "2026-10-23T18:36:54.12345678Z",
            "2026-10-23T18:36:54.123456780Z",
        ),
        (
            "2026-10-23T18:36:54.123456789Z",
            "2026-10-23T18:36:54.123456789Z",
        ),
        (
            "2026-10-23T18:36:54.000000001Z",
            "2026-10-23T18:36:54.000000001Z",
        ),
        // More than nine digits: the rest is dropped, never rounded.
        (
            "2026-10-23T18:36:54.1234567891234Z",
            "2026-10-23T18:36:54.123456789Z",
        ),
    ];
    for (read, written) in cases {
        assert_eq!(finished_at(read).as_deref(), Some(written), "{read}");
    }
}

#[test]
fn an_offset_is_written_as_the_same_instant_in_utc() {
    let cases = [
        ("2026-10-23T18:36:54+00:00", "2026-10-23T18:36:54Z"),
        ("2026-10-23T18:36:54-00:00", "2026-10-23T18:36:54Z"),
        (
            "2026-10-23T18:36:54.578963021+00:00",
            "2026-10-23T18:36:54.578963021Z",
        ),
        ("2026-10-23T18:36:54+02:00", "2026-10-23T16:36:54Z"),
        ("2026-10-23T18:36:54-05:30", "2026-10-24T00:06:54Z"),
        ("2026-10-23T18:36:54+23:59", "2026-10-22T18:37:54Z"),
        ("2026-01-01T00:30:00+01:00", "2025-12-31T23:30:00Z"),
    ];
    for (read, written) in cases {
        assert_eq!(finished_at(read).as_deref(), Some(written), "{read}");
    }
}

#[test]
fn the_separator_and_the_zone_letter_may_be_lower_case_or_a_space() {
    let cases = [
        ("2026-10-23t18:36:54z", "2026-10-23T18:36:54Z"),
        ("2026-10-23 18:36:54Z", "2026-10-23T18:36:54Z"),
        ("2026-10-23T18:36:54.1z", "2026-10-23T18:36:54.100Z"),
    ];
    for (read, written) in cases {
        assert_eq!(finished_at(read).as_deref(), Some(written), "{read}");
    }
}

#[test]
fn times_before_1970_and_at_the_ends_of_the_four_digit_year_keep_their_form() {
    let cases = [
        ("1969-12-31T23:59:59Z", "1969-12-31T23:59:59Z"),
        ("1969-12-31T23:59:59.5Z", "1969-12-31T23:59:59.500Z"),
        ("1900-01-01T00:00:00Z", "1900-01-01T00:00:00Z"),
        ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
        ("2024-02-29T12:00:00Z", "2024-02-29T12:00:00Z"),
        (
            "9999-12-31T23:59:59.999999999Z",
            "9999-12-31T23:59:59.999999999Z",
        ),
    ];
    for (read, written) in cases {
        assert_eq!(finished_at(read).as_deref(), Some(written), "{read}");
    }
}

#[test]
fn a_corrupt_timestamp_is_refused() {
    for text in [
        "",
        "x",
        "2024-01-01",
        "2024-01-01T00:00:00",
        "2026-10-23T18:36Z",
        "2026-10-23T18:36:54.Z",
        "2026-10-23T18:36:54,5Z",
        "20261023T183654Z",
        "02026-10-23T18:36:54Z",
        "2024-02-30T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2024-13-01T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "2024-01-01T00:60:00Z",
        "2026-10-23T18:36:54+24:00",
        "2026-10-23T18:36:54+02",
        "2026-10-23T18:36:54+00:00Z",
        "2026-10-23T18:36:54+02:00:30",
        "2026-10-23T18:36:54+02:00[Europe/Berlin]",
    ] {
        assert_eq!(finished_at(text), None, "{text:?} was read");
    }
}

#[test]
fn every_timestamp_field_of_the_state_file_keeps_the_form() {
    let active: SystemState =
        serde_json::from_str(r#"{"Active":{"activated_at":"2026-11-17T10:00:00.5+01:00"}}"#)
            .unwrap();
    assert_eq!(
        serde_json::to_string(&active).unwrap(),
        r#"{"Active":{"activated_at":"2026-11-17T09:00:00.500Z"}}"#
    );
    let degraded: SystemState = serde_json::from_str(
        r#"{"Degraded":{"since":"2026-11-17T10:00:00.1234Z","reason":"why"}}"#,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_string(&degraded).unwrap(),
        r#"{"Degraded":{"since":"2026-11-17T10:00:00.123400Z","reason":"why"}}"#
    );
    let file: StateFile = serde_json::from_str(
        r#"{"version":"0.3.0","state":"Inactive","last_modified":"2026-11-17T10:00:00.1234567Z"}"#,
    )
    .unwrap();
    let written = serde_json::to_value(&file).unwrap();
    assert_eq!(written["last_modified"], "2026-11-17T10:00:00.123456700Z");
}

/// The directory of the frozen state files.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/state/golden/time")
}

/// The frozen state files, with the SHA-256 of their bytes.
const FROZEN: &[(&str, &str)] = &[
    (
        "active-0-3-6.json",
        "9a448b62090b9229eb66c307b762f95af25523ef656525daecb6ec60a2f87cea", // pragma: allowlist secret
    ),
    (
        "degraded-9-3-6.json",
        "4a551e1d8992048cb0115415beb94e8b9060c0e75622e42511fa9e10a28a4a80", // pragma: allowlist secret
    ),
    (
        "inactive-year-bounds.json",
        "5383d1cde6ea740ff2854532098c448bbe2442abbbe294ff600914577fcd1c74", // pragma: allowlist secret
    ),
];

#[test]
fn the_frozen_state_files_are_unchanged() {
    use sha2::Digest;
    let mut on_disk: Vec<String> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let pinned: Vec<String> = FROZEN.iter().map(|(name, _)| name.to_string()).collect();
    assert_eq!(
        on_disk, pinned,
        "every frozen file is pinned, and only those"
    );
    for (name, sha256) in FROZEN {
        let bytes = std::fs::read(fixtures().join(name)).unwrap();
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&bytes)),
            *sha256,
            "{name} changed; it is what an earlier serialiser wrote and must stay so"
        );
    }
}

#[test]
fn every_frozen_state_file_loads_with_its_digest_and_is_written_back_byte_for_byte() {
    for (name, _) in FROZEN {
        let committed = std::fs::read_to_string(fixtures().join(name)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, &committed).unwrap();
        let loaded = StateFile::load_with_outcome(&path).unwrap();
        assert_eq!(loaded.outcome, LoadOutcome::Loaded, "{name}");
        assert_eq!(
            format!(
                "{}\n",
                serde_json::to_string_pretty(&loaded.state_file).unwrap()
            ),
            committed,
            "{name} came back changed"
        );
    }
}

#[test]
fn a_state_file_with_a_corrupt_timestamp_loads_as_corrupt() {
    let committed = std::fs::read_to_string(fixtures().join("active-0-3-6.json")).unwrap();
    for (good, bad) in [
        ("2026-11-17T10:00:00Z", "2026-11-17T10:00:00"),
        ("2026-11-17T10:00:00Z", "2026-02-30T10:00:00Z"),
        ("2026-11-17T10:00:03.120001Z", "not a time"),
        ("2026-11-17T10:00:03.120Z", "2026-11-17T25:00:03.120Z"),
    ] {
        let text = committed.replacen(good, bad, 1);
        assert_ne!(text, committed);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, &text).unwrap();
        let loaded = StateFile::load_with_outcome(&path).unwrap();
        assert_eq!(loaded.outcome, LoadOutcome::Corrupt, "{bad}");
        assert_eq!(loaded.state_file.state, SystemState::Inactive, "{bad}");
    }
}

#[test]
fn the_digest_is_checked_over_the_form_the_load_writes_back() {
    // The load checks the digest over the file as it writes it back, so the
    // same instant spelled with fewer digits still matches: what must not change
    // is the form a field is written back in.
    let committed = std::fs::read_to_string(fixtures().join("active-0-3-6.json")).unwrap();
    let text = committed.replacen("2026-11-17T10:00:03.120Z", "2026-11-17T10:00:03.12Z", 1);
    assert_ne!(text, committed);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, &text).unwrap();
    assert_eq!(
        StateFile::load_with_outcome(&path).unwrap().outcome,
        LoadOutcome::Loaded
    );
}
