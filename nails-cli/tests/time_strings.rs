// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The times `status` shows, pinned as the binary prints them.
//!
//! The human report shows a time in the local zone with its offset
//! (`2026-10-14 21:41:59 +02:00`) and a recent log line's time as `HH:MM:SS`
//! in that zone; the JSON report keeps UTC. The zone comes from `TZ` as a
//! POSIX rule, as a TZif file a test writes, or empty for UTC, so no zone
//! database of the machine running the tests is read. The cases cover a
//! positive and a negative offset, both ends of a daylight saving change from
//! a rule and from a file's transitions (counted in leap time in a file with
//! leap seconds), a file whose footer ends in `\r\n` or is a single newline,
//! times before 1970, offsets with seconds, and years past 9999 in summer and
//! in winter. These tests name no time library: they hold
//! for any code behind the report.

use std::path::PathBuf;
use std::process::Command;

use nails_core::StateFile;
use serde_json::Value;

/// A hidden root that is a plain directory, with a strict `nails.toml`.
struct Harness {
    dir: tempfile::TempDir,
    config: PathBuf,
    hidden_root: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let hidden_root = dir.path().join("hidden-volume");
        std::fs::create_dir_all(hidden_root.join("logs")).unwrap();
        let config = dir.path().join("nails.toml");
        std::fs::write(
            &config,
            format!(
                "hidden_volume_root = {root:?}\n\
                 state_file_path = {state:?}\n\
                 log_path = {log:?}\n\
                 show_opsec_reminders = false\n",
                root = hidden_root.display().to_string(),
                state = hidden_root.join("state.json").display().to_string(),
                log = hidden_root.join("logs").display().to_string(),
            ),
        )
        .unwrap();
        Self {
            dir,
            config,
            hidden_root,
        }
    }

    /// An inactive state whose last activation finished at `finished_at`.
    fn finished_at(&self, finished_at: &str) {
        let file: StateFile = serde_json::from_value(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "state": "Inactive",
            "last_activation": { "duration_ms": 1500, "finished_at": finished_at },
            "last_modified": "2026-01-01T00:00:00Z",
        }))
        .unwrap();
        file.save(
            &self.hidden_root.join("state.json"),
            self.hidden_root.to_str().unwrap(),
        )
        .unwrap();
    }

    /// A switch the soft-reboot refused at `at` (Unix seconds).
    fn refused_at(&self, at: u64) {
        std::fs::write(
            self.hidden_root.join("last-switch.json"),
            serde_json::json!({ "reason": "the next root has no init", "at": at }).to_string(),
        )
        .unwrap();
    }

    fn log(&self, lines: &[&str]) {
        std::fs::write(
            self.hidden_root.join("logs/nails.log"),
            format!("{}\n", lines.join("\n")),
        )
        .unwrap();
    }

    /// A zone file of its own, for `TZ`.
    fn zone_file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    }

    fn status(&self, tz: &str, args: &[&str]) -> String {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("nails"))
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("TERM")
            .env("TZ", tz)
            .arg("--no-log-file")
            .arg("--config")
            .arg(&self.config)
            .arg("status")
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    }

    fn status_json(&self) -> Value {
        let stdout = self.status("UTC0", &["--json"]);
        serde_json::from_str(stdout.trim()).unwrap()
    }
}

/// A TZif version 2 file (RFC 8536): `types` as (UT offset in seconds, DST
/// flag, designation), `transitions` as (Unix time, index into `types`), and
/// the POSIX TZ string of its footer. The version 1 block holds one type and
/// no transitions, as readers of version 2 skip it.
fn tzif(types: &[(i32, bool, &str)], transitions: &[(i64, u8)], footer: &str) -> Vec<u8> {
    tzif_with_leap_seconds(types, transitions, &[], footer)
}

/// The same with a leap-second table of (leap time, correction) records, as a
/// `right/` zone has; its transitions are then counted in leap time.
fn tzif_with_leap_seconds(
    types: &[(i32, bool, &str)],
    transitions: &[(i64, u8)],
    leap_seconds: &[(i64, i32)],
    footer: &str,
) -> Vec<u8> {
    fn header(out: &mut Vec<u8>, counts: [u32; 6]) {
        out.extend_from_slice(b"TZif2");
        out.extend_from_slice(&[0; 15]);
        for count in counts {
            out.extend_from_slice(&count.to_be_bytes());
        }
    }
    let mut out = Vec::new();
    // Version 1: isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt.
    header(&mut out, [0, 0, 0, 0, 1, 4]);
    out.extend_from_slice(&0i32.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(b"UTC\0");
    // Version 2.
    let mut chars = Vec::new();
    let mut index = Vec::new();
    for (_, _, name) in types {
        index.push(u8::try_from(chars.len()).unwrap());
        chars.extend_from_slice(name.as_bytes());
        chars.push(0);
    }
    let count = |n: usize| u32::try_from(n).unwrap();
    header(
        &mut out,
        [
            0,
            0,
            count(leap_seconds.len()),
            count(transitions.len()),
            count(types.len()),
            count(chars.len()),
        ],
    );
    for (at, _) in transitions {
        out.extend_from_slice(&at.to_be_bytes());
    }
    for (_, kind) in transitions {
        out.push(*kind);
    }
    for ((offset, dst, _), at) in types.iter().zip(&index) {
        out.extend_from_slice(&offset.to_be_bytes());
        out.push(u8::from(*dst));
        out.push(*at);
    }
    out.extend_from_slice(&chars);
    for (at, correction) in leap_seconds {
        out.extend_from_slice(&at.to_be_bytes());
        out.extend_from_slice(&correction.to_be_bytes());
    }
    out.push(b'\n');
    out.extend_from_slice(footer.as_bytes());
    out.push(b'\n');
    out
}

/// Central European time with its 2026 changes as transitions, and the rule
/// after them.
fn cet_file() -> Vec<u8> {
    tzif(
        &[(3600, false, "CET"), (7200, true, "CEST")],
        &[(1_774_746_000, 1), (1_792_890_000, 0)],
        "CET-1CEST,M3.5.0,M10.5.0/3",
    )
}

/// Offsets with seconds, as the local mean times before standard time: +00:19:32,
/// -00:01:15 and -00:00:29, then CET from 1970.
fn seconds_file() -> Vec<u8> {
    tzif(
        &[
            (1172, false, "LMT"),
            (-75, false, "NMT"),
            (-29, false, "SMT"),
            (3600, false, "CET"),
        ],
        &[(-2_000_000_000, 1), (-1_000_000_000, 2), (0, 3)],
        "CET-1",
    )
}

const CET_RULE: &str = "CET-1CEST,M3.5.0,M10.5.0/3";

/// The `Last activation` line's time for an activation that finished at
/// `utc`, in the zone `tz`.
fn finished(harness: &Harness, tz: &str, utc: &str) -> String {
    harness.finished_at(utc);
    let stdout = harness.status(tz, &[]);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("Last activation:"))
        .unwrap_or_else(|| panic!("no last activation line:\n{stdout}"));
    let (_, time) = line.split_once("(finished ").unwrap();
    time.trim_end_matches(')').to_string()
}

#[test]
fn a_fixed_offset_is_shown_with_its_sign() {
    let harness = Harness::new();
    let cases = [
        ("UTC0", "2023-11-14T22:13:20Z", "2023-11-14 22:13:20 +00:00"),
        ("", "2023-11-14T22:13:20Z", "2023-11-14 22:13:20 +00:00"),
        (
            "<+02>-2",
            "2023-11-14T22:13:20Z",
            "2023-11-15 00:13:20 +02:00",
        ),
        (
            "<+02>-2",
            "1903-06-16T10:40:00Z",
            "1903-06-16 12:40:00 +02:00",
        ),
        (
            "<-0530>5:30",
            "2023-11-14T22:13:20Z",
            "2023-11-14 16:43:20 -05:30",
        ),
        (
            "<-0530>5:30",
            "1970-01-01T00:00:00Z",
            "1969-12-31 18:30:00 -05:30",
        ),
        (
            "<+0130>-1:30",
            "2023-11-14T22:13:20Z",
            "2023-11-14 23:43:20 +01:30",
        ),
        // Surrounding blanks are no part of the rule.
        (
            " <+03>-3 ",
            "2023-11-14T22:13:20Z",
            "2023-11-15 01:13:20 +03:00",
        ),
        // A fraction of a second is not shown and never rounds the second up.
        (
            "UTC0",
            "2023-11-14T22:13:20.999999999Z",
            "2023-11-14 22:13:20 +00:00",
        ),
    ];
    for (tz, utc, shown) in cases {
        assert_eq!(finished(&harness, tz, utc), shown, "TZ={tz:?} {utc}");
    }
}

#[test]
fn a_daylight_saving_change_from_a_rule_moves_the_offset_at_its_instant() {
    let harness = Harness::new();
    let cases = [
        ("2023-11-14T22:13:20Z", "2023-11-14 23:13:20 +01:00"),
        ("2026-03-29T00:59:59Z", "2026-03-29 01:59:59 +01:00"),
        ("2026-03-29T01:00:00Z", "2026-03-29 03:00:00 +02:00"),
        ("2026-10-25T00:59:59Z", "2026-10-25 02:59:59 +02:00"),
        ("2026-10-25T01:00:00Z", "2026-10-25 02:00:00 +01:00"),
        ("1954-02-26T23:06:40Z", "1954-02-27 00:06:40 +01:00"),
        ("1903-06-16T10:40:00Z", "1903-06-16 12:40:00 +02:00"),
        ("2030-03-31T00:59:59Z", "2030-03-31 01:59:59 +01:00"),
        ("2030-03-31T01:00:00Z", "2030-03-31 03:00:00 +02:00"),
    ];
    for (utc, shown) in cases {
        assert_eq!(finished(&harness, CET_RULE, utc), shown, "{utc}");
    }
    // A rule whose change falls on a half hour.
    let half = "<+0130>-1:30<+0230>,M3.5.0,M10.5.0/3";
    assert_eq!(
        finished(&harness, half, "2023-11-14T22:13:20Z"),
        "2023-11-14 23:43:20 +01:30"
    );
    assert_eq!(
        finished(&harness, half, "2026-03-29T00:59:59Z"),
        "2026-03-29 03:29:59 +02:30"
    );
}

#[test]
fn a_zone_file_is_read_by_its_transitions_and_then_by_its_rule() {
    let harness = Harness::new();
    let path = harness.zone_file("cet.tzif", &cet_file());
    let cases = [
        // Before the first transition: the first type.
        ("1903-06-16T10:40:00Z", "1903-06-16 11:40:00 +01:00"),
        ("2026-03-29T00:59:59Z", "2026-03-29 01:59:59 +01:00"),
        ("2026-03-29T01:00:00Z", "2026-03-29 03:00:00 +02:00"),
        ("2026-10-25T00:59:59Z", "2026-10-25 02:59:59 +02:00"),
        ("2026-10-25T01:00:00Z", "2026-10-25 02:00:00 +01:00"),
        // After the last transition: the footer's rule.
        ("2030-03-31T00:59:59Z", "2030-03-31 01:59:59 +01:00"),
        ("2030-03-31T01:00:00Z", "2030-03-31 03:00:00 +02:00"),
        ("2030-10-27T00:59:59Z", "2030-10-27 02:59:59 +02:00"),
        ("2030-10-27T01:00:00Z", "2030-10-27 02:00:00 +01:00"),
    ];
    // `:path`, and a bare absolute path, name the same file.
    for tz in [format!(":{path}"), path.clone()] {
        for (utc, shown) in cases {
            assert_eq!(finished(&harness, &tz, utc), shown, "TZ={tz} {utc}");
        }
    }
}

#[test]
fn a_zone_file_whose_footer_ends_in_a_carriage_return_or_is_one_newline_is_read() {
    let harness = Harness::new();
    // An offset no machine's zone has, so a fallback to the zone of the
    // machine running the tests shows.
    let mut crlf = tzif(&[(12_420, false, "XST")], &[], "XST-3:27");
    crlf.pop();
    crlf.extend_from_slice(b"\r\n");
    let mut one_newline = tzif(
        &[(12_420, false, "XST"), (16_020, false, "XDT")],
        &[(1_774_746_000, 1)],
        "",
    );
    one_newline.pop();
    let crlf = harness.zone_file("crlf.tzif", &crlf);
    let one_newline = harness.zone_file("one-newline.tzif", &one_newline);
    let cases = [
        (&crlf, "2026-03-29T00:59:59Z", "2026-03-29 04:26:59 +03:27"),
        (&crlf, "2030-01-01T00:00:00Z", "2030-01-01 03:27:00 +03:27"),
        (
            &one_newline,
            "2026-03-29T00:59:59Z",
            "2026-03-29 04:26:59 +03:27",
        ),
        (
            &one_newline,
            "2026-03-29T01:00:00Z",
            "2026-03-29 05:27:00 +04:27",
        ),
        (
            &one_newline,
            "2030-01-01T00:00:00Z",
            "2030-01-01 04:27:00 +04:27",
        ),
    ];
    for (path, utc, shown) in cases {
        let tz = format!(":{path}");
        assert_eq!(finished(&harness, &tz, utc), shown, "TZ={tz} {utc}");
    }
}

#[test]
fn a_zone_file_with_leap_seconds_changes_on_the_unix_second() {
    let harness = Harness::new();
    // The 2026 changes in leap time, two leap seconds after Unix time.
    let file = tzif_with_leap_seconds(
        &[(3600, false, "CET"), (7200, true, "CEST")],
        &[(1_774_746_002, 1), (1_792_890_002, 0)],
        &[(78_796_800, 1), (94_694_401, 2)],
        CET_RULE,
    );
    let tz = format!(":{}", harness.zone_file("right-cet.tzif", &file));
    let cases = [
        ("2026-03-29T00:59:59Z", "2026-03-29 01:59:59 +01:00"),
        ("2026-03-29T01:00:00Z", "2026-03-29 03:00:00 +02:00"),
        ("2026-10-25T00:59:59Z", "2026-10-25 02:59:59 +02:00"),
        ("2026-10-25T01:00:00Z", "2026-10-25 02:00:00 +01:00"),
        ("2030-03-31T01:00:00Z", "2030-03-31 03:00:00 +02:00"),
    ];
    for (utc, shown) in cases {
        assert_eq!(finished(&harness, &tz, utc), shown, "{utc}");
    }
}

#[test]
fn an_offset_with_seconds_is_shown_to_the_nearest_minute() {
    let harness = Harness::new();
    let tz = format!(":{}", harness.zone_file("seconds.tzif", &seconds_file()));
    let cases = [
        // +00:19:32: the clock keeps the seconds, the offset rounds up.
        ("1903-06-16T10:40:00Z", "1903-06-16 10:59:32 +00:20"),
        // -00:01:15 rounds to -00:01.
        ("1922-06-20T21:20:00Z", "1922-06-20 21:18:45 -00:01"),
        // -00:00:29 rounds to zero minutes and keeps its sign.
        ("1954-02-26T23:06:40Z", "1954-02-26 23:06:11 -00:00"),
        ("2023-11-14T22:13:20Z", "2023-11-14 23:13:20 +01:00"),
    ];
    for (utc, shown) in cases {
        assert_eq!(finished(&harness, &tz, utc), shown, "{utc}");
    }
}

#[test]
fn a_refused_switch_keeps_its_time_forms_up_to_the_largest_year() {
    let harness = Harness::new();
    let cases = [
        (0, "1970-01-01T00:00:00+00:00", "1970-01-01 00:00:00 +00:00"),
        (
            1_700_000_000,
            "2023-11-14T22:13:20+00:00",
            "2023-11-14 22:13:20 +00:00",
        ),
        (
            253_402_300_799,
            "9999-12-31T23:59:59+00:00",
            "9999-12-31 23:59:59 +00:00",
        ),
        (
            253_402_300_800,
            "+10000-01-01T00:00:00+00:00",
            "+10000-01-01 00:00:00 +00:00",
        ),
        (
            8_210_266_876_799,
            "+262142-12-31T23:59:59+00:00",
            "+262142-12-31 23:59:59 +00:00",
        ),
    ];
    for (at, json, shown) in cases {
        harness.refused_at(at);
        let value = harness.status_json();
        assert_eq!(value["data"]["switch_refusal"]["at"], json, "{at}");
        let stdout = harness.status("UTC0", &[]);
        assert!(
            stdout.contains(&format!("Last switch:        refused at {shown}\n")),
            "{at}:\n{stdout}"
        );
    }
    // In a zone east of UTC, a refusal past 9999 still shows.
    harness.refused_at(253_402_300_800);
    let stdout = harness.status("<+02>-2", &[]);
    assert!(
        stdout.contains("Last switch:        refused at +10000-01-01 02:00:00 +02:00\n"),
        "{stdout}"
    );
    // Past the largest year a time is not read, and no refusal is shown.
    harness.refused_at(8_210_266_876_800);
    let value = harness.status_json();
    assert!(value["data"].get("switch_refusal").is_none(), "{value}");
    assert!(!harness.status("UTC0", &[]).contains("Last switch:"));
}

#[test]
fn a_summer_time_past_year_9999_keeps_its_daylight_saving_offset() {
    let harness = Harness::new();
    let cet = format!(":{}", harness.zone_file("cet.tzif", &cet_file()));
    // 10000-07-01T00:00:00Z and 262142-07-01T00:00:00Z.
    let cases = [
        (CET_RULE, 253_418_025_600, "+10000-07-01 02:00:00 +02:00"),
        (
            cet.as_str(),
            253_418_025_600,
            "+10000-07-01 02:00:00 +02:00",
        ),
        (
            "EST5EDT,M3.2.0,M11.1.0",
            253_418_025_600,
            "+10000-06-30 20:00:00 -04:00",
        ),
        (CET_RULE, 8_210_250_979_200, "+262142-07-01 02:00:00 +02:00"),
        (
            cet.as_str(),
            8_210_250_979_200,
            "+262142-07-01 02:00:00 +02:00",
        ),
    ];
    for (tz, at, shown) in cases {
        harness.refused_at(at);
        let stdout = harness.status(tz, &[]);
        assert!(
            stdout.contains(&format!("Last switch:        refused at {shown}\n")),
            "TZ={tz} {at}:\n{stdout}"
        );
    }
}

#[test]
fn the_json_report_keeps_the_last_activation_in_utc() {
    let harness = Harness::new();
    let cases = [
        ("2026-10-23T18:36:54.5+02:00", "2026-10-23T16:36:54.500Z"),
        ("2026-10-23T18:36:54Z", "2026-10-23T18:36:54Z"),
        ("2026-10-23T18:36:54.123456Z", "2026-10-23T18:36:54.123456Z"),
        (
            "2026-10-23T18:36:54.123456789Z",
            "2026-10-23T18:36:54.123456789Z",
        ),
        ("1969-12-31T23:59:59.25Z", "1969-12-31T23:59:59.250Z"),
    ];
    for (written, reported) in cases {
        harness.finished_at(written);
        let value = harness.status_json();
        assert_eq!(
            value["data"]["last_activation"]["finished_at"], reported,
            "{written}"
        );
    }
}

#[test]
fn a_log_line_shows_its_time_of_day_in_the_local_zone() {
    let harness = Harness::new();
    harness.finished_at("2026-01-01T00:00:00Z");
    let line = |at: &str, level: &str, message: &str| {
        serde_json::json!({ "timestamp": at, "level": level, "fields": { "message": message } })
            .to_string()
    };
    harness.log(&[
        &line("2026-03-29T00:59:59.123456Z", "INFO", "one"),
        &line("2026-03-29T01:00:00Z", "WARN", "two"),
        &line("2026-10-25T02:30:00+02:00", "INFO", "three"),
        &line("2026-10-25t01:30:00z", "INFO", "four"),
        &line("2026-10-25 01:30:00.5Z", "INFO", "five"),
        &line("2026-10-25T01:30:00 +01:00", "INFO", "six"),
        &line("2026-10-25T01:30Z", "INFO", "seven"),
        &line("2026-10-25T01:30:00.1234567891234Z", "ERROR", "eight"),
        &line("1969-12-31T23:59:59.5Z", "INFO", "nine"),
        &line("2026-10-25T01:30:00+0100", "INFO", "ten"),
        &line("+10000-01-01T00:00:00Z", "INFO", "eleven"),
        &line("2026-10-25T01:30:00Z", "DEBUG", "twelve"),
        &line("not a time", "INFO", "thirteen"),
    ]);
    let stdout = harness.status(CET_RULE, &["--details"]);
    let (_, logs) = stdout
        .split_once("Recent log lines:\n")
        .unwrap_or_else(|| panic!("no log lines:\n{stdout}"));
    assert_eq!(
        logs,
        "  [01:59:59] INFO one\n\
         \x20 [03:00:00] WARN two\n\
         \x20 [02:30:00] INFO three\n\
         \x20 [02:30:00] INFO four\n\
         \x20 [02:30:00] INFO five\n\
         \x20 [02:30:00] ERROR eight\n\
         \x20 [00:59:59] INFO nine\n"
    );
}
