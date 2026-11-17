// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The times the examiner's evidence names, pinned as it writes them: RFC 3339
//! in UTC to the second, a year past 9999 with its sign, and a time too large
//! or too small to be a date left out (LVM) or given as its seconds (an access
//! time).

use super::*;

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel.trim_start_matches('/'));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// The evidence of the LVM archive whose `creation_time` is `value`.
fn lvm_evidence(value: &str) -> String {
    let root = tempfile::tempdir().unwrap();
    write(
        root.path(),
        "/etc/lvm/archive/vg_00000-1.vg",
        format!(
            "description = \"Created *before* executing 'vgcreate vg /dev/sdb'\"\n\
             creation_host = \"decoy\"\ncreation_time = {value}\n\nvg {{\n}}\n"
        )
        .as_bytes(),
    );
    let report = examine(root.path(), &ExaminerOptions::default());
    report
        .findings()
        .find(|finding| finding.catalog_id == "lvm-metadata-archive")
        .unwrap()
        .evidence
        .clone()
}

#[test]
fn an_lvm_creation_time_is_named_in_utc_to_the_second() {
    let head = "volume group vg: Created *before* executing 'vgcreate vg /dev/sdb' on host decoy";
    let cases = [
        ("1790000000", Some("2026-09-21T14:13:20Z")),
        ("0", Some("1970-01-01T00:00:00Z")),
        ("-1", Some("1969-12-31T23:59:59Z")),
        ("-62167219200", Some("0000-01-01T00:00:00Z")),
        ("-62167219201", Some("-0001-12-31T23:59:59Z")),
        ("253402300799", Some("9999-12-31T23:59:59Z")),
        ("253402300800", Some("+10000-01-01T00:00:00Z")),
        ("8210266876799", Some("+262142-12-31T23:59:59Z")),
        ("-8334601228800", Some("-262143-01-01T00:00:00Z")),
        // Past the largest and the smallest year a time is left out.
        ("8210266876800", None),
        ("-8334601228801", None),
        ("9223372036854775807", None),
        ("-9223372036854775808", None),
        ("soon", None),
    ];
    for (value, time) in cases {
        let expected = match time {
            Some(time) => format!("{head} at {time}"),
            None => head.to_string(),
        };
        assert_eq!(lvm_evidence(value), expected, "{value}");
    }
}

#[test]
fn a_tools_access_time_is_named_in_utc_to_the_second() {
    use std::time::{Duration, UNIX_EPOCH};
    let cases = [
        (
            UNIX_EPOCH + Duration::new(1_700_000_000, 750_000_000),
            "2023-11-14T22:13:20Z",
        ),
        (
            UNIX_EPOCH - Duration::from_millis(500),
            "1969-12-31T23:59:59Z",
        ),
        (
            UNIX_EPOCH - Duration::from_secs(86_400),
            "1969-12-31T00:00:00Z",
        ),
    ];
    for (accessed, shown) in cases {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "/usr/bin/veracrypt", b"#!/bin/sh\n");
        let tool = root.path().join("usr/bin/veracrypt");
        std::fs::File::options()
            .write(true)
            .open(&tool)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_accessed(accessed))
            .unwrap();
        let report = examine(root.path(), &ExaminerOptions::default());
        let finding = report
            .findings()
            .find(|finding| finding.catalog_id == "backend-tooling")
            .unwrap();
        assert_eq!(
            finding.evidence,
            format!("installed, last access {shown}"),
            "{accessed:?}"
        );
    }
}
