// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for where systemd-coredump puts a core dump.

use super::*;

fn settings(text: &str) -> CoredumpSettings {
    let mut assignments = Vec::new();
    let _ = systemd_conf::parse_section(text, COREDUMP_SECTION, &mut assignments);
    CoredumpSettings::from_assignments(&assignments)
}

#[test]
fn sizes_parse_as_systemd_reads_them() {
    for (value, bytes) in [
        ("0", Some(0)),
        ("0B", Some(0)),
        ("0K", Some(0)),
        ("0.0G", Some(0)),
        ("+0", Some(0)),
        ("32G", Some(32 << 30)),
        ("1.5K", Some(1536)),
        ("1G 512M", Some((1 << 30) + (512 << 20))),
        ("1 G", Some(1 << 30)),
        ("10.M", Some(10 << 20)),
        ("infinity", Some(u64::MAX)),
        // Rejected: empty, negative, lower-case or unknown suffixes,
        // suffixes out of order, two plain numbers, an overflow.
        ("", None),
        ("-1", None),
        ("0k", None),
        ("1X", None),
        ("512M 1G", None),
        ("1 2", None),
        ("17E", None),
    ] {
        assert_eq!(parse_iec_size(value), bytes, "{value:?}");
    }
}

#[test]
fn only_storage_none_with_no_processing_keeps_cores_off_disk() {
    assert!(settings("[Coredump]\nStorage=none\nProcessSizeMax=0\n").keeps_cores_off_disk());
    assert!(settings("[Coredump]\nStorage=none\nProcessSizeMax=0K\n").keeps_cores_off_disk());
    for text in [
        "",
        "[Coredump]\n",
        "[Coredump]\nStorage=none\n",
        "[Coredump]\nStorage=journal\nProcessSizeMax=0\n",
        "[Coredump]\nStorage=external\nProcessSizeMax=0\n",
        "[Coredump]\nProcessSizeMax=0\n",
        "[Coredump]\nStorage=none\nProcessSizeMax=1\n",
        // Outside [Coredump] nothing counts.
        "Storage=none\nProcessSizeMax=0\n",
    ] {
        assert!(!settings(text).keeps_cores_off_disk(), "{text:?}");
    }
}

#[test]
fn rejected_values_keep_the_previous_one_and_an_empty_storage_resets() {
    let kept = settings("[Coredump]\nStorage=none\nProcessSizeMax=0\nProcessSizeMax=lots\n");
    assert!(kept.keeps_cores_off_disk(), "{kept:?}");
    let kept = settings("[Coredump]\nStorage=none\nStorage=bogus\nProcessSizeMax=0\n");
    assert!(kept.keeps_cores_off_disk(), "{kept:?}");
    let reset = settings("[Coredump]\nStorage=none\nStorage=\nProcessSizeMax=0\n");
    assert_eq!(reset.storage, None);
    assert!(!reset.keeps_cores_off_disk());
    // The last assignment wins.
    let last = settings("[Coredump]\nStorage=external\nStorage=none\nProcessSizeMax=0\n");
    assert!(last.keeps_cores_off_disk());
}

#[test]
fn each_finding_names_where_the_core_goes_and_the_fix() {
    let external = settings("").finding(false).unwrap();
    assert!(external.contains("keeps core dumps in /var/lib/systemd/coredump"));
    assert!(external.contains("Storage unset, so external"));
    assert!(
        external.contains("coredump.conf.d/50-discard.conf"),
        "{external}"
    );

    let none = settings("[Coredump]\nStorage=none\n")
        .finding(false)
        .unwrap();
    assert!(none.contains("while it processes it"), "{none}");
    assert!(none.contains("ProcessSizeMax unset, so 32G"), "{none}");

    let journal = settings("[Coredump]\nStorage=journal\nProcessSizeMax=0\n")
        .finding(true)
        .unwrap();
    assert!(
        journal.contains("before it stores it in the journal"),
        "{journal}"
    );
    assert!(
        journal.contains("systemd.coredump.settings.Coredump"),
        "NixOS gets the option: {journal}"
    );

    assert_eq!(
        settings("[Coredump]\nStorage=none\nProcessSizeMax=0\n").finding(true),
        None
    );
}

#[test]
fn both_the_pipe_and_the_socket_form_count_as_systemd_coredump() {
    for pattern in [
        "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h",
        "|/run/current-system/sw/lib/systemd/systemd-coredump %P",
        // systemd 262 / Linux 6.17+ kernel coredump socket.
        "@@/run/systemd/coredumpd/kernel",
        "@/run/systemd/coredump.socket",
    ] {
        assert!(pattern_targets_systemd_coredump(pattern), "{pattern:?}");
    }
    for pattern in [
        "core",
        "",
        "/var/crash/core.%e.%p",
        "|/bin/false",
        // a socket to some other collector is that collector's business.
        "@/run/apport/apport.socket",
        // a systemd socket that is not for coredumps, and a coredump
        // socket that is not systemd's: both halves must match, so one
        // alone is left alone.
        "@/run/systemd/notify.socket",
        "@@/run/othercoredumpd/kernel",
    ] {
        assert!(!pattern_targets_systemd_coredump(pattern), "{pattern:?}");
    }
}

#[test]
fn no_finding_suggests_turning_systemd_coredump_off() {
    for text in [
        "",
        "[Coredump]\nStorage=none\n",
        "[Coredump]\nStorage=journal\n",
    ] {
        for is_nixos in [false, true] {
            let finding = settings(text).finding(is_nixos).unwrap();
            let lower = finding.to_ascii_lowercase();
            assert!(
                !lower.contains("enable = false")
                    && !lower.contains("disable")
                    && !lower.contains("turn off"),
                "{finding}"
            );
        }
    }
}
