// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The plaso keys' unit tests, over event lines shaped like the json_line
//! export of the pinned plaso.

use super::*;

/// A classic-wtmp record event as the pinned plaso exports it: `pid`, `when`,
/// `offset` and the file `hash` vary, the rest is the record.
fn utmp_event(pid: i64, login_type: u8, when: u64, offset: u64, hash: &str) -> String {
    serde_json::json!({
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "data_type": "linux:utmp:event",
        "date_time": {
            "__class_name__": "PosixTimeInMicroseconds",
            "__type__": "DateTimeValues",
            "timestamp": when,
        },
        "display_name": "EXT:/var/log/wtmp",
        "exit_status": 0,
        "hostname": "localhost",
        "ip_address": "0.0.0.0",
        "login_type": login_type,
        "message": format!("Terminal: tty1 PID: {pid}"),
        "offset": offset,
        "parser": "utmp",
        "pathspec": {"__type__": "PathSpec", "location": "/var/log/wtmp", "type_indicator": "EXT"},
        "pid": pid,
        "sha256_hash": hash,
        "terminal": "tty1",
        "terminal_identifier": 830_043_252,
        "timestamp": when,
        "timestamp_desc": "Content Modification Time",
        "username": "LOGIN",
    })
    .to_string()
}

#[test]
fn a_record_event_is_keyed_by_its_content_fields() {
    let finding = plaso_finding(&utmp_event(618, 6, 1_000, 768, "aa")).expect("a record");
    assert_eq!(
        finding,
        Finding::new(
            Tool::Plaso,
            "/var/log/wtmp",
            "linux:utmp:event exit_status=0 hostname=localhost ip_address=0.0.0.0 \
             login_type=6 pid=512-1023 terminal=tty1 terminal_identifier=830043252 \
             username=LOGIN"
        )
    );
}

#[test]
fn the_same_record_at_another_time_offset_or_file_hash_is_one_key() {
    // A boot's getty record subtracts against the control cycle's even though
    // it was written at another time, sits at another offset and its file
    // hashes differently.
    let control = plaso_finding(&utmp_event(618, 6, 1_000, 768, "aa"));
    let after = plaso_finding(&utmp_event(627, 6, 9_999, 6_528, "bb"));
    assert!(control.is_some());
    assert_eq!(control, after);
}

#[test]
fn a_record_whose_process_continues_the_numbers_of_an_earlier_boot_is_new() {
    // The way back's getty runs as 1625 where a fresh kernel's runs as 618:
    // the record content differs only in that range, and must not subtract.
    let boot = plaso_finding(&utmp_event(618, 6, 1_000, 768, "aa"));
    let way_back = plaso_finding(&utmp_event(1625, 6, 1_000, 768, "aa"));
    assert_ne!(boot, way_back);
    assert!(way_back.unwrap().field.contains("pid=1024-2047"));
}

#[test]
fn a_record_of_another_user_or_host_is_a_new_key() {
    let base = utmp_event(618, 7, 1_000, 768, "aa");
    let hidden_user = base.replace("\"LOGIN\"", "\"hidden\"");
    let other_host = base.replace("\"localhost\"", "\"203.0.113.7\"");
    let key = |line: &str| plaso_finding(line).expect("a record").field;
    assert_ne!(key(&base), key(&hidden_user));
    assert_ne!(key(&base), key(&other_host));
    assert!(key(&other_host).contains("hostname=203.0.113.7"));
}

#[test]
fn a_date_time_field_is_left_out_whatever_its_name_and_a_null_too() {
    let line = r#"{"data_type":"bash:history:command","filename":"/root/.bash_history",
        "command":"ls","written_time":{"__type__":"DateTimeValues","timestamp":5},
        "extra":null,"count":3,"flags":["a","b"]}"#;
    assert_eq!(
        plaso_finding(line),
        Some(Finding::new(
            Tool::Plaso,
            "/root/.bash_history",
            r#"bash:history:command command=ls count=3 flags=["a","b"]"#
        ))
    );
}

#[test]
fn plaso_pulls_the_source_path_and_descriptor() {
    let line = r#"{"path":"/var/log/wtmp.db","data_type":"linux:wtmp:event","message":"boot"}"#;
    let finding = plaso_finding(line).expect("a path is present");
    assert_eq!(
        finding,
        Finding::new(Tool::Plaso, "/var/log/wtmp.db", "linux:wtmp:event")
    );
}

#[test]
fn a_file_system_event_is_keyed_by_path_and_type_alone() {
    // The file's own metadata event names the plain path, its records the
    // type-indicated one: both land on the same path.
    let stat = r#"{"data_type":"fs:stat","filename":"/var/log/wtmp","display_name":"EXT:/var/log/wtmp",
        "file_size":9600,"inode":"1179676","mode":436,"sha256_hash":"aa"}"#;
    let finding = plaso_finding(stat).expect("a stat event");
    assert_eq!(
        finding,
        Finding::new(Tool::Plaso, "/var/log/wtmp", "fs:stat")
    );
    let record = plaso_finding(&utmp_event(0, 2, 1, 0, "aa")).expect("a record");
    assert_eq!(record.path, finding.path);
}

#[test]
fn only_an_uppercase_type_indicator_before_a_path_is_dropped() {
    assert_eq!(strip_type_indicator("EXT:/var/log/wtmp"), "/var/log/wtmp");
    assert_eq!(strip_type_indicator("OS:/data/disk.img"), "/data/disk.img");
    assert_eq!(strip_type_indicator("APFS_2:/x"), "/x");
    assert_eq!(strip_type_indicator("/plain/path"), "/plain/path");
    assert_eq!(strip_type_indicator("ext:/x"), "ext:/x");
    assert_eq!(strip_type_indicator(":/x"), ":/x");
    assert_eq!(strip_type_indicator("EXT:relative"), "EXT:relative");
}

#[test]
fn plaso_without_a_path_is_skipped_and_bad_json_too() {
    assert!(plaso_finding(r#"{"message":"no path here"}"#).is_none());
    assert!(plaso_finding("not json at all").is_none());
}

#[test]
fn pid_range_keeps_the_power_of_two_range() {
    assert_eq!(pid_range(0), "0");
    assert_eq!(pid_range(-1), "-1");
    assert_eq!(pid_range(1), "1-1");
    assert_eq!(pid_range(2), "2-3");
    assert_eq!(pid_range(3), "2-3");
    assert_eq!(pid_range(618), "512-1023");
    assert_eq!(pid_range(627), "512-1023");
    assert_eq!(pid_range(1023), "512-1023");
    assert_eq!(pid_range(1024), "1024-2047");
    assert_eq!(pid_range(1625), "1024-2047");
    assert_eq!(
        pid_range(i64::MAX),
        format!("{}-{}", 1_i64 << 62, i64::MAX),
        "the top range ends at the largest id without overflowing"
    );
}

#[test]
fn journal_events_key_on_content_not_the_rotating_file() {
    // Two different journal files (rotation) carrying the same line collapse
    // to one content-keyed finding, so a benign line subtracts across images
    // instead of resurfacing under every new per-boot filename.
    let a = r#"{"data_type":"systemd:journal","display_name":"EXT:/var/log/journal/m/system@aaaa-0001-1111.journal","reporter":"systemd","body":"Stopped target System Shutdown."}"#;
    let b = r#"{"data_type":"systemd:journal","display_name":"EXT:/var/log/journal/m/system@bbbb-0002-2222.journal","reporter":"systemd","body":"Stopped target System Shutdown."}"#;
    let fa = plaso_finding(a).expect("a journal finding");
    let fb = plaso_finding(b).expect("a journal finding");
    assert_eq!(fa, fb, "same content must give the same finding");
    assert_eq!(
        fa,
        Finding::new(
            Tool::Plaso,
            "journal",
            "systemd: Stopped target System Shutdown."
        )
    );
}

#[test]
fn a_journal_line_keeps_its_host_and_drops_its_process_id() {
    let line = |host: &str, pid: u32| {
        serde_json::json!({
            "data_type": "systemd:journal",
            "body": "Started Session c1 of User root.",
            "hostname": host,
            "pid": pid,
            "reporter": "systemd-logind",
        })
        .to_string()
    };
    let decoy = plaso_finding(&line("decoy", 512)).expect("a journal finding");
    assert_eq!(
        decoy.field,
        "systemd-logind@decoy: Started Session c1 of User root."
    );
    assert_eq!(Some(&decoy), plaso_finding(&line("decoy", 9_000)).as_ref());
    assert_ne!(Some(decoy), plaso_finding(&line("hidden-host", 512)));
}

#[test]
fn a_journal_line_without_a_body_falls_back_to_plasos_message() {
    // plaso renders the message as `<host> [<reporter>, pid: <pid>] <body>`;
    // the process id there is in a known position and is masked.
    let line =
        r#"{"data_type":"systemd:journal","message":"decoy [sshd, pid: 1834] Received signal 15"}"#;
    assert_eq!(
        plaso_finding(line).expect("a journal finding").field,
        "decoy [sshd, pid: N] Received signal 15"
    );
}

#[test]
fn journal_file_stat_events_are_dropped() {
    // plaso's fs:stat for the rotating journal file itself is volatile by
    // path and is dropped; the journal's content is compared separately.
    let line = r#"{"data_type":"fs:stat","display_name":"/var/log/journal/m/system@cccc-0003-3333.journal"}"#;
    assert!(plaso_finding(line).is_none());
    // A non-journal file's stat is still a finding.
    let other = r#"{"data_type":"fs:stat","display_name":"/home/user/secret.txt"}"#;
    assert_eq!(
        plaso_finding(other),
        Some(Finding::new(
            Tool::Plaso,
            "/home/user/secret.txt",
            "fs:stat"
        ))
    );
}

#[test]
fn is_journal_file_matches_only_journal_files() {
    assert!(is_journal_file("/var/log/journal/m/system@x-1-2.journal"));
    assert!(is_journal_file(
        "EXT:/var/log/journal/m/user-1000@x.journal"
    ));
    assert!(!is_journal_file("/var/log/journal/m/secret.txt"));
    assert!(!is_journal_file("/var/log/wtmp.db"));
}

// --- journal normalization ---------------------------------------------------

#[test]
fn a_leaked_network_identity_survives_normalization() {
    // A session line that differs from the decoy's own only by address, port,
    // lease or account must not collapse onto it.
    for body in [
        "Accepted publickey for root from 203.0.113.7 port 50122 ssh2",
        "eth0: leased 192.168.1.57 for 86400 seconds",
        "eth0: carrier acquired, hardware address 52:54:00:12:34:56",
        "pam_unix(sshd:session): session opened for user user1001(uid=1001) by (uid=0)",
        "New session 3 of user hidden.",
        "Linux version 6.18.55 on fe80::5054:ff:fe12:3456",
    ] {
        assert_eq!(normalize_journal_body(body), body, "{body}");
    }
}

#[test]
fn a_process_id_in_a_known_position_is_masked() {
    assert_eq!(
        normalize_journal_body("Sending SIGKILL to PID 1234"),
        "Sending SIGKILL to PID N"
    );
    assert_eq!(
        normalize_journal_body("Received SIGTERM from (pid 77)."),
        "Received SIGTERM from (pid N)."
    );
    assert_eq!(
        normalize_journal_body("audit: pid=1 uid=0 auid=4294967295 res=success"),
        "audit: pid=N uid=0 auid=4294967295 res=success"
    );
    assert_eq!(
        normalize_journal_body("child ppid:42 exited"),
        "child ppid:N exited"
    );
    assert_eq!(
        normalize_journal_body("sshd[1834]: exited"),
        "sshd[N]: exited"
    );
    // A bracketed number with no name before it, empty or not all digits, is
    // kept, and so is an empty audit stamp.
    assert_eq!(
        normalize_journal_body("[1834] [12a] foo[] audit() 5.s"),
        "[1834] [12a] foo[] audit() 5.s"
    );
    // "pid" before a word keeps it.
    assert_eq!(normalize_journal_body("pid file gone"), "pid file gone");
}

#[test]
fn a_duration_a_size_and_an_audit_stamp_are_masked() {
    assert_eq!(
        normalize_journal_body("Startup finished in 1.234s (kernel) + 500ms (userspace) = 2min."),
        "Startup finished in Ns (kernel) + Nms (userspace) = Nmin."
    );
    assert_eq!(
        normalize_journal_body("Runtime Journal is 8.0M, max 64.0M (3.9G free)"),
        "Runtime Journal is NM, max NM (NG free)"
    );
    assert_eq!(
        normalize_journal_body("audit(1700000000.123:42): op=x"),
        "audit(N): op=x"
    );
    // A bare number, a dotted version and a number glued to other text stay.
    assert_eq!(
        normalize_journal_body("eth0 1500 6.18.55 1h30min 100% 1.2.3s"),
        "eth0 1500 6.18.55 1h30min 100% 1.2.3s"
    );
}

#[test]
fn a_boot_id_is_masked_only_where_a_boot_id_goes() {
    assert_eq!(
        normalize_journal_body("boot 3333f264b48240fc8d4c8635a75023a5 done"),
        "boot X done"
    );
    assert_eq!(
        normalize_journal_body("_BOOT_ID=3333f264-b482-40fc-8d4c-8635a75023a5"),
        "_BOOT_ID=X"
    );
    // Sixteen hex digits and dashes with a digit and a letter are an id; one
    // fewer is not.
    assert_eq!(normalize_journal_body("boot 0123456789abcdef."), "boot X.");
    // The same id elsewhere is an identity (a machine id, a disk UUID) and is
    // kept, and "boot" before a short word or number keeps that.
    for body in [
        "machine-id 3333f264b48240fc8d4c8635a75023a5",
        "boot 2 of 3",
        "boot 0123456789abcde",
        "boot deadbeefdeadbeefdead",
        "boot 0123456789012345",
    ] {
        assert_eq!(normalize_journal_body(body), body, "{body}");
    }
}

#[test]
fn a_journal_line_with_neither_reporter_nor_host_is_its_body() {
    let line = r#"{"data_type":"systemd:journal","body":"Reached target Shutdown."}"#;
    assert_eq!(
        plaso_finding(line),
        Some(Finding::new(
            Tool::Plaso,
            "journal",
            "Reached target Shutdown."
        ))
    );
}

#[test]
fn an_event_with_no_data_type_is_keyed_by_its_fields_alone() {
    assert_eq!(
        plaso_finding(r#"{"filename":"/x","b":"2","a":"1"}"#),
        Some(Finding::new(Tool::Plaso, "/x", "a=1 b=2"))
    );
}

#[test]
fn normalization_keeps_spacing_and_unmatched_words() {
    assert_eq!(
        normalize_journal_body("  session opened\tfor user testuser "),
        "  session opened\tfor user testuser "
    );
    assert_eq!(normalize_journal_body("cafe deed"), "cafe deed");
    assert_eq!(normalize_journal_body("1234"), "1234");
    assert_eq!(normalize_journal_body(""), "");
}
