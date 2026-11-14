// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

fn args(line: &str) -> Vec<Vec<u8>> {
    line.split_whitespace()
        .map(|word| word.as_bytes().to_vec())
        .collect()
}

fn file(path: &str, by: &str, what: &'static str) -> Log {
    Log::File(FileLog {
        path: path.to_string(),
        by: by.to_string(),
        what,
    })
}

fn unknown(log: Log) -> String {
    match log {
        Log::Unknown(why) => why,
        other => panic!("{other:?}"),
    }
}

#[test]
fn tuned_logs_to_its_file_with_the_log_option_in_every_form() {
    // Fedora's tuned.service: ExecStart=/usr/sbin/tuned -l -P.
    assert_eq!(tuned(&args("-l -P")), file(TUNED_LOG, "-l", "its log"));
    for line in [
        "-l",
        "--log",
        "--lo",
        "-P -l",
        "-Dl",
        "-l -D",
        "--log -P",
        "-p balanced -l",
        "-P /run/tuned/tuned.pid -l",
        "--log=/var/log/x.log -l",
    ] {
        assert_eq!(
            tuned(&args(line)),
            file(TUNED_LOG, "-l", "its log"),
            "{line}"
        );
    }
    for (line, path) in [
        ("-l /var/log/other.log", "/var/log/other.log"),
        ("-l/var/log/other.log", "/var/log/other.log"),
        ("-l=/var/log/other.log", "/var/log/other.log"),
        ("--log=/var/log/other.log", "/var/log/other.log"),
        ("--log /var/log/other.log -P", "/var/log/other.log"),
        ("-Dl/run/x", "/run/x"),
        ("-dl=/run/x", "/run/x"),
        // A cluster gives what follows the log option to it as its file.
        ("-ld", "d"),
        ("-l -", "-"),
    ] {
        assert_eq!(
            tuned(&args(line)),
            file(path, &format!("-l {path}"), "its log"),
            "{line}"
        );
    }
}

#[test]
fn tuned_logs_to_its_file_as_a_daemon_too() {
    let daemon = file(TUNED_LOG, "-d, which logs to a file as -l does", "its log");
    for line in ["-d", "--daemon", "--da -P", "-dP", "-Dd"] {
        assert_eq!(tuned(&args(line)), daemon, "{line}");
    }
    // Its log option names the file, with or without -d.
    assert_eq!(
        tuned(&args("-d -l /run/t.log")),
        file("/run/t.log", "-l /run/t.log", "its log")
    );
}

/// The verdict of a daemon that logs to `stream`, as `by` says.
fn to_stream(stream: Stream, by: &'static str) -> Log {
    Log::Stream { stream, by }
}

#[test]
fn tuned_without_the_log_option_logs_to_its_standard_error() {
    for line in [
        "",
        "-P",
        "-P /run/tuned/tuned.pid",
        "--pid=/run/tuned/tuned.pid",
        "-D --no-dbus --no-socket",
        "-p balanced",
        "--profile=balanced -P",
        "-pbalanced",
        // A word that names a profile is no option, even one called -l.
        "--profile=-l",
    ] {
        assert_eq!(
            tuned(&args(line)),
            to_stream(Stream::Error, "neither -l nor -d"),
            "{line}"
        );
    }
}

#[test]
fn what_tuned_would_read_otherwise_than_nails_is_unknown() {
    for (line, why) in [
        ("-x", "NAILS does not know its option -x"),
        ("-lP -x", "NAILS does not know its option -x"),
        ("--d", "NAILS does not know its option --d"),
        ("--logs", "NAILS does not know its option --logs"),
        ("--", "NAILS does not read its argument --"),
        ("balanced", "NAILS does not read its argument balanced"),
        ("-p", "its option --profile lacks its value"),
        ("-p -l", "its option --profile lacks its value"),
        ("--daemon=yes", "its option --daemon takes no value"),
        ("-l -5", "NAILS cannot tell whether -5 is a value of --log"),
        ("--log=", "it passes -l an empty file name"),
    ] {
        assert_eq!(unknown(tuned(&args(line))), why, "{line}");
    }
    // A word with a space may be a value.
    let spaced = vec![b"-l".to_vec(), b"-x y".to_vec()];
    assert_eq!(
        unknown(tuned(&spaced)),
        "NAILS cannot tell whether -x y is a value of --log"
    );
}

#[test]
fn tuned_ppd_logs_to_its_own_file_with_the_log_option() {
    // Fedora's tuned-ppd.service: ExecStart=/usr/sbin/tuned-ppd -l.
    assert_eq!(tuned_ppd(&args("-l")), file(TUNED_PPD_LOG, "-l", "its log"));
    assert_eq!(
        tuned_ppd(&args("--debug --log=/run/ppd.log")),
        file("/run/ppd.log", "-l /run/ppd.log", "its log")
    );
    for line in ["", "-D", "--debug"] {
        assert_eq!(
            tuned_ppd(&args(line)),
            to_stream(Stream::Error, "no -l"),
            "{line}"
        );
    }
    // tuned-ppd has no -d, nor tuned's other options.
    assert_eq!(
        unknown(tuned_ppd(&args("-d"))),
        "NAILS does not know its option -d"
    );
    assert_eq!(
        unknown(tuned_ppd(&args("-P"))),
        "NAILS does not know its option -P"
    );
}

#[test]
fn firewalld_appends_its_warnings_and_errors_to_its_file_by_default() {
    // Fedora's firewalld.service with FIREWALLD_ARGS empty.
    let warnings = file(
        FIREWALLD_LOG,
        "the log target mixed, the default",
        "its warnings and errors",
    );
    for line in ["--nofork --nopid", "", "--debug-gc --nofork", "--nof --nop"] {
        assert_eq!(firewalld(&args(line)), warnings, "{line}");
    }
    assert_eq!(
        firewalld(&args("--nofork --log-target=mixed")),
        file(
            FIREWALLD_LOG,
            "--log-target=mixed",
            "its warnings and errors"
        )
    );
    assert_eq!(
        firewalld(&args("--log-file /var/log/fw.log")),
        file(
            "/var/log/fw.log",
            "the log target mixed, the default",
            "its warnings and errors"
        )
    );
}

#[test]
fn firewalld_writes_every_message_with_debug_or_the_file_target() {
    let every = "every message it logs";
    for (line, by) in [
        (
            "--nofork --debug",
            "the log target mixed, the default and --debug",
        ),
        ("--debug=3", "the log target mixed, the default and --debug"),
        (
            "--debug 10 --nopid",
            "the log target mixed, the default and --debug",
        ),
        ("--log-target=file", "--log-target=file"),
        ("--log-target file --debug", "--log-target=file"),
        ("--log-t=file", "--log-target=file"),
    ] {
        assert_eq!(
            firewalld(&args(line)),
            file(FIREWALLD_LOG, by, every),
            "{line}"
        );
    }
}

#[test]
fn firewalld_with_the_syslog_target_logs_to_the_journal() {
    for line in [
        "--nofork --nopid --log-target=syslog",
        "--log-target syslog --debug",
        "--log-target=file --log-target=syslog",
        "--log-tar=syslog --log-file=/var/log/fw.log",
    ] {
        assert_eq!(
            firewalld(&args(line)),
            Log::Journal {
                by: "--log-target=syslog".to_string(),
                what: "every message it logs"
            },
            "{line}"
        );
    }
    assert_eq!(
        firewalld(&args("--log-target=console")),
        to_stream(Stream::Output, "the log target console")
    );
}

#[test]
fn what_firewalld_would_read_otherwise_than_nails_is_unknown() {
    for (line, why) in [
        ("--log-target", "its option --log-target lacks its value"),
        (
            "--log-target=journal",
            "it passes --log-target the target journal",
        ),
        ("--debug=11", "it passes --debug the level 11"),
        ("--debug verbose", "it passes --debug the level verbose"),
        ("--deb", "NAILS does not know its option --deb"),
        ("-d", "NAILS does not know its option -d"),
        ("--log-file=", "it passes --log-file an empty file"),
        (
            "--system-config",
            "its option --system-config lacks its value",
        ),
    ] {
        assert_eq!(unknown(firewalld(&args(line))), why, "{line}");
    }
}

#[test]
fn a_log_to_a_device_that_keeps_nothing_is_no_file() {
    // Python's RotatingFileHandler writes to the device and rolls nothing
    // over that is not a regular file.
    for line in ["-l /dev/null -P", "-l=/dev/null", "--log=/dev/console"] {
        assert_eq!(tuned(&args(line)), Log::NoFile, "{line}");
    }
    assert_eq!(tuned_ppd(&args("-l /dev/null")), Log::NoFile);
    assert_eq!(
        firewalld(&args("--log-target=file --log-file=/dev/null")),
        Log::NoFile
    );
    // -d takes the file -l names.
    assert_eq!(tuned(&args("-d -l /dev/null")), Log::NoFile);
    // Another device, as a disk's, is not judged; a file in /dev/shm, in
    // RAM, counts as a file.
    assert_eq!(
        unknown(tuned(&args("-l /dev/sda1"))),
        "it logs to /dev/sda1, a device NAILS does not judge"
    );
    assert_eq!(
        tuned(&args("-l /dev/shm/tuned.log")),
        file("/dev/shm/tuned.log", "-l /dev/shm/tuned.log", "its log")
    );
}
