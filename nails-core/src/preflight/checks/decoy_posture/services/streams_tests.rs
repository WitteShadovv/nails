// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::NailsError;

/// The `[Service]` assignments of `text`, one `Key=value` per line.
fn section(text: &str) -> Vec<Assignment> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| Assignment {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect()
}

fn file(path: &str, by: &str) -> Log {
    Log::File(FileLog {
        path: path.to_string(),
        by: by.to_string(),
        what: "its log",
    })
}

fn unknown(log: Log) -> String {
    match log {
        Log::Unknown(why) => why,
        other => panic!("not unknown: {other:?}"),
    }
}

const TUNED_BY: &str = "neither -l nor -d";

#[test]
fn a_stream_the_unit_leaves_alone_goes_to_no_file() {
    // Fedora's tuned.service sets neither: the standard error follows the
    // standard output, whose default the service manager never lets name a
    // file, and which follows a standard input of /dev/null where it is
    // inherit.
    for text in [
        "",
        "StandardError=inherit",
        "StandardOutput=inherit",
        "StandardOutput=journal",
        "StandardError=journal\nStandardOutput=append:/var/log/out.log",
        "StandardError=null",
        "StandardError=kmsg+console",
        "StandardError=tty",
        "StandardError=syslog",
        "StandardOutput=socket",
        "StandardError=socket",
        "StandardOutput=inherit\nStandardInput=tty-force",
        "StandardInput=data",
    ] {
        assert_eq!(
            of_unit(&section(text), Stream::Error, TUNED_BY),
            Log::NoFile,
            "{text:?}"
        );
    }
}

#[test]
fn a_stream_the_unit_sends_to_a_file_logs_there() {
    for (text, path, by) in [
        (
            "StandardError=append:/var/log/tuned/tuned.log",
            "/var/log/tuned/tuned.log",
            "neither -l nor -d and StandardError=append:/var/log/tuned/tuned.log",
        ),
        (
            "StandardError=truncate:/run/t.log",
            "/run/t.log",
            "neither -l nor -d and StandardError=truncate:/run/t.log",
        ),
        // A drop-in for every service, as `service.d/50-log.conf` is.
        (
            "StandardOutput=append:/var/log/daemons.log",
            "/var/log/daemons.log",
            "neither -l nor -d, StandardError= not set (inherit) and \
             StandardOutput=append:/var/log/daemons.log",
        ),
        (
            "StandardError=inherit\nStandardOutput=file:/var/log/both.log",
            "/var/log/both.log",
            "neither -l nor -d, StandardError=inherit and StandardOutput=file:/var/log/both.log",
        ),
        // No socket starts tuned, so its socket is its standard output.
        (
            "StandardError=socket\nStandardOutput=file:/var/log/both.log",
            "/var/log/both.log",
            "neither -l nor -d, StandardError=socket and StandardOutput=file:/var/log/both.log",
        ),
        // systemd ignores an empty value, which leaves the one before.
        (
            "StandardError=append:/var/log/e.log\nStandardError=",
            "/var/log/e.log",
            "neither -l nor -d and StandardError=append:/var/log/e.log",
        ),
    ] {
        assert_eq!(
            of_unit(&section(text), Stream::Error, TUNED_BY),
            file(path, by),
            "{text:?}"
        );
    }
    // The last value counts.
    assert_eq!(
        of_unit(
            &section("StandardError=append:/var/log/e.log\nStandardError=journal"),
            Stream::Error,
            TUNED_BY
        ),
        Log::NoFile
    );
    // firewalld's console target reads its standard output alone.
    assert_eq!(
        of_unit(
            &section("StandardError=append:/var/log/e.log"),
            Stream::Output,
            "the log target console"
        ),
        Log::NoFile
    );
}

#[test]
fn what_nails_cannot_follow_of_a_unit_is_unknown() {
    for (text, why) in [
        (
            "StandardError=fd:log",
            "it logs to its standard error, which NAILS cannot follow past StandardError=fd:log",
        ),
        (
            "StandardError=journall",
            "it logs to its standard error, which NAILS cannot follow past StandardError=journall",
        ),
        (
            "StandardOutput=inherit\nStandardInput=file:/var/log/in.log",
            "it logs to its standard error, which NAILS cannot follow past StandardError= not \
             set (inherit), StandardOutput=inherit and StandardInput=file:/var/log/in.log",
        ),
        // The default standard output may be inherit, which follows it.
        (
            "StandardInput=fd:input",
            "it logs to its standard error, which NAILS cannot follow past StandardError= not \
             set (inherit), StandardOutput= not set and StandardInput=fd:input",
        ),
    ] {
        assert_eq!(
            unknown(of_unit(&section(text), Stream::Error, TUNED_BY)),
            why,
            "{text:?}"
        );
    }
}

#[test]
fn a_process_stream_is_judged_by_where_its_descriptor_leads() {
    let by = TUNED_BY;
    for target in [
        "socket:[24680]",
        "pipe:[13579]",
        "/dev/null",
        "/dev/pts/1",
        "/dev/kmsg",
    ] {
        assert_eq!(
            led_to(Ok(PathBuf::from(target)), Stream::Error, by),
            Log::NoFile,
            "{target}"
        );
    }
    for target in [
        "/var/log/tuned/by-hand.log",
        "/root/nohup.out",
        "/var/log/old.log (deleted)",
        // A file in RAM is a file too.
        "/dev/shm/tuned.log",
    ] {
        assert_eq!(
            led_to(Ok(PathBuf::from(target)), Stream::Error, by),
            file(
                target,
                "neither -l nor -d, its standard error being that file"
            ),
            "{target}"
        );
    }
    assert_eq!(
        unknown(led_to(
            Ok(PathBuf::from("anon_inode:[eventfd]")),
            Stream::Output,
            by
        )),
        "it logs to its standard output, which leads to anon_inode:[eventfd]"
    );
    let error = |kind| {
        Err(NailsError::io(
            Path::new("/proc/812/fd/2"),
            std::io::Error::from(kind),
        ))
    };
    // A closed descriptor takes nothing, and an ended process logs no more.
    assert_eq!(
        led_to(error(std::io::ErrorKind::NotFound), Stream::Error, by),
        Log::NoFile
    );
    assert_eq!(
        unknown(led_to(
            error(std::io::ErrorKind::PermissionDenied),
            Stream::Error,
            by
        )),
        "it logs to its standard error, which only root may follow; run the command again \
         with sudo"
    );
    assert!(
        unknown(led_to(
            error(std::io::ErrorKind::InvalidInput),
            Stream::Error,
            by
        ))
        .starts_with("it logs to its standard error, which NAILS cannot follow ("),
    );
}
