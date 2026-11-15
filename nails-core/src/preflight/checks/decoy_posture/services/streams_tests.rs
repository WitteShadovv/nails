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
        namespace: None,
    })
}

fn unknown(log: Log) -> String {
    match log {
        Log::Unknown(why) => why,
        other => panic!("not unknown: {other:?}"),
    }
}

const TUNED_BY: &str = "neither -l nor -d";

/// A log to the journal, as `by` says.
fn journal(by: &str) -> Log {
    Log::Journal {
        by: by.to_string(),
        what: "its log",
    }
}

#[test]
fn a_stream_the_unit_leaves_alone_goes_to_the_journal_or_no_file() {
    // Fedora's tuned.service sets neither: the standard error follows the
    // standard output, whose default the service manager never lets name a
    // file: the journal, which may be a namespace's.
    let unset = "neither -l nor -d, StandardError= not set (inherit) and StandardOutput= not set";
    for (text, by) in [
        ("", unset),
        (
            "StandardError=inherit",
            "neither -l nor -d, StandardError=inherit and StandardOutput= not set",
        ),
        (
            "StandardOutput=journal",
            "neither -l nor -d, StandardError= not set (inherit) and StandardOutput=journal",
        ),
        (
            "StandardError=journal\nStandardOutput=append:/var/log/out.log",
            "neither -l nor -d and StandardError=journal",
        ),
        (
            "StandardError=syslog",
            "neither -l nor -d and StandardError=syslog",
        ),
        // The journal keeps what it hands on to the kernel's log buffer.
        (
            "StandardError=kmsg",
            "neither -l nor -d and StandardError=kmsg",
        ),
        (
            "StandardError=kmsg+console",
            "neither -l nor -d and StandardError=kmsg+console",
        ),
        ("StandardInput=data", unset),
    ] {
        assert_eq!(
            of_unit(&section(text), Stream::Error, TUNED_BY),
            journal(by),
            "{text:?}"
        );
    }
    for text in [
        "StandardError=null",
        "StandardError=tty",
        // A standard output left to inherit follows a terminal it reads.
        "StandardOutput=inherit\nStandardInput=tty-force",
        "StandardInput=tty",
        "StandardError=inherit\nStandardInput=tty-fail",
        // A device that keeps nothing it is given.
        "StandardError=file:/dev/null",
        "StandardError=append:/dev/console",
        "StandardError=inherit\nStandardOutput=truncate:/dev/tty1",
    ] {
        assert_eq!(
            of_unit(&section(text), Stream::Error, TUNED_BY),
            Log::NoFile,
            "{text:?}"
        );
    }
}

#[test]
fn an_inherited_standard_output_takes_the_default_as_an_unset_one() {
    // systemd's service_fix_stdio() gives StandardOutput=inherit the
    // manager's default, the journal, as it gives an unset one, unless the
    // standard input is a terminal, a socket or a named descriptor: a file
    // as the standard input is no reason to keep inherit either.
    for (text, by) in [
        (
            "StandardOutput=inherit",
            "neither -l nor -d, StandardError= not set (inherit) and StandardOutput=inherit",
        ),
        (
            "StandardError=inherit\nStandardOutput=inherit\nStandardInput=null",
            "neither -l nor -d, StandardError=inherit and StandardOutput=inherit",
        ),
        (
            "StandardOutput=inherit\nStandardInput=data",
            "neither -l nor -d, StandardError= not set (inherit) and StandardOutput=inherit",
        ),
        (
            "StandardOutput=inherit\nStandardInput=file:/var/log/in.log",
            "neither -l nor -d, StandardError= not set (inherit) and StandardOutput=inherit",
        ),
        // An earlier value is overridden.
        (
            "StandardOutput=file:/var/log/out.log\nStandardOutput=inherit",
            "neither -l nor -d, StandardError= not set (inherit) and StandardOutput=inherit",
        ),
    ] {
        assert_eq!(
            of_unit(&section(text), Stream::Error, TUNED_BY),
            journal(by),
            "{text:?}"
        );
    }
    // firewalld's console target writes to its standard output itself.
    assert_eq!(
        of_unit(
            &section("StandardOutput=inherit"),
            Stream::Output,
            "the log target console"
        ),
        journal("the log target console and StandardOutput=inherit")
    );
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
        journal("neither -l nor -d and StandardError=journal")
    );
    // firewalld's console target reads its standard output alone.
    assert_eq!(
        of_unit(
            &section("StandardError=append:/var/log/e.log"),
            Stream::Output,
            "the log target console"
        ),
        journal("the log target console and StandardOutput= not set")
    );
}

#[test]
fn what_nails_cannot_follow_of_a_unit_is_unknown() {
    let past = |settings: &str| {
        format!("it logs to its standard error, which NAILS cannot follow past {settings}")
    };
    for (text, settings) in [
        ("StandardError=fd:log", "StandardError=fd:log"),
        ("StandardError=journall", "StandardError=journall"),
        // The one descriptor a socket unit passes, a file among them.
        ("StandardError=socket", "StandardError=socket"),
        (
            "StandardError=socket\nStandardOutput=file:/var/log/both.log",
            "StandardError=socket",
        ),
        (
            "StandardOutput=socket",
            "StandardError= not set (inherit) and StandardOutput=socket",
        ),
        // A standard output left to inherit follows such an input.
        (
            "StandardOutput=inherit\nStandardInput=socket",
            "StandardError= not set (inherit), StandardOutput=inherit and StandardInput=socket",
        ),
        (
            "StandardInput=fd:input",
            "StandardError= not set (inherit), StandardOutput= not set and StandardInput=fd:input",
        ),
        // systemd ignores a file it does not take, which leaves the input
        // before it, and NAILS does not expand a specifier.
        (
            "StandardInput=file:in.log",
            "StandardError= not set (inherit), StandardOutput= not set and \
             StandardInput=file:in.log",
        ),
        (
            "StandardInput=file:/var/log/../in.log",
            "StandardError= not set (inherit), StandardOutput= not set and \
             StandardInput=file:/var/log/../in.log",
        ),
        (
            "StandardInput=file:%t/in.log",
            "StandardError= not set (inherit), StandardOutput= not set and \
             StandardInput=file:%t/in.log",
        ),
    ] {
        assert_eq!(
            unknown(of_unit(&section(text), Stream::Error, TUNED_BY)),
            past(settings),
            "{text:?}"
        );
    }
}

#[test]
fn a_process_stream_is_judged_by_where_its_descriptor_leads() {
    let by = TUNED_BY;
    // A socket is the journal's, which may be a namespace's.
    assert_eq!(
        led_to(Ok(PathBuf::from("socket:[24680]")), Stream::Error, by),
        journal("neither -l nor -d, its standard error being a socket, the journal's")
    );
    for target in [
        "/dev/null",
        "/dev/pts/1",
        "/dev/kmsg",
        "/dev/tty1",
        "/dev/ttyS0",
        "/dev/console",
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
    // Another device, as a disk's, is not judged.
    assert_eq!(
        unknown(led_to(Ok(PathBuf::from("/dev/sda1")), Stream::Error, by)),
        "it logs to /dev/sda1, a device NAILS does not judge"
    );
    // A pipe leads to its reader, which may copy what it reads into a file.
    assert_eq!(
        unknown(led_to(Ok(PathBuf::from("pipe:[13579]")), Stream::Error, by)),
        "it logs to its standard error, a pipe, which NAILS cannot follow past the process that \
         reads it"
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
