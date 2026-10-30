// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the locate-database check reads of a decoy's updatedb:
//! `/etc/updatedb.conf`, the `ExecStart=` of a service that runs updatedb,
//! and the shell of a cron job, with the options on their command lines.
//! NAILS has to read them as updatedb, systemd and the shell do: a difference
//! makes a decoy whose updatedb lists the hidden volume look safe.
//!
//! The input is the file's bytes up to the first two NULs in a row, after
//! them an `ExecStart=` value up to the next two, and after those a piece of
//! shell. The target checks that:
//!
//! - NAILS reads the file as plocate's `parse_updatedb_conf()` does (the
//!   model in `nails_fuzz::plocate`): the same lists, or a refusal on the
//!   same line, and the lists it reads, written back, read the same;
//! - the words NAILS splits the value into, quoted and escaped again, split
//!   into the same words;
//! - shell that names no updatedb runs none, and each updatedb command NAILS
//!   reads from the shell, its words quoted again, reads back the same;
//! - every prune entry, scan root, database and configuration file a command
//!   line gives is one of its words or part of one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_core::preflight::checks::locate_database::conf::{
    ConfErrorKind, UpdatedbConf, parse_updatedb_conf,
};
use nails_core::preflight::checks::locate_database::exec::{
    ExecCommand, exec_commands, is_updatedb, mentions_updatedb,
};
use nails_core::preflight::checks::locate_database::options::{Invocation, invocation};
use nails_core::preflight::checks::locate_database::shell::updatedb_runs;
use nails_fuzz::plocate;

fuzz_target!(|data: &[u8]| {
    let (conf, rest) = split(data);
    check_conf(conf);
    if let Some(rest) = rest {
        let (exec, shell) = split(rest);
        check_exec(&String::from_utf8_lossy(exec));
        if let Some(shell) = shell {
            check_shell(shell);
        }
    }
});

/// `bytes` up to its first two NULs in a row, and what follows them.
fn split(bytes: &[u8]) -> (&[u8], Option<&[u8]>) {
    match bytes.windows(2).position(|pair| pair == [0, 0]) {
        Some(at) => (&bytes[..at], Some(&bytes[at + 2..])),
        None => (bytes, None),
    }
}

/// `list` as updatedb keeps it: sorted, each entry once, and for `PRUNEFS`
/// in upper case.
fn finished(list: &[Vec<u8>], upper: bool) -> Vec<Vec<u8>> {
    let mut list: Vec<Vec<u8>> = list
        .iter()
        .map(|entry| {
            if upper {
                entry.to_ascii_uppercase()
            } else {
                entry.clone()
            }
        })
        .collect();
    list.sort();
    list.dedup();
    list
}

/// The message plocate prints for a refusal NAILS names `kind`.
fn message(kind: &ConfErrorKind) -> &'static str {
    match kind {
        ConfErrorKind::UnknownVariable(_) => "unknown variable",
        ConfErrorKind::VariableExpected => "variable name expected",
        ConfErrorKind::AlreadyDefined(_) => "variable was already defined",
        ConfErrorKind::EqualsExpected => "`=' expected after variable name",
        ConfErrorKind::QuotedValueExpected => "value in quotes expected after `='",
        ConfErrorKind::MissingClosingQuote => "missing closing `\"'",
        ConfErrorKind::InvalidBool(_) => "invalid value of PRUNE_BIND_MOUNTS",
        ConfErrorKind::DataAfterValue => "unexpected data after variable value",
    }
}

fn check_conf(bytes: &[u8]) {
    let read = parse_updatedb_conf(bytes);
    match (&read, plocate::parse_updatedb_conf(bytes)) {
        (Ok(conf), Ok(model)) => {
            assert_eq!(
                conf.prune_bind_mounts.unwrap_or(false),
                model.prune_bind_mounts
            );
            assert_eq!(finished(&conf.prunefs, true), model.prunefs);
            assert_eq!(finished(&conf.prunenames, false), model.prunenames);
            assert_eq!(finished(&conf.prunepaths, false), model.prunepaths);
        }
        (Err(error), Err(exit)) => {
            assert_eq!(error.line, exit.line, "{error:?} / {exit:?}");
            assert_eq!(message(&error.kind), exit.message, "{error:?} / {exit:?}");
        }
        (ours, theirs) => panic!("NAILS reads {ours:?}, updatedb {theirs:?}"),
    }
    if let Ok(conf) = read {
        assert_eq!(parse_updatedb_conf(&written(&conf)).as_ref(), Ok(&conf));
    }
}

/// `conf` written back as an `updatedb.conf`.
fn written(conf: &UpdatedbConf) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(flag) = conf.prune_bind_mounts {
        let line: &[u8] = if flag {
            b"PRUNE_BIND_MOUNTS = \"yes\"\n"
        } else {
            b"PRUNE_BIND_MOUNTS = \"no\"\n"
        };
        out.extend_from_slice(line);
    }
    for (name, list) in [
        ("PRUNEFS", &conf.prunefs),
        ("PRUNENAMES", &conf.prunenames),
        ("PRUNEPATHS", &conf.prunepaths),
    ] {
        if list.is_empty() {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b" = \"");
        out.extend_from_slice(&list.join(&b' '));
        out.extend_from_slice(b"\"\n");
    }
    out
}

/// `word` quoted for an `ExecStart=` value so that systemd reads it back as
/// it is: `%` doubled, and in an argument `$` doubled too; the quote, the
/// backslash and every byte that is not printable ASCII escaped.
fn quoted(word: &[u8], argument: bool) -> String {
    let mut out = String::from("\"");
    for &byte in word {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'%' => out.push_str("%%"),
            b'$' if argument => out.push_str("$$"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out.push('"');
    out
}

fn check_exec(value: &str) {
    let Ok(commands) = exec_commands(value) else {
        return;
    };
    for command in &commands {
        // A program that starts like a prefix, or that is a lone `;`, reads
        // as one again whatever its quotes.
        let reread = command
            .program
            .first()
            .is_some_and(|byte| b"-@:+!".contains(byte))
            || command.program == b";";
        if !reread {
            let mut again = quoted(&command.program, false);
            for arg in &command.args {
                again.push(' ');
                again.push_str(&quoted(arg, true));
            }
            assert_eq!(
                exec_commands(&again).as_deref(),
                Ok(std::slice::from_ref(command)),
                "{again}"
            );
        }
        check_options(command);
    }
}

fn check_options(command: &ExecCommand) {
    let Invocation::Scans(scan) = invocation(&command.args) else {
        return;
    };
    let given = |value: &[u8]| {
        value.is_empty()
            || command
                .args
                .iter()
                .any(|arg| arg.windows(value.len()).any(|window| window == value))
    };
    for change in [&scan.paths, &scan.fs, &scan.names] {
        for (value, _) in &change.entries {
            assert!(given(value), "{value:?} is in no argument");
        }
    }
    for value in [&scan.database_root, &scan.output, &scan.config_file]
        .into_iter()
        .flatten()
    {
        assert!(given(value), "{value:?} is in no argument");
    }
}

/// `word` in single quotes, which the shell reads back as it is: a quote in
/// it ends the quotes, is escaped, and opens them again.
fn single_quoted(word: &[u8]) -> Vec<u8> {
    let mut out = vec![b'\''];
    for &byte in word {
        if byte == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(byte);
        }
    }
    out.push(b'\'');
    out
}

fn check_shell(text: &[u8]) {
    let runs = updatedb_runs(text);
    if !mentions_updatedb(text) {
        assert!(runs.is_empty(), "{runs:?}");
    }
    for command in runs.into_iter().flatten() {
        assert!(is_updatedb(&command.program), "{command:?}");
        let mut again = single_quoted(&command.program);
        for arg in &command.args {
            again.push(b' ');
            again.extend(single_quoted(arg));
        }
        assert_eq!(
            updatedb_runs(&again),
            [Ok::<_, String>(command.clone())],
            "{}",
            String::from_utf8_lossy(&again)
        );
        check_options(&command);
    }
}
