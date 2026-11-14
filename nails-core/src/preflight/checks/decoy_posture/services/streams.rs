// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the standard output or the standard error of a daemon leads, for a
//! daemon that logs there: tuned and tuned-ppd without a log file, firewalld
//! with the log target `console`.
//!
//! By its unit, as the service manager sets the two up when it starts it
//! (systemd.exec(5)). `StandardError=` and `StandardOutput=` count by their
//! last value that is not empty: systemd ignores an empty one, which leaves
//! the one before. `file:`, `append:` and `truncate:` write the file they
//! name, unless it is a device that keeps nothing ([`log_to_path`]), and
//! `null`, `journal`, `kmsg`, `tty` and their `+console` forms write none. `inherit` sends the standard error where the standard output
//! goes, and the standard output where the standard input comes from, which
//! is no file unless `StandardInput=` names one or a descriptor of a socket
//! unit. So does `socket`, for a service that no socket starts. Unset, each
//! takes the service manager's default (`DefaultStandardError=` and
//! `DefaultStandardOutput=` in `system.conf`), which systemd never lets name
//! a file, a socket or a descriptor: the default standard error is `inherit`
//! unless `system.conf` sets another, and NAILS takes `inherit`, the only one
//! that may lead to a file. A value NAILS does not know, such as a named
//! descriptor (`fd:`), leaves it unknown.
//!
//! By a running process, as the link of its descriptor in `/proc` leads: a
//! socket, or a device that keeps nothing, is no file, and a descriptor that
//! is closed takes nothing. A pipe leads to the process that reads it, which may copy what
//! it reads into a file, as `tee` does, so NAILS cannot tell. Only root may
//! follow the descriptors of another user's process, so an unprivileged
//! `nails check` cannot tell where they lead.

use super::super::super::systemd_conf::Assignment;
use super::options::{FileLog, Log};
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// A standard stream a daemon logs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::preflight::checks::decoy_posture) enum Stream {
    /// Its standard output, descriptor 1.
    Output,
    /// Its standard error, descriptor 2.
    Error,
}

impl Stream {
    /// The unit setting that sends it.
    fn setting(self) -> &'static str {
        match self {
            Stream::Output => "StandardOutput",
            Stream::Error => "StandardError",
        }
    }

    /// Its name, as a finding says it.
    pub(super) fn name(self) -> &'static str {
        match self {
            Stream::Output => "standard output",
            Stream::Error => "standard error",
        }
    }

    /// Its descriptor.
    fn fd(self) -> u8 {
        match self {
            Stream::Output => 1,
            Stream::Error => 2,
        }
    }
}

/// The values of `StandardOutput=` and `StandardError=` that send a stream
/// to no file.
const NO_FILE: &[&str] = &[
    "null",
    "journal",
    "kmsg",
    "journal+console",
    "kmsg+console",
    "tty",
    "syslog",
    "syslog+console",
];

/// The values of `StandardInput=` from which a standard output that follows
/// the input writes to no file.
const NO_FILE_INPUT: &[&str] = &["null", "tty", "tty-force", "tty-fail", "data", "socket"];

/// The kinds of value that write the file after them.
const FILE_KINDS: &[&str] = &["file:", "append:", "truncate:"];

/// Whether `path` is a device that keeps nothing it is given: the null
/// device and its kin, a terminal or a console, or the kernel's log buffer,
/// whose lines go where the journal's do.
fn is_sink(path: &str) -> bool {
    let numbered = |prefix: &str| {
        path.strip_prefix(prefix).is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    };
    matches!(
        path,
        "/dev/null" | "/dev/zero" | "/dev/full" | "/dev/console" | "/dev/kmsg" | "/dev/tty"
    ) || ["/dev/tty", "/dev/pts/", "/dev/hvc"]
        .into_iter()
        .any(numbered)
}

/// Where a daemon logs that writes what it logs to `path`: nowhere for a
/// device that keeps nothing it is given ([`is_sink`]), unknown for another
/// device, and otherwise the file `file` gives, one in `/dev/shm`, which is
/// in RAM, among them.
pub(super) fn log_to_path(path: &str, file: impl FnOnce() -> Log) -> Log {
    if is_sink(path) {
        Log::NoFile
    } else if path.starts_with("/dev/") && !path.starts_with("/dev/shm/") {
        Log::Unknown(format!("it logs to {path}, a device NAILS does not judge"))
    } else {
        file()
    }
}

/// The last value of `key` in `assignments` that is not empty.
fn setting<'a>(assignments: &'a [Assignment], key: &str) -> Option<&'a str> {
    assignments
        .iter()
        .rev()
        .find(|assignment| assignment.key == key && !assignment.value.is_empty())
        .map(|assignment| assignment.value.as_str())
}

/// `parts` joined as a list is said: `a`, `a and b`, `a, b and c`.
fn listed(parts: &[String]) -> String {
    match parts.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// Where `stream` leads by the unit whose `[Service]` section is
/// `assignments`, for a daemon that logs to it as `by` says (see the
/// [module docs](self)).
pub(super) fn of_unit(assignments: &[Assignment], stream: Stream, by: &str) -> Log {
    let mut followed = vec![by.to_string()];
    let mut at = stream;
    let value = loop {
        let key = at.setting();
        let value = setting(assignments, key);
        followed.push(match (value, at) {
            (Some(value), _) => format!("{key}={value}"),
            (None, Stream::Error) => format!("{key}= not set (inherit)"),
            (None, Stream::Output) => format!("{key}= not set"),
        });
        let follows = matches!(
            (at, value),
            (_, None | Some("inherit")) | (Stream::Error, Some("socket"))
        );
        match (follows, at) {
            (false, _) => break value,
            (true, Stream::Error) => at = Stream::Output,
            // The standard output follows the standard input.
            (true, Stream::Output) => {
                let input = setting(assignments, "StandardInput");
                if input.is_none_or(|input| NO_FILE_INPUT.contains(&input)) {
                    return Log::NoFile;
                }
                followed.push(format!("StandardInput={}", input.unwrap_or_default()));
                break None;
            }
        }
    };
    let unknown = || {
        Log::Unknown(format!(
            "it logs to its {}, which NAILS cannot follow past {}",
            stream.name(),
            listed(&followed[1..])
        ))
    };
    let Some(value) = value else {
        return unknown();
    };
    if NO_FILE.contains(&value) || (at == Stream::Output && value == "socket") {
        return Log::NoFile;
    }
    match FILE_KINDS.iter().find_map(|kind| value.strip_prefix(kind)) {
        Some(path) => log_to_path(path, || {
            Log::File(FileLog {
                path: path.to_string(),
                by: listed(&followed),
                what: "its log",
            })
        }),
        None => unknown(),
    }
}

/// Where `stream` of process `pid` under `root` leads, for a daemon that logs
/// to it as `by` says, by the link of its descriptor.
pub(super) fn of_process<F: Filesystem>(
    fs: &F,
    root: &Path,
    pid: &str,
    stream: Stream,
    by: &str,
) -> Log {
    let link = root.join(format!("proc/{pid}/fd/{}", stream.fd()));
    led_to(fs.read_link(&link), stream, by)
}

/// Where a descriptor of `stream` leads, `target` being what reading its
/// link gave.
fn led_to(target: crate::Result<PathBuf>, stream: Stream, by: &str) -> Log {
    let name = stream.name();
    match target {
        Ok(target) => {
            let target = target.to_string_lossy().into_owned();
            if target.starts_with("socket:") {
                Log::NoFile
            } else if target.starts_with("pipe:") {
                Log::Unknown(format!(
                    "it logs to its {name}, a pipe, which NAILS cannot follow past the process \
                     that reads it"
                ))
            } else if target.starts_with('/') {
                log_to_path(&target, || {
                    Log::File(FileLog {
                        path: target.clone(),
                        by: format!("{by}, its {name} being that file"),
                        what: "its log",
                    })
                })
            } else {
                Log::Unknown(format!("it logs to its {name}, which leads to {target}"))
            }
        }
        // Closed, it takes nothing; or the process has ended since.
        Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => Log::NoFile,
        Err(e) if e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) => {
            Log::Unknown(format!(
                "it logs to its {name}, which only root may follow; run the command again with \
                 sudo"
            ))
        }
        Err(e) => Log::Unknown(format!(
            "it logs to its {name}, which NAILS cannot follow ({e})"
        )),
    }
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod tests;
