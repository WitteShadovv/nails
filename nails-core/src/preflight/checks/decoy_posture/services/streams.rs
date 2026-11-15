// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the standard output or the standard error of a daemon leads, for a
//! daemon that logs there: tuned and tuned-ppd without a log file, firewalld
//! with the log target `console`.
//!
//! By its unit, as the service manager of systemd 254 and later sets the two
//! up when it starts it (systemd.exec(5)). `StandardError=` and
//! `StandardOutput=` count by their last value that is not empty: systemd
//! ignores an empty one, which leaves the one before.
//!
//! - `file:`, `append:` and `truncate:` write the file they name, unless it
//!   is a device that keeps nothing ([`log_to_path`]).
//! - `journal`, `syslog`, `kmsg` and their `+console` forms send it to the
//!   journal, which may be a namespace's that persists
//!   ([`super::namespace`]): `kmsg` reaches the kernel's log buffer through
//!   the journal, which keeps each line as it hands it on.
//! - `null` and `tty` write no file.
//! - `socket` sends it to the one descriptor a socket unit passes the
//!   service, without which the service manager does not start it, and a
//!   named descriptor (`fd:`) to one a socket unit or the descriptor store
//!   passes. Either may be a file, as one a socket unit's `ListenSpecial=`
//!   opens is, so NAILS cannot tell where it leads.
//! - `inherit` sends the standard error where the standard output goes, and
//!   an unset standard error is `inherit`. Where the standard output takes
//!   its default, systemd gives such a standard error the default of
//!   `system.conf`, `DefaultStandardError=`, as well, which NAILS takes for
//!   `inherit`, systemd's own: a default never names a file, a socket or a
//!   descriptor, so none leads to a file where `inherit` does not.
//! - The standard output, `inherit` or unset, takes the service manager's
//!   default, `DefaultStandardOutput=`, which NAILS takes for the journal,
//!   systemd's own default and the only kind of default that may lead to a
//!   file, unless `StandardInput=` is a terminal (`tty`, `tty-force`,
//!   `tty-fail`), `socket` or a named descriptor: systemd's
//!   `service_fix_stdio()` gives an explicit `inherit` the default as it
//!   gives an unset one. After such an input the standard output goes where
//!   the input comes from, a terminal, which writes no file, or a socket
//!   unit's descriptor, which NAILS cannot tell of.
//!
//! A value NAILS does not know leaves the stream unknown.
//!
//! By a running process, as the link of its descriptor in `/proc` leads: a
//! socket is the journal's, and a device that keeps nothing is no file, and a
//! descriptor that is closed takes nothing. A pipe leads to the process that
//! reads it, which may copy what it reads into a file, as `tee` does, so
//! NAILS cannot tell. Only root may follow the descriptors of another user's
//! process, so an unprivileged `nails check` cannot tell where they lead.

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
const NO_FILE: &[&str] = &["null", "tty"];

/// The values of `StandardOutput=` and `StandardError=` that send a stream
/// to the journal: `kmsg` too, whose lines the journal keeps as it hands
/// them on to the kernel's log buffer.
const JOURNAL: &[&str] = &[
    "journal",
    "journal+console",
    "syslog",
    "syslog+console",
    "kmsg",
    "kmsg+console",
];

/// The values of `StandardInput=` that are a terminal, which a standard
/// output left to `inherit` writes to.
const TERMINAL_INPUT: &[&str] = &["tty", "tty-force", "tty-fail"];

/// Whether a standard output left to `inherit` takes the service manager's
/// default after `input`, the value of `StandardInput=`, as systemd's
/// `service_fix_stdio()` gives it: after `null`, `data` and a file. A file is
/// one only by an absolute path that names no specifier and no `..`, which
/// systemd takes; it ignores another, which leaves the value before, so
/// NAILS cannot tell.
fn takes_default_output(input: &str) -> bool {
    match input {
        "null" | "data" => true,
        _ => input.strip_prefix("file:").is_some_and(|path| {
            path.starts_with('/')
                && !path.contains('%')
                && !path.split('/').any(|part| part == "..")
        }),
    }
}

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
pub(super) fn listed(parts: &[String]) -> String {
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
        if !matches!(value, None | Some("inherit")) {
            break value;
        }
        if at == Stream::Error {
            at = Stream::Output;
            continue;
        }
        // The standard output takes the manager's default, the journal,
        // unless it follows a terminal or a socket unit's descriptor.
        match setting(assignments, "StandardInput") {
            Some(input) if TERMINAL_INPUT.contains(&input) => return Log::NoFile,
            Some(input) if !takes_default_output(input) => {
                followed.push(format!("StandardInput={input}"));
                break None;
            }
            _ => {
                return Log::Journal {
                    by: listed(&followed),
                    what: "its log",
                };
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
    if NO_FILE.contains(&value) {
        return Log::NoFile;
    }
    if JOURNAL.contains(&value) {
        return Log::Journal {
            by: listed(&followed),
            what: "its log",
        };
    }
    match FILE_KINDS.iter().find_map(|kind| value.strip_prefix(kind)) {
        Some(path) => log_to_path(path, || {
            Log::File(FileLog {
                path: path.to_string(),
                by: listed(&followed),
                what: "its log",
                namespace: None,
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
                Log::Journal {
                    by: format!("{by}, its {name} being a socket, the journal's"),
                    what: "its log",
                }
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
                        namespace: None,
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
