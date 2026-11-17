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
//! - `null` writes no file, and `tty` writes to the terminal `TTYPath=`
//!   names, `/dev/console` unless it names one, which counts as a device
//!   path does ([`log_to_path`]): the console, a virtual console or a serial
//!   line keeps nothing, while a pseudo-terminal leaves NAILS unable to
//!   tell. `TTYPath=` counts by its last value systemd takes: an empty one
//!   sets the default again, and systemd ignores a path that is not
//!   absolute or holds `..`, which leaves the one before; NAILS does not
//!   expand a specifier.
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
//!   the input comes from, the terminal, as for `tty`, or a socket unit's
//!   descriptor, which NAILS cannot tell of.
//!
//! A value NAILS does not know leaves the stream unknown.
//!
//! By a running process, as the link of its descriptor in `/proc` leads: a
//! device that keeps nothing is no file, and a descriptor that is closed
//! takes nothing. A pipe leads to the process that reads it, which may copy
//! what it reads into a file, as `tee` does, so NAILS cannot tell, and so
//! does a pseudo-terminal, whose other side the program that holds it may
//! copy into a file, as `script` does into its typescript. A socket is
//! judged by PID 1's socket table ([`super::sockets`]). Only root may follow
//! the descriptors of another user's process, so an unprivileged `nails
//! check` cannot tell where they lead.

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

/// The terminal of a unit whose `TTYPath=` names none.
const DEFAULT_TTY: &str = "/dev/console";

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

/// Whether `path` names a device by `prefix` and a number, as `/dev/tty1`.
fn numbered(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether `path` is a device that keeps nothing it is given: the null
/// device and its kin, the kernel's log buffer, whose lines go where the
/// journal's do, the console, a virtual console (`/dev/tty<n>`), a serial
/// line (`/dev/ttyS<n>`) or a hypervisor's console (`/dev/hvc<n>`).
fn is_sink(path: &str) -> bool {
    matches!(
        path,
        "/dev/null" | "/dev/zero" | "/dev/full" | "/dev/console" | "/dev/kmsg"
    ) || ["/dev/tty", "/dev/ttyS", "/dev/hvc"]
        .into_iter()
        .any(|prefix| numbered(path, prefix))
}

/// The controlling terminal of the process that opens it, which may be a
/// pseudo-terminal or not.
const CONTROLLING_TERMINAL: &str = "/dev/tty";

/// Whether `path` is a pseudo-terminal (`/dev/pts/<n>`), or the controlling
/// terminal (`/dev/tty`), which may be one: the program that holds its other
/// side may copy all it shows into a file.
fn is_pseudo_terminal(path: &str) -> bool {
    path == CONTROLLING_TERMINAL || numbered(path, "/dev/pts/")
}

/// Where a daemon logs that writes what it logs to `path`: nowhere for a
/// device that keeps nothing it is given ([`is_sink`]), unknown for a
/// pseudo-terminal ([`is_pseudo_terminal`]), as for a pipe, and for another
/// device, and otherwise the file `file` gives, one in `/dev/shm`, which is
/// in RAM, among them.
pub(super) fn log_to_path(path: &str, file: impl FnOnce() -> Log) -> Log {
    if is_sink(path) {
        Log::NoFile
    } else if is_pseudo_terminal(path) {
        let what = if path == CONTROLLING_TERMINAL {
            "the controlling terminal, which may be a pseudo-terminal"
        } else {
            "a pseudo-terminal"
        };
        Log::Unknown(format!(
            "it logs to {path}, {what}, whose other side the program that holds it may copy into a \
             file, as script does into its typescript"
        ))
    } else if path.starts_with("/dev/") && !path.starts_with("/dev/shm/") {
        Log::Unknown(format!("it logs to {path}, a device NAILS does not judge"))
    } else {
        file()
    }
}

/// The terminal of the unit whose `[Service]` section is `assignments`, as
/// systemd takes its `TTYPath=` (see the [module docs](self)).
///
/// # Errors
///
/// Why NAILS cannot tell: the value it takes has a specifier.
fn tty_path(assignments: &[Assignment]) -> Result<String, String> {
    let mut path = Ok(DEFAULT_TTY.to_string());
    for assignment in assignments
        .iter()
        .filter(|assignment| assignment.key == "TTYPath")
    {
        let value = assignment.value.as_str();
        if value.is_empty() {
            path = Ok(DEFAULT_TTY.to_string());
        } else if value.contains('%') {
            path = Err(format!(
                "NAILS does not expand the specifiers of its TTYPath={value}"
            ));
        } else if value.starts_with('/') && !value.split('/').any(|part| part == "..") {
            // systemd drops empty and `.` parts, as of a doubled slash.
            let parts: Vec<&str> = value
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect();
            path = Ok(format!("/{}", parts.join("/")));
        }
    }
    path
}

/// Where a stream of the unit whose `[Service]` section is `assignments`
/// leads that it sends to its terminal ([`tty_path`]), as a device path
/// leads ([`log_to_path`]): a terminal NAILS does not know leaves it unknown,
/// as systemd writes only to a terminal.
fn to_terminal(assignments: &[Assignment], stream: Stream) -> Log {
    match tty_path(assignments) {
        Ok(path) => log_to_path(&path, || {
            Log::Unknown(format!(
                "it logs to its {}, its terminal {path}, which NAILS does not judge",
                stream.name()
            ))
        }),
        Err(why) => Log::Unknown(format!(
            "it logs to its {}, its terminal, and {why}",
            stream.name()
        )),
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
            Some(input) if TERMINAL_INPUT.contains(&input) => {
                return to_terminal(assignments, stream);
            }
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
    match value {
        "null" => return Log::NoFile,
        "tty" => return to_terminal(assignments, stream),
        _ => {}
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
            let socket = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inode| inode.parse().ok());
            if let Some(inode) = socket {
                Log::Socket {
                    stream,
                    inode,
                    by: format!("{by}, its {name} being a socket, the journal's"),
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
