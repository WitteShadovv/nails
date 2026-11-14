// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The program PID 1 starts the binary copy through, where the session plan
//! records one ([`Plan::exec_prefix`]).
//!
//! Under SELinux a program PID 1 starts runs in the domain the policy gives
//! the type of the program's file, and in PID 1's own domain where it gives
//! that type none. The binary copy in `/run` carries the type of the files
//! there, so a step PID 1 starts from the copy itself runs in PID 1's domain,
//! which a targeted policy confines. A system program such as [`TRAMPOLINE`]
//! carries the type of the system's programs, which a targeted policy starts
//! in a service domain of its own, and `env` then runs the copy in its own
//! place: the step runs in that domain instead. So on a host that may run
//! SELinux the entry records [`TRAMPOLINE`] in the plan, and every unit and
//! drop-in by which PID 1 starts the copy starts it through the plan's prefix
//! ([`command`]):
//!
//! - the transition step's drop-in
//!   ([`crate::whole_root::transition::dropin_text`]), written once at entry
//!   and run in both directions;
//! - the hidden session's own units, the watcher and the sleep guard, whose
//!   text the entry writes into the plan
//!   ([`Plan::session_units`]);
//! - the pieces the way back leaves for the decoy's first start, the reconcile
//!   one-shot ([`crate::whole_root::boot_records`]) and the wtmpdb writer's
//!   drop-in ([`crate::whole_root::boot_writer`]).
//!
//! The udev rule that keeps unused disks read-only
//! ([`crate::whole_root::disk_guard`]) runs the copy directly: udev starts
//! it, not PID 1. Where the plan records no prefix, every one of them starts
//! the copy as before, word for word. Nothing is installed into the decoy's
//! policy.
//!
//! A step that does not start at all is worse than one that runs confined:
//! the drop-in's `-` ignores a start command that fails, and the switch goes
//! on without its step. So [`check`] tells whether a root holds the prefix as
//! PID 1 will start it there, and each root is checked before PID 1 starts
//! anything through it: the entry checks the decoy root, where the step of
//! the entry starts, and the next root, where the hidden session's units and
//! the step of the way back start; the way back checks the hidden root again
//! before it prepares anything, and the decoy root it mounts, where its pieces
//! for the decoy's first start run ([`crate::whole_root::ret`]).
//!
//! [`Plan::exec_prefix`]: crate::whole_root::plan::Plan::exec_prefix
//! [`Plan::session_units`]: crate::whole_root::plan::Plan::session_units

use crate::whole_root::nextroot;
use std::path::Path;

/// The program PID 1 starts the binary copy through on a host that may run
/// SELinux: given a program and its arguments, `env` runs that program in its
/// own place, and it takes no word after the program for an option of its
/// own.
pub const TRAMPOLINE: &str = "/usr/bin/env";

/// What PID 1 runs to start the binary copy at `binary`: `binary` alone, or
/// `prefix binary` where the plan records a `prefix`. The caller appends the
/// copy's arguments. `binary` is an absolute path, so `env` never reads it as
/// an option, and none of the copies' paths holds a `=`, which `env` would
/// read as a variable to set.
pub fn command(prefix: Option<&Path>, binary: &Path) -> String {
    match prefix {
        Some(prefix) => format!("{} {}", prefix.display(), binary.display()),
        None => binary.display().to_string(),
    }
}

/// Why a root cannot start the binary copy through a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// The prefix is not an absolute path of plain names ([`is_plain`]).
    NotPlain,
    /// Nothing is there, or a link on the way leads nowhere.
    Absent,
    /// The lookup failed otherwise, at a loop of links or a directory it may
    /// not search, say: its error.
    Unreachable(String),
    /// It resolves to something other than an executable regular file.
    NotExecutable,
}

/// What the prefix is or does in the root, to follow its path in a sentence:
/// "/usr/bin/env does not exist".
impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::NotPlain => write!(f, "is not an absolute path of plain names"),
            Unusable::Absent => write!(f, "does not exist"),
            Unusable::Unreachable(why) => write!(f, "cannot be looked up: {why}"),
            Unusable::NotExecutable => write!(f, "is not an executable file"),
        }
    }
}

/// Whether `prefix` is an absolute path of plain names, written as such: a
/// `/` before each name, none after the last, each name made of ASCII letters,
/// digits, `.`, `_`, `+` and `-` and none of them `.` or `..`. systemd reads
/// such a path from a unit file's start command word for word, with no
/// specifier, quote, escape or variable in it to expand, so the command starts
/// the program the plan names.
pub fn is_plain(prefix: &Path) -> bool {
    let Some(names) = prefix.to_str().and_then(|text| text.strip_prefix('/')) else {
        return false;
    };
    names.split('/').all(|name| {
        !matches!(name, "" | "." | "..")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    })
}

/// Check that `prefix` starts in `root` as PID 1 starts it once `root` is its
/// root: a plain absolute path ([`is_plain`]) that resolves inside `root`, its
/// links followed there as PID 1's start of it follows them, to an executable
/// regular file ([`nextroot::executable_in_root`]). The lookup reads no file,
/// so the program's access time stays as it is; a link on the way gets one,
/// as when PID 1 starts the program.
pub fn check(root: &Path, prefix: &Path) -> Result<(), Unusable> {
    if !is_plain(prefix) {
        return Err(Unusable::NotPlain);
    }
    match nextroot::executable_in_root(root, prefix) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Unusable::NotExecutable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Unusable::Absent),
        Err(e) => Err(Unusable::Unreachable(e.to_string())),
    }
}

#[cfg(test)]
#[path = "exec_prefix_tests.rs"]
mod tests;
