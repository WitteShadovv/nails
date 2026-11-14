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
//! The check asks the running kernel's SELinux as well ([`domain`]), since a
//! program can stand where the prefix is and still keep the step in PID 1's
//! domain, or out of reach: the domain follows the label of the program's
//! file, and a file a hidden session renames or copies over the prefix with
//! its attributes keeps the label of where it came from. Where a policy is
//! loaded, the prefix must carry a label from which the policy lets PID 1
//! start it (`execute`, `read` and `open` on the file), gives that start a
//! domain other than PID 1's, and lets PID 1 enter that domain through it
//! (`transition` to the domain, and `entrypoint` on the file for the domain):
//! the permissions the kernel checks to open the file and to change the
//! domain at the start. What the domain may do once entered, the mapping of
//! the file and the start of the copy by `env` among it, is the policy's, and
//! is not asked.
//!
//! [`Plan::exec_prefix`]: crate::whole_root::plan::Plan::exec_prefix
//! [`Plan::session_units`]: crate::whole_root::plan::Plan::session_units

use crate::whole_root::nextroot;
use crate::whole_root::selinux::{self, Selinux};
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
    /// It carries `label`, which the loaded policy gives no domain of its own
    /// when PID 1, in the context `pid1`, starts it.
    OwnDomain {
        /// The label of the file.
        label: String,
        /// PID 1's context.
        pid1: String,
    },
    /// It carries `label`, and the loaded policy denies PID 1, in the context
    /// `pid1`, what the start needs.
    Denied {
        /// The label of the file.
        label: String,
        /// PID 1's context.
        pid1: String,
        /// What the policy denies.
        denial: Denial,
    },
    /// What the loaded policy makes of the start could not be told: why.
    Unjudged(String),
}

/// What the loaded policy denies a start of the prefix by PID 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// These permissions on the file, which PID 1 needs to start it.
    Start(Vec<&'static str>),
    /// The change from PID 1's context to this one, which the policy gives
    /// the start.
    Transition(String),
    /// Entering this context, which the policy gives the start, through the
    /// file.
    Entrypoint(String),
}

/// What a start of the prefix by PID 1 comes to, where a root cannot start
/// the copy through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// The start fails: what PID 1 starts through the prefix does not run.
    NotStarted,
    /// What PID 1 starts through the prefix runs in PID 1's own domain.
    OwnDomain,
    /// Either may happen, or neither: the policy could not be asked.
    Unknown,
}

/// What would make the prefix usable in the root again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    /// A program at the prefix: install it, or bring the decoy's back.
    Program,
    /// A program the policy starts as the check needs: give it the label the
    /// policy gives the system's programs, or bring the decoy's back.
    Label,
    /// A policy the check can ask.
    Policy,
}

impl Unusable {
    /// What a start of the prefix by PID 1 comes to.
    pub fn effect(&self) -> Effect {
        match self {
            Unusable::OwnDomain { .. } => Effect::OwnDomain,
            Unusable::Unjudged(_) => Effect::Unknown,
            _ => Effect::NotStarted,
        }
    }

    /// What would make the prefix usable in the root again.
    pub fn remedy(&self) -> Remedy {
        match self {
            Unusable::OwnDomain { .. } | Unusable::Denied { .. } => Remedy::Label,
            Unusable::Unjudged(_) => Remedy::Policy,
            _ => Remedy::Program,
        }
    }
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
            Unusable::OwnDomain { label, pid1 } => write!(
                f,
                "is labelled {label}, which the loaded SELinux policy gives no domain of its own \
                 when PID 1 ({pid1}) starts it"
            ),
            Unusable::Denied {
                label,
                pid1,
                denial,
            } => {
                write!(f, "is labelled {label}, and the loaded SELinux policy ")?;
                match denial {
                    Denial::Start(perms) => {
                        write!(f, "does not let PID 1 ({pid1}) {} it", either(perms))
                    }
                    Denial::Transition(domain) => write!(
                        f,
                        "gives PID 1's start of it the domain {domain} but does not let PID 1 \
                         ({pid1}) change to it"
                    ),
                    Denial::Entrypoint(domain) => write!(
                        f,
                        "gives PID 1's start of it the domain {domain} but does not let that \
                         domain be entered through it"
                    ),
                }
            }
            Unusable::Unjudged(why) => {
                write!(
                    f,
                    "cannot be judged against the loaded SELinux policy: {why}"
                )
            }
        }
    }
}

/// `words` as a list in a sentence that denies each: "execute, read or open".
fn either(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
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
/// regular file ([`nextroot::executable_in_root`]), which PID 1 starts in a
/// domain of its own where `selinux` has a policy loaded ([`domain`]). The
/// lookup reads no file, so the program's access time stays as it is; a link
/// on the way gets one, as when PID 1 starts the program.
pub fn check(root: &Path, prefix: &Path, selinux: &dyn Selinux) -> Result<(), Unusable> {
    if !is_plain(prefix) {
        return Err(Unusable::NotPlain);
    }
    match nextroot::executable_in_root(root, prefix) {
        Ok(true) => domain(root, prefix, selinux),
        Ok(false) => Err(Unusable::NotExecutable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Unusable::Absent),
        Err(e) => Err(Unusable::Unreachable(e.to_string())),
    }
}

/// The permissions on a program's file that PID 1 needs to start it: the
/// kernel asks `execute` at the lookup, and `read` and `open` as it opens the
/// file for the start.
pub const START: [&str; 3] = ["execute", "read", "open"];

/// Check what the loaded policy, as `selinux` tells it, makes of PID 1's start
/// of `prefix` in `root`: nothing where no policy is loaded
/// ([`Selinux::pid1`]). Else the file at `prefix` must carry a label that PID 1
/// may start ([`START`]), from which the policy gives the start a domain other
/// than PID 1's, compared by type ([`selinux::type_of`]), and lets PID 1 change
/// to it (`transition`) and the domain be entered through the file
/// (`entrypoint`). A question that fails, as with no selinuxfs mounted, fails
/// the check too ([`Unusable::Unjudged`]).
pub fn domain(root: &Path, prefix: &Path, selinux: &dyn Selinux) -> Result<(), Unusable> {
    let unjudged = |what: &str, e: std::io::Error| Unusable::Unjudged(format!("{what}: {e}"));
    let Some(pid1) = selinux
        .pid1()
        .map_err(|e| unjudged("PID 1's context cannot be read", e))?
    else {
        return Ok(());
    };
    let label = selinux
        .label(root, prefix)
        .map_err(|e| unjudged("its label cannot be read", e))?;
    let asked = |e| unjudged("the policy cannot be asked", e);
    let start = selinux
        .denied(&pid1, &label, "file", &START)
        .map_err(asked)?;
    let denied = |denial| Unusable::Denied {
        label: label.clone(),
        pid1: pid1.clone(),
        denial,
    };
    if !start.is_empty() {
        return Err(denied(Denial::Start(start)));
    }
    let entered = selinux.exec_context(&pid1, &label).map_err(asked)?;
    match (selinux::type_of(&pid1), selinux::type_of(&entered)) {
        (Some(own), Some(new)) if own == new => {
            return Err(Unusable::OwnDomain {
                label: label.clone(),
                pid1: pid1.clone(),
            });
        }
        (Some(_), Some(_)) => {}
        _ => {
            return Err(Unusable::Unjudged(format!(
                "{pid1} or {entered} is no SELinux context with a type"
            )));
        }
    }
    if !selinux
        .denied(&pid1, &entered, "process", &["transition"])
        .map_err(asked)?
        .is_empty()
    {
        return Err(denied(Denial::Transition(entered)));
    }
    if !selinux
        .denied(&entered, &label, "file", &["entrypoint"])
        .map_err(asked)?
        .is_empty()
    {
        return Err(denied(Denial::Entrypoint(entered)));
    }
    Ok(())
}

#[cfg(test)]
#[path = "exec_prefix_tests.rs"]
mod tests;
