// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux label of NAILS's own program in RAM.
//!
//! PID 1 starts NAILS's own steps from a RAM copy of the binary: the
//! transition step of `systemd-soft-reboot.service`, in both directions, and
//! the hidden session's watcher and sleep guard from the copy in
//! [`RUNTIME_DIR`](crate::whole_root::plan::RUNTIME_DIR); after the way back,
//! the decoy's reconcile one-shot and the wtmpdb writer's drop-in from the copy
//! in [`FIXUP_DIR_PATH`](crate::whole_root::boot_records::FIXUP_DIR_PATH).
//! Under SELinux a program PID 1 starts runs in the domain the loaded policy
//! gives a start from PID 1's context through the label of the program's
//! file, and in PID 1's own domain where it gives none. A file written in
//! `/run` takes the label of the files there, which a targeted policy gives no
//! domain of its own: every one of those steps would run in PID 1's domain,
//! which that policy confines, and be denied the kernel log the way back takes
//! its cursor from, the network state it puts back and the copy it leaves for
//! the decoy's first start.
//!
//! So where the session plan records a label ([`Plan::program_label`]), every
//! RAM copy of the binary gets it, [`PROGRAM_LABEL`], the label of the
//! system's programs: a targeted policy starts a program of that label that
//! PID 1 runs in [`DOMAIN`], which it does not confine, and the unit files and
//! drop-ins name the copy as they do on every other host. Nothing is
//! installed into the policy: the label and the change of domain are both the
//! policy's own. The entry decides it from the host facts and records it in
//! the plan, so both directions agree:
//!
//! - [`label_file`] gives a copy the label right after it is written, through
//!   the descriptor it was written through, and reads it back: a label that
//!   does not read back as written fails, so no step starts from a copy that
//!   kept the label of the files in `/run`. The entry does this for its copy,
//!   and the way back's last step for the copy it leaves for the decoy's first
//!   start ([`crate::whole_root::boot_records::install`]), whose pieces it
//!   leaves out when the copy does not take the label;
//! - [`ready`] gives the copy at a path the label again and asks the loaded
//!   policy what PID 1's start of it comes to ([`check_start`]): the entry,
//!   `deactivate` and the emergency's way back do this right before they arm
//!   their switch, so that whatever relabelled `/run` meanwhile does not
//!   decide the domain of the step;
//! - [`check_start`] fails unless the policy lets PID 1 start a file of that
//!   label in [`DOMAIN`], under every condition PID 1 may start NAILS's units
//!   in: from `/run`, which systemd mounts `nosuid`, and with
//!   `NoNewPrivileges=`, which a drop-in for every service can set.
//!
//! The switch itself can take the label off again. At a switch where PID 1
//! loads the policy anew, as on a host that runs SELinux permissive or whose
//! policy lets PID 1 map the policy file, it gives every file on `/run` the
//! label of the files there, after the switch's last step started from the
//! copy and before it starts the units of the root it switched to; a
//! `restorecon` over `/run` does the same at any time. So each unit PID 1
//! starts from a copy after a switch checks its own domain first
//! ([`enter_domain`]): the hidden session's watcher and sleep guard, and the
//! decoy's reconcile one-shot and the wtmpdb writer's drop-in. One that runs
//! anywhere but in [`DOMAIN`] gives its copy the label again and starts
//! itself again from it, once; the policy gives that start from PID 1's own
//! domain what it gives a start by PID 1. One that then still runs elsewhere,
//! or whose copy does not take the label, does not do its work there: the
//! caller ends it as its fail-closed end has it.
//!
//! The udev rule that keeps unused disks read-only
//! ([`crate::whole_root::disk_guard`]) runs the copy too, but udevd starts
//! it, not PID 1, and keeps its own domain for a program of this label.
//!
//! [`Plan::program_label`]: crate::whole_root::plan::Plan::program_label

use crate::whole_root::selinux::{Selinux, type_of};
use rustix::fd::{AsFd, BorrowedFd};
use rustix::fs::{FileType, Mode, OFlags};
use std::io;
use std::path::Path;

/// The label of the system's programs under a targeted policy, which every
/// RAM copy of the binary gets where the plan records a label.
pub const PROGRAM_LABEL: &str = "system_u:object_r:bin_t:s0";

/// The domain a targeted policy starts a program of [`PROGRAM_LABEL`] in when
/// PID 1 starts it: the unconfined domain of the system's services.
pub const DOMAIN: &str = "unconfined_service_t";

/// The policy capability without which the kernel changes no domain at the
/// start of a program from a `nosuid` mount or under `no_new_privs`, except
/// into a domain the policy bounds by the old one.
pub const NNP_NOSUID: &str = "nnp_nosuid_transition";

/// The permissions on a program's file that PID 1 needs to start it: the
/// kernel asks `execute` as it looks the file up, and `read` and `open` as it
/// opens it for the start, both in PID 1's domain.
pub const START: [&str; 3] = ["execute", "read", "open"];

/// How a copy is opened to give it the label again: the file itself, for its
/// attributes only, a link in its place not followed.
const COPY: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// The label a copy takes as it is written, and the SELinux that writes it
/// and reads it back.
#[derive(Debug, Clone, Copy)]
pub struct Labelling<'a> {
    /// What writes the label and reads it back: the running kernel, or a
    /// test's stand-in.
    pub selinux: &'a dyn Selinux,
    /// The label, as the plan records it ([`PROGRAM_LABEL`]).
    pub label: &'a str,
}

/// Why a copy does not carry the label, to follow its path in a sentence:
/// "/run/overlay-runtime/control is not a regular file".
#[derive(Debug)]
pub enum Unlabelled {
    /// It could not be opened, as where it is missing or a link stands in its
    /// place: the kernel's error.
    Open(io::Error),
    /// Something other than a regular file stands where the copy should be.
    NotAFile,
    /// The label could not be written: the kernel's error, as where its
    /// filesystem stores no labels or the policy does not let NAILS relabel.
    Write(io::Error),
    /// The label could not be read back after the write: the kernel's error.
    Read(io::Error),
    /// It reads back as this other label.
    Other(String),
}

impl std::fmt::Display for Unlabelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unlabelled::Open(e) => write!(f, "could not be opened: {e}"),
            Unlabelled::NotAFile => f.write_str("is not a regular file"),
            Unlabelled::Write(e) => write!(f, "could not take the label: {e}"),
            Unlabelled::Read(e) => write!(f, "could not be read back after the label: {e}"),
            Unlabelled::Other(found) => write!(f, "reads back as {found} after the label"),
        }
    }
}

/// Give the copy open as `file` the SELinux label `label`, as libselinux
/// writes one (with its NUL), and read it back. A label that does not read
/// back as `label`, whatever NUL ends either, is an error, as is a write or a
/// read the kernel refuses.
pub fn label_file(
    selinux: &dyn Selinux,
    file: BorrowedFd<'_>,
    label: &str,
) -> Result<(), Unlabelled> {
    let mut value = label.as_bytes().to_vec();
    value.push(0);
    selinux.set_label(file, &value).map_err(Unlabelled::Write)?;
    let found = selinux.label(file).map_err(Unlabelled::Read)?;
    let found = without_nul(&found);
    if found == label.as_bytes() {
        Ok(())
    } else {
        Err(Unlabelled::Other(
            String::from_utf8_lossy(found).into_owned(),
        ))
    }
}

/// [`label_file`] for the copy at `path`, opened without following a link in
/// its last component: it must be a regular file. Opening it reads nothing,
/// so no access time moves.
pub fn label_path(selinux: &dyn Selinux, path: &Path, label: &str) -> Result<(), Unlabelled> {
    let file = rustix::fs::open(path, COPY, Mode::empty())
        .map_err(|e| Unlabelled::Open(io::Error::from(e)))?;
    let stat = rustix::fs::fstat(&file).map_err(|e| Unlabelled::Open(io::Error::from(e)))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(Unlabelled::NotAFile);
    }
    label_file(selinux, file.as_fd(), label)
}

/// `value` without the NULs it ends with.
fn without_nul(value: &[u8]) -> &[u8] {
    let end = value
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |at| at + 1);
    &value[..end]
}

/// What PID 1's start of a file of the label comes to under the loaded
/// policy, where it does not run in [`DOMAIN`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unfit {
    /// The policy denies PID 1, in the context `pid1`, these permissions on
    /// the file, which the start needs ([`START`]).
    Start {
        /// PID 1's context.
        pid1: String,
        /// What the policy denies.
        perms: Vec<&'static str>,
    },
    /// The policy gives the start no domain of its own: it runs in PID 1's.
    OwnDomain {
        /// PID 1's context.
        pid1: String,
    },
    /// The policy gives the start the context `entered`, whose domain is not
    /// [`DOMAIN`].
    Elsewhere {
        /// PID 1's context.
        pid1: String,
        /// The context the start enters.
        entered: String,
    },
    /// The policy gives the start [`DOMAIN`] but denies `perms` of `class`
    /// that the change needs.
    Denied {
        /// PID 1's context.
        pid1: String,
        /// The context the start enters.
        entered: String,
        /// The class of the permissions denied.
        class: &'static str,
        /// What the policy denies.
        perms: Vec<&'static str>,
    },
    /// The policy does not turn [`NNP_NOSUID`] on.
    Capability,
    /// What the policy makes of the start could not be told: why.
    Unjudged(String),
}

/// What a start of the copy by PID 1 comes to, where it does not run in
/// [`DOMAIN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// The start fails: the step does not run, and a switch goes on without
    /// it.
    NotStarted,
    /// The step runs in a domain the policy may confine: PID 1's own, or
    /// another one.
    Confined,
    /// Either may happen, or neither: the policy could not be asked.
    Unknown,
}

impl Unfit {
    /// What PID 1's start of the copy comes to. The kernel fails a start the
    /// policy denies `execute`, `read`, `open`, `transition` or `entrypoint`
    /// for; it keeps PID 1's domain where the policy gives none, or where the
    /// change from a `nosuid` mount or under `no_new_privs` is not allowed.
    pub fn effect(&self) -> Effect {
        match self {
            Unfit::Start { .. } => Effect::NotStarted,
            Unfit::Denied { class, .. } if *class != "process2" => Effect::NotStarted,
            Unfit::Unjudged(_) => Effect::Unknown,
            _ => Effect::Confined,
        }
    }
}

/// `words` as a list in a sentence: "execute, read or open".
fn either(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// What PID 1's start of a file of the label comes to, to follow "PID 1's
/// start of a file so labelled" in a sentence.
impl std::fmt::Display for Unfit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unfit::Start { pid1, perms } => write!(
                f,
                "is denied: the loaded SELinux policy does not let PID 1 ({pid1}) {} such a file",
                either(perms)
            ),
            Unfit::OwnDomain { pid1 } => write!(
                f,
                "runs in PID 1's own domain ({pid1}): the loaded SELinux policy gives it no \
                 domain of its own"
            ),
            Unfit::Elsewhere { pid1, entered } => write!(
                f,
                "runs in {entered}, not in {DOMAIN}: that is the domain the loaded SELinux policy \
                 gives it when PID 1 ({pid1}) starts it"
            ),
            Unfit::Denied {
                pid1,
                entered,
                class,
                perms,
            } => write!(
                f,
                "would enter {entered}, but the loaded SELinux policy denies the {class} \
                 permission {} that PID 1 ({pid1}) needs to change into it",
                either(perms)
            ),
            Unfit::Capability => write!(
                f,
                "keeps PID 1's own domain: the kernel changes the domain at a start from a \
                 nosuid mount, as /run is, or under NoNewPrivileges= only where the loaded \
                 SELinux policy turns its capability {NNP_NOSUID} on, and it does not"
            ),
            Unfit::Unjudged(why) => {
                write!(
                    f,
                    "cannot be judged against the loaded SELinux policy: {why}"
                )
            }
        }
    }
}

/// Check what the loaded policy, as `selinux` tells it, makes of PID 1's start
/// of a file labelled `label`: nothing where no policy is loaded
/// ([`Selinux::pid1`]). Else the policy must let PID 1 start such a file
/// ([`START`]), give the start the domain [`DOMAIN`], compared by type
/// ([`type_of`]), and let PID 1 change into it (`transition`, and
/// `nnp_transition` and `nosuid_transition` with [`NNP_NOSUID`] on, as the
/// copies lie on a `nosuid` mount and a unit may set `NoNewPrivileges=`) and
/// the domain be entered through the file (`entrypoint`): the permissions the
/// kernel checks to open the file and to change the domain at the start. What
/// the domain may do once entered is the policy's, and is not asked. A
/// question that fails, as with no selinuxfs mounted, fails the check too
/// ([`Unfit::Unjudged`]).
pub fn check_start(selinux: &dyn Selinux, label: &str) -> Result<(), Unfit> {
    let unjudged = |what: &str, e: io::Error| Unfit::Unjudged(format!("{what}: {e}"));
    let Some(pid1) = selinux
        .pid1()
        .map_err(|e| unjudged("PID 1's context cannot be read", e))?
    else {
        return Ok(());
    };
    let asked = |e| unjudged("the policy cannot be asked", e);
    let start = selinux
        .denied(&pid1, label, "file", &START)
        .map_err(asked)?;
    if !start.is_empty() {
        return Err(Unfit::Start { pid1, perms: start });
    }
    let entered = selinux.exec_context(&pid1, label).map_err(asked)?;
    match (type_of(&pid1), type_of(&entered)) {
        (Some(own), Some(new)) if own == new => return Err(Unfit::OwnDomain { pid1 }),
        (Some(_), Some(DOMAIN)) => {}
        (Some(_), Some(_)) => return Err(Unfit::Elsewhere { pid1, entered }),
        _ => {
            return Err(Unfit::Unjudged(format!(
                "{pid1} or {entered} is no SELinux context with a type"
            )));
        }
    }
    let changes: [(&str, &str, &'static str, &[&'static str]); 3] = [
        (pid1.as_str(), entered.as_str(), "process", &["transition"]),
        (
            pid1.as_str(),
            entered.as_str(),
            "process2",
            &["nnp_transition", "nosuid_transition"],
        ),
        (entered.as_str(), label, "file", &["entrypoint"]),
    ];
    for (source, target, class, perms) in changes {
        let denied = selinux
            .denied(source, target, class, perms)
            .map_err(asked)?;
        if !denied.is_empty() {
            return Err(Unfit::Denied {
                pid1: pid1.clone(),
                entered: entered.clone(),
                class,
                perms: denied,
            });
        }
    }
    if !selinux.capability(NNP_NOSUID).map_err(asked)? {
        return Err(Unfit::Capability);
    }
    Ok(())
}

/// Why a copy is not ready for a switch.
#[derive(Debug)]
pub enum NotReady {
    /// It does not carry the label.
    Unlabelled(Unlabelled),
    /// PID 1's start of it would not run in [`DOMAIN`].
    Unfit(Unfit),
}

/// Give the copy at `path` the label `label` again ([`label_path`]) and check
/// what PID 1's start of it comes to ([`check_start`]): what every switch
/// needs right before it is armed.
pub fn ready(selinux: &dyn Selinux, path: &Path, label: &str) -> Result<(), NotReady> {
    label_path(selinux, path, label).map_err(NotReady::Unlabelled)?;
    check_start(selinux, label).map_err(NotReady::Unfit)
}

/// The environment variable a unit PID 1 started from a RAM copy sets when
/// it starts itself again from that copy ([`enter_domain`]), so that the
/// start again does not start itself once more.
pub const STARTED_AGAIN: &str = "OVERLAY_RUNTIME_STARTED_AGAIN";

/// Why a unit PID 1 started from a RAM copy does not run in [`DOMAIN`]. It
/// is not shown: such a unit runs with no output and no log.
#[derive(Debug)]
pub enum Outside {
    /// Whether a policy is loaded, or the context it runs in, could not be
    /// read: the kernel's error.
    Unread(io::Error),
    /// Its copy did not take the label again.
    Unlabelled(Unlabelled),
    /// Its start again from its copy failed: the kernel's error.
    NotStarted(io::Error),
    /// It runs in this context, though it is the start again from its copy
    /// with the label.
    Still(String),
}

/// Keep a unit that PID 1 started from the RAM copy at `copy` from doing its
/// work anywhere but in [`DOMAIN`], where a policy is loaded as `selinux`
/// tells it. A unit that runs elsewhere gives `copy` the label
/// [`PROGRAM_LABEL`] again ([`label_path`]) and starts itself again from it
/// through `start_again`, which returns only where that start fails: from
/// PID 1's own domain the policy gives the start what it gives a start by
/// PID 1. The start again (`again`) that still runs elsewhere fails, as does
/// a unit whose copy does not take the label and one that cannot read its
/// context. `Ok` is a unit that runs in [`DOMAIN`], one that runs where no
/// policy is loaded ([`Selinux::pid1`]), which is asked nothing more, and
/// one PID 1 did not start (`by_pid1`), which is asked nothing at all: only
/// PID 1 starts NAILS's units, and what an operator starts by hand runs in
/// the operator's domain.
pub fn enter_domain(
    selinux: &dyn Selinux,
    copy: &Path,
    by_pid1: bool,
    again: bool,
    start_again: impl FnOnce() -> io::Error,
) -> Result<(), Outside> {
    if !by_pid1 || selinux.pid1().map_err(Outside::Unread)?.is_none() {
        return Ok(());
    }
    let own = selinux.current().map_err(Outside::Unread)?;
    if type_of(&own) == Some(DOMAIN) {
        return Ok(());
    }
    if again {
        return Err(Outside::Still(own));
    }
    label_path(selinux, copy, PROGRAM_LABEL).map_err(Outside::Unlabelled)?;
    Err(Outside::NotStarted(start_again()))
}

/// What keeps the copy at `path` from being ready, as a sentence of its own
/// for a report: "the RAM copy of the binary at /run/overlay-runtime/control
/// could not take the label: ...".
pub fn not_ready_text(path: &Path, label: &str, not_ready: &NotReady) -> String {
    let path = path.display();
    match not_ready {
        NotReady::Unlabelled(unlabelled) => format!(
            "the RAM copy of the binary at {path}, which must carry the SELinux label {label}, \
             {unlabelled}"
        ),
        NotReady::Unfit(unfit) => {
            format!(
                "PID 1's start of the RAM copy of the binary at {path}, labelled {label}, {unfit}"
            )
        }
    }
}

#[cfg(test)]
#[path = "program_label_tests.rs"]
mod tests;
