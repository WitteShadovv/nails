// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the loaded SELinux policy lets the disk guard do, where the RAM copy
//! of the binary takes the label of the system's programs.
//!
//! With `[session_mounts] read_only`, the hidden session's udev rule runs the
//! RAM copy of the binary for every disk and partition that appears
//! ([`crate::whole_root::disk_guard`]). udevd starts it, not PID 1, and a
//! targeted policy gives udevd's start of a program labelled
//! [`PROGRAM_LABEL`](crate::whole_root::program_label::PROGRAM_LABEL) no
//! domain of its own: the guard runs in udevd's domain, `udev_t`, which such a
//! policy confines. Whether the guard can do its work there is the policy's to
//! say, and [`check_guard`] asks it through selinuxfs, as
//! [`check_start`](crate::whole_root::program_label::check_start) asks about
//! PID 1's start of the copy: the context of the running systemd-udevd, what
//! its start of the copy enters, which must be udevd's own domain, and the
//! permissions of that domain on what the guard uses:
//!
//! - the rule NAILS installs in `/run/udev/rules.d`, which udevd reads to
//!   start the guard, and the copy, which the guard starts from without a
//!   change of domain and maps;
//! - `/run` and the runtime directory on the way to it, the plan it reads
//!   there, and the record of the disks it sets read-only, which it adds to,
//!   or creates where nothing made it yet. Each with the label the policy
//!   gives what makes it: the runtime directory as the activation makes it in
//!   `/run`, the plan as the activation and the steps PID 1 starts write it,
//!   and the record as those steps or the guard create it, and the rule as
//!   the step of the entry writes it, in a `/run/udev/rules.d` it makes where
//!   there is none yet ([`Selinux::new_label`]);
//! - the node of a disk or partition, which it opens to set it read-only
//!   (`BLKROSET`, which also takes the capability `sys_admin`), with each of
//!   the labels a targeted policy gives such a node ([`DISK_LABELS`]);
//! - what it reads to tell the disks the session uses: sysfs, the links in
//!   `/dev`, and its own mount table in `/proc`.
//!
//! The check runs on the decoy, before the entry: the decoy's running udevd
//! stands for the hidden session's, which runs the same program under the
//! same loaded policy, as the decoy's policy stays loaded across the switch.
//!
//! A denied permission, a start of the copy that enters another domain than
//! udevd's own, a udevd that does not run and a question that cannot be asked
//! each fail the check ([`GuardUnfit`]). The policy's rules for single `ioctl`
//! numbers are not asked, as selinuxfs answers none, nor whether a label may be
//! stored on the filesystem of `/run`, nor the labels a relabel of `/run` would
//! give these files.

use crate::whole_root::disk_guard::{RECORD_NAME, RULE_DIR};
use crate::whole_root::plan::RUNTIME_DIR;
use crate::whole_root::selinux::{Selinux, type_of};
use std::io;
use std::path::Path;

/// The labels a targeted policy gives the node of a disk or partition: of a
/// fixed disk, of a removable one, and of a node udev gave no label of its
/// own.
pub const DISK_LABELS: [&str; 3] = [
    "system_u:object_r:fixed_disk_device_t:s0",
    "system_u:object_r:removable_device_t:s0",
    "system_u:object_r:device_t:s0",
];

/// The label of sysfs under a targeted policy.
const SYSFS: &str = "system_u:object_r:sysfs_t:s0";

/// The label of `/dev` and its links under a targeted policy.
const DEVICES: &str = "system_u:object_r:device_t:s0";

/// The label of `/proc` and its link to the process's own directory under a
/// targeted policy.
const PROCFS: &str = "system_u:object_r:proc_t:s0";

/// The permissions on the copy that starting a program from it takes where
/// the domain does not change: the kernel asks `execute` as it looks the file
/// up, `read` and `open` as it opens it, `map` as it maps it, and
/// `execute_no_trans` as the start keeps the domain.
const START: &[&str] = &[
    "getattr",
    "open",
    "read",
    "execute",
    "map",
    "execute_no_trans",
];

/// The permissions on a directory the guard looks names up in.
const SEARCH: &[&str] = &["getattr", "search"];

/// The permissions on a file the guard reads.
const READ: &[&str] = &["getattr", "open", "read"];

/// The permissions on a directory the guard lists.
const LIST: &[&str] = &["getattr", "open", "read", "search"];

/// The permissions on a link the guard follows.
const FOLLOW: &[&str] = &["getattr", "read"];

/// The permissions on the record that adding a line to it takes: it is
/// opened to append.
const APPEND: &[&str] = &["getattr", "open", "append"];

/// The permissions on a disk's node that setting it read-only takes.
const SET_READ_ONLY: &[&str] = &["getattr", "open", "read", "ioctl"];

/// What the guard needs a permission for, to follow "which the guard needs"
/// in a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// To be started from the rule udevd reads.
    Rule,
    /// To start from the copy.
    Start,
    /// To reach the copy and its files in `/run`.
    Run,
    /// To reach the runtime directory and add the record there.
    Runtime,
    /// To read the plan.
    Plan,
    /// To add to the record.
    Record,
    /// To create the record.
    CreateRecord,
    /// To set a disk read-only.
    Disk,
    /// To read sysfs.
    Sysfs,
    /// To look a disk up in `/dev`.
    Devices,
    /// To read its own mount table.
    Mounts,
}

impl std::fmt::Display for Need {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Need::Rule => "to be started from the rule NAILS installs in /run/udev/rules.d",
            Need::Start => "to start from the RAM copy of the binary",
            Need::Run => "on the way to the RAM copy and its files in /run",
            Need::Runtime => {
                "to reach the runtime directory and add the record of the disks it sets \
                 read-only there"
            }
            Need::Plan => "to read the session plan",
            Need::Record => "to add to the record of the disks it sets read-only",
            Need::CreateRecord => "to create the record of the disks it sets read-only",
            Need::Disk => "to set a disk read-only",
            Need::Sysfs => "to tell from sysfs which disks the session uses",
            Need::Devices => "to look the disks up in /dev",
            Need::Mounts => "to read its own mount table in /proc",
        })
    }
}

/// Why the disk guard could not do its work in the domain the loaded policy
/// gives it, to follow "The disk guard udev starts for NAILS" in a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardUnfit {
    /// No systemd-udevd runs to show the domain udev starts programs in.
    NoUdevd,
    /// The policy gives udevd's start of the copy `entered`, not udevd's own
    /// domain (`udevd`).
    Elsewhere {
        /// udevd's context.
        udevd: String,
        /// The context the start enters.
        entered: String,
    },
    /// The policy denies the guard's domain, in the context `domain`, these
    /// permissions of `class` on `target`, which the guard needs for `need`.
    Denied {
        /// The guard's context.
        domain: String,
        /// The label the permissions are on.
        target: String,
        /// Their class.
        class: &'static str,
        /// What the policy denies.
        perms: Vec<&'static str>,
        /// What the guard needs them for.
        need: Need,
    },
    /// What the policy makes of the guard could not be told: why.
    Unjudged(String),
}

/// `words` as a list in a sentence: "open, read or ioctl".
fn either(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

impl std::fmt::Display for GuardUnfit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardUnfit::NoUdevd => f.write_str(
                "runs in the domain of systemd-udevd, which starts it, but no systemd-udevd runs \
                 here to show that domain",
            ),
            GuardUnfit::Elsewhere { udevd, entered } => write!(
                f,
                "would run in {entered}: the loaded SELinux policy gives udevd's ({udevd}) start \
                 of the RAM copy of the binary that context, not udevd's own domain, the one \
                 domain NAILS judges the guard in"
            ),
            GuardUnfit::Denied {
                domain,
                target,
                class,
                perms,
                need,
            } => write!(
                f,
                "runs in {domain}, and the loaded SELinux policy denies that domain the {class} \
                 permission {} on {target}, which the guard needs {need}",
                either(perms)
            ),
            GuardUnfit::Unjudged(why) => {
                write!(
                    f,
                    "cannot be judged against the loaded SELinux policy: {why}"
                )
            }
        }
    }
}

/// One question about the guard's domain: the permissions `perms` of `class`
/// on `target`, which it needs for `need`.
struct Ask {
    target: String,
    class: &'static str,
    perms: &'static [&'static str],
    need: Need,
}

impl Ask {
    fn new(target: &str, class: &'static str, perms: &'static [&'static str], need: Need) -> Self {
        Self {
            target: target.to_string(),
            class,
            perms,
            need,
        }
    }
}

/// Check what the loaded policy, as `selinux` tells it, lets the disk guard
/// do where its copy is labelled `label`: nothing where no policy is loaded
/// ([`Selinux::pid1`]), which is `Ok(None)`. Else the guard runs in the
/// context of the running systemd-udevd ([`Selinux::udevd`]) where the
/// policy gives udevd's start of the copy no other, and the policy must grant
/// that domain every permission the module docs list; `Ok` holds the guard's
/// context then. The labels of the files NAILS keeps in `/run` are the ones the
/// policy gives what makes them, from the label of `/run` and the contexts of
/// the process asking, which is the activation's, and of PID 1's start of the
/// copy, where the steps that write the plan run. A question that fails fails
/// the check too ([`GuardUnfit::Unjudged`]).
pub fn check_guard(selinux: &dyn Selinux, label: &str) -> Result<Option<String>, GuardUnfit> {
    let unjudged = |what: &str, e: io::Error| GuardUnfit::Unjudged(format!("{what}: {e}"));
    let Some(pid1) = selinux
        .pid1()
        .map_err(|e| unjudged("PID 1's context cannot be read", e))?
    else {
        return Ok(None);
    };
    let udevd = selinux
        .udevd()
        .map_err(|e| unjudged("the context of systemd-udevd cannot be read", e))?
        .ok_or(GuardUnfit::NoUdevd)?;
    let asked = |e| unjudged("the policy cannot be asked", e);
    let guard = selinux.exec_context(&udevd, label).map_err(asked)?;
    match (type_of(&udevd), type_of(&guard)) {
        (Some(own), Some(new)) if own == new => {}
        (Some(_), Some(_)) => {
            return Err(GuardUnfit::Elsewhere {
                udevd,
                entered: guard,
            });
        }
        _ => {
            return Err(GuardUnfit::Unjudged(format!(
                "{udevd} or {guard} is no SELinux context with a type"
            )));
        }
    }
    for ask in asks(selinux, &pid1, &guard, label)? {
        let denied = selinux
            .denied(&guard, &ask.target, ask.class, ask.perms)
            .map_err(asked)?;
        if !denied.is_empty() {
            return Err(GuardUnfit::Denied {
                domain: guard,
                target: ask.target,
                class: ask.class,
                perms: denied,
                need: ask.need,
            });
        }
    }
    Ok(Some(guard))
}

/// The questions about the guard's domain, in the context `guard`, whose copy
/// is labelled `label`, where PID 1 runs in `pid1`: one for each kind of file
/// it uses and each label that file may have, each question asked once.
fn asks(
    selinux: &dyn Selinux,
    pid1: &str,
    guard: &str,
    label: &str,
) -> Result<Vec<Ask>, GuardUnfit> {
    let unjudged = |what: &str, e: io::Error| GuardUnfit::Unjudged(format!("{what}: {e}"));
    let asked = |e| unjudged("the policy cannot be asked", e);
    let runtime_dir = Path::new(RUNTIME_DIR);
    let run_dir = runtime_dir.parent().unwrap_or(runtime_dir);
    let runtime_name = runtime_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let own = selinux
        .current()
        .map_err(|e| unjudged("the context of this process cannot be read", e))?;
    let steps = selinux.exec_context(pid1, label).map_err(asked)?;
    let run = selinux.path_label(run_dir).map_err(|e| {
        unjudged(
            &format!("the label of {} cannot be read", run_dir.display()),
            e,
        )
    })?;
    let runtime = selinux
        .new_label(&own, &run, "dir", Some(runtime_name))
        .map_err(asked)?;
    let new_file = |source: &str, name: Option<&str>| {
        selinux
            .new_label(source, &runtime, "file", name)
            .map_err(asked)
    };
    let plans = [new_file(&own, None)?, new_file(&steps, None)?];
    let records = [
        new_file(&steps, Some(RECORD_NAME))?,
        new_file(guard, Some(RECORD_NAME))?,
    ];
    let (rules, rule) = rule_labels(selinux, run_dir, &steps)?;

    let mut asks = vec![
        Ask::new(&rules, "dir", LIST, Need::Rule),
        Ask::new(&rule, "file", READ, Need::Rule),
        Ask::new(label, "file", START, Need::Start),
        Ask::new(&run, "dir", SEARCH, Need::Run),
        Ask::new(
            &runtime,
            "dir",
            &["getattr", "search", "write", "add_name"],
            Need::Runtime,
        ),
    ];
    asks.extend(
        plans
            .iter()
            .map(|plan| Ask::new(plan, "file", READ, Need::Plan)),
    );
    asks.extend(
        records
            .iter()
            .map(|record| Ask::new(record, "file", APPEND, Need::Record)),
    );
    asks.push(Ask::new(
        &records[1],
        "file",
        &["create"],
        Need::CreateRecord,
    ));
    asks.extend(
        DISK_LABELS
            .iter()
            .map(|disk| Ask::new(disk, "blk_file", SET_READ_ONLY, Need::Disk)),
    );
    asks.extend([
        Ask::new(guard, "capability", &["sys_admin"], Need::Disk),
        Ask::new(SYSFS, "dir", LIST, Need::Sysfs),
        Ask::new(SYSFS, "file", READ, Need::Sysfs),
        Ask::new(SYSFS, "lnk_file", FOLLOW, Need::Sysfs),
        Ask::new(DEVICES, "dir", SEARCH, Need::Devices),
        Ask::new(DEVICES, "lnk_file", FOLLOW, Need::Devices),
        Ask::new(PROCFS, "dir", SEARCH, Need::Mounts),
        Ask::new(PROCFS, "lnk_file", &["read"], Need::Mounts),
        Ask::new(guard, "dir", SEARCH, Need::Mounts),
        Ask::new(guard, "file", READ, Need::Mounts),
    ]);
    let mut seen = Vec::new();
    asks.retain(|ask| {
        let key = (ask.target.clone(), ask.class, ask.perms);
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
    Ok(asks)
}

/// The labels of the directory of the guard's rule below `run_dir` and of the
/// rule itself, as the step of the entry, running in `steps`, writes it: the
/// directory's own label where it is there, else the one the policy gives it
/// in its parent, which is there wherever udevd runs.
fn rule_labels(
    selinux: &dyn Selinux,
    run_dir: &Path,
    steps: &str,
) -> Result<(String, String), GuardUnfit> {
    let unread = |path: &Path, e: io::Error| {
        GuardUnfit::Unjudged(format!(
            "the label of {} cannot be read: {e}",
            path.display()
        ))
    };
    let asked = |e| GuardUnfit::Unjudged(format!("the policy cannot be asked: {e}"));
    let dir = run_dir.join(RULE_DIR);
    let rules = match selinux.path_label(&dir) {
        Ok(label) => label,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = dir.parent().unwrap_or(&dir);
            let name = dir.file_name().and_then(|name| name.to_str());
            let above = selinux.path_label(parent).map_err(|e| unread(parent, e))?;
            selinux
                .new_label(steps, &above, "dir", name)
                .map_err(asked)?
        }
        Err(e) => return Err(unread(&dir, e)),
    };
    let rule = selinux
        .new_label(steps, &rules, "file", None)
        .map_err(asked)?;
    Ok((rules, rule))
}

#[cfg(test)]
#[path = "guard_policy_tests.rs"]
mod tests;
