// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The journal namespace a daemon logs to, where it logs to the journal.
//!
//! A unit's `LogNamespace=` sends all it logs, by its standard output and
//! standard error and by `syslog()`, to the journal of that namespace
//! (systemd.exec(5)), which an instance of its own,
//! `systemd-journald@<namespace>.service`, keeps. That instance reads
//! `journald@<namespace>.conf` and its drop-ins, never `journald.conf`, and
//! keeps the journal on the disk, in `/var/log/journal/<machine-id>.<namespace>`,
//! unless they set another `Storage=`: `persistent` is its default
//! (journald.conf(5)). So a daemon that logs to the journal of a namespace
//! that persists writes to the decoy disk around a switch, as one with a log
//! file does, however volatile the decoy's own journal is.
//!
//! The namespace is read as systemd reads `LogNamespace=`: the last value
//! counts, an empty one sets none, and a name systemd does not take (one
//! with a character outside letters, digits and `:`, `-`, `_`, `.`, `@`,
//! or `.` or `..`) is ignored, which leaves the one before. NAILS does not
//! expand a specifier (`%`), so a name with one leaves the namespace
//! unknown. For a running process the namespace is read from the mount
//! systemd sets up for it, of `/run/systemd/journal.<namespace>` over
//! `/run/systemd/journal`, in its own mount table, which every user may
//! read.

use super::super::super::journald_storage::namespace_persistence_at;
use super::super::super::systemd_conf::Assignment;
use super::options::{FileLog, JournalFix, Log};
use crate::Filesystem;
use crate::filesystem::parse_mountinfo;
use std::path::Path;

/// Where systemd mounts the journal of a unit's namespace in the unit's
/// mount namespace.
const JOURNAL_RUN_DIR: &str = "/run/systemd/journal";

/// Whether systemd takes `name` as the name of a journal namespace: a file
/// name that is not `.` or `..`, of the characters a unit instance may hold
/// but a backslash, which `log_namespace_name_valid()` refuses. NAILS sets
/// no bound on its length, so a longer one than systemd takes counts.
fn valid(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":-_.@".contains(&byte))
}

/// Why NAILS cannot tell the journal namespace a daemon logs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Untold {
    /// Its unit names it with a specifier, which NAILS does not expand, as
    /// this says.
    Specifier(String),
    /// Its process's mount table does not show it, as this says.
    Mounts(String),
}

/// The journal namespace the unit whose `[Service]` section is
/// `assignments` logs to, `None` for the decoy's own journal.
///
/// # Errors
///
/// Why NAILS cannot tell: the value it takes has a specifier.
pub(super) fn of_unit(assignments: &[Assignment]) -> Result<Option<String>, Untold> {
    let mut namespace = Ok(None);
    for assignment in assignments
        .iter()
        .filter(|assignment| assignment.key == "LogNamespace")
    {
        let value = assignment.value.as_str();
        if value.is_empty() {
            namespace = Ok(None);
        } else if value.contains('%') {
            namespace = Err(Untold::Specifier(format!(
                "NAILS does not expand the specifiers of its LogNamespace={value}"
            )));
        } else if valid(value) {
            namespace = Ok(Some(value.to_string()));
        }
    }
    namespace
}

/// The journal namespace process `pid` under `root` logs to, `None` for the
/// decoy's own journal or a process that has ended since it was listed.
///
/// # Errors
///
/// Why NAILS cannot tell: its mount table cannot be read, or something
/// other than a namespace's journal directory is mounted over
/// `/run/systemd/journal` there.
pub(super) fn of_process<F: Filesystem>(
    fs: &F,
    root: &Path,
    pid: &str,
) -> Result<Option<String>, Untold> {
    let path = root.join(format!("proc/{pid}/mountinfo"));
    let text = match fs.read_file_content(&path) {
        Ok(text) => text,
        Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => return Ok(None),
        Err(e) if e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) => {
            return Err(Untold::Mounts(format!(
                "NAILS cannot read /proc/{pid}/mountinfo, which shows its journal; run the \
                 command again with sudo"
            )));
        }
        Err(e) => {
            return Err(Untold::Mounts(format!(
                "NAILS cannot read /proc/{pid}/mountinfo, which shows its journal ({e})"
            )));
        }
    };
    // The last mount there is the one on top.
    let Some(mount) = parse_mountinfo(&text)
        .into_iter()
        .rev()
        .find(|entry| entry.mount_point == Path::new(JOURNAL_RUN_DIR))
    else {
        return Ok(None);
    };
    let namespace = mount
        .root
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("journal."))
        .filter(|namespace| valid(namespace));
    match namespace {
        Some(namespace) => Ok(Some(namespace.to_string())),
        None => Err(Untold::Mounts(format!(
            "process {pid} has {} mounted over {JOURNAL_RUN_DIR}, which NAILS does not read as \
             the journal of a namespace",
            mount.root.display()
        ))),
    }
}

/// Where a daemon that logs to the journal, as `by` says, logs what `what`
/// says, the journal being that of `namespace` (see the [module
/// docs](self)): no file for the decoy's own journal, which the journal's
/// own check judges, nor for a namespace whose journal stays in RAM or is
/// kept nowhere; the namespace's journal on the decoy disk for one that
/// persists. Where NAILS cannot tell, the fix that lets it is the
/// namespace's own, or naming it without a specifier.
pub(super) fn journal_log<F: Filesystem>(
    fs: &F,
    root: &Path,
    namespace: Result<Option<String>, Untold>,
    by: &str,
    what: &'static str,
) -> Log {
    let namespace = match namespace {
        Ok(None) => return Log::NoFile,
        Ok(Some(namespace)) => namespace,
        Err(Untold::Specifier(why)) => {
            return Log::UntoldJournal {
                why: format!("it logs to the journal, and {why}"),
                fix: JournalFix::Specifier,
            };
        }
        Err(Untold::Mounts(why)) => {
            return Log::Unknown(format!("it logs to the journal, and {why}"));
        }
    };
    match namespace_persistence_at(fs, root, &namespace) {
        Ok(false) => Log::NoFile,
        Ok(true) => Log::File(FileLog {
            path: format!("/var/log/journal/<machine-id>.{namespace}"),
            by: format!(
                "{by}, to the journal of its namespace {namespace}, which journald keeps on the \
                 decoy disk unless journald@{namespace}.conf sets Storage=volatile"
            ),
            what,
            namespace: Some(namespace),
        }),
        Err(unread) => Log::UntoldJournal {
            why: format!(
                "it logs to the journal of its namespace {namespace}, and NAILS cannot tell where \
                 journald keeps it: {}",
                unread.with_advice()
            ),
            fix: JournalFix::Namespaces(vec![namespace]),
        },
    }
}

#[cfg(test)]
#[path = "namespace_tests.rs"]
mod tests;
