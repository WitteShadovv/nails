// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! sssd on the decoy, the service through which a decoy joins a domain.
//!
//! A decoy joined to a domain (Active Directory or FreeIPA, through sssd)
//! checks logins and account lookups with the domain controller, which keeps
//! its own records of them, with their times. The hidden session's logins
//! reach the controller as the decoy's do, and nothing NAILS does on this
//! computer reaches those records. sssd also keeps caches under `/var/lib/sss`
//! and logs under `/var/log/sssd`. NAILS is not tested on decoys joined to a
//! domain, so `check` and activation warn while sssd is in use on the decoy,
//! which any of these shows:
//!
//! - one of its service units is active, as [`loggers::unit_active`] reads it
//!   (an invocation marker or a populated cgroup);
//! - one of its daemons runs: the monitor `sssd`, or a responder or back end
//!   named `sssd_<name>`, read from `<root>/proc`;
//! - the socket of its Kerberos ticket cache is in place. `sssd-kcm.socket`
//!   only listens until a program asks for a ticket, and a socket unit that
//!   runs no program leaves neither an invocation marker nor a cgroup, so the
//!   socket file in `/run` is what shows it. A stopped socket leaves the file
//!   there until the next boot;
//! - `/var/lib/sss` holds one of the files sssd writes when it runs: its
//!   configuration databases, the memory caches of its accounts, the database
//!   of its Kerberos ticket cache and the sockets of its responders. Its
//!   package installs only the directories.
//!
//! Fedora 44 Cloud enables `sssd-kcm.socket` by default, so a decoy made from
//! it warns even when it is not joined to a domain.
//!
//! Every probe reads metadata, or files under `/proc`, `/run` and `/sys`;
//! nothing on the decoy disk is opened or listed, so no access time there
//! changes. A symlink in the last place of a path is never followed, which
//! would update its access time. Nothing here writes.

use super::loggers;
use crate::Filesystem;
use std::path::Path;

/// sssd's service units: its monitor, its Kerberos ticket cache and the
/// responders systemd can start on their own.
const UNITS: &[&str] = &[
    "sssd.service",
    "sssd-kcm.service",
    "sssd-nss.service",
    "sssd-pam.service",
    "sssd-autofs.service",
    "sssd-ssh.service",
    "sssd-sudo.service",
    "sssd-pac.service",
    "sssd-ifp.service",
];

/// The monitor's process name.
const DAEMON: &str = "sssd";

/// How the names of its responders and back ends begin (`sssd_be`,
/// `sssd_nss`, `sssd_kcm`, ...).
const DAEMON_PREFIX: &str = "sssd_";

/// The socket `sssd-kcm.socket` listens on, relative to the root: where
/// Kerberos looks for a ticket cache of the KCM kind.
const KCM_SOCKET: &str = "run/.heim_org.h5l.kcm-socket";

/// Files sssd writes under `/var/lib/sss` when it runs, relative to the root:
/// the configuration database of the monitor and that of sssd-kcm, the memory
/// caches its NSS responder maps into every process, the database of its
/// Kerberos ticket cache, and the sockets of its responders, which stay when
/// they stop.
const STATE_FILES: &[&str] = &[
    "var/lib/sss/db/config.ldb",
    "var/lib/sss/db/config_kcm.ldb",
    "var/lib/sss/mc/passwd",
    "var/lib/sss/mc/group",
    "var/lib/sss/mc/initgroups",
    "var/lib/sss/mc/sid",
    "var/lib/sss/secrets/secrets.ldb",
    "var/lib/sss/pipes/nss",
    "var/lib/sss/pipes/pam",
];

/// The warning for sssd in use on the decoy under `root`, or `None` when
/// nothing shows it.
pub(super) fn sssd_finding<F: Filesystem>(fs: &F, root: &Path) -> Option<String> {
    let signs = signs(fs, root);
    if signs.is_empty() {
        return None;
    }
    Some(format!(
        "sssd is in use on the decoy ({}). NAILS is not tested on a decoy joined to a \
         domain (Active Directory, FreeIPA): the domain controller records the hidden \
         session's logins and the account lookups sssd makes for it, out of NAILS's reach, \
         and sssd keeps caches under /var/lib/sss and logs under /var/log/sssd. Use a decoy \
         that is not joined to a domain, and where nothing on it needs sssd, disable it \
         (systemctl disable --now sssd.service sssd-kcm.socket)",
        signs.join(", ")
    ))
}

/// What shows sssd in use on the decoy under `root`, one phrase each: its
/// active units (or, when none is, a daemon that runs), the socket of its
/// ticket cache, and the first of its state files found.
fn signs<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
    let mut signs: Vec<String> = UNITS
        .iter()
        .filter(|unit| loggers::unit_active(fs, root, unit))
        .map(|unit| format!("{unit} is active"))
        .collect();
    // A daemon matters on its own only where no unit shows it: one started
    // outside systemd, or by a systemd that left no marker.
    if signs.is_empty()
        && let Some(daemon) = loggers::running_process_names(fs, root)
            .into_iter()
            .find(|name| is_daemon(name))
    {
        signs.push(format!("{daemon} runs"));
    }
    if present(fs, &root.join(KCM_SOCKET)) {
        signs.push(format!(
            "the socket of its Kerberos ticket cache, /{KCM_SOCKET}, is in place (a stopped \
             socket leaves it until the next boot)"
        ));
    }
    if let Some(file) = STATE_FILES
        .iter()
        .find(|file| present(fs, &root.join(file)))
    {
        signs.push(format!("/{file} holds its state"));
    }
    signs
}

/// Whether a process name is sssd's: the monitor, or a responder or back end.
fn is_daemon(name: &str) -> bool {
    name == DAEMON || name.starts_with(DAEMON_PREFIX)
}

/// Whether `path` is there, as a file, socket, directory or symlink.
///
/// A symlink is counted as itself, before anything follows it: following it
/// would update its access time.
fn present<F: Filesystem>(fs: &F, path: &Path) -> bool {
    fs.is_symlink(path).unwrap_or(false) || fs.path_exists(path).unwrap_or(false)
}

#[cfg(test)]
#[path = "sssd_tests.rs"]
mod tests;
