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
//! - its Kerberos ticket cache listens: the socket file is in place in `/run`
//!   and `<root>/proc/net/unix` lists a socket listening on it.
//!   `sssd-kcm.socket` only listens until a program asks for a ticket, and a
//!   socket unit that runs no program leaves neither an invocation marker nor
//!   a cgroup, so the listening socket is what shows it. That socket is where
//!   every Kerberos ticket cache of the KCM kind listens, not only sssd's:
//!   Heimdal's daemon, `kcm`, binds it itself, so while a process of that name
//!   runs the socket counts as its and not as sssd's. A socket file that
//!   nothing listens on, which a stopped socket leaves in `/run` until the
//!   next boot, is no sign;
//! - `/var/lib/sss` holds one of the files sssd writes when it runs: its
//!   configuration databases, the memory caches of its accounts, the database
//!   of its Kerberos ticket cache and the sockets of its responders. Its
//!   package installs only the directories.
//!
//! Fedora 44 Cloud enables `sssd-kcm.socket` by default, so a decoy made from
//! it warns even when it is not joined to a domain.
//!
//! The warning's advice turns sssd off: `systemctl disable --now` of
//! `sssd.service`, and of `sssd-kcm.socket` where that unit exists, stops
//! every unit in [`UNITS`], since each responder is bound to `sssd.service`
//! and `sssd-kcm.service` requires its socket. They are two commands because
//! systemd before 257 refuses a `disable` that names a unit it does not have
//! and leaves every unit as it was, while Debian and Ubuntu install
//! `sssd-kcm.socket` only with the `sssd-kcm` package. On NixOS the
//! configuration owns the units and `systemctl disable` cannot change them, so
//! the advice names the `services.sssd` options instead. sssd leaves its state
//! files behind when it stops, and they keep the warning, so the advice also
//! names each one found with the `rm` that deletes it. That is safe once sssd
//! is stopped: sssd makes each of them again when it starts, its configuration
//! databases from `sssd.conf`, and only the Kerberos tickets its ticket cache
//! kept are lost, which nothing reaches while `sssd-kcm` is off. The advice
//! never deletes the socket: once `sssd-kcm.socket` is stopped nothing listens
//! on it, and another daemon may.
//!
//! Every probe reads metadata, or files under `/proc`, `/run` and `/sys`;
//! nothing on the decoy disk is opened or listed, so no access time there
//! changes. A symlink in the last place of a path is never followed, which
//! would update its access time. Nothing here writes.

use super::loggers;
use crate::Filesystem;
use std::cell::OnceCell;
use std::collections::BTreeSet;
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
/// Kerberos looks for a ticket cache of the KCM kind, whichever daemon serves
/// it.
const KCM_SOCKET: &str = "run/.heim_org.h5l.kcm-socket";

/// The paths a listening KCM socket is bound at, as `/proc/net/unix` names
/// them: the path its daemon gave, in `/run` or in `/var/run`, which links
/// to `/run`.
const KCM_BOUND_AT: &[&str] = &[
    "/run/.heim_org.h5l.kcm-socket",
    "/var/run/.heim_org.h5l.kcm-socket",
];

/// The flag `/proc/net/unix` sets on a listening socket (`__SO_ACCEPTCON`).
const LISTENING: u32 = 1 << 16;

/// The KCM daemons that are not sssd's, by process name: Heimdal's, which
/// binds the socket itself and so runs while the socket is its.
const OTHER_KCM_DAEMONS: &[&str] = &["kcm"];

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
/// nothing shows it. `is_nixos` picks how its advice turns sssd off.
pub(super) fn sssd_finding<F: Filesystem>(fs: &F, root: &Path, is_nixos: bool) -> Option<String> {
    let signs = signs(fs, root);
    if signs.is_empty() {
        return None;
    }
    Some(format!(
        "sssd is in use on the decoy ({}). NAILS is not tested on a decoy joined to a \
         domain (Active Directory, FreeIPA): the domain controller records the hidden \
         session's logins and the account lookups sssd makes for it, out of NAILS's reach, \
         and sssd keeps caches under /var/lib/sss and logs under /var/log/sssd. Use a decoy \
         that is not joined to a domain, and where nothing on it needs sssd, {}{}",
        signs.join(", "),
        turn_off(is_nixos),
        delete(&left_behind(fs, root)),
    ))
}

/// What shows sssd in use on the decoy under `root`, one phrase each: its
/// active units (or, when none is, a daemon that runs), its listening ticket
/// cache, and the first of its state files found.
fn signs<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
    // The process names are read once, and only when a sign needs them.
    let names = OnceCell::new();
    let running = || names.get_or_init(|| loggers::running_process_names(fs, root));
    let mut signs: Vec<String> = UNITS
        .iter()
        .filter(|unit| loggers::unit_active(fs, root, unit))
        .map(|unit| format!("{unit} is active"))
        .collect();
    // A daemon matters on its own only where no unit shows it: one started
    // outside systemd, or by a systemd that left no marker.
    if signs.is_empty()
        && let Some(daemon) = running().iter().find(|name| is_daemon(name))
    {
        signs.push(format!("{daemon} runs"));
    }
    if kcm_listens(fs, root) && !other_kcm_runs(running()) {
        signs.push(format!(
            "its Kerberos ticket cache listens on /{KCM_SOCKET}"
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

/// Whether a ticket cache listens on the KCM socket of the decoy under `root`:
/// its file is in place and `<root>/proc/net/unix` lists a socket listening
/// there. A file that nothing listens on is what a stopped socket leaves.
fn kcm_listens<F: Filesystem>(fs: &F, root: &Path) -> bool {
    present(fs, &root.join(KCM_SOCKET))
        && fs
            .read_file_content(&root.join("proc/net/unix"))
            .is_ok_and(|table| table.lines().any(listens_on_kcm))
}

/// Whether a line of `/proc/net/unix` is a socket listening at the KCM
/// socket. Its fields are `Num RefCount Protocol Flags Type St Inode Path`,
/// the flags in hex; a line whose path holds a space has more fields and is
/// never the KCM socket.
fn listens_on_kcm(line: &str) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let &[_, _, _, flags, _, _, _, path] = fields.as_slice() else {
        return false;
    };
    u32::from_str_radix(flags, 16).is_ok_and(|flags| flags & LISTENING != 0)
        && KCM_BOUND_AT.contains(&path)
}

/// Whether a KCM daemon that is not sssd's runs among `running`, the process
/// names: then the KCM socket is its.
fn other_kcm_runs(running: &BTreeSet<String>) -> bool {
    OTHER_KCM_DAEMONS
        .iter()
        .any(|daemon| running.contains(*daemon))
}

/// The files sssd leaves behind when it stops, as paths on the decoy under
/// `root`: every one of its state files there. Each keeps the warning after
/// sssd is off.
fn left_behind<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
    STATE_FILES
        .iter()
        .filter(|file| present(fs, &root.join(file)))
        .map(|file| format!("/{file}"))
        .collect()
}

/// How the advice turns sssd off: on NixOS through its options, since the
/// configuration owns the units there, and elsewhere with one `systemctl
/// disable --now` for each unit (see the module docs).
fn turn_off(is_nixos: bool) -> &'static str {
    if is_nixos {
        "turn it off (set services.sssd.enable and services.sssd.kcm to false, then run \
         nixos-rebuild switch)"
    } else {
        "disable it (systemctl disable --now sssd.service, and systemctl disable --now \
         sssd-kcm.socket where that unit exists)"
    }
}

/// The rest of the advice: delete the files sssd left behind (`left`), which
/// would keep the warning after it is off. Empty when there are none.
fn delete(left: &[String]) -> String {
    if left.is_empty() {
        return String::new();
    }
    format!(
        ", then delete the files it leaves behind, which keep this warning (rm {}): sssd \
         makes each again when it starts",
        left.join(" ")
    )
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
