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
//! - its Kerberos ticket cache may listen: the socket file is in place in
//!   `/run`, and PID 1's socket table, `<root>/proc/1/net/unix`, lists a
//!   socket listening on it or cannot tell. That table lists the sockets of
//!   the network namespace systemd runs in, whichever one `nails` runs in. It
//!   is read as bytes, since the kernel prints a socket's name byte for byte
//!   and any process can bind one whose name is not text. It is read twice,
//!   and the socket counts when either read lists it listening, since the
//!   table is no snapshot: the kernel prints it a page at a time, and a socket
//!   closed between two pages can make it skip a line. It cannot tell when it
//!   cannot be read or does not begin with the header the kernel prints, as
//!   when `/proc` hides other users' processes from a check that is not root,
//!   and then the warning says that `sudo` can tell. `sssd-kcm.socket` only
//!   listens until a program asks for a
//!   ticket, and a socket unit that runs no program leaves neither an
//!   invocation marker nor a cgroup, so the socket is what shows it. That
//!   socket is where every Kerberos ticket cache of the KCM kind listens, not
//!   only sssd's: Heimdal's daemon, `kcm`, binds it itself. So the socket is
//!   no sign either on a decoy that is not NixOS where none of the unit
//!   directories in [`UNIT_PATH`] may hold a unit file of `sssd-kcm.socket`
//!   and a process whose `comm` is `kcm` runs as root in PID 1's mount
//!   namespace, as Heimdal's daemon does. A directory a symlink leads to, as
//!   `/lib` on a merged `/usr`, or one a lookup on the way to fails, may hold
//!   one, since the check follows no link and cannot rule it out; NixOS's
//!   unit directories are links into the Nix store, so there the socket
//!   always counts. Any process can give itself that name, so only a root one
//!   counts, its real and effective user read from the `Uid:` line of its
//!   status: the owner of its `/proc` directory would be no sign, since a
//!   process that makes itself not dumpable has root own it. A root process
//!   in a container without a user namespace of its own is root there too,
//!   but its mount namespace, whose `/run` its daemon serves, is not PID 1's.
//!   A socket file the table shows nothing listening on, which a stopped
//!   socket leaves in `/run` until the next boot, is no sign;
//! - `/var/lib/sss` holds one of the nine files in [`STATE_FILES`], which sssd
//!   writes there when it runs: its two configuration databases, the four
//!   memory caches of its NSS responder, the database of its Kerberos ticket
//!   cache and the sockets of its NSS and PAM responders. Its package installs
//!   only the directories. sssd keeps more there, such as the cache of each
//!   domain, under names that hold the domain's own. Finding those would take
//!   a listing of the directories, which changes their access times, so they
//!   are not looked for.
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
//! files behind when it stops, and those of [`STATE_FILES`] keep the warning,
//! so the advice also names each of them found with the `rm` that deletes it.
//! That is safe once sssd is stopped: sssd makes each of them again when it
//! starts, its configuration databases from `sssd.conf`, and only the Kerberos
//! tickets its ticket cache kept are lost, which nothing reaches while
//! `sssd-kcm` is off. The advice never deletes the socket: once
//! `sssd-kcm.socket` is stopped nothing listens on it, and another daemon may.
//!
//! Every probe reads metadata, or files under `/proc`, `/run` and `/sys`;
//! nothing on the decoy disk is opened or listed, so no access time there
//! changes. A symlink in the last place of a path is never followed, which
//! would update its access time, and a unit directory a symlink leads to,
//! such as `/lib` on a merged `/usr` or `/etc/systemd/system` on NixOS, is not
//! looked in. Nothing here writes.

use super::loggers;
use crate::Filesystem;
use crate::next_step::{NextStep, sudo_line};
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

/// The socket table of PID 1's network namespace, relative to the root: the
/// one systemd and the decoy's daemons listen in, whichever one `nails` runs
/// in.
const SOCKET_TABLE: &str = "proc/1/net/unix";

/// The first line of the socket table, as the kernel prints it.
const SOCKET_TABLE_HEADER: &[u8] = b"Num       RefCount Protocol Flags    Type St Inode Path";

/// The paths a listening KCM socket is bound at, as the socket table names
/// them: the path its daemon gave, in `/run` or in `/var/run`, which links
/// to `/run`.
const KCM_BOUND_AT: &[&str] = &[
    "/run/.heim_org.h5l.kcm-socket",
    "/var/run/.heim_org.h5l.kcm-socket",
];

/// The flag the socket table sets on a listening socket (`__SO_ACCEPTCON`).
const LISTENING: u32 = 1 << 16;

/// The unit through which sssd listens on the KCM socket.
const KCM_SOCKET_UNIT: &str = "sssd-kcm.socket";

/// The unit directories a unit file of `sssd-kcm.socket` is looked for in,
/// relative to the root: those systemd's system manager loads unit files
/// from, in the order it reads them, and `/lib/systemd/system`, which systemd
/// built for a split `/usr` reads too.
const UNIT_PATH: &[&str] = &[
    "etc/systemd/system.control",
    "run/systemd/system.control",
    "run/systemd/transient",
    "run/systemd/generator.early",
    "etc/systemd/system",
    "etc/systemd/system.attached",
    "run/systemd/system",
    "run/systemd/system.attached",
    "run/systemd/generator",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "run/systemd/generator.late",
];

/// The `comm` of Heimdal's KCM daemon, which binds the KCM socket itself.
const HEIMDAL_KCM: &str = "kcm";

/// Files sssd writes under `/var/lib/sss` when it runs, relative to the root:
/// the configuration database of the monitor and that of sssd-kcm, the memory
/// caches its NSS responder maps into every process, the database of its
/// Kerberos ticket cache, and the sockets of its NSS and PAM responders, which
/// stay when they stop. These are all the check looks for there.
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
    let (signs, untold) = signs(fs, root, is_nixos);
    if signs.is_empty() {
        return None;
    }
    Some(format!(
        "sssd is in use on the decoy ({}). NAILS is not tested on a decoy joined to a \
         domain (Active Directory, FreeIPA): the domain controller records the hidden \
         session's logins and the account lookups sssd makes for it, out of NAILS's reach, \
         and sssd keeps caches under /var/lib/sss and logs under /var/log/sssd. Use a decoy \
         that is not joined to a domain, and where nothing on it needs sssd, {}{}{}",
        signs.join(", "),
        turn_off(is_nixos),
        delete(&left_behind(fs, root)),
        sudo_hint(untold),
    ))
}

/// What shows sssd in use on the decoy under `root`, one phrase each: its
/// active units (or, when none is, a daemon that runs), the socket of its
/// ticket cache, and the first of its state files found. With them, whether
/// the socket counts only because its table cannot tell whether it listens.
/// `is_nixos` says whether the decoy is NixOS (see [`heimdal_serves_kcm`]).
fn signs<F: Filesystem>(fs: &F, root: &Path, is_nixos: bool) -> (Vec<String>, bool) {
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
    let mut untold = false;
    if let Some(sign) = kcm_sign(fs, root, is_nixos) {
        untold = sign == KcmSign::Untold;
        signs.push(sign.phrase());
    }
    if let Some(file) = STATE_FILES
        .iter()
        .find(|file| present(fs, &root.join(file)))
    {
        signs.push(format!("/{file} holds its state"));
    }
    (signs, untold)
}

/// What PID 1's socket table says of the ticket cache's socket, when the
/// socket counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KcmSign {
    /// A read of the table lists a socket listening on it.
    Listens,
    /// The table cannot tell whether anything listens on it.
    Untold,
}

impl KcmSign {
    /// The phrase that names it among the signs.
    fn phrase(self) -> String {
        match self {
            KcmSign::Listens => format!("its Kerberos ticket cache listens on /{KCM_SOCKET}"),
            KcmSign::Untold => format!(
                "the socket of its Kerberos ticket cache, /{KCM_SOCKET}, is in place, and \
                 /{SOCKET_TABLE} cannot tell whether it listens"
            ),
        }
    }
}

/// The sign of the ticket cache's socket on the decoy under `root`: its file
/// is in place, PID 1's socket table lists a socket listening on it or cannot
/// tell, and Heimdal's daemon does not serve it. `None` when the file is gone,
/// when the table shows nothing listening there, which is what a stopped
/// socket leaves, or when the socket is Heimdal's.
fn kcm_sign<F: Filesystem>(fs: &F, root: &Path, is_nixos: bool) -> Option<KcmSign> {
    if !present(fs, &root.join(KCM_SOCKET)) {
        return None;
    }
    let sign = match kcm_listening(fs, root) {
        Some(false) => return None,
        Some(true) => KcmSign::Listens,
        None => KcmSign::Untold,
    };
    (!heimdal_serves_kcm(fs, root, is_nixos)).then_some(sign)
}

/// The end of the advice when the socket counts only because its table cannot
/// tell whether it listens: where `/proc` hides other users' processes, a
/// check that is not root cannot read the table, and one run with `sudo` can.
fn sudo_hint(untold: bool) -> String {
    if !untold {
        return String::new();
    }
    format!(
        ". Where /proc hides other users' processes, {} can tell whether the ticket cache \
         listens",
        sudo_line(NextStep::Check)
    )
}

/// Whether a socket listens at the KCM socket, as PID 1's socket table under
/// `root` shows it. The table is no snapshot: the kernel prints it a page at a
/// time, and a socket closed between two pages can make it skip a line, so it
/// is read twice (see [`either_lists`]). `None` when the reads cannot tell.
fn kcm_listening<F: Filesystem>(fs: &F, root: &Path) -> Option<bool> {
    let read = || table_lists_kcm(fs, root);
    either_lists(read(), read())
}

/// Two reads of the socket table taken together: a listener when either
/// lists one, none only when both were read and list none, and `None`, cannot
/// tell, otherwise.
fn either_lists(first: Option<bool>, second: Option<bool>) -> Option<bool> {
    match (first, second) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

/// Whether one read of PID 1's socket table under `root` lists a socket
/// listening at the KCM socket: `None` when the table cannot be read, or does
/// not begin with the header the kernel prints, so it cannot tell.
fn table_lists_kcm<F: Filesystem>(fs: &F, root: &Path) -> Option<bool> {
    let table = fs.read_file_bytes(&root.join(SOCKET_TABLE)).ok()?;
    let mut lines = table.split(|&byte| byte == b'\n');
    if lines.next() != Some(SOCKET_TABLE_HEADER) {
        return None;
    }
    Some(lines.any(listens_on_kcm))
}

/// Whether a line of the socket table is a socket listening at the KCM
/// socket. Its fields are `Num RefCount Protocol Flags Type St Inode Path`,
/// the flags in hex. The kernel prints a socket's name byte for byte, so a
/// line need not be text, and a name that holds a space gives the line more
/// fields; neither is the KCM socket.
fn listens_on_kcm(line: &[u8]) -> bool {
    let fields: Vec<&[u8]> = line
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .collect();
    let &[_, _, _, flags, _, _, _, path] = fields.as_slice() else {
        return false;
    };
    std::str::from_utf8(flags)
        .ok()
        .and_then(|flags| u32::from_str_radix(flags, 16).ok())
        .is_some_and(|flags| flags & LISTENING != 0)
        && KCM_BOUND_AT.iter().any(|bound| bound.as_bytes() == path)
}

/// Whether the KCM socket is Heimdal's and not sssd's. Never on NixOS, whose
/// unit directories are links into the Nix store; elsewhere only when no unit
/// directory may hold a unit file of `sssd-kcm.socket` and a process whose
/// `comm` is `kcm` runs as root in PID 1's mount namespace.
fn heimdal_serves_kcm<F: Filesystem>(fs: &F, root: &Path, is_nixos: bool) -> bool {
    !is_nixos
        && !UNIT_PATH.iter().any(|dir| may_hold_kcm_unit(fs, root, dir))
        && host_root_kcm_runs(fs, root)
}

/// Whether the unit directory `dir`, relative to `root`, may hold a unit file
/// of `sssd-kcm.socket`: the file is there, as a file or a link, or the check
/// cannot rule it out, because a symlink leads to the directory or a lookup
/// on the way fails. Each component is looked at from the top down, and only
/// one that is no link is looked into, so no link is followed.
fn may_hold_kcm_unit<F: Filesystem>(fs: &F, root: &Path, dir: &str) -> bool {
    let mut path = root.to_path_buf();
    for component in Path::new(dir).components() {
        path.push(component);
        match lookup(fs, &path) {
            Lookup::Missing => return false,
            Lookup::Found => {}
            Lookup::Link | Lookup::Failed => return true,
        }
    }
    lookup(fs, &path.join(KCM_SOCKET_UNIT)) != Lookup::Missing
}

/// What a lookup of a path finds, a symlink in its last place not followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup {
    /// Nothing is there.
    Missing,
    /// A file or a directory that is no link.
    Found,
    /// A symlink, which is not followed.
    Link,
    /// The lookup failed, so the check cannot tell.
    Failed,
}

/// Look `path` up with lstat and, when it is no link, with stat, which then
/// looks at the same file and tells a missing path from a failed lookup.
fn lookup<F: Filesystem>(fs: &F, path: &Path) -> Lookup {
    match fs.is_symlink(path) {
        Ok(true) => Lookup::Link,
        Err(_) => Lookup::Failed,
        Ok(false) => match fs.inode(path) {
            Ok(Some(_)) => Lookup::Found,
            Ok(None) => Lookup::Missing,
            Err(_) => Lookup::Failed,
        },
    }
}

/// Whether a process whose `comm` is `kcm` runs as root in PID 1's mount
/// namespace under `<root>/proc`: the `Uid:` line of its status gives 0 as
/// its real and effective user, and its `ns/mnt` gives the inode PID 1's
/// does. Both are read on procfs, and a check that cannot read PID 1's finds
/// none.
fn host_root_kcm_runs<F: Filesystem>(fs: &F, root: &Path) -> bool {
    let proc = root.join("proc");
    let Ok(Some(host)) = fs.inode(&proc.join("1/ns/mnt")) else {
        return false;
    };
    let Ok(entries) = fs.list_directory(&proc) else {
        return false;
    };
    entries
        .iter()
        .filter(|entry| is_pid_dir(entry))
        .any(|entry| {
            fs.read_file_content(&entry.join("comm"))
                .is_ok_and(|comm| comm.trim_end_matches('\n') == HEIMDAL_KCM)
                && fs
                    .read_file_content(&entry.join("status"))
                    .is_ok_and(|status| runs_as_root(&status))
                && fs
                    .inode(&entry.join("ns/mnt"))
                    .is_ok_and(|mnt| mnt == Some(host))
        })
}

/// Whether a process's status gives root as its real and effective user, the
/// first two numbers of its `Uid:` line.
fn runs_as_root(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .is_some_and(|uids| {
            let mut uids = uids.split_whitespace();
            uids.next() == Some("0") && uids.next() == Some("0")
        })
}

/// Whether `entry`, under `<root>/proc`, is the directory of a process: its
/// name is a number.
fn is_pid_dir(entry: &Path) -> bool {
    entry
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The state files sssd leaves behind when it stops, as paths on the decoy
/// under `root`: every one of [`STATE_FILES`] there. Each keeps the warning
/// after sssd is off.
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

/// The rest of the advice: delete the state files sssd left behind (`left`),
/// which would keep the warning after it is off. Empty when there are none.
fn delete(left: &[String]) -> String {
    if left.is_empty() {
        return String::new();
    }
    format!(
        ", then delete the files it left behind that keep this warning (rm {}): sssd \
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
