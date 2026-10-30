// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Syslog and audit daemons that record the hidden session on the decoy disk.
//!
//! A classic syslog daemon (rsyslog, syslog-ng, a syslogd from sysklogd,
//! inetutils or busybox, metalog, socklog) or the audit daemon writes every
//! logged line to `/var/log` on the decoy disk, outside journald and before the
//! overlays are mounted, so an active one fails activation closed. A daemon is
//! caught by any of the ways systemd or the daemon present themselves:
//!
//! - its service unit (`rsyslog.service`, `inetutils-syslogd.service`,
//!   `auditd.service`, ...);
//! - a template instance of it (`syslog-ng@default.service`), matched by its
//!   unit stem so the instance name need not be known in advance;
//! - `syslog.service`, the name systemd gives whichever syslog daemon is
//!   enabled. On NixOS that is the unit's own name. Elsewhere it is an alias: a
//!   link in a unit directory to the daemon's own unit, and systemd records the
//!   running unit (its invocation marker and its cgroup) only under that unit's
//!   own name. So the link is followed to the unit it names, which is then
//!   probed, and a daemon this module does not know is caught that way too;
//! - the running process itself (`rsyslogd`, `syslog-ng`, `syslogd`, ...),
//!   read from `<root>/proc`, which also catches a daemon started outside
//!   systemd, one with no invocation marker.
//!
//! `klogd` is not one of them: it only hands the kernel's messages on to the
//! syslog daemon, which is caught itself. Every probe reads; nothing here
//! writes.

use crate::Filesystem;
use std::collections::BTreeSet;
use std::path::Path;

/// Directory systemd populates with an `invocation:<unit>` marker per *active*
/// unit, relative to the root. Its presence is a write-free way to tell a
/// running unit from an installed-but-stopped one. The marker is a symlink to
/// the unit's invocation id, which names no file, so it is looked for as a link:
/// following it finds nothing.
pub(super) const INVOCATION_DIR: &str = "run/systemd/units";

/// The name systemd gives the enabled syslog daemon.
const SYSLOG_ALIAS: &str = "syslog.service";

/// The unit directories an alias link is looked for in, relative to the root,
/// in the order systemd reads them: the administrator's, the runtime ones, the
/// packages'.
pub(super) const UNIT_DIRS: &[&str] = &[
    "etc/systemd/system",
    "run/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
];

/// A syslog or audit daemon watched for on the decoy: the finding shown when it
/// is active, the service units it runs as and the process names it runs
/// under (`comm`, capped at 15 bytes by the kernel, or `argv[0]`'s basename).
/// One finding per daemon, however many of its routes fire; the order is the
/// order findings appear.
struct Logger {
    /// The finding.
    message: &'static str,
    /// Its service units.
    units: &'static [&'static str],
    /// Its process names.
    processes: &'static [&'static str],
}

/// The syslog daemons, which [`SYSLOG_ALIAS`] may name.
const SYSLOG_DAEMONS: &[Logger] = &[
    Logger {
        message: "rsyslog is active and writes logs to the decoy disk",
        units: &["rsyslog.service"],
        processes: &["rsyslogd"],
    },
    Logger {
        message: "syslog-ng is active and writes logs to the decoy disk",
        units: &["syslog-ng.service"],
        processes: &["syslog-ng"],
    },
    Logger {
        message: "a syslogd (sysklogd, inetutils or busybox) is active and writes logs to the \
                  decoy disk",
        units: &[
            "syslogd.service",
            "sysklogd.service",
            "inetutils-syslogd.service",
            "busybox-syslogd.service",
        ],
        processes: &["syslogd"],
    },
    Logger {
        message: "metalog is active and writes logs to the decoy disk",
        units: &["metalog.service"],
        processes: &["metalog"],
    },
    Logger {
        message: "socklog is active and writes logs to the decoy disk",
        units: &[],
        processes: &["socklog"],
    },
];

/// The audit daemon.
const AUDITD: Logger = Logger {
    message: "auditd is active and writes audit records to the decoy disk",
    units: &["auditd.service"],
    processes: &["auditd"],
};

/// The fail-closed findings for active syslog/audit daemons on the decoy under
/// `root`, one per daemon however it was detected.
///
/// The enabled syslog daemon is found under `syslog.service` as well; when no
/// daemon of [`SYSLOG_DAEMONS`] is found by its own names, an active
/// `syslog.service` is reported by the unit it resolves to.
pub(super) fn active_logger_blockers<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
    let running = running_process_names(fs, root);
    let active = |logger: &Logger| {
        logger.units.iter().any(|unit| unit_active(fs, root, unit))
            || logger.processes.iter().any(|name| running.contains(*name))
    };

    let mut out: Vec<String> = SYSLOG_DAEMONS
        .iter()
        .filter(|&logger| active(logger))
        .map(|logger| logger.message.to_string())
        .collect();
    if out.is_empty()
        && let Some(finding) = enabled_syslog_finding(fs, root)
    {
        out.push(finding);
    }
    if active(&AUDITD) {
        out.push(AUDITD.message.to_string());
    }
    out
}

/// The finding for an active `syslog.service` whose daemon is not found by its
/// own names: the unit it is, when it runs under that name (as on NixOS), or
/// the unit its alias link names.
fn enabled_syslog_finding<F: Filesystem>(fs: &F, root: &Path) -> Option<String> {
    let unit = resolve_alias(fs, root, SYSLOG_ALIAS).unwrap_or_else(|| SYSLOG_ALIAS.to_string());
    if !unit_active(fs, root, &unit) {
        return None;
    }
    Some(if unit == SYSLOG_ALIAS {
        "a syslog daemon (syslog.service) is active and writes logs to the decoy disk".to_string()
    } else {
        format!(
            "a syslog daemon ({unit}, enabled as syslog.service) is active and writes logs to \
             the decoy disk"
        )
    })
}

/// The unit an alias names: the file name of the unit file a link called
/// `alias` in a unit directory resolves to. `None` when no unit directory
/// holds such a link.
///
/// Only a path that is a link is resolved, so a decoy without the alias (the
/// amnesic one NAILS asks for) has nothing read beyond its metadata.
fn resolve_alias<F: Filesystem>(fs: &F, root: &Path, alias: &str) -> Option<String> {
    UNIT_DIRS.iter().find_map(|dir| {
        let link = root.join(dir).join(alias);
        if !fs.is_symlink(&link).unwrap_or(false) {
            return None;
        }
        let target = fs.canonicalize(&link).ok()?;
        let unit = target.file_name()?.to_str()?;
        (unit != alias && unit.ends_with(".service")).then(|| unit.to_string())
    })
}

/// Whether a systemd unit is active, inferred without writing anything.
///
/// A unit is active when systemd left its runtime invocation marker, when a
/// template instance of the same stem (`<stem>@<instance>.service`) left one, or
/// when its cgroup under `system.slice` reports a live process. A
/// stopped-but-installed unit has none of these, so this never fires on a
/// package that ships a disabled service. The cgroup is a second route to a
/// running unit. A daemon started outside systemd leaves neither, and its
/// process is what shows it ([`running_process_names`]). A oneshot unit that
/// has run and exited, such as `kdump-tools.service`, keeps no process and no
/// populated cgroup, so its marker is all that shows it.
pub(in crate::preflight::checks) fn unit_active<F: Filesystem>(
    fs: &F,
    root: &Path,
    unit: &str,
) -> bool {
    let invocations = root.join(INVOCATION_DIR);
    // The marker is a link to the invocation id (see INVOCATION_DIR): a probe
    // that follows it, such as `path_exists`, never sees it.
    if fs
        .is_symlink(&invocations.join(format!("invocation:{unit}")))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(stem) = unit.strip_suffix(".service") {
        let prefix = format!("invocation:{stem}@");
        if let Ok(entries) = fs.list_directory(&invocations)
            && entries.iter().any(|entry| {
                entry
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".service"))
            })
        {
            return true;
        }
    }
    let events = root
        .join("sys/fs/cgroup/system.slice")
        .join(unit)
        .join("cgroup.events");
    fs.read_file_content(&events)
        .is_ok_and(|content| content.lines().any(|line| line == "populated 1"))
}

/// The `comm` and `argv[0]` basenames of every process under `<root>/proc`.
///
/// Reads `comm` and `cmdline` only, both world-readable, so an unprivileged
/// `nails check` sees daemons that run as root.
pub(super) fn running_process_names<F: Filesystem>(fs: &F, root: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Ok(entries) = fs.list_directory(&root.join("proc")) else {
        return names;
    };
    for entry in entries {
        let is_pid = entry
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()));
        if !is_pid {
            continue;
        }
        if let Ok(comm) = fs.read_file_content(&entry.join("comm")) {
            names.insert(comm.trim().to_string());
        }
        if let Ok(cmdline) = fs.read_file_content(&entry.join("cmdline"))
            && let Some(argv0) = cmdline.split('\0').find(|arg| !arg.is_empty())
            && let Some(base) = Path::new(argv0).file_name().and_then(|name| name.to_str())
        {
            names.insert(base.to_string());
        }
    }
    names
}
