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

use super::PersistenceFinding;
use crate::Filesystem;
use crate::filesystem::automount::describe;
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
/// `root`, one per daemon however it was detected, and one for each daemon
/// whose unit NAILS cannot tell runs, which counts as one that does.
///
/// The enabled syslog daemon is found under `syslog.service` as well; when no
/// daemon of [`SYSLOG_DAEMONS`] is found by its own names, an active
/// `syslog.service` is reported by the unit it resolves to.
pub(super) fn active_logger_blockers<F: Filesystem>(
    fs: &F,
    root: &Path,
) -> Vec<PersistenceFinding> {
    let running = running_process_names(fs, root);
    let activity = |logger: &Logger| {
        if logger.processes.iter().any(|name| running.contains(*name)) {
            return Activity::Active;
        }
        Activity::any(logger.units.iter().map(|unit| unit_active(fs, root, unit)))
    };
    let finding = |logger: &Logger| match activity(logger) {
        Activity::Active => Some(PersistenceFinding::kept(logger.message)),
        Activity::Inactive => None,
        Activity::Untold(why) => Some(PersistenceFinding::untold(why)),
    };

    let mut out: Vec<PersistenceFinding> = SYSLOG_DAEMONS.iter().filter_map(finding).collect();
    if out.iter().all(|found| found.untold.is_some())
        && let Some(found) = enabled_syslog_finding(fs, root)
    {
        out.push(found);
    }
    out.extend(finding(&AUDITD));
    out
}

/// The finding for an active `syslog.service` whose daemon is not found by its
/// own names: the unit it is, when it runs under that name (as on NixOS), or
/// the unit its alias link names. NAILS cannot tell when it cannot look up the
/// alias or tell whether the unit runs, which counts as one that runs.
fn enabled_syslog_finding<F: Filesystem>(fs: &F, root: &Path) -> Option<PersistenceFinding> {
    let unit = match resolve_alias(fs, root, SYSLOG_ALIAS) {
        Ok(unit) => unit.unwrap_or_else(|| SYSLOG_ALIAS.to_string()),
        Err(why) => return Some(PersistenceFinding::untold(why)),
    };
    match unit_active(fs, root, &unit) {
        Activity::Active => {}
        Activity::Inactive => return None,
        Activity::Untold(why) => return Some(PersistenceFinding::untold(why)),
    }
    Some(PersistenceFinding::kept(if unit == SYSLOG_ALIAS {
        "a syslog daemon (syslog.service) is active and writes logs to the decoy disk".to_string()
    } else {
        format!(
            "a syslog daemon ({unit}, enabled as syslog.service) is active and writes logs to \
             the decoy disk"
        )
    }))
}

/// The unit an alias names: the file name of the unit file a link called
/// `alias` in a unit directory resolves to. `None` when no unit directory
/// holds such a link.
///
/// Only a path that is a link is resolved, so a decoy without the alias (the
/// amnesic one NAILS asks for) has nothing read beyond its metadata.
///
/// A link that names no other service, such as a mask, or one that cannot
/// be resolved, names none, and the next unit directory is looked in.
///
/// # Errors
///
/// Why NAILS cannot tell which daemon the alias names: the lookup of the
/// alias in a unit directory failed, or was not made, before a link that
/// names a service was found.
fn resolve_alias<F: Filesystem>(
    fs: &F,
    root: &Path,
    alias: &str,
) -> Result<Option<String>, String> {
    for dir in UNIT_DIRS {
        let link = root.join(dir).join(alias);
        match fs.is_symlink(&link) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                return Err(format!(
                    "NAILS cannot tell which daemon {alias} names: {}",
                    describe(&link.display().to_string(), &error).sentence
                ));
            }
        }
        let unit = fs.canonicalize(&link).ok().and_then(|target| {
            target
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|unit| *unit != alias && unit.ends_with(".service"))
                .map(str::to_string)
        });
        if unit.is_some() {
            return Ok(unit);
        }
    }
    Ok(None)
}

/// Whether a unit runs, as [`unit_active`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::preflight::checks) enum Activity {
    /// It runs.
    Active,
    /// Nothing shows that it runs.
    Inactive,
    /// NAILS cannot tell whether it runs, for this reason, which names the
    /// unit and the path it could not look up.
    Untold(String),
}

impl Activity {
    /// What a set of routes to a running unit says together: it runs when
    /// one shows it running; else NAILS cannot tell when one cannot tell,
    /// the first one's reason; else nothing shows it running.
    pub(in crate::preflight::checks) fn any(routes: impl IntoIterator<Item = Activity>) -> Self {
        let mut untold = None;
        for route in routes {
            match route {
                Activity::Active => return Activity::Active,
                Activity::Inactive => {}
                Activity::Untold(why) => {
                    untold.get_or_insert(why);
                }
            }
        }
        untold.map_or(Activity::Inactive, Activity::Untold)
    }
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
/// populated cgroup, so its marker is all that shows it. When the marker
/// cannot be looked up and no other route shows the unit running, NAILS
/// cannot tell.
pub(in crate::preflight::checks) fn unit_active<F: Filesystem>(
    fs: &F,
    root: &Path,
    unit: &str,
) -> Activity {
    let invocations = root.join(INVOCATION_DIR);
    // The marker is a link to the invocation id (see INVOCATION_DIR): a probe
    // that follows it, such as `path_exists`, never sees it.
    let marker = invocations.join(format!("invocation:{unit}"));
    let marked = match fs.is_symlink(&marker) {
        Ok(true) => return Activity::Active,
        Ok(false) => Activity::Inactive,
        Err(error) => Activity::Untold(format!(
            "NAILS cannot tell whether {unit} runs: {}",
            describe(&marker.display().to_string(), &error).sentence
        )),
    };
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
            return Activity::Active;
        }
    }
    let events = root
        .join("sys/fs/cgroup/system.slice")
        .join(unit)
        .join("cgroup.events");
    if fs
        .read_file_content(&events)
        .is_ok_and(|content| content.lines().any(|line| line == "populated 1"))
    {
        return Activity::Active;
    }
    marked
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
