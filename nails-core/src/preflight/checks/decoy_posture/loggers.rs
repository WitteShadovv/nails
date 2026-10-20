// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Syslog and audit daemons that record the hidden session on the decoy disk.
//!
//! A classic syslog daemon (rsyslog, syslog-ng, metalog) or the audit daemon
//! writes every logged line to `/var/log` on the decoy disk, outside journald
//! and before the overlays are mounted, so an active one fails activation
//! closed. A daemon is caught by three routes, so none of the ways systemd or
//! the daemon present themselves slips through:
//!
//! - a plain service unit (`rsyslog.service`, `auditd.service`, ...);
//! - a template instance (`syslog-ng@default.service`), matched by its unit
//!   stem so the instance name need not be known in advance;
//! - the running process itself (`rsyslogd`, `syslog-ng`, `metalog`, `auditd`),
//!   read from `<root>/proc`, which catches a daemon started outside systemd and
//!   a recent systemd that no longer writes an invocation marker for every unit.
//!
//! Every probe reads; nothing here writes.

use crate::Filesystem;
use std::collections::BTreeSet;
use std::path::Path;

/// Directory systemd populates with an `invocation:<unit>` marker per *active*
/// unit, relative to the root. Its presence is a write-free way to tell a
/// running unit from an installed-but-stopped one.
pub(super) const INVOCATION_DIR: &str = "run/systemd/units";

/// A syslog/audit unit watched for on the decoy, with the finding shown when it
/// is active and the key that keeps the same daemon from being reported twice
/// when more than one route detects it. The order is the order findings appear.
const LOGGER_UNITS: &[(&str, &str, &str)] = &[
    (
        "rsyslog.service",
        "syslog",
        "rsyslog is active and writes logs to the decoy disk",
    ),
    // NixOS runs rsyslogd as syslog.service; elsewhere syslog.service is the
    // conventional alias of whichever syslog daemon is installed. Shares the
    // `syslog` key with rsyslog.service, so only the first of the two is named.
    (
        "syslog.service",
        "syslog",
        "a syslog daemon (syslog.service) is active and writes logs to the decoy disk",
    ),
    (
        "syslog-ng.service",
        "syslog-ng",
        "syslog-ng is active and writes logs to the decoy disk",
    ),
    (
        "metalog.service",
        "metalog",
        "metalog is active and writes logs to the decoy disk",
    ),
    (
        "auditd.service",
        "auditd",
        "auditd is active and writes audit records to the decoy disk",
    ),
];

/// A logger/audit daemon watched for among running processes, by its `comm`
/// (and its `argv[0]` basename), with the dedup key and finding it shares with
/// the matching unit. `comm` is capped at 15 bytes by the kernel; each fits.
const LOGGER_PROCESSES: &[(&str, &str, &str)] = &[
    (
        "rsyslogd",
        "syslog",
        "rsyslog is active and writes logs to the decoy disk",
    ),
    (
        "syslog-ng",
        "syslog-ng",
        "syslog-ng is active and writes logs to the decoy disk",
    ),
    (
        "metalog",
        "metalog",
        "metalog is active and writes logs to the decoy disk",
    ),
    (
        "auditd",
        "auditd",
        "auditd is active and writes audit records to the decoy disk",
    ),
];

/// The fail-closed findings for active syslog/audit daemons on the decoy under
/// `root`, one per daemon however it was detected.
///
/// A daemon detected by more than one route (a unit and its process, say) is
/// reported once: the first finding for each dedup key wins, so the unit wording
/// is kept over the process wording.
pub(super) fn active_logger_blockers<F: Filesystem>(fs: &F, root: &Path) -> Vec<String> {
    let running = running_process_names(fs, root);
    let mut seen: Vec<&'static str> = Vec::new();
    let mut out: Vec<String> = Vec::new();

    for &(unit, key, message) in LOGGER_UNITS {
        if unit_active(fs, root, unit) && !seen.contains(&key) {
            seen.push(key);
            out.push(message.to_string());
        }
    }
    for &(comm, key, message) in LOGGER_PROCESSES {
        if running.contains(comm) && !seen.contains(&key) {
            seen.push(key);
            out.push(message.to_string());
        }
    }

    out
}

/// Whether a systemd unit is active, inferred without writing anything.
///
/// A unit is active when systemd left its runtime invocation marker, when a
/// template instance of the same stem (`<stem>@<instance>.service`) left one, or
/// when its cgroup under `system.slice` reports a live process. A
/// stopped-but-installed unit has none of these, so this never fires on a
/// package that ships a disabled service. Recent systemd no longer writes a
/// marker for every unit, which the cgroup and the process judge cover.
pub(super) fn unit_active<F: Filesystem>(fs: &F, root: &Path, unit: &str) -> bool {
    let invocations = root.join(INVOCATION_DIR);
    if fs
        .path_exists(&invocations.join(format!("invocation:{unit}")))
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
/// `nails check` sees daemons that run as root. Shared with the Fedora posture
/// probe, which watches for its own process names.
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
