// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Kill all of userspace at once, except PID 1 and this invocation.
//!
//! In a whole-root session every userspace process is a hidden process: the
//! desktop, its applications, every service. The emergency path enqueues the
//! soft-reboot first (a pending stop job keeps `Restart=` from reviving a unit)
//! and then kills every unit that can hold a hidden program with `cgroup.kill`,
//! so the orderly shutdown has little left to wait for. Spared are
//! `init.scope` (PID 1), the service manager's own machinery (mount, swap
//! and socket units, `systemd-*` services and the bus; see
//! [`left_to_the_shutdown`]), which the shutdown stops itself, and the cgroups
//! holding a process of this invocation, where every process but the
//! invocation's own is killed one by one through a pidfd. The invocation is the
//! emergency's command chain ([`Invocation`]), and it dies with the
//! soft-reboot moments later.

use crate::cgroup;
use crate::proc::{self, Invocation, ProcessHandle};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// What the kill did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KillReport {
    /// cgroups killed with `cgroup.kill` (or the per-process fallback).
    pub cgroups: Vec<PathBuf>,
    /// Processes killed one by one, next to the invocation.
    pub processes: Vec<u32>,
}

/// The pids directly in the cgroup at `dir` (not below it).
fn direct_procs(dir: &Path) -> Vec<u32> {
    std::fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// The processes `invocation` spares, as `/proc` lists them now.
pub fn spared_pids(invocation: &Invocation) -> Vec<u32> {
    proc::pids()
        .into_iter()
        .filter(|&pid| invocation.contains(pid, proc::stat(pid).as_ref()))
        .collect()
}

/// SIGKILL, one by one through a pidfd, every process of `pids` that is not in
/// `spare`. Returns the pids killed.
pub fn kill_unspared(pids: impl IntoIterator<Item = u32>, spare: &[u32]) -> Vec<u32> {
    let mut killed = Vec::new();
    for pid in pids {
        if !spare.contains(&pid) && ProcessHandle::open(pid).is_some_and(|h| h.kill()) {
            killed.push(pid);
        }
    }
    killed
}

/// The cgroup v2 paths that hold one of the processes `spare`.
fn protected_paths(spare: &[u32]) -> BTreeSet<String> {
    spare
        .iter()
        .filter_map(|&pid| proc::cgroup(pid).and_then(|c| cgroup::v2_path(&c)))
        .collect()
}

/// Kill every cgroup below `cgroup_root` except `init.scope` and the cgroups
/// holding `invocation`, and every process in those cgroups that is not part
/// of the invocation.
pub fn kill_userspace(cgroup_root: &Path, invocation: &Invocation) -> KillReport {
    kill_below(cgroup_root, "", invocation)
}

/// [`kill_userspace`] limited to the subtree `subtree` (a cgroup path such as
/// `/user.slice`, or `""` for everything) of the hierarchy at `cgroup_root`.
pub fn kill_below(cgroup_root: &Path, subtree: &str, invocation: &Invocation) -> KillReport {
    let spare = spared_pids(invocation);
    let protected = protected_paths(&spare);
    let mut report = KillReport::default();
    let start = cgroup::dir(cgroup_root, subtree);
    visit(
        &start,
        subtree.trim_end_matches('/'),
        &protected,
        &spare,
        &mut report,
    );
    report
}

/// Units the emergency leaves to the orderly shutdown it enqueued: the service
/// manager's own machinery. A mount, swap or automount unit's cgroup holds only
/// PID 1's `mount`/`umount`/`swapon` helpers, and killing one mid-way leaves a
/// half-done mount for the way back; `systemd-*` services (journald, udevd,
/// logind, oomd) and the bus hold no hidden application, and killing journald
/// leaves the hidden service manager's last messages queued in the journal
/// socket that the decoy's journald reads after the switch. The shutdown stops
/// them within moments.
fn left_to_the_shutdown(unit: &str) -> bool {
    [".mount", ".swap", ".automount", ".socket", ".device"]
        .iter()
        .any(|suffix| unit.ends_with(suffix))
        || (unit.starts_with("systemd-") && unit.ends_with(".service"))
        || matches!(unit, "dbus.service" | "dbus-broker.service")
}

fn visit(
    dir: &Path,
    relative: &str,
    protected: &BTreeSet<String>,
    spare: &[u32],
    report: &mut KillReport,
) {
    let Ok(children) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<(PathBuf, String)> = children
        .flatten()
        .filter(|c| c.file_type().is_ok_and(|t| t.is_dir()))
        .map(|c| {
            let name = c.file_name().to_string_lossy().into_owned();
            (c.path(), format!("{relative}/{name}"))
        })
        .collect();
    subdirs.sort();
    for (path, child) in subdirs {
        let name = child.rsplit('/').next().unwrap_or("");
        if child == "/init.scope" || left_to_the_shutdown(name) {
            continue;
        }
        if name.ends_with(".slice") && !protected.contains(&child) {
            // A slice is descended into, not killed whole, so the units the
            // shutdown must stop itself survive inside it.
            visit(&path, &child, protected, spare, report);
            continue;
        }
        if protected.iter().any(|own| cgroup::contains(&child, own)) {
            visit(&path, &child, protected, spare, report);
            if protected.contains(&child) {
                report
                    .processes
                    .extend(kill_unspared(direct_procs(&path), spare));
            }
        } else if cgroup::kill(&path, spare).is_ok() {
            report.cgroups.push(path);
        }
    }
}
