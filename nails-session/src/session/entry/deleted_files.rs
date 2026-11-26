// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The deleted files the decoy's PID 1 and udevd still use, which keep a
//! decoy filesystem from going read-only for the write fence.

use std::path::Path;

/// The `systemctl` calls that make the decoy's PID 1 and udevd let go of
/// the deleted files they still use, under the procfs at `proc`, in order:
/// `daemon-reexec` where PID 1 [`holds_deleted`] one, and a restart of
/// udevd where one of its processes does. None where nothing holds one, so
/// a plain activation reads none of their unit files. The switch leaves
/// udevd to PID 1's final kill, as a plain soft-reboot does
/// ([`nails_teardown::whole_root::tail::LEFT_TO_THE_SWITCH`]).
pub fn deleted_file_releases(proc: &Path) -> Vec<&'static [&'static str]> {
    let mut calls: Vec<&'static [&'static str]> = Vec::new();
    if holds_deleted(&proc.join("1")) {
        calls.push(&["daemon-reexec"]);
    }
    let udevd = nails_teardown::whole_root::tail::LEFT_TO_THE_SWITCH;
    let pids: Vec<u32> = std::fs::read_dir(proc)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid > 1)
        .collect();
    if pids.iter().any(|&pid| {
        nails_teardown::whole_root::tail::services_of(proc, &[pid])
            .iter()
            .any(|unit| udevd.contains(&unit.as_str()))
            && holds_deleted(&proc.join(pid.to_string()))
    }) {
        calls.push(&["restart", "systemd-udevd.service"]);
    }
    calls
}

/// Whether the process at `proc_pid` maps or holds open a deleted file that
/// lies on a filesystem (no memfd, device or RAM file).
pub fn holds_deleted(proc_pid: &Path) -> bool {
    let on_disk = |path: &str| {
        path.starts_with('/')
            && !path.starts_with("/memfd:")
            && !path.starts_with("/dev/")
            && !path.starts_with("/run/")
            && !path.starts_with("/tmp/")
    };
    let maps = std::fs::read_to_string(proc_pid.join("maps")).unwrap_or_default();
    let mapped = maps.lines().any(|line| {
        line.strip_suffix(" (deleted)")
            .and_then(|l| l.split_whitespace().nth(5))
            .is_some_and(on_disk)
    });
    mapped
        || std::fs::read_dir(proc_pid.join("fd"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|fd| std::fs::read_link(fd.path()).ok())
            .filter_map(|t| t.to_str().map(str::to_string))
            .any(|t| t.strip_suffix(" (deleted)").is_some_and(on_disk))
}
