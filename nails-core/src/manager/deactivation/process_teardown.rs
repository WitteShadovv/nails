// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process, session and overlay-device inspection for teardown.
//!
//! The pure helpers that decide which live processes a teardown must spare
//! (its own invocation, the shells sharing its session/group) and which are
//! genuinely overlay-rooted, plus the best-effort signalling primitives.

use super::ManagerDeactivationKind;
use std::path::{Path, PathBuf};

/// Merge this process's ancestry with any PIDs handed across the `systemd-run`
/// boundary by the detached invocation (via `NAILS_SHELL_CLEANUP_PROTECTED_PIDS`,
/// a test-only injection point nothing sets in production),
/// de-duplicating while preserving order.
///
/// The merged set is the shells that must survive deactivation: the process
/// tree running the teardown plus the caller's session recorded before detach.
pub(super) fn merge_protected_pids(
    mut ancestry: Vec<u32>,
    handoff: Option<&std::ffi::OsStr>,
) -> Vec<u32> {
    if let Some(handoff) = handoff {
        for pid in handoff
            .to_string_lossy()
            .split(',')
            .filter_map(|value| value.trim().parse::<u32>().ok())
        {
            if !ancestry.contains(&pid) {
                ancestry.push(pid);
            }
        }
    }

    ancestry
}

/// Protected PIDs for shell cleanup: this process's ancestry plus the detached
/// handoff set. Computed once per deactivation and passed explicitly to
/// [`kill_user_shells`], replacing the previous global environment variable.
#[cfg(not(test))]
pub(super) fn collect_protected_shell_pids(env: &crate::RuntimeEnv) -> Vec<u32> {
    // The handoff knob exists only in test-hooks builds (read from the startup
    // snapshot); shipped builds protect the teardown's own process tree and
    // nothing else.
    #[cfg(feature = "test-hooks")]
    let handoff = env.test_hooks.shell_cleanup_protected_pids.clone();
    #[cfg(not(feature = "test-hooks"))]
    let handoff: Option<std::ffi::OsString> = {
        let _ = env;
        None
    };

    let mut protected = merge_protected_pids(current_process_ancestry(), handoff.as_deref());

    // Spare every shell that shares this teardown's own session or process group,
    // not only its direct ancestry. When `nails emergency` is run in a pipeline —
    // which the NixOS test driver always does to capture output
    // (`nails emergency | ( base64 -w 0; echo )`) — the pipe-reading subshell is a
    // sibling, so it is not in the ancestry, yet killing it severs the console
    // reading the teardown's own result. It shares the session (and process group,
    // for a pipeline launched from one shell), so sparing those spares it. A
    // shipped emergency runs detached in its own session, so this spares only the
    // teardown's own invocation, never the operator's decoy shells.
    for pid in own_session_or_group_shell_pids() {
        if !protected.contains(&pid) {
            protected.push(pid);
        }
    }

    protected
}

/// Every live process sharing this teardown's session or process group.
///
/// Scanned once from `/proc` just before the pre-unmount shell kill and merged
/// into the protected set so [`kill_shells_for_teardown`] spares the teardown's
/// own invocation — in particular the sibling that reads its piped output — the
/// same way [`is_own_invocation_process`] spares it from the overlay-rooted kill.
#[cfg(not(test))]
pub(super) fn own_session_or_group_shell_pids() -> Vec<u32> {
    let (self_sid, self_pgid) = self_session_and_pgid();
    if self_sid == 0 && self_pgid == 0 {
        return Vec::new();
    }

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut pids = Vec::new();
    for entry in proc_dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Some((sid, pgid)) = read_session_and_pgid(pid)
            && is_own_invocation_process(pid, sid, pgid, &[], self_sid, self_pgid)
        {
            pids.push(pid);
        }
    }
    pids
}

pub(super) fn current_process_ancestry() -> Vec<u32> {
    let mut lineage = Vec::new();
    let mut next = Some(std::process::id());

    while let Some(pid) = next {
        if pid == 0 || lineage.contains(&pid) {
            break;
        }

        lineage.push(pid);
        next = read_parent_pid(pid);
    }

    lineage
}

pub(super) fn read_parent_pid(pid: u32) -> Option<u32> {
    let status_path = Path::new("/proc").join(pid.to_string()).join("status");
    let content = std::fs::read_to_string(status_path).ok()?;

    content.lines().find_map(|line| {
        let rest = line.strip_prefix("PPid:\t")?;
        rest.split_whitespace().next()?.parse::<u32>().ok()
    })
}

/// The raw `/proc/<pid>/cgroup` contents, for matching against the graphical
/// session guard's cgroup fragments. `None` when the process has gone or the file
/// cannot be read. Returned verbatim so the match works for both cgroup v2 (a
/// single `0::/…` line) and v1 (one line per controller).
pub(super) fn read_proc_cgroup(pid: u32) -> Option<String> {
    std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("cgroup")).ok()
}

/// The session id and process-group id of `pid`, read from `/proc/<pid>/stat`.
///
/// `/proc/<pid>/stat` lists these right after the `comm` field, which may itself
/// contain spaces or parentheses, so the scan starts past the final `)`. Returns
/// `None` when the process has gone or the file cannot be parsed.
pub(super) fn read_session_and_pgid(pid: u32) -> Option<(u32, u32)> {
    let stat_path = Path::new("/proc").join(pid.to_string()).join("stat");
    let content = std::fs::read_to_string(stat_path).ok()?;
    let after_comm = content.get(content.rfind(')')? + 1..)?;
    // Fields after `comm`: state, ppid, pgrp, session, ...
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let pgid = fields.get(2)?.parse::<u32>().ok()?;
    let sid = fields.get(3)?.parse::<u32>().ok()?;
    Some((sid, pgid))
}

/// Whether a process must be spared from the emergency overlay-rooted kill and
/// the owner-signalling because it belongs to this teardown's own invocation.
///
/// A process is spared when it is in the teardown's ancestry, shares its session,
/// or shares its process group. When `nails emergency` is run in a pipeline
/// (`nails emergency | base64`) the pipe reader shares the session — and, in the
/// non-interactive shell that launches the pipeline, the process group — while
/// its cwd sits inside the full-root overlay, so without this guard it is flagged
/// write-blocking and killed, and the final success line is then written into a
/// closed pipe. PID reuse can likewise make a recorded activation owner collide
/// with such a consumer, so the same guard protects the owner signal. The zero
/// sentinels guard against an unreadable self or candidate id matching by
/// accident.
pub(super) fn is_own_invocation_process(
    candidate_pid: u32,
    candidate_sid: u32,
    candidate_pgid: u32,
    ancestry: &[u32],
    self_sid: u32,
    self_pgid: u32,
) -> bool {
    ancestry.contains(&candidate_pid)
        || (self_sid != 0 && candidate_sid == self_sid)
        || (self_pgid != 0 && candidate_pgid == self_pgid)
}

/// This process's session id and process-group id, best-effort (`0` when a value
/// cannot be determined, which the spare check treats as "no match").
pub(super) fn self_session_and_pgid() -> (u32, u32) {
    let sid = nix::unistd::getsid(None)
        .map(|pid| pid.as_raw() as u32)
        .unwrap_or(0);
    let pgid = nix::unistd::getpgrp().as_raw() as u32;
    (sid, pgid)
}

/// Decide whether a path-matched emergency-kill candidate is genuinely rooted in
/// an overlay and so should be signalled.
///
/// The process classifier matched it to an overlay target by path prefix only.
/// That is kept when:
/// - no overlay device could be read (`!overlay_device_set_known`): fall back to
///   the path match rather than spare everything and leave the overlays pinned;
/// - the process is an unverifiable writer (a foreign mount namespace or chroot
///   whose device cannot be trusted): fail-safe, keep killing it;
/// - a reference of the process actually resolves onto an overlay device.
///
/// Otherwise the path matched the decoy directory the overlay is mounted over, not
/// the overlay itself, so the process is spared.
pub(super) fn candidate_is_overlay_rooted(
    is_unverifiable_writer: bool,
    references_overlay_device: bool,
    overlay_device_set_known: bool,
) -> bool {
    if !overlay_device_set_known || is_unverifiable_writer {
        return true;
    }
    references_overlay_device
}

/// The set of device ids behind the given overlay mount points. Each overlay
/// mount carries its own anonymous `st_dev`, distinct from the decoy filesystem it
/// is stacked on, so this set identifies "inside the overlay".
pub(super) fn overlay_mount_devices(targets: &[PathBuf]) -> std::collections::HashSet<u64> {
    use std::os::unix::fs::MetadataExt;
    targets
        .iter()
        .filter_map(|target| std::fs::metadata(target).ok().map(|meta| meta.dev()))
        .collect()
}

/// Whether any of a process's path references (cwd, root, or an open fd) resolves
/// onto one of `overlay_devices`.
///
/// The `/proc/<pid>/{cwd,root,fd/*}` magic links resolve to the real dentry, so a
/// `metadata` (stat, which follows the link) reports the device of the actual
/// object — the overlay's own device when the reference is inside the overlay, the
/// decoy device when it only shares the path string. A vanished process or an
/// unreadable link simply contributes no match.
pub(super) fn process_references_overlay_device(
    pid: u32,
    overlay_devices: &std::collections::HashSet<u64>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let base = format!("/proc/{pid}");
    for link in ["cwd", "root"] {
        if let Ok(meta) = std::fs::metadata(format!("{base}/{link}"))
            && overlay_devices.contains(&meta.dev())
        {
            return true;
        }
    }
    if let Ok(entries) = std::fs::read_dir(format!("{base}/fd")) {
        for entry in entries.flatten() {
            if let Ok(meta) = std::fs::metadata(entry.path())
                && overlay_devices.contains(&meta.dev())
            {
                return true;
            }
        }
    }
    false
}

/// Send `signal` (e.g. `TERM`, `KILL`) to `pid`, best-effort.
///
/// Routes through the shared process runner so the host-tool resolution and the
/// test-runtime guard apply exactly as they do for every other external command.
pub(super) fn signal_pid(pid: u32, signal: &str) {
    use crate::process::run::{ProcessRunner, RealProcessRunner, signal_command};
    let _ = RealProcessRunner.run(&signal_command(pid, signal));
}

/// Decide whether a recorded activation owner pid should be signalled before an
/// emergency/recover teardown.
///
/// Owner-pid signalling is a try-lock, not a hard gate: it applies only to the
/// state-independent teardowns (`Emergency`/`Recover`), never to a normal
/// Active-only deactivate which owns the state itself, and never targets the
/// unset sentinel (`0`) or our own process. The aliveness probe and the actual
/// signal happen at the call site; this function holds only the pure decision so
/// it can be unit-tested without touching `/proc` or sending a real signal.
pub(super) fn owner_pid_to_signal(
    kind: ManagerDeactivationKind,
    owner_pid: u32,
    self_pid: u32,
) -> Option<u32> {
    let signals_owner = matches!(
        kind,
        ManagerDeactivationKind::Emergency | ManagerDeactivationKind::Recover
    );
    if signals_owner && owner_pid != 0 && owner_pid != self_pid {
        Some(owner_pid)
    } else {
        None
    }
}

/// How long the batched `systemctl stop --no-block` may take. It only enqueues
/// jobs, so it returns at once on a healthy manager; the deadline keeps a wedged
/// manager from delaying the kill and the unmount behind it.
pub(super) const STOP_ENQUEUE_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// Enqueue a stop job for every unit, without waiting for the jobs to run.
///
/// Best-effort and bounded: a failure only means systemd may restart a unit
/// after the kill, which the caller cannot do anything more about.
pub(super) fn enqueue_unit_stops(units: &std::collections::BTreeSet<String>) {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
    if units.is_empty() {
        return;
    }
    tracing::info!(units = ?units, "Enqueuing stop jobs before the overlay kill so Restart= cannot revive them");
    let command = ProcessCommand::tool("systemctl")
        .arg("stop")
        .arg("--no-block")
        .arg("--")
        .args(units.iter())
        .deadline(STOP_ENQUEUE_BUDGET);
    if let Err(e) = RealProcessRunner.run(&command) {
        tracing::warn!(error = %e, "Could not enqueue the stop jobs; continuing with the kill");
    }
}
