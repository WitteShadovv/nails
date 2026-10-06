// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Post-mount writer rescan.
//!
//! An overlay only redirects *new* path lookups. A process that opened a file,
//! `cwd`'d into a directory or memory-mapped a file before the mount keeps
//! resolving the decoy's inode and keeps writing to the decoy lower tree once the
//! overlay is up. The pre-mount classification restarts the writers it can; this
//! rescan is the safety net that runs *after* every overlay has mounted, walks
//! `/proc` once, and records any process still holding a write-capable reference
//! to an overlaid target.
//!
//! Each such process is tagged with a [`WriterKind`]: a process whose references
//! cannot be verified against the host mount namespace (chrooted or in a foreign
//! namespace) is [`WriterKind::Unverifiable`]; every other write-blocking holder
//! is [`WriterKind::StaleLower`]. A process already recorded by the pre-mount
//! pass keeps its [`WriterKind::Surviving`] tag and only gains any newly observed
//! target, so the two passes never double-count a PID.

use crate::DecoyWriter;
use crate::WriterKind;
use crate::process::detection::{ProcSnapshot, ProcessInfo};
use std::path::{Path, PathBuf};

/// Walk `/proc` once and merge every write-blocking holder of an overlaid target
/// into `writers`.
///
/// Integrity-verified targets are skipped for the same reason the pre-mount pass
/// skips them (`record_surviving_writers`): a verified lower never leaks, so a
/// holder of it is not a decoy writer.
///
/// In a test or runtime-safety build [`ProcSnapshot::capture`] returns an empty
/// snapshot, so this is a no-op and leaves the pre-mount writer set untouched.
pub(super) fn rescan_post_mount_writers(writers: &mut Vec<DecoyWriter>, targets: &[PathBuf]) {
    let snapshot = match ProcSnapshot::capture() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            // A failed rescan must not fail an otherwise-successful activation: the
            // overlays are up and the pre-mount writer set still stands. Log and
            // proceed so the posture is at worst optimistic, never a hard abort.
            tracing::warn!(error = %err, "post-mount writer rescan could not read /proc; skipping");
            return;
        }
    };
    for target in targets {
        if is_integrity_verified(target) {
            continue;
        }
        merge_target_writers(writers, target, &snapshot.processes_using(target));
    }
}

/// The testable core: classify every write-blocking holder of a single `target`
/// and merge it into `writers`. A read-only consumer is left out — it cannot
/// write to the decoy through the references it holds.
fn merge_target_writers(writers: &mut Vec<DecoyWriter>, target: &Path, candidates: &[ProcessInfo]) {
    for info in candidates {
        if !info.is_write_blocking() {
            continue;
        }
        let kind = if info.is_unverifiable_writer {
            WriterKind::Unverifiable
        } else {
            WriterKind::StaleLower
        };
        tracing::warn!(
            pid = info.pid,
            process = %info.name,
            target = %target.display(),
            kind = ?kind,
            "post-mount rescan: process still references the decoy through {}",
            target.display()
        );
        merge_one(writers, target, info, kind);
    }
}

/// Whether `target` is an integrity-verified lower that never contributes decoy
/// writers. Mirrors the pre-mount exemption so both passes agree.
fn is_integrity_verified(target: &Path) -> bool {
    super::super::INTEGRITY_VERIFIED_TARGETS
        .iter()
        .any(|verified| target == Path::new(verified))
}

/// Merge one rescanned holder into the writer list by PID.
///
/// A PID already present (from the pre-mount pass or an earlier target in this
/// rescan) gains the new target but keeps its existing kind, so a `Surviving`
/// writer is never downgraded and a `StaleLower` one is never relabelled by a
/// later target.
fn merge_one(writers: &mut Vec<DecoyWriter>, target: &Path, info: &ProcessInfo, kind: WriterKind) {
    match writers.iter_mut().find(|w| w.pid == info.pid) {
        Some(writer) => {
            if !writer.targets.iter().any(|t| t == target) {
                writer.targets.push(target.to_path_buf());
            }
        }
        None => writers.push(DecoyWriter {
            pid: info.pid,
            name: info.name.clone(),
            service: info.service_name.clone(),
            targets: vec![target.to_path_buf()],
            kind,
        }),
    }
}

#[cfg(test)]
mod tests;
