// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activation progress record on the hidden volume.
//!
//! A detached activation has no terminal: the worker runs as a transient unit
//! with its output discarded, so the operator cannot see which phase it is in.
//! The activation therefore keeps a small progress record on the hidden volume,
//! rewritten atomically at every phase change, and `nails status` reads it while
//! the state is `Activating` to show the current phase and how long the
//! activation has been running.
//!
//! The record lives on the hidden volume next to the state file, never on the
//! decoy, and is removed once the activation finishes (successfully or not). A
//! leftover record is harmless: status consults it only while the persisted
//! state is `Activating`.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Filesystem, NailsError, Result};

/// File name of the progress record, relative to the hidden-volume root.
pub const PROGRESS_FILE: &str = "progress.json";

/// One snapshot of an activation in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationProgress {
    /// Stable machine identifier of the current phase (e.g. `overlay_mount`).
    pub phase: String,
    /// Human-readable label of the current phase (e.g. `Mounting overlays`).
    pub label: String,
    /// 1-based index of the current phase.
    pub step: u32,
    /// Number of phases this activation runs.
    pub total_steps: u32,
    /// When the activation started.
    pub started_at: DateTime<Utc>,
    /// When the current phase started.
    pub phase_started_at: DateTime<Utc>,
    /// Optional finer-grained detail within the phase, such as the overlay
    /// being mounted or the most recent build line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ActivationProgress {
    /// Seconds elapsed since the activation started, measured against `now`.
    /// Clamped to zero when the clock moved backwards.
    pub fn elapsed_secs(&self, now: DateTime<Utc>) -> u64 {
        u64::try_from(now.signed_duration_since(self.started_at).num_seconds()).unwrap_or(0)
    }
}

/// Atomically (re)write the progress record beneath `hidden_root`.
///
/// Written through the symlink-safe hidden-root writer at mode `0600`, so a
/// planted symlink cannot redirect it onto the decoy.
pub fn write_progress<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
    progress: &ActivationProgress,
) -> Result<()> {
    let json = serde_json::to_string(progress).map_err(|e| {
        NailsError::ConfigError(format!("Failed to serialize activation progress: {e}"))
    })?;
    fs.write_hidden_file_atomic(hidden_root, Path::new(PROGRESS_FILE), &json, 0o600)
}

/// Read the progress record, or `None` when it is absent or unparseable.
pub fn read_progress<F: Filesystem>(fs: &F, hidden_root: &Path) -> Option<ActivationProgress> {
    let content = fs
        .read_file_content(&hidden_root.join(PROGRESS_FILE))
        .ok()?;
    serde_json::from_str(&content).ok()
}

/// Remove the progress record. Best-effort: a missing record or a failed
/// removal is ignored, since status only consults it while `Activating`.
pub fn clear_progress<F: Filesystem>(fs: &F, hidden_root: &Path) {
    let path = hidden_root.join(PROGRESS_FILE);
    if fs.path_exists(&path).unwrap_or(false) {
        let _ = fs.remove_file(&path);
    }
}

/// Keeps the progress record current for one activation and removes it when
/// dropped, so the record never outlives the activation that wrote it, whether
/// that activation committed, failed or was cancelled.
///
/// Write failures are logged at debug level and never fail the activation: the
/// record is an operator convenience, not part of the activation's safety.
pub struct ProgressFileWriter<F: Filesystem> {
    fs: F,
    hidden_root: std::path::PathBuf,
    current: ActivationProgress,
}

impl<F: Filesystem> ProgressFileWriter<F> {
    /// Start a record for an activation that began at `started_at` and runs
    /// `total_steps` phases, writing its first snapshot immediately.
    ///
    /// Only create this once the hidden volume is known to be mounted (after the
    /// pre-flight checks), so the record can never land on the decoy disk.
    pub fn start(
        fs: F,
        hidden_root: std::path::PathBuf,
        started_at: DateTime<Utc>,
        step: u32,
        total_steps: u32,
        phase: &str,
        label: &str,
    ) -> Self {
        let writer = Self {
            fs,
            hidden_root,
            current: ActivationProgress {
                phase: phase.to_string(),
                label: label.to_string(),
                step,
                total_steps,
                started_at,
                phase_started_at: Utc::now(),
                detail: None,
            },
        };
        writer.flush();
        writer
    }

    /// Record that the activation entered `phase` (step `step`).
    pub fn set_phase(&mut self, step: u32, phase: &str, label: &str) {
        self.current.step = step;
        self.current.phase = phase.to_string();
        self.current.label = label.to_string();
        self.current.phase_started_at = Utc::now();
        self.current.detail = None;
        self.flush();
    }

    /// Replace the detail line within the current phase.
    pub fn set_detail(&mut self, detail: Option<String>) {
        if self.current.detail != detail {
            self.current.detail = detail;
            self.flush();
        }
    }

    /// The snapshot most recently written.
    pub fn current(&self) -> &ActivationProgress {
        &self.current
    }

    fn flush(&self) {
        if let Err(e) = write_progress(&self.fs, &self.hidden_root, &self.current) {
            tracing::debug!(error = %e, "Could not update the activation progress record");
        }
    }
}

/// The progress record as a reporter: steps become phases, details and the
/// most recent build line of a long step become the detail. The record lives
/// on the hidden volume, so it may carry the build line that terminal-less
/// surfaces never show.
impl<F: Filesystem> crate::reporter::progress::Reporter for ProgressFileWriter<F> {
    fn step(&mut self, step: crate::reporter::progress::Step<'_>) {
        self.set_phase(step.index, step.phase, step.label);
    }

    fn detail(&mut self, detail: &str) {
        self.set_detail(Some(detail.trim().to_string()));
    }

    fn heartbeat(
        &mut self,
        _activity: &str,
        _elapsed: std::time::Duration,
        last_line: Option<&str>,
    ) {
        if let Some(line) = last_line.map(str::trim).filter(|line| !line.is_empty()) {
            self.set_detail(Some(line.to_string()));
        }
    }

    /// The record is removed when the writer is dropped.
    fn finish(&mut self, _success: bool) {}
}

impl<F: Filesystem> Drop for ProgressFileWriter<F> {
    fn drop(&mut self) {
        clear_progress(&self.fs, &self.hidden_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use std::path::PathBuf;

    #[test]
    fn writer_tracks_phases_and_removes_the_record_on_drop() {
        let fs = MockFilesystem::new();
        let root = PathBuf::from("/hidden");
        fs.create_directory(&root).unwrap();
        let started = Utc::now();

        let mut writer = ProgressFileWriter::start(
            fs.clone(),
            root.clone(),
            started,
            2,
            7,
            "session_management",
            "Preparing session management",
        );
        let first = read_progress(&fs, &root).expect("first snapshot written");
        assert_eq!(first.step, 2);
        assert_eq!(first.phase, "session_management");
        assert_eq!(first.started_at, started);

        writer.set_phase(4, "overlay_mount", "Mounting overlays");
        writer.set_detail(Some("mounting /home (1/3)".to_string()));
        let now = read_progress(&fs, &root).expect("updated snapshot");
        assert_eq!(now.step, 4);
        assert_eq!(now.total_steps, 7);
        assert_eq!(now.label, "Mounting overlays");
        assert_eq!(now.detail.as_deref(), Some("mounting /home (1/3)"));
        assert_eq!(now.started_at, started, "start time is kept across phases");

        // Entering a new phase drops the previous phase's detail.
        writer.set_phase(5, "profile_switch", "Applying hidden configuration");
        assert_eq!(read_progress(&fs, &root).unwrap().detail, None);

        drop(writer);
        assert_eq!(read_progress(&fs, &root), None, "record removed on drop");
    }

    fn sample(started_at: DateTime<Utc>) -> ActivationProgress {
        ActivationProgress {
            phase: "overlay_mount".to_string(),
            label: "Mounting overlays".to_string(),
            step: 4,
            total_steps: 7,
            started_at,
            phase_started_at: started_at,
            detail: Some("mounting /home (3/12)".to_string()),
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let fs = MockFilesystem::new();
        let root = PathBuf::from("/hidden");
        fs.create_directory(&root).unwrap();
        let progress = sample(Utc::now());

        write_progress(&fs, &root, &progress).unwrap();

        assert_eq!(read_progress(&fs, &root), Some(progress));
    }

    #[test]
    fn read_is_none_when_absent_or_garbage() {
        let fs = MockFilesystem::new();
        let root = PathBuf::from("/hidden");
        fs.create_directory(&root).unwrap();
        assert_eq!(read_progress(&fs, &root), None);

        fs.write_file_content(&root.join(PROGRESS_FILE), "not json")
            .unwrap();
        assert_eq!(read_progress(&fs, &root), None);
    }

    #[test]
    fn clear_removes_the_record_and_tolerates_absence() {
        let fs = MockFilesystem::new();
        let root = PathBuf::from("/hidden");
        fs.create_directory(&root).unwrap();
        write_progress(&fs, &root, &sample(Utc::now())).unwrap();

        clear_progress(&fs, &root);
        assert_eq!(read_progress(&fs, &root), None);

        // A second clear on an absent record is a no-op.
        clear_progress(&fs, &root);
    }

    #[test]
    fn elapsed_is_measured_from_activation_start_and_clamped() {
        let start = Utc::now();
        let progress = sample(start);
        assert_eq!(
            progress.elapsed_secs(start + chrono::Duration::seconds(130)),
            130
        );
        assert_eq!(
            progress.elapsed_secs(start - chrono::Duration::seconds(5)),
            0
        );
    }
}
