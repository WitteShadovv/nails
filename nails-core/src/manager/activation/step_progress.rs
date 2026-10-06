// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The multi-step activation progress reporter and its hidden-volume record.

use super::*;

impl<F: Filesystem> NailsManager<F> {
    /// Progress for one activation: seven steps when a declarative layer runs,
    /// five otherwise, reported through this manager's reporter.
    pub(super) fn step_progress(&self, layer_runs: bool) -> StepProgress {
        StepProgress::new(
            self.verbosity,
            if layer_runs { 7 } else { 5 },
            self.reporter.clone(),
        )
    }

    /// Start keeping `step`'s hidden-volume progress record. Only call once the
    /// hidden volume is confirmed mounted, so the record never lands on the decoy.
    ///
    /// Also arms the activation-in-progress marker the login dispatcher polls
    /// on, removed with the progress record when the activation returns.
    pub(super) fn attach_progress_record(&self, step: &mut StepProgress) {
        step.attach_file(
            self.filesystem.clone(),
            self.config.hidden_volume_root.clone(),
        );
        step.result_marker = Some(crate::notification::deliver::ResultPendingMarker::arm(
            &self.config.hidden_volume_root,
        ));
    }
}

/// Sequential activation progress whose count follows the active execution path.
///
/// The total is fixed up front from whether a declarative configuration layer
/// runs (NixOS, and not `--overlay-only`); each emitted step advances the counter
/// so the `[n/total]` numbering stays contiguous even when the layer steps are
/// skipped. A step is counted whatever the verbosity, so the numbering a quiet
/// run would show matches a verbose one.
///
/// Every step is logged at debug level (the hidden-root log) and reported
/// through a [`Tee`]: to the manager's operator-facing reporter (muted below
/// Normal verbosity) and, once attached, to the hidden-volume progress record.
/// The tee is installed as the active reporter for the activation's lifetime,
/// so heartbeats and details raised deep in the build and mount code reach it.
/// Unless [`succeed`](Self::succeed) is called, dropping the progress reports
/// the current step as failed; dropping it also removes the progress record.
pub(super) struct StepProgress {
    pub(super) current: u8,
    pub(super) total: u8,
    /// The phase id and label most recently emitted, so a progress record
    /// attached mid-activation starts from the phase already in progress.
    last: (&'static str, String),
    /// When the activation started, recorded in the progress record.
    started_at: chrono::DateTime<chrono::Utc>,
    hub: std::sync::Arc<std::sync::Mutex<Tee>>,
    succeeded: bool,
    /// Tells the login dispatcher an activation is in progress; removed on drop.
    result_marker: Option<crate::notification::deliver::ResultPendingMarker>,
    /// Declared last so the active-reporter slot is released after `hub`.
    _scope: crate::reporter::progress::ActiveScope,
}

impl StepProgress {
    pub(super) fn new(verbosity: Verbosity, total: u8, reporter: SharedReporter) -> Self {
        let hub = std::sync::Arc::new(std::sync::Mutex::new(Tee::new(
            reporter,
            verbosity >= Verbosity::Normal,
        )));
        let active: SharedReporter = hub.clone();
        Self {
            current: 0,
            total,
            last: ("", String::new()),
            started_at: chrono::Utc::now(),
            hub,
            succeeded: false,
            result_marker: None,
            _scope: crate::reporter::progress::install(active),
        }
    }

    fn hub(&self) -> std::sync::MutexGuard<'_, Tee> {
        self.hub
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The label a step message contributes: the message without its trailing
    /// ellipsis.
    fn label(message: &str) -> String {
        message.trim_end_matches('.').to_string()
    }

    /// Advance to the next step: log it and report it.
    pub(super) fn emit(&mut self, phase: &'static str, message: &str) {
        self.current += 1;
        self.last = (phase, Self::label(message));
        tracing::debug!(
            event = "progress",
            phase = phase,
            current = self.current,
            total = self.total,
            "[{}/{}] {}",
            self.current,
            self.total,
            self.last.1
        );
        let (index, total) = (u32::from(self.current), u32::from(self.total));
        let label = self.last.1.clone();
        self.hub().step(Step {
            index,
            total,
            phase,
            label: &label,
        });
    }

    /// Start keeping the hidden-volume progress record, beginning with the phase
    /// already in progress. The record is removed when this progress is dropped.
    fn attach_file<F: Filesystem>(&mut self, fs: F, hidden_root: std::path::PathBuf) {
        let writer = crate::progress::ProgressFileWriter::start(
            fs,
            hidden_root,
            self.started_at,
            u32::from(self.current),
            u32::from(self.total),
            self.last.0,
            &self.last.1,
        );
        self.hub().attach(Box::new(writer));
    }

    /// The activation succeeded: report the final step as done.
    pub(super) fn succeed(&mut self) {
        self.succeeded = true;
        self.hub().finish(true);
    }
}

impl Drop for StepProgress {
    fn drop(&mut self) {
        if !self.succeeded {
            self.hub().finish(false);
        }
    }
}
