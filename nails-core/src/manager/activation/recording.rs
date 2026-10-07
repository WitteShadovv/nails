// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Recording activation results into the state file: Active state, the last-
//! activation record, switch warnings, the hidden session plan and added units.

use super::*;

impl<F: Filesystem> NailsManager<F> {
    /// Write the Active state together with this activation's duration.
    ///
    /// The duration is kept across deactivation so `nails status` can report how
    /// long the last activation took. If the write fails, the previous record is
    /// put back before the rollback persists the state, so a failed activation
    /// never reports a duration.
    pub(crate) fn commit_active_state(
        &mut self,
        active_state: crate::SystemState,
        elapsed: std::time::Duration,
    ) -> Result<()> {
        let previous = self.record_last_activation(elapsed);
        self.update_state(active_state).inspect_err(|_| {
            self.restore_last_activation(previous);
        })
    }

    /// Record the duration of this activation in the cached state so it is
    /// written out with the Active state, returning the record it replaced.
    fn record_last_activation(
        &self,
        duration: std::time::Duration,
    ) -> Option<crate::state::LastActivation> {
        let mut cached = self.cached_state.borrow_mut();
        let state_file = cached.as_mut()?;
        state_file
            .last_activation
            .replace(crate::state::LastActivation {
                duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
                finished_at: chrono::Utc::now(),
            })
    }

    /// Put back the last-activation record replaced by
    /// [`record_last_activation`](Self::record_last_activation).
    fn restore_last_activation(&self, previous: Option<crate::state::LastActivation>) {
        if let Some(ref mut state_file) = *self.cached_state.borrow_mut() {
            state_file.last_activation = previous;
        }
    }

    /// Record (or clear) the last hidden NixOS switch warning in the cached state
    /// so it is written out with the next state save. `None` clears a prior
    /// warning after a clean switch.
    pub(crate) fn record_switch_warning(&self, warning: Option<&str>) {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.set_switch_warning(warning.map(ToString::to_string));
        }
    }

    /// Record the hidden graphical session in the cached state from the
    /// session-kill restart plan, as a record of what activation took over. No
    /// teardown acts on it: emergency never ends a logind session and never touches
    /// the display manager or X server. A no-op when activation did not
    /// take over a graphical session (no target uid in the plan).
    pub(crate) fn record_hidden_session(&self, plan: &crate::process::SessionRestartPlan) {
        let Some(target_uid) = plan.target_uid else {
            return;
        };
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.hidden_session = Some(crate::state::HiddenSession {
                target_uid,
                session_id: None,
                display_manager: plan.display_manager.clone(),
            });
        }
    }

    /// Record the service units the hidden switch added (units active after it
    /// that were not known at all before it — see
    /// `ServiceController::list_known_units`) in the cached state, so
    /// emergency teardown stops exactly those units instead of switching the
    /// whole decoy configuration back. A no-op when nothing was added.
    ///
    /// Only an applied hidden switch can introduce units for teardown to stop: an
    /// overlay-only run (or any host without a declarative layer) reports
    /// [`HiddenConfigOutcome::NotRequested`] and adds nothing, so recording is
    /// skipped unless the switch actually applied. This keeps the overlay-only
    /// path from ever recording the running decoy units and having emergency stop
    /// the live system.
    ///
    /// The diff is also only trustworthy when the "before" snapshot actually
    /// enumerated the host's units. An empty "before" means the enumeration
    /// returned nothing (systemctl failed, or no units were listed), and then
    /// every active unit would be mistaken for one the hidden switch introduced —
    /// so emergency would stop the entire running system, the operator's session
    /// and all. Treat an empty "before" as "unknown" and record nothing rather
    /// than risk that: a genuine hidden service is better left running than the
    /// whole decoy torn down.
    pub(crate) fn record_hidden_added_units(
        &self,
        outcome: &HiddenConfigOutcome,
        before: &[String],
        after: &[String],
    ) {
        if !matches!(outcome, HiddenConfigOutcome::Applied { .. }) {
            return;
        }
        if before.is_empty() {
            tracing::warn!(
                "Skipping the hidden-added unit snapshot: the pre-switch unit list was empty, \
                 so the added-unit diff cannot be trusted"
            );
            return;
        }
        let before_set: std::collections::HashSet<&str> =
            before.iter().map(String::as_str).collect();
        let added: Vec<String> = after
            .iter()
            .filter(|unit| !before_set.contains(unit.as_str()))
            .filter(|unit| !is_protected_base_unit(unit))
            .cloned()
            .collect();
        if added.is_empty() {
            return;
        }
        for unit in &added {
            self.record_plan_step(nails_teardown::Undo::StopUnit { unit: unit.clone() });
        }
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.hidden_added_units = added;
        }
    }

    /// Record the Debian-family platform section in the cached state so a host
    /// with no declarative layer still carries a typed platform marker. A no-op
    /// once a NixOS section is recorded (an overlay-only run on NixOS keeps the
    /// platform unset rather than claiming Debian-family).
    pub(crate) fn record_debian_family_platform(&self) {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.mark_debian_family();
        }
    }
}
