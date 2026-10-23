// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root session through the manager: what `activate`, `deactivate`
//! and `recover` do with the configuration, the state file and the host.
//!
//! The mechanics are in [`crate::session`] and `nails_teardown::whole_root`;
//! this adds the pre-flight registry, the hidden NixOS configuration, the
//! state file and the backend chain.

use super::{NailsManager, PreflightOptions};
use crate::error::{NailsError, Result};
use crate::filesystem::Filesystem;
use crate::platform::PlatformKind;
use crate::session::entry::{self, EntryHost, EntryInputs};
use crate::session::{LeaveTo, Paths, SessionView, TargetHost};
use crate::state::{LastActivation, SystemState};
use chrono::Utc;
use nails_teardown::mountinfo::{MountEntry, read_mountinfo};
use std::path::PathBuf;

/// What `activate` asked for.
#[derive(Debug, Clone, Default)]
pub struct EnterOptions {
    /// Enter with the decoy's own system: no hidden NixOS build (on FHS the
    /// hidden configuration is whatever the upper's `/etc` holds anyway).
    pub overlay_only: bool,
    /// Allow a persistent decoy posture for this activation.
    pub allow_persistent_decoy: bool,
    /// The running binary, copied to RAM for the panic path.
    pub binary: PathBuf,
    /// Accept a hidden root on storage the attach gate takes for the decoy's
    /// (`--allow-decoy-storage`). The activation's own writes accept it, the
    /// pre-flight check warns, and the plan records it.
    pub allow_decoy_storage: bool,
    /// Accept discards over the hidden volume for this run (the buried
    /// `--allow-discards` expert flag): the backend-detect pre-flight check
    /// then warns instead of refusing. Per run only; there is no stored
    /// equivalent.
    pub allow_discards: bool,
}

impl EnterOptions {
    /// The pre-flight options of this activation: what `nails check` builds
    /// from the same flags, so both run the same checks. The registry stays
    /// read-only, as it does for `check`.
    pub fn preflight(&self) -> PreflightOptions {
        PreflightOptions {
            overlay_only: self.overlay_only,
            allow_persistent_decoy: self.allow_persistent_decoy,
            allow_decoy_storage: self.allow_decoy_storage,
            allow_discards: self.allow_discards,
            ..PreflightOptions::default()
        }
    }

    /// The attach-gate override these options ask for.
    pub fn allow(&self) -> crate::hidden_root::Allow {
        if self.allow_decoy_storage {
            crate::hidden_root::Allow::DecoyStorage
        } else {
            crate::hidden_root::Allow::Nothing
        }
    }
}

/// What [`NailsManager::enter_session`] did.
#[derive(Debug, Clone)]
pub enum EnterOutcome {
    /// Already in the hidden root; nothing changed.
    AlreadyActive,
    /// The entry is prepared and armed; [`NailsManager::trigger_entry`] starts
    /// the soft-reboot.
    Prepared {
        /// The prepared entry.
        entry: Box<entry::Entry>,
        /// How long the activation took, from its start to the commit to
        /// Active: the duration the state file records as the last
        /// activation, so `activate` and `status` show the same time.
        elapsed: std::time::Duration,
    },
}

/// What [`NailsManager::recover_session`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRecovery {
    /// Nothing was left to recover.
    Clean,
    /// An interrupted entry was rolled back.
    RolledBack {
        /// Mounts still below `/run/nextroot` (empty when everything came off).
        remaining: Vec<PathBuf>,
        /// The hidden backend's device-mapper devices that were still open,
        /// and whether they are closed now or still in use.
        backend: Vec<(String, nails_teardown::whole_root::ret::BackendClose)>,
    },
}

/// What the session flow reads of the machine: the system paths and the live
/// mount table in production; the tests give a scratch tree and a fixed table.
struct Machine {
    paths: Paths,
    /// The mount table, or `None` to read the live one.
    mounts: Option<Vec<MountEntry>>,
}

impl Machine {
    fn system() -> Self {
        Self {
            paths: Paths::system(),
            mounts: None,
        }
    }

    fn mounts(&self) -> std::io::Result<Vec<MountEntry>> {
        match &self.mounts {
            Some(mounts) => Ok(mounts.clone()),
            None => read_mountinfo(),
        }
    }
}

/// Why `hidden_root` is not a volume of its own, when only the operator's
/// override (`allow`) lets the entry use it: what the plan records.
fn accepted_decoy_storage<F: Filesystem>(
    fs: &F,
    hidden_root: &std::path::Path,
    allow: crate::hidden_root::Allow,
) -> Result<Option<String>> {
    use crate::hidden_root::{Assessment, HiddenRoot};
    Ok(match HiddenRoot::assess_allowing(fs, hidden_root, allow)? {
        Assessment::Warned(refusal) if refusal.overridden() => Some(refusal.reason),
        _ => None,
    })
}

/// `step`, between two cancel checkpoints: a Ctrl+C reaches the step's
/// child processes too, so a cancel outranks the failure it caused.
fn cancellable<T>(step: impl FnOnce() -> Result<T>) -> Result<T> {
    crate::cancel::checkpoint()?;
    let result = step();
    crate::cancel::checkpoint()?;
    result
}

impl<F: Filesystem> NailsManager<F> {
    /// Where the machine is right now.
    pub fn session_view(&self) -> SessionView {
        self.session_view_on(&Machine::system())
    }

    fn session_view_on(&self, machine: &Machine) -> SessionView {
        let mounts = machine.mounts().unwrap_or_default();
        crate::session::probe::probe_with(&machine.paths, &self.config.hidden_volume_root, &mounts)
    }

    fn require_supported_host(&self, machine: &Machine) -> Result<bool> {
        match self.host_profile() {
            Some(profile) => {
                profile.require_supported()?;
                Ok(profile.kind == PlatformKind::NixOs)
            }
            None => Ok(machine.paths.run.join("current-system").exists()),
        }
    }

    /// The builder the entry builds the hidden NixOS system with: only on a
    /// NixOS host (`nixos`), with a configured build target, and not under
    /// `--overlay-only`.
    fn hidden_builder(
        &self,
        nixos: bool,
        options: &EnterOptions,
    ) -> Option<&crate::nixos::NixOSBuilder> {
        self.nixos_builder
            .as_ref()
            .filter(|_| nixos && !options.overlay_only)
    }

    /// Whether entering with `options` builds a hidden NixOS system into the
    /// next root, decided as the entry decides it. False on a host the entry
    /// would refuse.
    pub fn builds_hidden_system(&self, options: &EnterOptions) -> bool {
        self.builds_hidden_system_on(&Machine::system(), options)
    }

    fn builds_hidden_system_on(&self, machine: &Machine, options: &EnterOptions) -> bool {
        self.require_supported_host(machine)
            .is_ok_and(|nixos| self.hidden_builder(nixos, options).is_some())
    }

    /// Prepare the entry into the hidden root: pre-flight, the hidden NixOS
    /// configuration, the next root and the armed plan. The state file records
    /// the session as active before the soft-reboot, because the activating
    /// process dies in it.
    ///
    /// A SIGINT or SIGTERM ([`crate::cancel`]) stops it at the next step
    /// boundary with [`NailsError::Cancelled`], everything undone: the last
    /// boundary is right before the state is recorded, after which the caller
    /// only enqueues the soft-reboot.
    pub fn enter_session(
        &mut self,
        options: &EnterOptions,
        host: &dyn EntryHost,
    ) -> Result<EnterOutcome> {
        self.enter_session_on(&Machine::system(), options, host)
    }

    fn enter_session_on(
        &mut self,
        machine: &Machine,
        options: &EnterOptions,
        host: &dyn EntryHost,
    ) -> Result<EnterOutcome> {
        // Activation always runs the full pre-flight registry.
        self.enter_session_running(machine, options, host, true)
    }

    /// Prepare the entry, running the pre-flight registry only when
    /// `run_preflight` is set. Activation always sets it; the `run_preflight =
    /// false` path exists for the tests that exercise the entry mechanics
    /// directly, without the registry reading the real host.
    fn enter_session_running(
        &mut self,
        machine: &Machine,
        options: &EnterOptions,
        host: &dyn EntryHost,
        run_preflight: bool,
    ) -> Result<EnterOutcome> {
        let result = self.enter_session_inner(machine, options, host, run_preflight);
        // Mark the end of the activation for a watching event stream, unless
        // there was nothing to do (already in the hidden root).
        if !matches!(result, Ok(EnterOutcome::AlreadyActive)) {
            crate::reporter::progress::finish(result.is_ok());
        }
        result
    }

    /// Prepare the entry without the pre-flight registry (tests only).
    #[cfg(test)]
    fn enter_session_no_preflight_on(
        &mut self,
        machine: &Machine,
        options: &EnterOptions,
        host: &dyn EntryHost,
    ) -> Result<EnterOutcome> {
        self.enter_session_running(machine, options, host, false)
    }

    fn enter_session_inner(
        &mut self,
        machine: &Machine,
        options: &EnterOptions,
        host: &dyn EntryHost,
        run_preflight: bool,
    ) -> Result<EnterOutcome> {
        if self.session_view_on(machine).is_hidden() {
            return Ok(EnterOutcome::AlreadyActive);
        }
        crate::cancel::checkpoint()?;
        // The activation's one clock: it covers the staging and the pre-flight
        // checks too, as the progress line and the recorded duration say.
        let started = std::time::Instant::now();
        // What the operator accepted holds for every write of this activation.
        self.allow = options.allow();
        let nixos = self.require_supported_host(machine)?;
        // The full pre-flight registry stages the hidden configuration and then
        // runs every check, the decoy-entry refusal (`backend-entries`), the
        // decoy's-own-flake refusal (`nixos-build-target`) and the discard
        // refusal (`backend-detect`) among them.
        if run_preflight {
            cancellable(|| self.stage_hidden_config(options.overlay_only))?;
            cancellable(|| self.run_preflight_checks(&options.preflight()))?;
        }
        let hidden_root = self.config.hidden_volume_root.clone();
        let entries = machine
            .mounts()
            .map_err(|e| NailsError::io("/proc/self/mountinfo", e))?;
        let decoy_root = entry::decoy_root_of(&entries, std::path::Path::new("/"))?;
        let backend = crate::backend_lock::resolve_backend_chain(&self.filesystem, &hidden_root)
            .ok()
            .flatten()
            .map(|chain| chain.dm_names)
            .unwrap_or_default();
        let config_toml = toml::to_string(&self.config).ok();
        let accepted_decoy_storage =
            accepted_decoy_storage(&self.filesystem, &hidden_root, self.allow)?;
        let builder = self.hidden_builder(nixos, options);
        let inputs = EntryInputs {
            hidden_root: &hidden_root,
            decoy_root,
            nixos,
            builder,
            binary: &options.binary,
            config_toml,
            session_units: crate::session::units::session_units(&self.config),
            backend,
            persona: self.config.persona.clone(),
            operator: crate::TargetUser::resolve_with(self.runtime_env()).ok(),
            rebuild_space_mb: self.config.rebuild_space_mb,
            read_only_disks: self.config.session_mounts.read_only,
            accepted_decoy_storage,
        };
        let prepared = entry::prepare(&machine.paths, &inputs, host)?;
        let elapsed = started.elapsed();
        // The last boundary: once recorded, the caller only enqueues the
        // soft-reboot.
        let recorded =
            crate::cancel::checkpoint().and_then(|()| self.record_entry(&prepared, elapsed));
        if let Err(e) = recorded {
            entry::rollback(&machine.paths);
            let _ = host.daemon_reload();
            return Err(e);
        }
        Ok(EnterOutcome::Prepared {
            entry: Box::new(prepared),
            elapsed,
        })
    }

    fn record_entry(
        &mut self,
        prepared: &entry::Entry,
        elapsed: std::time::Duration,
    ) -> Result<()> {
        // A new activation supersedes the last switch's refusal, if any, so a
        // stale reason never outlives the switch it described.
        nails_teardown::whole_root::switch_refusal::clear(&self.config.hidden_volume_root);
        let now = Utc::now();
        // The FHS family of the detected host; the state file keeps only Fedora
        // and Arch (see `StateFile::mark_fhs_family`), so a Debian-family host
        // records no family and its state file stays byte identical.
        let family = self.host_profile().and_then(|profile| profile.family);
        {
            let mut cached = self.cached_state.borrow_mut();
            if cached.is_none() {
                *cached = crate::StateFile::load(&self.state_file_path).ok();
            }
            if let Some(state_file) = cached.as_mut() {
                match &prepared.plan.hidden.system {
                    Some(system) => {
                        state_file.set_nixos_generation(Some(system.display().to_string()));
                    }
                    None if prepared.plan.decoy.system.is_none() => {
                        state_file.mark_fhs_family(family)
                    }
                    None => state_file.clear_platform(),
                }
                state_file.decoy_system = prepared
                    .plan
                    .decoy
                    .system
                    .as_ref()
                    .map(|p| p.display().to_string());
                state_file.last_activation = Some(LastActivation {
                    duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                    finished_at: now,
                });
            }
        }
        self.force_state(SystemState::Active { activated_at: now })
    }

    /// Enqueue the soft-reboot into the prepared root. On failure the entry is
    /// rolled back and the state returns to inactive.
    pub fn trigger_entry(
        &mut self,
        target: &dyn TargetHost,
        entry_host: &dyn EntryHost,
    ) -> Result<()> {
        self.trigger_entry_on(&Machine::system(), target, entry_host)
    }

    fn trigger_entry_on(
        &mut self,
        machine: &Machine,
        target: &dyn TargetHost,
        entry_host: &dyn EntryHost,
    ) -> Result<()> {
        if let Err(e) = target.start_target("soft-reboot.target") {
            entry::rollback(&machine.paths);
            let _ = entry_host.daemon_reload();
            let _ = self.force_state(SystemState::Inactive);
            return Err(e);
        }
        Ok(())
    }

    /// Leave the hidden root: soft-reboot back to the plain decoy (or power
    /// off). The state file is set inactive first, while the hidden volume is
    /// still mounted.
    pub fn leave_session(
        &mut self,
        to: LeaveTo,
        host: &dyn TargetHost,
    ) -> Result<crate::session::LeaveReport> {
        self.leave_session_on(&Machine::system(), to, host)
    }

    fn leave_session_on(
        &mut self,
        machine: &Machine,
        to: LeaveTo,
        host: &dyn TargetHost,
    ) -> Result<crate::session::LeaveReport> {
        let mut plan = match self.session_view_on(machine) {
            SessionView::Hidden(plan) => *plan,
            SessionView::HiddenWithoutPlan(why) => {
                return Err(NailsError::InvalidState(format!(
                    "in the hidden root, but the way back is unknown: {why}. Power the machine \
                     off to end the session."
                )));
            }
            _ => {
                return Err(NailsError::InvalidState(
                    "not in a hidden session".to_string(),
                ));
            }
        };
        // Leaving is a new switch: supersede the last one's refusal, if any.
        nails_teardown::whole_root::switch_refusal::clear(&self.config.hidden_volume_root);
        self.force_state(SystemState::Inactive)?;
        rustix::fs::sync();
        crate::session::leave(&machine.paths, &mut plan, to, host)
    }

    /// Remove the leftovers of an interrupted entry on the decoy.
    pub fn recover_session(&mut self, host: &dyn EntryHost) -> Result<SessionRecovery> {
        self.recover_session_on(&Machine::system(), host)
    }

    fn recover_session_on(
        &mut self,
        machine: &Machine,
        host: &dyn EntryHost,
    ) -> Result<SessionRecovery> {
        match self.session_view_on(machine) {
            SessionView::Decoy => {
                if matches!(self.current_state(), Ok(SystemState::Active { .. })) {
                    self.force_state(SystemState::Inactive)?;
                }
                Ok(SessionRecovery::Clean)
            }
            SessionView::Interrupted { .. } => {
                let paths = &machine.paths;
                let plan = nails_teardown::whole_root::plan::Plan::load(&paths.plan()).ok();
                let remaining = entry::rollback(paths);
                let _ = host.daemon_reload();
                let _ = self.force_state(SystemState::Inactive);
                // Nothing hidden runs on the decoy: close the hidden backend
                // where nothing uses it, so its key leaves RAM, and report it
                // where something does.
                let backend = plan
                    .map(|plan| {
                        nails_teardown::whole_root::ret::close_idle_backend(
                            &plan,
                            std::path::Path::new("/dev/mapper"),
                        )
                    })
                    .unwrap_or_default();
                Ok(SessionRecovery::RolledBack { remaining, backend })
            }
            SessionView::Entering(_) => Err(NailsError::InvalidState(
                "an activation is entering the hidden root right now".to_string(),
            )),
            SessionView::Hidden(_) | SessionView::HiddenWithoutPlan(_) => {
                use crate::next_step::{NextStep, sudo_line};
                Err(NailsError::InvalidState(format!(
                    "in the hidden session: use `{}` (or `{}`)",
                    sudo_line(NextStep::Deactivate),
                    sudo_line(NextStep::Emergency)
                )))
            }
        }
    }
}

#[cfg(test)]
#[path = "session_flow_tests.rs"]
mod tests;
