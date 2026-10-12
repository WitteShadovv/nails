// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root session through the manager: what `activate`, `deactivate`
//! and `recover` do with the configuration, the state file and the host.
//!
//! The mechanics are in [`crate::session`] and `nails_teardown::whole_root`;
//! this adds the pre-flight registry, the hidden NixOS configuration, the
//! state file and the backend chain.

use super::NailsManager;
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
    /// Skip the pre-flight checks (expert use).
    pub skip_preflight: bool,
    /// Enter with the decoy's own system: no hidden NixOS build (on FHS the
    /// hidden configuration is whatever the upper's `/etc` holds anyway).
    pub overlay_only: bool,
    /// Accept a persistent decoy posture.
    pub accept_persistent_decoy: bool,
    /// The running binary, copied to RAM for the panic path.
    pub binary: PathBuf,
}

/// What [`NailsManager::enter_session`] did.
#[derive(Debug, Clone)]
pub enum EnterOutcome {
    /// Already in the hidden root; nothing changed.
    AlreadyActive,
    /// The entry is prepared and armed; [`NailsManager::trigger_entry`] starts
    /// the soft-reboot.
    Prepared(Box<entry::Entry>),
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

    /// Prepare the entry into the hidden root: pre-flight, the hidden NixOS
    /// configuration, the next root and the armed plan. The state file records
    /// the session as active before the soft-reboot, because the activating
    /// process dies in it.
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
        if self.session_view_on(machine).is_hidden() {
            return Ok(EnterOutcome::AlreadyActive);
        }
        let nixos = self.require_supported_host(machine)?;
        if !options.skip_preflight {
            self.stage_hidden_config(options.overlay_only)?;
            self.run_preflight_checks(options.overlay_only, options.accept_persistent_decoy)?;
        }
        let started = std::time::Instant::now();
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
        let builder = self
            .nixos_builder
            .as_ref()
            .filter(|_| nixos && !options.overlay_only);
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
        };
        let prepared = entry::prepare(&machine.paths, &inputs, host)?;
        if let Err(e) = self.record_entry(&prepared, started.elapsed()) {
            entry::rollback(&machine.paths);
            let _ = host.daemon_reload();
            return Err(e);
        }
        Ok(EnterOutcome::Prepared(Box::new(prepared)))
    }

    fn record_entry(
        &mut self,
        prepared: &entry::Entry,
        elapsed: std::time::Duration,
    ) -> Result<()> {
        let now = Utc::now();
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
                    None if prepared.plan.decoy.system.is_none() => state_file.mark_debian_family(),
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
                Err(NailsError::InvalidState(
                    "in the hidden session: use `nails deactivate` (or `nails emergency`)"
                        .to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "session_flow_tests.rs"]
mod tests;
