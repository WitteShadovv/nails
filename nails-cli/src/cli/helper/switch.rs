// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operations that switch sides or clean up after a switch: activate and
//! deactivate (each a plan and an apply), emergency and recover.
//!
//! Each runs the CLI's own handler, or the two halves of it around the
//! confirmation, under `--json`, so the window gets the CLI's envelope and exit
//! code for every ending. An activation's apply streams its steps as events,
//! names the point of no return, and is cancelled when the window closes its
//! pipe before that point ([`super::hangup`]).

use std::path::Path;

use nails_api::Event;
use nails_api::protocol::{
    ActivateArgs, ActivatePlanData, DeactivateArgs, DeactivatePlanData, EmergencyArgs,
};
use nails_core::RuntimeEnv;
use nails_core::app::activate::LockedActivation;
use nails_core::app::deactivate::ReadyDeactivation;
use nails_core::cancel::CancelToken;
use nails_core::reporter::{EventReporter, EventSink, progress};
use nails_core::session::LeaveTo;

use super::hangup::HangupWatch;
use super::ops::{Engine, Planned, answer_from, captured, json_settings};
use super::session::{Answer, EventOut};
use crate::cli::commands;
use crate::cli::output::ExitStatus;
use crate::cli::output::envelope::capture;

const ACTIVATE: &str = "activate";
const DEACTIVATE: &str = "deactivate";

/// An activation planned for the window: past its gates, holding the lock.
pub(crate) struct PlannedActivation {
    locked: LockedActivation,
}

/// A deactivation planned for the window: a way back exists.
pub(crate) struct PlannedDeactivation {
    ready: ReadyDeactivation,
    to: LeaveTo,
    warnings: Vec<String>,
}

/// The CLI's `activate` arguments for `args`, confirmed: the plan and its apply
/// are the window's confirmation.
fn activate_args(args: &ActivateArgs) -> crate::cli::args::ActivateArgs {
    crate::cli::args::ActivateArgs {
        yes: true,
        nixos_flake: args.nixos_flake.clone(),
        dry_run: false,
        overlay_only: args.overlay_only,
        allow_persistent_decoy: args.allow_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
        allow_discards: args.allow_discards,
    }
}

impl Engine<'_> {
    /// The plan half of `nails activate`: the configuration, the gates and the
    /// state lock, kept behind a token. An activation that ends before the lock
    /// (refused, or already active) answers as the CLI does and keeps nothing.
    pub(super) fn activate_plan(&mut self, args: &ActivateArgs) -> Answer {
        let settings = json_settings();
        let args = activate_args(args);
        let (begun, line) =
            capture(|| commands::activate::begin(&settings, self.env, &args, self.config()));
        let begun = match begun {
            Ok(begun) => begun,
            Err(exit) => return answer_from(ACTIVATE, exit, line),
        };
        let builds_hidden_system = begun.locked.builds_hidden_system();
        let planned = PlannedActivation {
            locked: begun.locked,
        };
        let (warning, defaults_notice) = (begun.warning, begun.defaults_notice);
        self.hold(ACTIVATE, Planned::Activate(Box::new(planned)), |token| {
            ActivatePlanData {
                warning,
                defaults_notice,
                builds_hidden_system,
                token,
            }
        })
    }

    /// The apply half of `nails activate`: the residue baseline, the entry with
    /// each step sent as an event, the point of no return and the commit, as
    /// the CLI runs them once confirmed.
    ///
    /// While it runs, a window that closes its end of the pipe trips a cancel
    /// token installed on this thread, which the entry's checkpoints read as a
    /// Ctrl+C: up to the point of no return the activation unwinds, and after
    /// it no checkpoint is left, so the helper finishes the switch.
    pub(super) fn activate_apply(&self, planned: PlannedActivation, events: EventOut) -> Answer {
        let token = CancelToken::new();
        let _watch = self
            .pipe
            .as_ref()
            .and_then(|pipe| HangupWatch::start(pipe, token.clone()));
        let _cancel = token.install();
        let mut at_point = events.clone();
        let _scope = progress::install(progress::shared(EventReporter::new(events)));
        let settings = json_settings();
        captured(ACTIVATE, || {
            commands::activate::finish(&settings, planned.locked, || {
                at_point.emit(Event::PointOfNoReturn);
            })
        })
    }

    /// The plan half of `nails deactivate`: whether there is a way back, and
    /// what it will not put back, kept behind a token. Off the hidden root, or
    /// in one without a way back, it answers as the CLI does and keeps
    /// nothing. The apply takes the lock, as the CLI does once confirmed.
    pub(super) fn deactivate_plan(&mut self, args: &DeactivateArgs) -> Answer {
        let settings = json_settings();
        let args = crate::cli::args::DeactivateArgs {
            yes: true,
            poweroff: args.poweroff,
        };
        let prepared = nails_core::app::deactivate::prepare(self.env, self.config());
        let mut ready = None;
        let (exit, line) = capture(|| {
            commands::deactivate::deactivate_prepared_with(
                &settings,
                &args,
                prepared,
                |deactivation, to, warnings| {
                    ready = Some(PlannedDeactivation {
                        ready: deactivation,
                        to,
                        warnings,
                    });
                    ExitStatus::Ok
                },
            )
        });
        let Some(planned) = ready else {
            return answer_from(DEACTIVATE, exit, line);
        };
        let poweroff = planned.to == LeaveTo::Poweroff;
        let warnings = planned.warnings.clone();
        self.hold(
            DEACTIVATE,
            Planned::Deactivate(Box::new(planned)),
            |token| DeactivatePlanData {
                poweroff,
                warnings,
                token,
            },
        )
    }
}

/// The apply half of `nails deactivate`: take the lock and leave, as the CLI
/// does once confirmed.
pub(super) fn deactivate_apply(planned: PlannedDeactivation) -> Answer {
    let settings = json_settings();
    captured(DEACTIVATE, || {
        commands::deactivate::lock_and_leave(&settings, planned.ready, planned.to, planned.warnings)
    })
}

/// `nails emergency`, at once: the countdown is the window's.
pub(super) fn emergency(env: &RuntimeEnv, args: &EmergencyArgs, config: Option<&Path>) -> Answer {
    let settings = json_settings();
    let args = crate::cli::args::EmergencyArgs {
        countdown: None,
        poweroff: args.poweroff,
        reboot: args.reboot,
    };
    captured("emergency", || {
        commands::emergency::execute(&settings, env, &args, config)
    })
}

/// `nails recover`, which also resets a record left active on the decoy.
pub(super) fn recover(env: &RuntimeEnv, config: Option<&Path>) -> Answer {
    let settings = json_settings();
    captured("recover", || {
        commands::recover::execute(&settings, env, &crate::cli::args::RecoverArgs {}, config)
    })
}

#[cfg(test)]
#[path = "switch_tests.rs"]
mod tests;
