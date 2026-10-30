// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operations a window can run through the helper, each answered with the
//! exit code and the envelope the CLI gives for the same command under
//! `--json`.
//!
//! Each operation goes through the code its CLI command goes through: the
//! engine facade and the CLI's own envelope builders, or the CLI's command
//! handler itself under `--json`, whose envelope the helper captures instead
//! of printing ([`captured`]). So the two front ends cannot describe one
//! outcome differently.
//!
//! An operation the CLI confirms, and init, run in two requests (the discard
//! here, activate and deactivate in [`switch`], init in [`maintain`]). The
//! plan keeps what the apply needs (for a discard and an activation, the
//! exclusive state lock too) behind a single-use token drawn from the kernel's
//! random source; the apply carrying that token runs exactly that plan. Any
//! other request withdraws the plan and releases its lock, so a plan never
//! outlives the next request.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use nails_api::protocol::{
    CheckArgs, ConfigShowArgs, DiscardPlanArgs, DiscardPlanData, ErrorCode, Op, ProtocolError,
    TOKEN_HEX_DIGITS,
};
use nails_core::app::discard_upper::{DiscardData, LockedDiscard};
use nails_core::reporter::{EventReporter, progress};
use nails_core::{NailsError, ResetUpperPlan, RuntimeEnv};

use super::session::{Answer, Dispatch, EventOut};
use super::{maintain, switch};
use crate::cli::args::{ConfigCommand, RehearseStep};
use crate::cli::commands;
use crate::cli::output::envelope::{Envelope, ErrorBody, error_envelope};
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};

/// What a plan keeps for its apply.
pub(crate) enum Planned {
    /// A discard, with the lock it was made under.
    Discard(Box<PlannedDiscard>),
    /// An activation past its gates, holding the lock.
    Activate(Box<switch::PlannedActivation>),
    /// A deactivation with a way back.
    Deactivate(Box<switch::PlannedDeactivation>),
    /// An init whose preconditions held.
    Init(crate::cli::args::InitArgs),
}

/// A discard planned for the window.
pub(crate) struct PlannedDiscard {
    /// What the apply deletes.
    plan: ResetUpperPlan,
    /// The lock the plan was made under.
    locked: LockedDiscard,
}

/// A plan waiting for its apply.
struct Pending {
    token: String,
    planned: Planned,
}

/// The engine behind a session.
pub(crate) struct Engine<'a> {
    pub(super) env: &'a RuntimeEnv,
    config: Option<PathBuf>,
    pending: Option<Pending>,
    /// The helper's end of the window's pipe, watched for a hangup while an
    /// activation runs. `None` where no pipe is watched (the unit tests).
    pub(super) pipe: Option<OwnedFd>,
}

impl<'a> Engine<'a> {
    /// The engine for `env`, reading the configuration `config` names (the
    /// helper's own `--config`, never a path a window sends).
    pub(crate) fn new(env: &'a RuntimeEnv, config: Option<PathBuf>) -> Self {
        Self {
            env,
            config,
            pending: None,
            pipe: None,
        }
    }

    /// The engine, watching `pipe` (the helper's end of the window's pipe) for
    /// a hangup while an activation runs.
    pub(crate) fn watching(mut self, pipe: OwnedFd) -> Self {
        self.pipe = Some(pipe);
        self
    }

    /// Whether a plan waits for its apply.
    #[cfg(test)]
    pub(super) fn has_plan(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn config(&self) -> Option<&Path> {
        self.config.as_deref()
    }

    /// Keep `planned` behind a fresh token and answer the plan of `command`
    /// with the data `data` makes of that token.
    pub(super) fn hold<T: serde::Serialize>(
        &mut self,
        command: &'static str,
        planned: Planned,
        data: impl FnOnce(String) -> T,
    ) -> Answer {
        let token = match random_token() {
            Ok(token) => token,
            Err(error) => {
                let body = ErrorBody::new(command, format!("could not draw a plan token: {error}"));
                return Answer::result(ExitStatus::Failed, &error_envelope(command, body));
            }
        };
        let answer = Answer::result(
            ExitStatus::Ok,
            &Envelope::success(command, data(token.clone())),
        );
        self.pending = Some(Pending { token, planned });
        answer
    }
}

impl Dispatch for Engine<'_> {
    fn run(&mut self, op: Op, events: EventOut) -> Answer {
        // A plan lives until the next request: its apply, or anything else,
        // which withdraws it and releases its lock before that request runs.
        let planned = match op.apply_token() {
            Some(token) => redeem(self.pending.take(), token),
            None => {
                self.pending = None;
                None
            }
        };
        match op {
            Op::Status => status(self.config()),
            Op::Check(args) => check(self.env, &args, self.config(), events),
            Op::ConfigPath => config(self.config(), &ConfigCommand::Path),
            Op::ConfigShow(ConfigShowArgs { nixos_flake }) => config(
                self.config(),
                &ConfigCommand::Show {
                    example: false,
                    nixos_flake,
                },
            ),
            Op::ConfigValidate => config(self.config(), &ConfigCommand::Validate { path: None }),
            Op::DiscardPlan(args) => self.discard_plan(&args),
            Op::DiscardApply(_) => match planned {
                Some(Planned::Discard(planned)) => discard_apply(&planned.plan, &planned.locked),
                _ => bad_token(),
            },
            Op::ActivatePlan(args) => self.activate_plan(&args),
            Op::ActivateApply(_) => match planned {
                Some(Planned::Activate(planned)) => self.activate_apply(*planned, events),
                _ => bad_token(),
            },
            Op::DeactivatePlan(args) => self.deactivate_plan(&args),
            Op::DeactivateApply(_) => match planned {
                Some(Planned::Deactivate(planned)) => switch::deactivate_apply(*planned),
                _ => bad_token(),
            },
            Op::Emergency(args) => switch::emergency(self.env, &args, self.config()),
            Op::Recover => switch::recover(self.env, self.config()),
            Op::Verify(args) => maintain::verify(self.env, &args, self.config()),
            Op::RehearseStatus => maintain::rehearse(self.env, RehearseStep::Status, self.config()),
            Op::RehearsePlant(args) => {
                maintain::rehearse(self.env, maintain::plant_step(&args), self.config())
            }
            Op::RehearseScan(args) => {
                maintain::rehearse(self.env, maintain::scan_step(&args), self.config())
            }
            Op::RehearseReset => maintain::rehearse(self.env, RehearseStep::Reset, self.config()),
            Op::InitPlan(args) => self.init_plan(&args),
            Op::InitApply(_) => match planned {
                Some(Planned::Init(args)) => maintain::init_apply(&args),
                _ => bad_token(),
            },
            // The session answers the hello itself and never passes one on.
            Op::Hello(_) => Answer::Refused(ProtocolError {
                code: ErrorCode::Handshake,
                message: "the hello was already given".to_string(),
            }),
        }
    }
}

/// What the plan `pending` keeps, when `token` is its token. Either way the
/// plan is spent.
fn redeem(pending: Option<Pending>, token: &str) -> Option<Planned> {
    pending
        .filter(|pending| pending.token == token)
        .map(|pending| pending.planned)
}

/// The refusal of an apply whose token names no plan of its kind.
fn bad_token() -> Answer {
    Answer::Refused(ProtocolError {
        code: ErrorCode::BadToken,
        message: "the token names no plan: make the plan again".to_string(),
    })
}

/// The output settings of a CLI command run for the window: `--json`, since
/// the helper answers with the envelope.
pub(super) fn json_settings() -> OutputSettings {
    OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    }
}

/// Run `handler`, a CLI command handler under [`json_settings`], and answer
/// with its exit status and the envelope it printed, captured instead of
/// printed. A handler that printed none (none does under `--json`) answers as
/// a failure of `command`.
pub(super) fn captured(command: &'static str, handler: impl FnOnce() -> ExitStatus) -> Answer {
    let (exit, line) = crate::cli::output::envelope::capture(handler);
    answer_from(command, exit, line)
}

/// The answer of `command`, which ended with `exit` and printed `line`.
pub(super) fn answer_from(command: &'static str, exit: ExitStatus, line: Option<String>) -> Answer {
    match line.as_deref().map(serde_json::from_str) {
        Some(Ok(envelope)) => Answer::Result { exit, envelope },
        _ => {
            let body = ErrorBody::new(command, "the operation reported no result");
            Answer::result(ExitStatus::Failed, &error_envelope(command, body))
        }
    }
}

/// `nails status`.
fn status(config: Option<&Path>) -> Answer {
    use crate::cli::output::status::{status_envelope, status_unknown_envelope};
    use commands::status::status_exit_code;
    use nails_core::app::StatusOutcome;
    use nails_core::status::Posture;

    let loaded = match commands::resolve_config(config) {
        Ok(loaded) => loaded,
        Err(error) => return config_failure("status", &error),
    };
    match nails_core::app::status(loaded.into_config()) {
        StatusOutcome::Report(report) => {
            Answer::result(status_exit_code(report.posture), &status_envelope(&report))
        }
        StatusOutcome::Unknown { message, source } => {
            let sudo = commands::sudo_line_for(&source, "status");
            Answer::result(
                status_exit_code(Posture::Unknown),
                &status_unknown_envelope(message, sudo),
            )
        }
    }
}

/// `nails check`, with each check's result sent as an event as it finishes.
fn check(env: &RuntimeEnv, args: &CheckArgs, config: Option<&Path>, events: EventOut) -> Answer {
    use crate::cli::commands::check::{exit_status, readiness_report};
    use crate::cli::output::check::COMMAND;
    let args = crate::cli::args::CheckArgs {
        overlay_only: args.overlay_only,
        nixos_flake: args.nixos_flake.clone(),
        allow_persistent_decoy: args.allow_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
        allow_discards: args.allow_discards,
    };
    let _scope = progress::install(progress::shared(EventReporter::new(events)));
    match readiness_report(env, &args, config, |_| {}) {
        Ok(report) => Answer::result(
            exit_status(&report),
            &Envelope::outcome(COMMAND, report.ready, &report),
        ),
        Err((exit, error)) => Answer::result(exit, &error_envelope(COMMAND, error)),
    }
}

/// A `nails config` subcommand.
fn config(config: Option<&Path>, command: &ConfigCommand) -> Answer {
    let (exit, envelope) = commands::config::json_outcome(config, command);
    Answer::Result { exit, envelope }
}

impl Engine<'_> {
    /// The plan half of `nails discard`: plan under the lock, keep both behind
    /// a token. An empty plan answers as the CLI does and keeps nothing.
    fn discard_plan(&mut self, args: &DiscardPlanArgs) -> Answer {
        let loaded = match commands::resolve_config(self.config()) {
            Ok(loaded) => loaded,
            Err(error) => return config_failure(DISCARD, &error),
        };
        let ready = nails_core::app::discard_upper::prepare(self.env, loaded.into_config());
        let allow = if args.allow_decoy_storage {
            nails_core::hidden_root::Allow::DecoyStorage
        } else {
            nails_core::hidden_root::Allow::Nothing
        };
        let locked = match ready.lock(allow) {
            Ok(locked) => locked,
            Err(error) => {
                let (exit, body) = commands::lock_error_body(error, DISCARD);
                return Answer::result(exit, &error_envelope(DISCARD, body));
            }
        };
        let plan = match locked.plan(Path::new(&args.target)) {
            Ok(plan) => plan,
            Err(error) => return discard_failure(&error),
        };
        if plan.is_empty() {
            return Answer::result(
                ExitStatus::Ok,
                &Envelope::success(DISCARD, DiscardData::from_plan(&plan)),
            );
        }
        let target = plan.target.display().to_string();
        let removals = plan
            .removals()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let resets_nix_store = plan.resets_nix_store;
        self.hold(
            DISCARD,
            Planned::Discard(Box::new(PlannedDiscard { plan, locked })),
            |token| DiscardPlanData {
                target,
                removals,
                resets_nix_store,
                token,
            },
        )
    }
}

/// The apply half of `nails discard`: delete the plan its token named, which
/// was the plan of the request just before.
fn discard_apply(plan: &ResetUpperPlan, locked: &LockedDiscard) -> Answer {
    if let Err(error) = locked.apply(plan) {
        let body = ErrorBody::new(DISCARD, error.to_string());
        return Answer::result(ExitStatus::Failed, &error_envelope(DISCARD, body));
    }
    Answer::result(
        ExitStatus::Ok,
        &Envelope::success(DISCARD, DiscardData::from_plan(plan)),
    )
}

const DISCARD: &str = "discard";

/// A plan that could not be made, as `nails discard` reports it.
fn discard_failure(error: &NailsError) -> Answer {
    let (exit, body) = commands::discard::plan_failure(error);
    Answer::result(exit, &error_envelope(DISCARD, body))
}

/// A configuration that could not be loaded for `command`, as the CLI
/// reports it.
fn config_failure(command: &'static str, error: &NailsError) -> Answer {
    let body = commands::config_error_body(error, command);
    Answer::result(ExitStatus::Config, &error_envelope(command, body))
}

/// A fresh token: [`TOKEN_HEX_DIGITS`] hexadecimal digits from the kernel's
/// random source.
fn random_token() -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; TOKEN_HEX_DIGITS / 2];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
