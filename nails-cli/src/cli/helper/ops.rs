// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operations a window can run through the helper, each answered with the
//! exit code and the envelope the CLI gives for the same command under
//! `--json`.
//!
//! Each operation goes through the code its CLI command goes through (the
//! engine facade and the CLI's own envelope builders), so the two front ends
//! cannot describe one outcome differently.
//!
//! A discard runs in two requests. The plan takes the exclusive state lock and
//! keeps it, with the plan, behind a single-use token drawn from the kernel's
//! random source; the apply deletes exactly that plan, under that lock, when it
//! carries the token. Any other request withdraws the plan and releases the
//! lock, so a plan never outlives the next request.

use std::path::{Path, PathBuf};

use nails_api::protocol::{
    CheckArgs, ConfigShowArgs, DiscardPlanArgs, DiscardPlanData, ErrorCode, Op, ProtocolError,
    TOKEN_HEX_DIGITS,
};
use nails_core::app::discard_upper::{DiscardData, LockedDiscard};
use nails_core::reporter::{EventReporter, progress};
use nails_core::{NailsError, ResetUpperPlan, RuntimeEnv};

use super::session::{Answer, Dispatch, EventOut};
use crate::cli::args::ConfigCommand;
use crate::cli::commands;
use crate::cli::output::ExitStatus;
use crate::cli::output::envelope::{Envelope, ErrorBody, error_envelope};

/// A plan waiting for its apply, with the lock it was made under.
struct Pending {
    token: String,
    plan: ResetUpperPlan,
    locked: LockedDiscard,
}

/// The engine behind a session.
pub(crate) struct Engine<'a> {
    env: &'a RuntimeEnv,
    config: Option<PathBuf>,
    pending: Option<Pending>,
}

impl<'a> Engine<'a> {
    /// The engine for `env`, reading the configuration `config` names (the
    /// helper's own `--config`, never a path a window sends).
    pub(crate) fn new(env: &'a RuntimeEnv, config: Option<PathBuf>) -> Self {
        Self {
            env,
            config,
            pending: None,
        }
    }

    fn config(&self) -> Option<&Path> {
        self.config.as_deref()
    }
}

impl Dispatch for Engine<'_> {
    fn run(&mut self, op: Op, events: EventOut) -> Answer {
        // A plan lives until the next request: its apply, or anything else,
        // which withdraws it and releases its lock before that request runs.
        let pending = match op {
            Op::DiscardApply(_) => self.pending.take(),
            _ => {
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
            Op::DiscardApply(token) => discard_apply(pending, &token.token),
            // The session answers the hello itself and never passes one on.
            Op::Hello(_) => Answer::Refused(ProtocolError {
                code: ErrorCode::Handshake,
                message: "the hello was already given".to_string(),
            }),
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
        let token = match random_token() {
            Ok(token) => token,
            Err(error) => {
                let body = ErrorBody::new(DISCARD, format!("could not draw a plan token: {error}"));
                return Answer::result(ExitStatus::Failed, &error_envelope(DISCARD, body));
            }
        };
        let data = DiscardPlanData {
            target: plan.target.display().to_string(),
            removals: plan
                .removals()
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            resets_nix_store: plan.resets_nix_store,
            token: token.clone(),
        };
        self.pending = Some(Pending {
            token,
            plan,
            locked,
        });
        Answer::result(ExitStatus::Ok, &Envelope::success(DISCARD, data))
    }
}

/// The apply half of `nails discard`: delete the plan `token` names, which
/// must be the plan of the request just before.
fn discard_apply(pending: Option<Pending>, token: &str) -> Answer {
    let Some(pending) = pending.filter(|pending| pending.token == token) else {
        return Answer::Refused(ProtocolError {
            code: ErrorCode::BadToken,
            message: "the token names no plan: plan the discard again".to_string(),
        });
    };
    if let Err(error) = pending.locked.apply(&pending.plan) {
        let body = ErrorBody::new(DISCARD, error.to_string());
        return Answer::result(ExitStatus::Failed, &error_envelope(DISCARD, body));
    }
    Answer::result(
        ExitStatus::Ok,
        &Envelope::success(DISCARD, DiscardData::from_plan(&pending.plan)),
    )
}

const DISCARD: &str = "discard";

/// A plan that could not be made, as `nails discard` reports it.
fn discard_failure(error: &NailsError) -> Answer {
    let exit = match error {
        NailsError::InvalidState(_) => ExitStatus::InvalidState,
        _ => ExitStatus::Failed,
    };
    let body = ErrorBody::new(DISCARD, error.to_string());
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
