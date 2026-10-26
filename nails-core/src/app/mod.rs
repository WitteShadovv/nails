// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # The engine facade
//!
//! One function per operation, so every front end drives the same
//! orchestration. The CLI parses arguments and renders the result; a future
//! window speaks to these functions over its helper. The sequence of library
//! calls that takes a session up or down, the reading of the live state and the
//! judging of a host live here, once.
//!
//! Each function takes the already-resolved inputs (a [`Config`](crate::Config),
//! the [`RuntimeEnv`](crate::RuntimeEnv) and the operation's own options) and
//! returns a typed outcome. The outcome names what happened — a report, a
//! refusal, a prepared entry — so a front end maps it to its own output and exit
//! code without re-deriving the decision. Nothing here prints, prompts or reads
//! an exit code: those are the front end's.
//!
//! The gates are in the types. An operation that writes under the exclusive
//! state lock ([`lock`]) hands out the handle that runs its writing steps
//! only from its lock step, which takes the lock and holds it for as long as
//! the handle lives:
//!
//! - [`activate::ReadyActivation::lock`] also refuses, under the lock, a state
//!   file it cannot trust, and hands out the [`activate::LockedActivation`]
//!   that alone enters and commits;
//! - [`deactivate::ReadyDeactivation::lock`] hands out the
//!   [`deactivate::LockedDeactivation`] that alone leaves;
//! - [`discard_upper::ReadyDiscard::lock`] hands out the
//!   [`discard_upper::LockedDiscard`] that alone plans and applies.
//!
//! [`init`] and [`recover`] take the lock themselves and [`emergency`] runs
//! without it, so a front end must not hold it around them: the lock is taken
//! per open file, so [`init`] would fail on a lock its own front end holds,
//! and [`recover`] would wait for it in vain and go on without it. No outcome
//! carries a secret: a [`rehearse`] outcome names the canary by its
//! fingerprint and redacts the token from every path.
//!
//! Two things stay with the front end:
//!
//! - the confirmation, and the cancel checks between the steps;
//! - the argument combinations the CLI's parser refuses, other than the ones an
//!   operation refuses itself ([`verify`] refuses an offline scan without its
//!   image root, and an image root, the examiner's view or its disk without
//!   the scan they belong to).

pub mod activate;
pub mod config;
pub mod config_view;
pub mod deactivate;
pub mod discard_upper;
pub mod emergency;
pub mod engine;
pub mod init;
pub mod lock;
pub mod readiness;
pub mod recover;
pub mod refusal;
pub mod rehearse;
pub mod status;
pub mod verify;

pub use config::{
    ConfigSource, config_error_line, load_config_for_teardown, load_config_or_defaults,
    resolve_config,
};
pub use config_view::config_view;
pub use status::{StatusOutcome, status};
