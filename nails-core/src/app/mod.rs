// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # The engine facade
//!
//! One function per operation, so every front end drives the same
//! orchestration. The CLI parses arguments and renders the result; a future
//! window speaks to these functions over its helper. Neither holds the sequence
//! of library calls that takes a session up or down, reads the live state or
//! judges a host: that lives here, once.
//!
//! Each function takes the already-resolved inputs (a [`Config`](crate::Config),
//! the [`RuntimeEnv`](crate::RuntimeEnv) and the operation's own options) and
//! returns a typed outcome. The outcome names what happened — a report, a
//! refusal, a prepared entry — so a front end maps it to its own output and exit
//! code without re-deriving the decision. Nothing here prints, prompts or reads
//! an exit code: those are the front end's.

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
