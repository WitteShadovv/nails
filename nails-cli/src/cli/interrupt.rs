// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Under `--json`, the one cancel envelope for a signal that ends a command
//! which does not handle the signal itself.
//!
//! The mutating commands install the cancellation handlers
//! ([`nails_core::cancel::install_handlers`]) and decide themselves what a
//! Ctrl+C does: at a prompt, during an emergency's countdown and in an
//! activation before its point of no return it cancels, reported as every
//! cancel is (under `--json` the cancel envelope) with exit 130; a teardown
//! that has begun runs to the end and reports its result. Every other command
//! keeps the signal's default action, which ends the process with nothing on
//! stdout. Under `--json` that would break the contract of one envelope per
//! run, so [`report_signals_as_cancel`] has the first SIGINT or SIGTERM print
//! the cancel envelope (the error `cancelled`, no data) and end the process
//! with exit 130. When the command's own envelope is already out, the signal
//! changes nothing and the command ends with its own exit code.

use crate::cli::output::ExitStatus;
use crate::cli::output::envelope::{ErrorBody, error_envelope, print_envelope_line};

/// The message of that cancel envelope, from the catalogue.
pub(crate) const INTERRUPTED: &str = nails_core::catalog::CANCEL_INTERRUPTED.text;

/// Have the first SIGINT or SIGTERM end the run of `command` with its cancel
/// envelope and exit 130 (see the module docs).
pub(crate) fn report_signals_as_cancel(command: &'static str) {
    nails_core::cancel::watch_signals(move || {
        let line = error_envelope(command, ErrorBody::new("cancelled", INTERRUPTED)).to_line();
        if print_envelope_line(&line) {
            crate::cli::output::flush_stdio();
            crate::cli::chokepoint::exit_process(ExitStatus::Cancelled.code());
        }
    });
}

#[cfg(test)]
#[path = "interrupt_tests.rs"]
mod tests;
