// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Init command handler.
//!
//! Bootstraps the NAILS directory structure on a hidden volume. The planning
//! and the writing live in [`nails_core::app::init`]; this parses the target and
//! flags, maps a refusal or a precondition failure to an exit code, and renders
//! the report. Each item is reported as created or already present, and the run
//! ends with the numbered next steps the operator takes to activate.

use std::fmt::Write as _;
use std::path::Path;

use crate::cli::args::InitArgs;
use crate::cli::output::envelope::{Envelope, EnvelopePrint, ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::{ExitStatus, OutputSettings};
use nails_core::Filesystem;
use nails_core::app::init::{self, InitFailure, InitOptions, InitPlan, InitReport};

/// The init options the clap arguments ask for.
fn options(args: &InitArgs) -> InitOptions {
    InitOptions {
        path: args.path.clone(),
        allow_decoy_storage: args.allow_decoy_storage,
        no_hardware_config: args.no_hardware_config,
        hardware_config: args.hardware_config.clone(),
    }
}

/// Execute the init command.
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `init` arguments (target path and bootstrap flags)
/// * `config_override` - The global `--config`, which init does not use
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the layout exists
/// - [`ExitStatus::Config`] when the global `--config` was passed
/// - [`ExitStatus::PreflightRefused`] when the attach gate refuses the target
///   or a precondition is not met
/// - [`ExitStatus::Failed`] when a filesystem operation fails
pub fn execute(
    settings: &OutputSettings,
    args: &InitArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    // init takes its target positionally and writes a fixed layout; the global
    // --config (which points at an existing config file) has no meaning here, so
    // accepting it silently would hide an operator mistake.
    if config_override.is_some() {
        return report_error(
            json,
            "init",
            ExitStatus::Config,
            ErrorBody::new(
                "config",
                "nails init takes the hidden volume path as its positional argument; \
                 the global --config flag is not used by init",
            )
            .with_hint("run `nails init <hidden-volume-root>`"),
        );
    }

    run(settings, &nails_core::RealFilesystem, args)
}

/// Drive init against a filesystem: validate, apply, report.
fn run<F: Filesystem>(settings: &OutputSettings, fs: &F, args: &InitArgs) -> ExitStatus {
    let json = settings.is_json();

    let plan = match plan(fs, args) {
        Ok(plan) => plan,
        Err(InitFailure::NotSeparate(refusal)) => {
            return report_refusal(json, "init", &refusal);
        }
        Err(InitFailure::Preconditions(failures)) => {
            return report_error(
                json,
                "init",
                ExitStatus::PreflightRefused,
                ErrorBody::new("preconditions", failures.join("; ")),
            );
        }
        Err(InitFailure::Io(error)) => {
            return report_error(
                json,
                "init",
                ExitStatus::Failed,
                ErrorBody::new("io", error.to_string()),
            );
        }
    };

    let report = match apply(fs, &args.path, plan) {
        Ok(report) => report,
        Err(error) => {
            return report_error(
                json,
                "init",
                ExitStatus::Failed,
                ErrorBody::new("io", error.to_string()),
            );
        }
    };

    render_report(settings, &report);
    ExitStatus::Ok
}

/// Plan the layout for `args`: the facade operation with the clap arguments
/// mapped to its options.
fn plan<F: Filesystem>(fs: &F, args: &InitArgs) -> std::result::Result<InitPlan, InitFailure> {
    init::plan(fs, &options(args))
}

/// Write the planned layout.
fn apply<F: Filesystem>(fs: &F, base: &Path, plan: InitPlan) -> nails_core::Result<InitReport> {
    init::apply(fs, base, plan)
}

/// Render the report: one JSON envelope under `--json`, otherwise any warnings
/// on stderr (kept under `-q`) and [`render_text`] on stdout.
fn render_report(settings: &OutputSettings, report: &InitReport) {
    if settings.is_json() {
        Envelope::success("init", report).print();
        return;
    }

    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }

    if settings.is_quiet() {
        return;
    }

    print!("{}", render_text(report));
}

/// The human-readable report: the item lines, any informational notes, and the
/// numbered next steps, which always come last.
fn render_text(report: &InitReport) -> String {
    let mut out = String::new();
    for item in &report.items {
        let _ = writeln!(out, "  {}: {}", item.status.label(), item.path);
    }
    for note in &report.notes {
        let _ = writeln!(out, "info: {note}");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "NAILS layout initialized at {}", report.root);
    let _ = writeln!(out);
    let _ = writeln!(out, "Next steps:");
    for (index, step) in report.next_steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {step}", index + 1);
    }
    out
}

#[cfg(test)]
mod tests;
