// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS CLI Binary Entry Point
//!
//! Command-line interface binary for the nails overlay environment manager.
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use nails::cli::logging::StdoutFormat;
use nails::cli::{Cli, Commands, OutputSettings, execute_command};

/// `activate --json` streams progress events as NDJSON on stdout ahead of the
/// final result; every other command keeps diagnostics on stderr.
fn stdout_format_for(command: &Commands, settings: &OutputSettings) -> StdoutFormat {
    match command {
        Commands::Activate(_) if settings.is_json() => StdoutFormat::ActivateJsonStream,
        _ => StdoutFormat::Human,
    }
}

/// Whether a command may write a log file onto the hidden volume.
///
/// Only the commands that act on an attached hidden volume do. Read-only
/// commands (`status`, `verify`, `check`, `notify-dispatch`, `config`) and `init` — which
/// runs before the volume holds any NAILS structure — never create a log
/// directory or file, so running them from the decoy or a download directory
/// leaves nothing behind there. The attach gate is still the backstop: even a
/// writing command logs to a file only when the hidden volume is really mounted.
fn command_writes_logs(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Activate(_)
            | Commands::Deactivate(_)
            | Commands::Reapply(_)
            | Commands::Emergency(_)
            | Commands::ResetUpper(_)
    )
}

fn main() -> std::process::ExitCode {
    // First, before parsing: no crash from here on may dump core onto the decoy.
    let core_dump_error = nails::cli::disable_core_dumps();

    // The emergency hot path runs here, before clap, the environment snapshot,
    // the configuration and tracing exist (ADR 0007): the overlays are gone
    // before any of that runs. The emergency command then does the bookkeeping
    // and prints the result. Any other command line is left untouched.
    nails::cli::early::dispatch();

    let cli = Cli::parse_checked();

    // Read the environment exactly once. Every handler receives this snapshot,
    // and it is installed for the leaf helpers (the process runner, the
    // runtime-safety switch) that sit below every handler; nothing else reads
    // the process environment.
    let runtime_env = nails_core::RuntimeEnv::from_process_env();
    nails_core::runtime_env::install(runtime_env.clone());

    // Resolve verbosity, colour and ASCII once, before anything prints.
    let settings = OutputSettings::detect(&cli.global, &runtime_env);
    settings.install();

    // Refuse privileged commands run without root before logging is initialised
    // or any handler runs, so an unprivileged invocation writes no log or state
    // file and the operator gets one clear `sudo` instruction.
    if let Some(status) =
        nails::cli::main_guard::enforce_root(&cli.command, &settings, &runtime_env)
    {
        return status.to_exit_code();
    }

    let log_file = !cli.global.no_log_file && command_writes_logs(&cli.command);
    nails::cli::logging::init_subscriber(
        &settings,
        log_file,
        cli.global.config.as_deref(),
        stdout_format_for(&cli.command, &settings),
    );

    // Route panics through tracing (the hidden-root log when one is active) and
    // keep source paths and payloads off stderr, so a detached worker's crash
    // never lands in the decoy journal. Installed after the subscriber exists.
    nails::cli::install_panic_hook();

    if let Some(err) = core_dump_error {
        tracing::debug!(error = %err, "could not fully disable core dumps");
    }

    execute_command(cli, &settings, &runtime_env).to_exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails::cli::args::{ActivateArgs, VerifyArgs};
    use nails::cli::output::OutputMode;

    fn json() -> OutputSettings {
        OutputSettings {
            mode: OutputMode::Json,
            ..OutputSettings::default()
        }
    }

    #[test]
    fn activate_json_uses_json_stream_stdout_format() {
        let activate = Commands::Activate(ActivateArgs::default());
        assert_eq!(
            stdout_format_for(&activate, &json()),
            StdoutFormat::ActivateJsonStream
        );
    }

    #[test]
    fn activate_without_json_uses_human_stdout_format() {
        let activate = Commands::Activate(ActivateArgs::default());
        assert_eq!(
            stdout_format_for(&activate, &OutputSettings::default()),
            StdoutFormat::Human
        );
    }

    #[test]
    fn other_commands_with_json_keep_tracing_on_stderr() {
        let verify = Commands::Verify(VerifyArgs::default());
        assert_eq!(stdout_format_for(&verify, &json()), StdoutFormat::Human);
    }

    #[test]
    fn writing_commands_enable_the_log_file() {
        use nails::cli::args::ResetUpperArgs;
        use std::path::PathBuf;

        assert!(command_writes_logs(&Commands::Activate(
            ActivateArgs::default()
        )));
        assert!(command_writes_logs(&Commands::Deactivate(
            Default::default()
        )));
        assert!(command_writes_logs(&Commands::ResetUpper(ResetUpperArgs {
            target: PathBuf::from("/home"),
            yes: true,
        })));
    }

    #[test]
    fn read_only_and_setup_commands_never_create_log_files() {
        use nails::cli::args::InitArgs;
        use std::path::PathBuf;

        assert!(!command_writes_logs(&Commands::Verify(
            VerifyArgs::default()
        )));
        assert!(!command_writes_logs(&Commands::Check(Default::default())));
        assert!(!command_writes_logs(&Commands::Status(Default::default())));
        assert!(!command_writes_logs(&Commands::Init(InitArgs {
            path: PathBuf::from("/mnt/data"),
            ..Default::default()
        })));
        assert!(!command_writes_logs(&Commands::NotifyDispatch));
    }
}
