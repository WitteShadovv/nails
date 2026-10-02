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
/// commands (`status`, `verify`, `notify-dispatch`, `config`) and `init` — which
/// runs before the volume holds any NAILS structure — never create a log
/// directory or file, so running them from the decoy or a download directory
/// leaves nothing behind there. The attach gate is still the backstop: even a
/// writing command logs to a file only when the hidden volume is really mounted.
fn command_writes_logs(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Activate(_)
            | Commands::Deactivate(_)
            | Commands::Emergency(_)
            | Commands::ResetUpper(_)
    )
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse_checked();

    // Resolve verbosity, colour and ASCII once, before anything prints.
    let settings = OutputSettings::detect(&cli.global);
    settings.install();

    let log_file = !cli.global.no_log_file && command_writes_logs(&cli.command);
    nails::cli::logging::init_subscriber(
        &settings,
        log_file,
        cli.global.config.as_deref(),
        stdout_format_for(&cli.command, &settings),
    );

    execute_command(cli, &settings).to_exit_code()
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
        assert!(!command_writes_logs(&Commands::Status(Default::default())));
        assert!(!command_writes_logs(&Commands::Init(InitArgs {
            path: PathBuf::from("/mnt/data"),
        })));
        assert!(!command_writes_logs(&Commands::NotifyDispatch));
    }
}
