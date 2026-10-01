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

fn main() -> std::process::ExitCode {
    let cli = Cli::parse_checked();

    // Resolve verbosity, colour and ASCII once, before anything prints.
    let settings = OutputSettings::detect(&cli.global);
    settings.install();

    nails::cli::logging::init_subscriber(
        &settings,
        !cli.global.no_log_file,
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
}
