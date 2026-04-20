//! # NAILS CLI Binary Entry Point
//!
//! Command-line interface binary for NixOS Anti-forensics Isolation & Layering System.
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use clap::Parser;
use nails::cli::logging::StdoutFormat;
use nails::cli::{Cli, Commands, execute_command};

fn stdout_format_for_command(command: &Commands) -> StdoutFormat {
    match command {
        Commands::Activate { json: true, .. } => StdoutFormat::ActivateJsonStream,
        _ => StdoutFormat::Human,
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Parse CLI args to extract verbosity BEFORE initializing tracing
    let cli = Cli::parse();

    // Configure output formatting (NO_COLOR environment variable)
    // Story 14.7: Integrate output module with NO_COLOR support
    if std::env::var("NO_COLOR").is_ok() {
        nails_core::set_plain_mode(true);
    }

    let stdout_format = stdout_format_for_command(&cli.command);

    // Initialize tracing subscriber with verbosity-aware filtering
    // Story 9.3: Wire verbosity flags to tracing subscriber (AC #5)
    nails::cli::logging::init_stdout_subscriber_with_mode(
        cli.verbose,
        cli.quiet,
        cli.no_logs,
        cli.config.as_deref(),
        stdout_format,
    );

    execute_command(cli)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activate_command(json: bool) -> Commands {
        Commands::Activate {
            no_preflight: false,
            quiet: false,
            verbose: 0,
            json,
            no_color: false,
            plain: false,
            no_clear_history: false,
            kill_session: false,
            no_kill_session: false,
            accept_pivot_risks: false,
            no_pivot: false,
            yes: false,
            interactive: false,
            nixos_flake: None,
            dry_run: false,
            overlay_only: false,
        }
    }

    #[test]
    fn activate_json_uses_json_stream_stdout_format() {
        assert_eq!(
            stdout_format_for_command(&activate_command(true)),
            StdoutFormat::ActivateJsonStream
        );
    }

    #[test]
    fn activate_without_json_uses_human_stdout_format() {
        assert_eq!(
            stdout_format_for_command(&activate_command(false)),
            StdoutFormat::Human
        );
    }
}
