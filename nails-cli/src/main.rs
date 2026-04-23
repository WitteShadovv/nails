//! # NAILS CLI Binary Entry Point
//!
//! Command-line interface binary for NixOS Anti-forensics Isolation & Layering System.
//!
//! The actual CLI logic is in lib.rs to allow for proper unit test coverage.

use clap::Parser;
use nails::cli::logging::StdoutFormat;
use nails::cli::{execute_command, Cli, Commands};

fn render_flags_for_command(command: &Commands) -> (bool, bool) {
    match command {
        Commands::Activate {
            no_color, plain, ..
        }
        | Commands::Deactivate {
            no_color, plain, ..
        }
        | Commands::Emergency {
            no_color, plain, ..
        }
        | Commands::Status {
            no_color, plain, ..
        } => (*no_color, *plain),
        _ => (false, false),
    }
}

fn stdout_format_for_command(command: &Commands) -> StdoutFormat {
    match command {
        Commands::Activate { json: true, .. } => StdoutFormat::ActivateJsonStream,
        _ => StdoutFormat::Human,
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Parse CLI args to extract verbosity BEFORE initializing tracing
    let cli = Cli::parse();
    let (no_color, plain) = render_flags_for_command(&cli.command);

    // Configure output formatting (NO_COLOR environment variable)
    nails_core::set_plain_mode(plain);
    nails_core::set_color_enabled(
        !(plain
            || no_color
            || std::env::var("NO_COLOR").is_ok()
            || std::env::var(nails_core::obfuscate::env_no_color()).is_ok()),
    );

    let stdout_format = stdout_format_for_command(&cli.command);

    // Initialize tracing subscriber with verbosity-aware filtering
    // Story 9.3: Wire verbosity flags to tracing subscriber (AC #5)
    nails::cli::logging::init_stdout_subscriber_with_mode(
        cli.verbose,
        cli.quiet,
        cli.no_logs,
        no_color,
        plain,
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
    fn status_render_flags_are_detected() {
        let command = Commands::Status {
            json: false,
            no_color: true,
            plain: false,
            verbose: false,
        };

        assert_eq!(render_flags_for_command(&command), (true, false));
    }

    #[test]
    fn non_rendering_commands_default_to_colored_human_mode() {
        let command = Commands::Verify {
            deep: false,
            json: false,
        };

        assert_eq!(render_flags_for_command(&command), (false, false));
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
