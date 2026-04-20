pub mod args;
pub mod commands;
mod detach;
pub mod logging;
pub mod output;
pub mod safety;

// Re-export main types for convenience
pub use args::{Cli, Commands};
pub use logging::init_stdout_subscriber;
pub use safety::check_real_operations_allowed;

/// Execute the CLI command - extracted for testability
pub fn execute_command(cli: Cli) -> std::result::Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Activate {
            no_preflight,
            quiet,
            verbose,
            json,
            no_color,
            plain,
            no_clear_history,
            kill_session: _,
            no_kill_session,
            accept_pivot_risks,
            no_pivot: _,
            yes: _,
            interactive,
            nixos_flake,
            dry_run,
            overlay_only,
        } => commands::activate::execute(
            no_preflight,
            quiet,
            verbose,
            json,
            no_color,
            plain,
            no_clear_history,
            no_kill_session,
            accept_pivot_risks,
            interactive,
            nixos_flake,
            dry_run,
            overlay_only,
            cli.config,
            check_real_operations_allowed,
        ),
        Commands::Deactivate {
            no_clear_history,
            quiet,
            verbose,
            json,
            no_color,
            plain,
        } => commands::deactivate::execute(
            cli.config,
            no_clear_history,
            quiet,
            verbose,
            json,
            no_color,
            plain,
        ),
        Commands::Emergency {
            no_countdown,
            quiet,
            verbose,
            json,
            no_color,
            plain,
        } => commands::emergency::execute(
            cli.config,
            no_countdown,
            quiet,
            verbose,
            json,
            no_color,
            plain,
            check_real_operations_allowed,
        ),
        Commands::Status {
            json,
            no_color,
            plain,
            verbose,
        } => commands::status::execute(cli.config, json, no_color, plain, verbose),
        Commands::Verify { deep, json } => commands::verify::execute(deep, json, cli.config),
        Commands::Init(args) => commands::init::execute(args),
        Commands::NotifyDispatch { json } => commands::notify_dispatch::execute(cli.config, json),
    }
}

#[cfg(test)]
mod tests_activate;
#[cfg(test)]
mod tests_commands;
