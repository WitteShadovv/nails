pub mod args;
pub mod commands;
mod detach;
pub mod logging;
pub mod output;
pub mod safety;

// Re-export main types for convenience
pub use args::{Cli, Commands, ConfigCommand, GlobalArgs};
pub use logging::init_subscriber;
pub use output::{ExitStatus, OutputSettings};
pub use safety::check_real_operations_allowed;

/// Execute the CLI command - extracted for testability.
///
/// `settings` are the output settings `main` resolved once from the global
/// flags; every handler renders with them and returns an [`ExitStatus`] that
/// `main` turns into the process exit code.
pub fn execute_command(cli: Cli, settings: &OutputSettings) -> ExitStatus {
    let config = cli.global.config.as_deref();

    match cli.command {
        Commands::Activate(args) => {
            commands::activate::execute(settings, &args, config, check_real_operations_allowed)
        }
        Commands::Deactivate(args) => {
            commands::deactivate::execute(settings, &args, config, check_real_operations_allowed)
        }
        Commands::Emergency(args) => {
            commands::emergency::execute(settings, &args, config, check_real_operations_allowed)
        }
        Commands::Status(args) => commands::status::execute(settings, &args, config),
        Commands::Verify(args) => commands::verify::execute(settings, &args, config),
        Commands::Init(args) => match commands::init::execute(args) {
            Ok(()) => ExitStatus::Ok,
            Err(e) => {
                eprintln!("error: {e}");
                ExitStatus::Failed
            }
        },
        Commands::ResetUpper(args) => {
            commands::reset_upper::execute(settings, &args, config, check_real_operations_allowed)
        }
        Commands::Config(command) => commands::config::execute(settings, config, &command),
        Commands::NotifyDispatch => commands::notify_dispatch::execute(settings, config),
    }
}

#[cfg(test)]
mod tests_activate;
#[cfg(test)]
mod tests_commands;
