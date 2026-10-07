// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod args;
pub mod commands;
mod detach;
pub mod early;
pub mod logging;
pub mod main_guard;
pub mod output;

// Re-export main types for convenience
pub use args::{Cli, Commands, ConfigCommand, GlobalArgs};
pub use detach::install_panic_hook;
pub use logging::init_subscriber;
pub use output::{ExitStatus, OutputSettings};

/// Whether a command mutates the system and so must survive interrupting signals
/// and OOM pressure.
///
/// The mutating commands take overlays up or down and run a chain of rollback
/// guards that a signal's default action would skip; for them we install the
/// cancellation handlers and bias the process away from the OOM killer. Read-only
/// commands (`status`, `verify`, `check`, `config`, `notify-dispatch`) and `init`
/// touch no live overlay, so they keep the default signal behaviour.
fn command_is_mutating(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Activate(_)
            | Commands::Deactivate(_)
            | Commands::Reapply(_)
            | Commands::Emergency(_)
            | Commands::Recover(_)
            | Commands::ResetUpper(_)
    )
}

/// Bias this process away from the OOM killer, best-effort.
///
/// Writes a negative `oom_score_adj` so that under memory pressure the kernel
/// prefers to kill a child (such as the nix evaluator) over the nails process
/// that is mid-activation; children are reset to a neutral score when they are
/// spawned. Negative values need `CAP_SYS_RESOURCE`, which a mutating command run
/// under `sudo` has, but a denial is not fatal — it only means the default
/// scoring applies — so a failure is logged and ignored.
fn lower_oom_score() {
    const PROTECTED_OOM_SCORE_ADJ: &str = "-500";
    if let Err(err) = std::fs::write("/proc/self/oom_score_adj", PROTECTED_OOM_SCORE_ADJ) {
        tracing::debug!(error = %err, "could not lower oom_score_adj; default OOM scoring applies");
    }
}

/// Disable core dumps for this process and every child it spawns, best-effort.
///
/// `main` calls this before anything else: a crash before `/var` is overlaid
/// would otherwise dump the process memory onto the decoy disk (a `core` file or
/// a systemd-coredump entry). Returns the error, if any, so `main` can log it
/// once the subscriber exists; a failure never stops the command.
pub fn disable_core_dumps() -> Option<std::io::Error> {
    nails_core::process::hardening::disable_core_dumps().err()
}

/// Execute the CLI command - extracted for testability.
///
/// `settings` are the output settings `main` resolved once from the global
/// flags; every handler renders with them and returns an [`ExitStatus`] that
/// `main` turns into the process exit code. `env` is the environment snapshot
/// `main` read once; handlers that build a manager, resolve the operator, detect
/// the session or detach take their values from it.
pub fn execute_command(
    cli: Cli,
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
) -> ExitStatus {
    let config = cli.global.config.as_deref();

    // Before dispatching a mutating command, install the signal handlers so an
    // interrupt rolls back cleanly instead of killing the process mid-teardown,
    // and bias the process away from the OOM killer. Both are process-wide and
    // best-effort; read-only commands keep the default behaviour.
    if command_is_mutating(&cli.command) {
        nails_core::cancel::install_handlers();
        lower_oom_score();
    }

    match cli.command {
        Commands::Activate(args) => commands::activate::execute(settings, env, &args, config),
        Commands::Deactivate(args) => commands::deactivate::execute(settings, env, &args, config),
        Commands::Reapply(args) => commands::reapply::execute(settings, env, &args, config),
        Commands::Emergency(args) => commands::emergency::execute(settings, env, &args, config),
        Commands::Recover(args) => commands::recover::execute(settings, env, &args, config),
        Commands::Status(args) => commands::status::execute(settings, &args, config),
        Commands::Verify(args) => commands::verify::execute(settings, env, &args, config),
        Commands::Rehearse(args) => commands::rehearse::execute(settings, env, &args, config),
        Commands::Check(args) => commands::check::execute(settings, env, &args, config),
        Commands::Init(args) => commands::init::execute(settings, &args, config),
        Commands::ResetUpper(args) => commands::reset_upper::execute(settings, env, &args, config),
        Commands::Config(command) => commands::config::execute(settings, config, &command),
        Commands::Completions(args) => commands::completions::execute(&args),
        Commands::NotifyDispatch => commands::notify_dispatch::execute(settings, env, config),
        Commands::Watch => commands::watch::execute(settings, env, config),
        Commands::SleepGuard => commands::sleep_guard::execute(settings, env, config),
    }
}

#[cfg(test)]
mod tests_activate;
#[cfg(test)]
mod tests_commands;
