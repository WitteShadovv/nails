//! Early privilege gate for the commands that mutate the host.
//!
//! Activation, deactivation and the emergency teardown all drive privileged
//! syscalls (overlay mounts, pivots, process signalling) and write a log and a
//! state file onto the hidden volume. Run without root they would fail partway,
//! after the subscriber was initialised and a log file was already opened on the
//! decoy. This gate runs in `main` *before* logging init and before any command
//! handler, so an unprivileged invocation leaves nothing behind and the operator
//! gets one clear, copy-pasteable instruction instead of a mid-run syscall error.
//!
//! The check is a compile-time constant in shipped builds: there is no
//! environment variable or path layout that disables it. Only a `test-hooks`
//! build (the binary `cargo test` drives) honours `NAILS_TEST_ENFORCE_ROOT`, and
//! then only to *enable* the gate for the one integration test that asserts the
//! exit-5 behaviour — the hundreds of other integration tests that drive the
//! real write paths unprivileged are never affected.

use crate::cli::args::Commands;
use crate::cli::output::{ExitStatus, OutputSettings};

/// Whether `command` must run as root.
///
/// `activate --dry-run` is read-only (it is an alias for `check`), so it is
/// exempt; every other activation, and deactivation and emergency teardown,
/// require root.
pub fn requires_root(command: &Commands) -> bool {
    match command {
        Commands::Activate(args) => !args.dry_run,
        Commands::Deactivate(_) | Commands::Emergency(_) | Commands::Reapply(_) => true,
        _ => false,
    }
}

/// The subcommand name used in the remediation hint.
fn subcommand_name(command: &Commands) -> &'static str {
    match command {
        Commands::Activate(_) => "activate",
        Commands::Deactivate(_) => "deactivate",
        Commands::Reapply(_) => "reapply",
        Commands::Emergency(_) => "emergency",
        Commands::Status(_) => "status",
        Commands::Verify(_) => "verify",
        Commands::Check(_) => "check",
        Commands::Init(_) => "init",
        Commands::ResetUpper(_) => "reset-upper",
        Commands::Config(_) => "config",
        Commands::NotifyDispatch => "notify-dispatch",
    }
}

/// Build the "must run as root" message for `subcommand`.
///
/// The absolute path to the running binary is used so the suggested `sudo`
/// invocation works regardless of the caller's `PATH` and regardless of whether
/// the binary is reached through a decoy symlink. When the path cannot be
/// resolved the bare command name is used as a last resort.
fn needs_root_message(argv0: Option<&std::path::Path>, subcommand: &str) -> String {
    let binary = argv0
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "nails".to_string());
    format!("this command must run as root: try `sudo {binary} {subcommand}`")
}

/// True when the effective user is root.
fn effective_user_is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Whether the root gate is enforced in this build.
///
/// Shipped builds always enforce it. A `test-hooks` build enforces it only when
/// `NAILS_TEST_ENFORCE_ROOT` is set, so the integration suite — which runs
/// unprivileged and must still exercise the real activate/deactivate/emergency
/// paths — is unaffected unless a test opts in.
#[cfg(any(test, feature = "test-hooks"))]
fn gate_enforced() -> bool {
    std::env::var_os("NAILS_TEST_ENFORCE_ROOT").is_some()
}

#[cfg(not(any(test, feature = "test-hooks")))]
#[inline]
fn gate_enforced() -> bool {
    true
}

/// Enforce the root requirement for `command`.
///
/// Returns `Some(ExitStatus::NeedsRoot)` after printing the remediation hint
/// when a privileged command is run unprivileged, and `None` otherwise. `main`
/// turns the returned status into the process exit code (5) without initialising
/// logging or running the command handler.
pub fn enforce_root(command: &Commands, settings: &OutputSettings) -> Option<ExitStatus> {
    if !gate_enforced() || !requires_root(command) || effective_user_is_root() {
        return None;
    }

    let argv0 = std::env::current_exe().ok();
    let message = needs_root_message(argv0.as_deref(), subcommand_name(command));
    emit_needs_root(settings, &message);
    Some(ExitStatus::NeedsRoot)
}

/// Print the remediation message on stderr using the resolved stderr style.
///
/// Errors are always shown, even under `--quiet`: a refused privileged command
/// that printed nothing would look like a silent failure.
fn emit_needs_root(settings: &OutputSettings, message: &str) {
    use nails_core::output::Mark;
    eprintln!("{}", settings.stderr_style().marked(Mark::Fail, message));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{ActivateArgs, DeactivateArgs, EmergencyArgs, StatusArgs, VerifyArgs};
    use std::path::Path;

    #[test]
    fn mutating_commands_require_root() {
        assert!(requires_root(&Commands::Activate(ActivateArgs::default())));
        assert!(requires_root(&Commands::Deactivate(
            DeactivateArgs::default()
        )));
        assert!(requires_root(
            &Commands::Emergency(EmergencyArgs::default())
        ));
    }

    #[test]
    fn dry_run_activate_is_read_only() {
        let args = ActivateArgs {
            dry_run: true,
            ..ActivateArgs::default()
        };
        assert!(!requires_root(&Commands::Activate(args)));
    }

    #[test]
    fn read_only_commands_do_not_require_root() {
        assert!(!requires_root(&Commands::Status(StatusArgs::default())));
        assert!(!requires_root(&Commands::Verify(VerifyArgs::default())));
        assert!(!requires_root(&Commands::Check(Default::default())));
        assert!(!requires_root(&Commands::NotifyDispatch));
    }

    #[test]
    fn message_names_the_absolute_binary_and_subcommand() {
        let msg = needs_root_message(Some(Path::new("/opt/hidden/nails")), "activate");
        assert_eq!(
            msg,
            "this command must run as root: try `sudo /opt/hidden/nails activate`"
        );
    }

    #[test]
    fn message_falls_back_to_bare_name_without_argv0() {
        let msg = needs_root_message(None, "deactivate");
        assert!(msg.contains("sudo nails deactivate"));
    }
}
