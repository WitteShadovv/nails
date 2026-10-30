// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Command handler modules
//!
//! Each command handler is a standalone module that encapsulates the logic for a
//! specific CLI command. Handlers are called from the dispatcher in the parent
//! module and return an [`ExitStatus`] rather than exiting the process, so
//! `main` owns the process exit code and every `--json` failure can still print
//! one envelope on stdout.

use std::path::Path;

use nails_core::{LoadedConfig, NailsError};

use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::exit::ExitStatus;

// The configuration resolution that any front end shares now lives in the
// engine facade; the CLI keeps only the error rendering (the sudo line, the
// structured body) on top of it.
pub(crate) use nails_core::app::{config_error_line, load_config_or_defaults};

pub mod activate;
pub mod check;
pub mod completions;
pub mod config;
pub(crate) mod config_edit;
pub mod deactivate;
pub mod discard;
pub mod emergency;
pub mod init;
mod prompt;
pub mod recover;
pub mod rehearse;
pub mod sleep_guard;
pub mod status;
pub mod verify;
pub mod watch;

/// Resolve and load the configuration strictly.
///
/// This is the one place the CLI turns the optional `--config` path into a
/// [`LoadedConfig`]; every command and the file-logging setup in
/// [`crate::cli::logging`] route through it, so none of them can disagree on
/// where the configuration came from or treat a broken file as if it were the
/// built-in defaults.
///
/// * `config_override` is `Some` (`--config`): the file must exist.
/// * `config_override` is `None`: the binary-relative file is optional and
///   built-in defaults apply when it is missing.
///
/// Either way an unreadable or invalid file is an error. `loaded_config_path`
/// is set to the consulted path so cleanup preserves it.
pub(crate) fn resolve_config(config_override: Option<&Path>) -> Result<LoadedConfig, NailsError> {
    nails_core::app::resolve_config(config_override)
}

/// The next step after a configuration read that was refused for lack of
/// permission: the `sudo` line that runs the same invocation again, its
/// `--config` and flags included. `init` leaves the configuration readable by
/// root only, so this is what an unprivileged `status` or `check` meets. Root
/// gets no hint, since sudo would not help.
pub(crate) fn config_read_hint(error: &NailsError, command: &str) -> Option<String> {
    sudo_line_for(error, command).map(|line| format!("run it as root: {line}"))
}

/// The `sudo` line that runs this invocation again with the running binary,
/// when `error` refused a read for lack of permission and the user is not
/// root. `command` names the subcommand when no arguments can be read.
pub(crate) fn sudo_line_for(error: &NailsError, command: &str) -> Option<String> {
    sudo_line(
        error,
        command,
        crate::cli::main_guard::effective_user_is_root(),
        std::env::current_exe().ok().as_deref(),
        &crate::cli::main_guard::invocation_args(),
    )
}

fn sudo_line(
    error: &NailsError,
    command: &str,
    is_root: bool,
    binary: Option<&Path>,
    args: &[std::ffi::OsString],
) -> Option<String> {
    let refused = matches!(error, NailsError::PermissionDenied(_))
        || error.io_kind() == Some(std::io::ErrorKind::PermissionDenied);
    (refused && !is_root).then(|| crate::cli::main_guard::sudo_command(binary, command, args))
}

/// The structured error for a configuration load failure of `command`, with
/// the `sudo` line when the read was refused for lack of permission.
pub(crate) fn config_error_body(error: &NailsError, command: &str) -> ErrorBody {
    let body = ErrorBody::new("config", config_error_line(error));
    match config_read_hint(error, command) {
        Some(hint) => body.with_hint(hint),
        None => body,
    }
}

/// Load the configuration for a command that must not run on a file the operator
/// did not mean: report one error and ask the caller to exit with
/// [`ExitStatus::Config`] on any problem.
pub(crate) fn load_config_or_report(
    config_override: Option<&Path>,
    command: &'static str,
    json: bool,
) -> Result<LoadedConfig, ExitStatus> {
    resolve_config(config_override).map_err(|error| {
        report_error(
            json,
            command,
            ExitStatus::Config,
            config_error_body(&error, command),
        )
    })
}

/// Report why an operation's lock step handed out no handle, and return the
/// status to exit with.
///
/// The gate, the acquisition and the trusted-state check live in the
/// operation's lock step ([`nails_core::app::lock`]); this renders their
/// refusals. A root the attach gate refuses is reported with the gate's text
/// and code (exit 4), as `activate` reports it; a lock held by another
/// operation is a `state_locked` failure (exit 1); a state file an activation
/// cannot trust is `invalid_state` (exit 6).
pub(crate) fn report_lock_error(
    error: nails_core::app::lock::LockError,
    command: &'static str,
    json: bool,
) -> ExitStatus {
    let (status, body) = lock_error_body(error, command);
    report_error(json, command, status, body)
}

/// The exit status and error body of a lock step that handed out no handle
/// ([`report_lock_error`] reports them; the window's helper answers with them).
pub(crate) fn lock_error_body(
    error: nails_core::app::lock::LockError,
    command: &'static str,
) -> (ExitStatus, ErrorBody) {
    use nails_core::app::lock::LockError;
    use nails_core::next_step::{NextStep, sudo_line};
    match error {
        LockError::Refused(refusal) => {
            let exe = std::env::current_exe().ok();
            (
                ExitStatus::PreflightRefused,
                crate::cli::output::refusal::refusal_error(&refusal, exe.as_deref()),
            )
        }
        LockError::Unavailable(error) => (
            ExitStatus::Failed,
            ErrorBody::new("state_locked", error.to_string()),
        ),
        LockError::UntrustedState => (
            ExitStatus::InvalidState,
            ErrorBody::new(
                "invalid_state",
                format!(
                    "refusing to {command}: the state file is corrupt or unreadable, so the \
                     current state is unknown. Run `{}` and recover the hidden volume first.",
                    sudo_line(NextStep::Verify)
                ),
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::sudo_line;
    use nails_core::NailsError;
    use std::path::Path;

    /// Each reason a lock step hands out no handle keeps the exit it had
    /// when the front end took the lock and made the check itself.
    #[test]
    fn each_lock_error_keeps_its_exit() {
        use super::report_lock_error;
        use crate::cli::output::ExitStatus;
        use nails_core::app::lock::LockError;
        use nails_core::hidden_root::{Refusal, RefusalKind};
        let refused = LockError::Refused(Box::new(Refusal::new(
            RefusalKind::SameDeviceAsRoot,
            Path::new("/mnt/data"),
        )));
        let held = LockError::Unavailable(NailsError::OperationInProgress { pid: 42 });
        assert_eq!(
            report_lock_error(refused, "discard", true),
            ExitStatus::PreflightRefused
        );
        assert_eq!(report_lock_error(held, "discard", true), ExitStatus::Failed);
        assert_eq!(
            report_lock_error(LockError::UntrustedState, "activate", true),
            ExitStatus::InvalidState
        );
    }

    fn unreadable(kind: std::io::ErrorKind) -> NailsError {
        NailsError::io("/mnt/data/config/nails.toml", std::io::Error::from(kind))
    }

    #[test]
    fn an_unreadable_config_names_the_file_and_the_sudo_line() {
        let error = unreadable(std::io::ErrorKind::PermissionDenied);
        assert!(
            super::config_error_line(&error)
                .starts_with("cannot read config /mnt/data/config/nails.toml: "),
            "{}",
            super::config_error_line(&error)
        );
        // The README's own quick start, run without sudo: the line keeps the
        // configuration it named.
        let invocation: Vec<std::ffi::OsString> = [
            "--config",
            "/mnt/data/config/nails.toml.new",
            "config",
            "show",
        ]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();
        assert_eq!(
            sudo_line(
                &error,
                "config show",
                false,
                Some(Path::new("/mnt/data/nails")),
                &invocation
            ),
            Some(
                "sudo /mnt/data/nails --config /mnt/data/config/nails.toml.new config show"
                    .to_string()
            )
        );
        let denied = NailsError::PermissionDenied("state.json".into());
        assert_eq!(
            sudo_line(&denied, "status", false, None, &[]),
            Some("sudo nails status".to_string())
        );
    }

    #[test]
    fn only_a_refused_read_by_a_non_root_user_gets_the_sudo_line() {
        let binary = Some(Path::new("/mnt/data/nails"));
        let denied = unreadable(std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            sudo_line(&denied, "status", true, binary, &[]),
            None,
            "root"
        );
        let other = unreadable(std::io::ErrorKind::IsADirectory);
        assert_eq!(sudo_line(&other, "status", false, binary, &[]), None);
        let invalid = NailsError::ConfigError("invalid config".into());
        assert_eq!(sudo_line(&invalid, "status", false, binary, &[]), None);
    }
}
