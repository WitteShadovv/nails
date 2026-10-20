// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Command handler modules
//!
//! Each command handler is a standalone module that encapsulates the logic for a
//! specific CLI command. Handlers are called from the dispatcher in the parent
//! module and return an [`ExitStatus`] rather than exiting the process, so
//! `main` owns the process exit code and every `--json` failure can still print
//! one envelope on stdout.

use std::path::{Path, PathBuf};

use nails_core::{LoadedConfig, NailsError};

use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::exit::ExitStatus;

// The configuration resolution that any front end shares now lives in the
// engine facade; the CLI keeps only the error rendering (the sudo line, the
// structured body) on top of it.
pub(crate) use nails_core::app::{
    config_error_line, load_config_for_teardown, load_config_or_defaults,
};

pub mod activate;
pub mod check;
pub mod completions;
pub mod config;
pub mod deactivate;
pub mod emergency;
pub mod init;
pub mod recover;
pub mod rehearse;
pub mod reset_upper;
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

/// Build a [`NailsManager`](nails_core::NailsManager) with the NixOS build target
/// activation would pick for the same configuration.
///
/// The host is detected once here and the build target is then asked of that
/// host's platform backend through
/// [`NailsManager::discover_host_target`](nails_core::NailsManager::discover_host_target):
/// on NixOS that is overlay-only (no builder) → explicit `config.nixos_flake` →
/// a flake in the hidden volume → the decoy's own `/etc/nixos/flake.nix`
/// (refused: no builder, and the build-target check fails) → a legacy
/// `/etc/nixos/configuration.nix` or system profile → no NixOS; a host without
/// a declarative config layer has no build target at all. Activation, the
/// `check`/`doctor` command (which also uses this to build its pre-flight
/// registry and its profile summary) and the `nixos-build-target` check all go
/// through that one discovery on the same host profile, so none of them can
/// report a different build target than the others. A failed detection leaves
/// no profile, and discovery then runs the NixOS cascade as it always has.
pub(crate) fn build_nixos_manager(
    config: nails_core::Config,
    state_path: PathBuf,
    overlay_only: bool,
    env: &nails_core::RuntimeEnv,
) -> nails_core::NailsManager<nails_core::RealFilesystem> {
    use nails_core::{HostTarget, NailsManager, RealFilesystem};

    let mut manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    if let Err(e) = manager.initialize_platform() {
        tracing::debug!(error = %e, "platform detection failed; continuing without a host profile");
    }

    let target = manager
        .discover_host_target(overlay_only)
        .unwrap_or(HostTarget::None);
    if let Some(builder) = nixos_builder_for(target) {
        manager.set_nixos_builder(builder);
    }
    manager
}

/// The builder of a build target. Overlay-only, no target and the refused
/// decoy flake get none.
fn nixos_builder_for(target: nails_core::HostTarget) -> Option<nails_core::NixOSBuilder> {
    use nails_core::{HostTarget, NixOSBuilder};

    match target {
        HostTarget::OverlayOnly | HostTarget::None | HostTarget::DecoyFlake { .. } => None,
        HostTarget::ExplicitFlake(flake_ref) => Some(NixOSBuilder::new_with_flake_ref(flake_ref)),
        HostTarget::Flake(dir) => Some(NixOSBuilder::new(dir)),
        HostTarget::Legacy(path) => Some(NixOSBuilder::new_legacy(path)),
    }
}

/// Directory holding the state file (and its `.lock`) on the hidden volume.
fn state_lock_dir(state_file_path: &Path) -> &Path {
    state_file_path.parent().unwrap_or_else(|| Path::new("."))
}

/// Take the exclusive state lock for an ordinary mutating command, or report.
///
/// A concurrent `nails` operation holds this lock, so a second one fails fast
/// with a message naming the holder PID rather than racing it over the mounts
/// and the state file. The lock lies next to the state file and is created only
/// on the volume mounted at `hidden_root`, or on the root the operator accepted
/// with `allow` (`activate --allow-decoy-storage`). A root the attach gate
/// refuses is reported with the gate's text and code (exit 4), as `activate`
/// reports it: `deactivate` refuses a root another disk was mounted over with
/// `root_covered`, and `emergency` is the way out. The returned guard must be
/// kept alive for the whole operation; dropping it (on exit) releases the lock.
#[must_use = "the returned guard releases the lock when dropped"]
pub(crate) fn acquire_state_lock_or_report(
    hidden_root: &Path,
    allow: nails_core::hidden_root::Allow,
    state_file_path: &Path,
    command: &'static str,
    json: bool,
) -> Result<nails_core::StateLock, ExitStatus> {
    if let Ok(nails_core::hidden_root::Assessment::Refused(refusal)) =
        nails_core::HiddenRoot::assess_allowing(&nails_core::RealFilesystem, hidden_root, allow)
    {
        return Err(crate::cli::output::refusal::report_refusal(
            json, command, &refusal,
        ));
    }
    let dir = state_lock_dir(state_file_path);
    nails_core::hidden_root::ensure_state_dir_attached_allowing(
        &nails_core::RealFilesystem,
        hidden_root,
        dir,
        allow,
    )
    .and_then(|()| nails_core::StateLock::try_acquire(dir))
    .map_err(|error| {
        report_error(
            json,
            command,
            ExitStatus::Failed,
            ErrorBody::new("state_locked", error.to_string()),
        )
    })
}

/// Take the state lock for emergency teardown, proceeding without it on timeout.
///
/// Emergency must never be blocked by a crashed or unresponsive holder, so after
/// a short wait it continues without the lock. The returned guard (when present)
/// must be kept alive for the duration of the teardown.
#[must_use = "the returned guard releases the lock when dropped"]
pub(crate) fn acquire_state_lock_for_emergency(
    hidden_root: &Path,
    state_file_path: &Path,
) -> Option<nails_core::StateLock> {
    // Never create `.lock` in a bare mount-point directory on the decoy, nor on
    // a disk mounted over the hidden volume: then emergency proceeds without
    // the lock.
    let dir = state_lock_dir(state_file_path);
    if let Err(error) =
        nails_core::ensure_state_dir_attached(&nails_core::RealFilesystem, hidden_root, dir)
    {
        tracing::warn!(%error, "Hidden volume not attached; proceeding with emergency teardown without the state lock");
        return None;
    }
    match nails_core::StateLock::acquire_with_timeout(dir, nails_core::EMERGENCY_LOCK_TIMEOUT) {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            tracing::warn!(
                "Proceeding with emergency teardown without the state lock (acquire timed out)"
            );
            None
        }
        Err(error) => {
            tracing::warn!(%error, "Could not open the state lock; proceeding with emergency teardown");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{nixos_builder_for, sudo_line};
    use nails_core::{HostTarget, NailsError};
    use std::path::{Path, PathBuf};

    /// Activation builds nothing for the refused decoy flake, as for
    /// overlay-only and no target; every other target gets its builder.
    #[test]
    fn the_refused_decoy_flake_gets_no_builder() {
        let decoy = HostTarget::DecoyFlake {
            dir: PathBuf::from("/etc/nixos"),
            hidden_volume_root: PathBuf::from("/mnt/data"),
        };
        for target in [decoy, HostTarget::OverlayOnly, HostTarget::None] {
            assert_eq!(nixos_builder_for(target.clone()), None, "{target:?}");
        }

        let flake = nixos_builder_for(HostTarget::Flake(PathBuf::from("/mnt/data/nixos")));
        assert_eq!(
            flake.as_ref().and_then(|b| b.flake_dir()),
            Some(Path::new("/mnt/data/nixos"))
        );
        let explicit = nixos_builder_for(HostTarget::ExplicitFlake("/srv/cfg#host".into()));
        assert_eq!(
            explicit.map(|b| b.effective_flake_arg()).as_deref(),
            Some("/srv/cfg#host")
        );
        let legacy = nixos_builder_for(HostTarget::Legacy(PathBuf::from(
            "/etc/nixos/configuration.nix",
        )));
        assert_eq!(
            legacy.as_ref().and_then(|b| b.legacy_config()),
            Some(Path::new("/etc/nixos/configuration.nix"))
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
