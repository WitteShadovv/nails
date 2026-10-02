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

pub mod activate;
pub mod check;
pub mod config;
pub mod deactivate;
pub mod emergency;
pub mod init;
pub mod notify_dispatch;
pub mod reset_upper;
pub mod status;
pub mod verify;

/// Resolve and load the configuration strictly.
///
/// * `config_override` is `Some` (`--config`): the file must exist.
/// * `config_override` is `None`: the binary-relative file is optional and
///   built-in defaults apply when it is missing.
///
/// Either way an unreadable or invalid file is an error. `loaded_config_path`
/// is set to the consulted path so cleanup preserves it.
pub(crate) fn resolve_config(config_override: Option<&Path>) -> Result<LoadedConfig, NailsError> {
    let path = nails_core::config::discover_config_path(config_override);
    let mut loaded = if config_override.is_some() {
        LoadedConfig::load(&path)?
    } else {
        LoadedConfig::load_or_default(&path)?
    };
    loaded.config.loaded_config_path = Some(path);
    Ok(loaded)
}

/// One-line description of a configuration load failure.
pub(crate) fn config_error_line(error: &NailsError) -> String {
    match error {
        NailsError::ConfigNotFound { path } => format!(
            "config file not found: {} (run `nails init <root>` or pass --config)",
            path.display()
        ),
        NailsError::ConfigError(message) => message.clone(),
        other => other.to_string(),
    }
}

/// The structured error for a configuration load failure.
pub(crate) fn config_error_body(error: &NailsError) -> ErrorBody {
    ErrorBody::new("config", config_error_line(error))
}

/// Load the configuration for a command that must not run on a file the operator
/// did not mean: report one error and ask the caller to exit with
/// [`ExitStatus::Config`] on any problem.
pub(crate) fn load_config_or_report(
    config_override: Option<&Path>,
    command: &'static str,
    json: bool,
) -> Result<LoadedConfig, ExitStatus> {
    resolve_config(config_override)
        .map_err(|error| report_error(json, command, ExitStatus::Config, config_error_body(&error)))
}

/// Load the configuration for a teardown command, which must never refuse.
///
/// On any problem this logs a single warning and continues with built-in
/// defaults, whose hidden volume root is derived from the binary location;
/// the teardown itself then only unmounts what the live mount table shows
/// NAILS created.
pub(crate) fn load_config_or_defaults(config_override: Option<&Path>) -> LoadedConfig {
    resolve_config(config_override).unwrap_or_else(|error| {
        let path: PathBuf = nails_core::config::discover_config_path(config_override);
        tracing::warn!(
            "{}; continuing with defaults derived from the binary location",
            config_error_line(&error)
        );
        let mut loaded = LoadedConfig::defaults(&path);
        loaded.config.loaded_config_path = Some(path);
        loaded
    })
}

/// Build a [`NailsManager`](nails_core::NailsManager) with the NixOS build target
/// activation would pick for the same configuration.
///
/// The discovery cascade is: overlay-only (no builder) → explicit
/// `config.nixos_flake` → a flake in the hidden volume → `/etc/nixos/flake.nix` →
/// a legacy `/etc/nixos/configuration.nix` or system profile → no NixOS. The
/// `check`/`doctor` command uses it so its pre-flight registry matches the one
/// activation would run; keeping it in one place lets a later platform/host-profile
/// seam replace the cascade in a single spot.
pub(crate) fn build_nixos_manager(
    config: nails_core::Config,
    state_path: PathBuf,
    overlay_only: bool,
) -> nails_core::NailsManager<nails_core::RealFilesystem> {
    use nails_core::{NailsManager, NixOSBuilder, RealFilesystem};

    let filesystem = RealFilesystem;
    let nails_profile = PathBuf::from("/nix/var/nix/profiles/nails-system");

    if overlay_only {
        NailsManager::new(filesystem, config, state_path)
    } else if let Some(flake_ref) = config.nixos_flake.clone() {
        let builder = NixOSBuilder::new_with_flake_ref(flake_ref, nails_profile);
        NailsManager::with_nixos(filesystem, config, state_path, builder)
    } else {
        let nixos_flake_dir = config.hidden_volume_root.join("nixos");
        let nixos_flake = nixos_flake_dir.join("flake.nix");
        let etc_flake = PathBuf::from("/etc/nixos/flake.nix");
        let legacy_config = PathBuf::from("/etc/nixos/configuration.nix");
        let system_profile = PathBuf::from("/nix/var/nix/profiles/system");

        if nixos_flake.exists() {
            let builder = NixOSBuilder::new(nixos_flake_dir, nails_profile);
            NailsManager::with_nixos(filesystem, config, state_path, builder)
        } else if etc_flake.exists() {
            let builder = NixOSBuilder::new(PathBuf::from("/etc/nixos"), nails_profile);
            NailsManager::with_nixos(filesystem, config, state_path, builder)
        } else if legacy_config.exists() || system_profile.exists() {
            let builder = NixOSBuilder::new_legacy(legacy_config, nails_profile);
            NailsManager::with_nixos(filesystem, config, state_path, builder)
        } else {
            NailsManager::new(filesystem, config, state_path)
        }
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
/// and the state file. The returned guard must be kept alive for the whole
/// operation; dropping it (on exit) releases the lock.
#[must_use = "the returned guard releases the lock when dropped"]
pub(crate) fn acquire_state_lock_or_report(
    state_file_path: &Path,
    command: &'static str,
    json: bool,
) -> Result<nails_core::StateLock, ExitStatus> {
    nails_core::StateLock::try_acquire(state_lock_dir(state_file_path)).map_err(|error| {
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
    state_file_path: &Path,
) -> Option<nails_core::StateLock> {
    match nails_core::StateLock::acquire_with_timeout(
        state_lock_dir(state_file_path),
        nails_core::EMERGENCY_LOCK_TIMEOUT,
    ) {
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
