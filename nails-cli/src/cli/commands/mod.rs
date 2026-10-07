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
/// Where a teardown's configuration was ultimately loaded from.
///
/// Reported to the operator so a teardown that had to fall back off the failed
/// hidden volume says so, rather than silently acting on the wrong data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    /// The real configuration file (on the hidden volume or binary-relative).
    File,
    /// The RAM-backed copy under `/run`, used because the file was unreadable.
    RuntimeCopy,
    /// Built-in defaults, used because neither the file nor a copy was available.
    Defaults,
}

impl ConfigSource {
    /// A short phrase naming the source, for human-facing output.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            ConfigSource::File => "configuration file",
            ConfigSource::RuntimeCopy => "RAM-backed runtime copy",
            ConfigSource::Defaults => "built-in defaults",
        }
    }
}

/// Load the configuration for a teardown (emergency or recover) that must never
/// be blocked by a failed hidden volume.
///
/// The real config file lives on the hidden volume, so when that volume is the
/// thing that failed the file is unreadable. This tries, in order: the config
/// file, the mirrored copy in the RAM-backed runtime directory under `/run`
/// (written at activation precisely for this case), and finally the built-in
/// defaults. The source is returned so the caller can tell the operator which one
/// was used; in every case the teardown only acts on what the live mount table
/// shows NAILS created.
pub(crate) fn load_config_for_teardown(
    config_override: Option<&Path>,
) -> (nails_core::Config, ConfigSource) {
    // An authoritative config file wins: either an explicit `--config` (which
    // errors rather than defaulting when absent) or a binary-relative file that
    // was actually present. A *missing* binary-relative file is not authoritative:
    // `resolve_config` returns built-in defaults for it, whose hidden volume root
    // is derived from the running binary's own location. When emergency runs from
    // the RAM-backed copy under `/run` that root points into `/run`, not at the
    // real overlays, so those defaults must not be preferred over the mirrored
    // config the copy carries.
    let file_config = match resolve_config(config_override) {
        Ok(loaded) if config_override.is_some() || loaded.file_found => Some(loaded.into_config()),
        _ => None,
    };

    // The RAM-backed runtime copy under `/run` records the real hidden root and
    // state path from activation, written precisely so teardown still works when
    // the hidden volume (and the real config and state files on it) are gone. It
    // is strictly better than binary-relative defaults, so it is consulted whenever
    // no authoritative file was found — not only when the file was unreadable.
    let runtime_copy_config = if file_config.is_some() {
        None
    } else {
        match nails_core::runtime_copy::read_config_copy(&nails_core::RealFilesystem) {
            Ok(copy) => copy,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the runtime config copy; using defaults");
                None
            }
        }
    };

    let defaults = || load_config_or_defaults(config_override).into_config();
    pick_teardown_config(file_config, runtime_copy_config, defaults)
}

/// Choose the teardown configuration and record where it came from.
///
/// Precedence: an authoritative config file, then the RAM-backed runtime copy
/// under `/run`, then built-in defaults. The runtime copy must outrank defaults
/// so an emergency launched from the copy (when the hidden volume is gone) tears
/// down the real overlays instead of a set derived from the copied binary's own
/// location. `defaults` is only evaluated when neither of the first two is present.
fn pick_teardown_config(
    file_config: Option<nails_core::Config>,
    runtime_copy_config: Option<nails_core::Config>,
    defaults: impl FnOnce() -> nails_core::Config,
) -> (nails_core::Config, ConfigSource) {
    if let Some(config) = file_config {
        return (config, ConfigSource::File);
    }
    if let Some(config) = runtime_copy_config {
        tracing::warn!("config file not found; using the RAM-backed runtime copy under /run");
        return (config, ConfigSource::RuntimeCopy);
    }
    (defaults(), ConfigSource::Defaults)
}

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
/// The host is detected once here and the build target is then asked of that
/// host's platform backend through
/// [`NailsManager::discover_host_target`](nails_core::NailsManager::discover_host_target):
/// on NixOS that is overlay-only (no builder) → explicit `config.nixos_flake` →
/// a flake in the hidden volume → `/etc/nixos/flake.nix` → a legacy
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
    use nails_core::{HostTarget, NailsManager, NixOSBuilder, RealFilesystem};

    let mut manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    if let Err(e) = manager.initialize_platform() {
        tracing::debug!(error = %e, "platform detection failed; continuing without a host profile");
    }

    let builder = match manager
        .discover_host_target(overlay_only)
        .unwrap_or(HostTarget::None)
    {
        HostTarget::OverlayOnly | HostTarget::None => None,
        HostTarget::ExplicitFlake(flake_ref) => Some(NixOSBuilder::new_with_flake_ref(flake_ref)),
        HostTarget::Flake(dir) => Some(NixOSBuilder::new(dir)),
        HostTarget::Legacy(path) => Some(NixOSBuilder::new_legacy(path)),
    };
    if let Some(builder) = builder {
        manager.set_nixos_builder(builder);
    }
    manager
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
    let dir = state_lock_dir(state_file_path);
    nails_core::ensure_state_dir_attached(&nails_core::RealFilesystem, dir)
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
    state_file_path: &Path,
) -> Option<nails_core::StateLock> {
    // Never create `.lock` in a bare mount-point directory on the decoy: with the
    // hidden volume gone, emergency proceeds without the lock.
    let dir = state_lock_dir(state_file_path);
    if let Err(error) = nails_core::ensure_state_dir_attached(&nails_core::RealFilesystem, dir) {
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
    use super::{ConfigSource, pick_teardown_config};
    use nails_core::Config;
    use std::path::PathBuf;

    fn config_rooted_at(root: &str) -> Config {
        Config {
            hidden_volume_root: PathBuf::from(root),
            ..Config::test_default()
        }
    }

    #[test]
    fn teardown_config_prefers_an_authoritative_file() {
        let file = config_rooted_at("/mnt/data/file");
        let copy = config_rooted_at("/mnt/data/copy");
        let (config, source) = pick_teardown_config(Some(file), Some(copy), || {
            panic!("defaults must not be evaluated when a file is present")
        });
        assert_eq!(source, ConfigSource::File);
        assert_eq!(config.hidden_volume_root, PathBuf::from("/mnt/data/file"));
    }

    #[test]
    fn teardown_config_prefers_the_runtime_copy_over_defaults() {
        // The regression: a missing binary-relative config yields built-in
        // defaults, whose hidden root is derived from the running binary. When
        // emergency runs from the RAM-backed copy that root points into /run, so
        // the mirrored copy — which records the real hidden root — must win.
        let copy = config_rooted_at("/mnt/data/real-hidden-root");
        let (config, source) = pick_teardown_config(None, Some(copy), || {
            panic!("defaults must not be evaluated when a runtime copy is present")
        });
        assert_eq!(source, ConfigSource::RuntimeCopy);
        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/mnt/data/real-hidden-root")
        );
    }

    #[test]
    fn teardown_config_falls_back_to_defaults_when_nothing_else_is_available() {
        let defaults = config_rooted_at("/derived/from/binary");
        let (config, source) = pick_teardown_config(None, None, || defaults.clone());
        assert_eq!(source, ConfigSource::Defaults);
        assert_eq!(
            config.hidden_volume_root,
            PathBuf::from("/derived/from/binary")
        );
    }
}
