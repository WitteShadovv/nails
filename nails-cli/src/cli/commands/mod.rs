//! Command handler modules
//!
//! Each command handler is a standalone module that encapsulates the logic
//! for a specific CLI command. Handlers are called from the main command dispatcher
//! in the parent module.

use std::fmt::Display;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

pub mod activate;
pub mod deactivate;
pub mod emergency;
pub mod init;
pub mod notify_dispatch;
pub mod status;
pub mod verify;

pub(crate) fn exit_config_error(config_path: &Path, error: impl Display) -> ! {
    eprintln!(
        "Error loading config from {}: {}",
        config_path.display(),
        error
    );
    std::process::exit(2);
}

pub(crate) fn exit_lock_error(context: &str, error: impl Display) -> ! {
    eprintln!(
        "Error: internal state unavailable while {}: {}",
        context, error
    );
    std::process::exit(2);
}

/// Load configuration, failing closed when the user explicitly specified `--config`.
///
/// * `config_override` is `Some` → strict load; missing/unreadable file is a fatal error.
/// * `config_override` is `None`  → implicit discovery; missing file falls back to defaults.
pub(crate) fn load_config_or_exit(
    config_path: &Path,
    config_override: Option<&Path>,
) -> nails_core::Config {
    if config_override.is_some() {
        // Explicit --config: fail closed on any error (including missing file)
        nails_core::Config::load(config_path)
            .unwrap_or_else(|error| exit_config_error(config_path, error))
    } else {
        // Implicit discovery: fall back to defaults when file is missing
        nails_core::Config::load_or_default(config_path)
            .unwrap_or_else(|error| exit_config_error(config_path, error))
    }
}

pub(crate) fn lock_manager_or_exit<'a, F: nails_core::Filesystem>(
    manager: &'a Arc<Mutex<nails_core::NailsManager<F>>>,
    context: &str,
) -> MutexGuard<'a, nails_core::NailsManager<F>> {
    manager
        .lock()
        .unwrap_or_else(|error| exit_lock_error(context, error))
}

/// Directory holding the state file (and its `.lock`) on the hidden volume.
fn state_lock_dir(state_file_path: &Path) -> &Path {
    state_file_path.parent().unwrap_or_else(|| Path::new("."))
}

/// Take the exclusive state lock for an ordinary mutating command, or exit.
///
/// A concurrent `nails` operation holds this lock, so a second one fails fast
/// with a message naming the holder PID rather than racing it over the mounts
/// and the state file. The returned guard must be kept alive for the whole
/// operation; dropping it (on exit) releases the lock.
#[must_use = "the returned guard releases the lock when dropped"]
pub(crate) fn acquire_state_lock_or_exit(state_file_path: &Path) -> nails_core::StateLock {
    nails_core::StateLock::try_acquire(state_lock_dir(state_file_path)).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(2);
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
