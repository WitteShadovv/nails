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
