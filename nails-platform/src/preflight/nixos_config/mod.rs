// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! NixOS configuration pre-flight check
//!
//! Validates NixOS configuration overlay structure in hidden storage.
//!
//! The base configuration in the decoy's `/etc/nixos` is looked up through
//! the automount guard ([`crate::filesystem::automount`]): a file there can
//! link into a home that an automounter mounts, and a lookup that would mount
//! an automount point that nothing is mounted on yet is not made. Such a
//! lookup, or one that fails for another reason than that nothing is there,
//! leaves NAILS unable to tell, which refuses, naming the path and the
//! point, and how to mount it.

use super::{CheckResult, PreFlightCheck};
use crate::filesystem::automount::{Guarded, OnSkip, Snapshot, describe, settle};
use crate::{
    Filesystem, NailsError, NixParser, RealNixParser, Result, parse_check_composed_config,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The decoy's base NixOS configuration: the hardware configuration, and the
/// configuration or the flake beside it.
const BASE_HARDWARE: &str = "/etc/nixos/hardware-configuration.nix";
const BASE_CONFIG: &str = "/etc/nixos/configuration.nix";
const BASE_FLAKE: &str = "/etc/nixos/flake.nix";

/// The `init` line that stages the hidden NixOS layout, with the real binary
/// path.
fn init_line() -> String {
    nails_base::next_step::sudo_line(nails_base::next_step::NextStep::Init)
}

/// Validates NixOS configuration overlay structure in hidden storage
///
/// Ensures the hidden storage contains all required NixOS configuration files
/// for the overlay mechanism:
/// - `{hidden}/etc/nixos/` directory exists
/// - `{hidden}/etc/nixos/hardware-configuration.nix` exists (modified with import)
/// - `{hidden}/config/nixos/configuration.nix` exists (hidden environment config)
/// - Modified hardware-configuration.nix contains relative import `./nails/configuration.nix`
/// - `{hidden}/etc/nixos/nails/configuration.nix` symlink exists (staged during activation)
/// - Base `/etc/nixos/configuration.nix` OR `/etc/nixos/flake.nix` exists
///
/// # Example
///
/// `run` ends with a `nix-instantiate --parse` gate over the composed config,
/// so the example is `no_run` (it shells out on a real host).
///
/// ```no_run
/// use nails_platform::preflight::{NixOSConfigCheck, PreFlightCheck, CheckResult};
/// use nails_base::MockFilesystem;
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
/// fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
/// fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
/// fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
/// fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
/// fs.mock_set_is_symlink("/mnt/hidden/etc/nixos/nails/configuration.nix", true);
/// fs.mock_set_file_content(
///     "/mnt/hidden/etc/nixos/hardware-configuration.nix",
///     "{ imports = [ ./nails/configuration.nix ]; }"
/// );
///
/// let check = NixOSConfigCheck::new(PathBuf::from("/mnt/hidden"));
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct NixOSConfigCheck {
    hidden_storage_path: PathBuf,
    parser: Arc<dyn NixParser>,
}

impl NixOSConfigCheck {
    /// Create a new NixOSConfigCheck
    ///
    /// # Arguments
    ///
    /// * `hidden_storage_path` - Path to hidden storage root
    pub fn new(hidden_storage_path: PathBuf) -> Self {
        Self {
            hidden_storage_path,
            parser: Arc::new(RealNixParser),
        }
    }

    /// Create a check with an injected Nix parser (used by tests to exercise the
    /// parse gate without invoking `nix-instantiate`).
    #[cfg(test)]
    pub(crate) fn with_parser(hidden_storage_path: PathBuf, parser: Arc<dyn NixParser>) -> Self {
        Self {
            hidden_storage_path,
            parser,
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for NixOSConfigCheck {
    fn name(&self) -> &'static str {
        "nixos-config"
    }

    fn description(&self) -> &'static str {
        "Validates NixOS configuration overlay structure"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Checks 1 and 2: the decoy's base configuration, looked up through
        // the automount guard.
        let decoy = Guarded::new(fs.clone(), &Snapshot::read(fs, Path::new("/")));
        if let Some(refusal) = base_config_refusal(&decoy) {
            return Ok(settle(refusal, &decoy.skipped(), OnSkip::Refuse(None)));
        }

        // Check 3: Hidden etc/nixos directory exists
        let hidden_etc_nixos = crate::nixos::config::hidden_etc_nixos(&self.hidden_storage_path);
        if !fs.path_exists(&hidden_etc_nixos)? {
            return Ok(CheckResult::fail(format!(
                "Hidden storage missing etc/nixos/ directory at {}. Create this directory with modified hardware-configuration.nix.",
                hidden_etc_nixos.display()
            )));
        }

        // Check 4: Modified hardware-configuration.nix exists.
        //
        // This check is read-only: it never creates the file. Activation stages
        // it (via `stage_hidden_nixos_config`) before the pre-flight phase runs,
        // so a missing file here means the volume was never initialised with the
        // hidden NixOS layout.
        let modified_config = hidden_etc_nixos.join("hardware-configuration.nix");
        if !fs.path_exists(&modified_config)? {
            return Ok(CheckResult::fail(format!(
                "Modified hardware-configuration.nix not found at {}. Run `{}` to stage the hidden NixOS layout.",
                modified_config.display(),
                init_line()
            )));
        }

        // Check 5: Modified hardware-configuration.nix has relative import to hidden config
        let content = fs.read_file_content(&modified_config)?;
        let expected_import = crate::artifacts::NIXOS_IMPORT_MARKER;
        if !crate::nixos::contains_nails_import(&content) {
            return Ok(CheckResult::fail(format!(
                "Modified hardware-configuration.nix missing hidden import. Add: imports = [ ... {} ];",
                expected_import
            )));
        }

        // Check 6: Hidden configuration.nix exists at the new location.
        //
        // Read-only, like Check 4: activation stages this module before the
        // pre-flight phase, so a missing file here means the volume was not
        // initialised with the hidden NixOS layout.
        let hidden_config = self
            .hidden_storage_path
            .join("config/nixos/configuration.nix");
        if !fs.path_exists(&hidden_config)? {
            return Ok(CheckResult::fail(format!(
                "Hidden configuration.nix not found at {}. Run `{}` to stage the hidden NixOS layout.",
                hidden_config.display(),
                init_line()
            )));
        }

        // Check 7: the composed configuration parses. This runs
        // `nix-instantiate --parse` over the wrapper, the preserved base file,
        // and the hidden module — syntax only, nothing is evaluated or copied
        // into the decoy store. It runs before any overlay is mounted, so a
        // syntax error fails the activation while the user is still safely on
        // the decoy generation.
        let hidden_module = self
            .hidden_storage_path
            .join("config/nixos/configuration.nix");
        if let Err(message) = parse_check_composed_config(
            self.parser.as_ref(),
            fs,
            &hidden_etc_nixos,
            &hidden_module,
        )? {
            return Ok(CheckResult::fail(format!(
                "NixOS configuration failed to parse before mounting: {message}"
            )));
        }

        Ok(CheckResult::Pass(
            "NixOS configuration overlay structure is valid".into(),
        ))
    }
}

/// The refusal of a decoy whose base NixOS configuration, looked up through
/// `decoy`, is missing, or that NAILS cannot tell about: the hardware
/// configuration (check 1), and the configuration or the flake beside it
/// (check 2), either of which counts where it is there. A lookup that failed
/// for another reason than that nothing is there, or that the automount
/// guard did not make, is never a file that is not there.
fn base_config_refusal<F: Filesystem>(decoy: &F) -> Option<CheckResult> {
    let untold = |path: &str, error: &NailsError| {
        CheckResult::fail(format!(
            "NAILS cannot tell whether the base NixOS configuration exists: {}",
            describe(path, error).sentence
        ))
    };
    match decoy.path_exists(Path::new(BASE_HARDWARE)) {
        Ok(true) => {}
        Ok(false) => {
            return Some(CheckResult::fail(
                "Base /etc/nixos/hardware-configuration.nix not found. Ensure NixOS is properly installed.".to_string(),
            ));
        }
        Err(error) => return Some(untold(BASE_HARDWARE, &error)),
    }
    let config = decoy.path_exists(Path::new(BASE_CONFIG));
    if matches!(config, Ok(true)) {
        return None;
    }
    match (config, decoy.path_exists(Path::new(BASE_FLAKE))) {
        (_, Ok(true)) => None,
        (Ok(_), Ok(false)) => Some(CheckResult::fail(
            "Base NixOS config missing: neither /etc/nixos/configuration.nix nor /etc/nixos/flake.nix exists."
                .to_string(),
        )),
        (Err(error), _) => Some(untold(BASE_CONFIG, &error)),
        (_, Err(error)) => Some(untold(BASE_FLAKE, &error)),
    }
}

#[cfg(test)]
mod tests;
