//! NixOS configuration pre-flight check
//!
//! Validates NixOS configuration overlay structure in hidden storage (Story 4.12).

use super::super::{CheckResult, PreFlightCheck};
use crate::{
    Filesystem, NixParser, RealNixParser, Result, ensure_hidden_configuration_module,
    ensure_hidden_hardware_configuration, parse_check_composed_config,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Validates NixOS configuration overlay structure in hidden storage
///
/// Ensures the hidden storage contains all required NixOS configuration files
/// for the overlay mechanism:
/// - `{hidden}/etc/nixos/` directory exists
/// - `{hidden}/etc/nixos/hardware-configuration.nix` exists (modified with import)
/// - `{hidden}/config/nixos/configuration.nix` exists (hidden environment config)
/// - Modified hardware-configuration.nix contains relative import `./nails/configuration.nix`
/// - `{hidden}/etc/nixos/nails/configuration.nix` symlink exists (staged by Story 15.2)
/// - Base `/etc/nixos/configuration.nix` OR `/etc/nixos/flake.nix` exists
///
/// # Example
///
/// `run` ends with a `nix-instantiate --parse` gate over the composed config,
/// so the example is `no_run` (it shells out on a real host).
///
/// ```no_run
/// use nails_core::preflight::{NixOSConfigCheck, PreFlightCheck, CheckResult};
/// use nails_core::MockFilesystem;
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

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // Check 1: Base hardware-configuration.nix exists
        let base_config = PathBuf::from("/etc/nixos/hardware-configuration.nix");
        if !fs.path_exists(&base_config)? {
            return Ok(CheckResult::Fail(
                "Base /etc/nixos/hardware-configuration.nix not found. Ensure NixOS is properly installed.".into()
            ));
        }

        // Check 2: Base NixOS config exists (non-flake or flake)
        let base_config_nix = PathBuf::from("/etc/nixos/configuration.nix");
        let base_flake = PathBuf::from("/etc/nixos/flake.nix");
        if !fs.path_exists(&base_config_nix)? && !fs.path_exists(&base_flake)? {
            return Ok(CheckResult::Fail(
                "Base NixOS config missing: neither /etc/nixos/configuration.nix nor /etc/nixos/flake.nix exists."
                    .into(),
            ));
        }

        // Check 3: Hidden etc/nixos directory exists
        let hidden_etc_nixos = self.hidden_storage_path.join("etc/nixos");
        if !fs.path_exists(&hidden_etc_nixos)? {
            return Ok(CheckResult::Fail(format!(
                "Hidden storage missing etc/nixos/ directory at {}. Create this directory with modified hardware-configuration.nix.",
                hidden_etc_nixos.display()
            )));
        }

        // Check 4: Modified hardware-configuration.nix exists (auto-create if missing)
        let modified_config = hidden_etc_nixos.join("hardware-configuration.nix");
        if !fs.path_exists(&modified_config)? {
            if let Err(e) =
                ensure_hidden_hardware_configuration(fs, &self.hidden_storage_path, &base_config)
            {
                return Ok(CheckResult::Fail(format!(
                    "Modified hardware-configuration.nix not found at {}. Auto-create failed: {}",
                    modified_config.display(),
                    e
                )));
            }
            tracing::info!(
                "Auto-created modified hardware-configuration.nix at {}",
                modified_config.display()
            );
        }

        // Check 5: Modified hardware-configuration.nix has relative import to hidden config
        let content = fs.read_file_content(&modified_config)?;
        let expected_import = "./nails/configuration.nix";
        if !crate::nixos::contains_nails_import(&content) {
            return Ok(CheckResult::Fail(format!(
                "Modified hardware-configuration.nix missing hidden import. Add: imports = [ ... {} ];",
                expected_import
            )));
        }

        // Check 6: Hidden configuration.nix exists at new location (auto-create if missing)
        let hidden_config = self
            .hidden_storage_path
            .join("config/nixos/configuration.nix");
        if !fs.path_exists(&hidden_config)?
            && let Err(e) = ensure_hidden_configuration_module(fs, &self.hidden_storage_path)
        {
            return Ok(CheckResult::Fail(format!(
                "Hidden configuration.nix not found at {}. Auto-create failed: {}",
                hidden_config.display(),
                e
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
            return Ok(CheckResult::Fail(format!(
                "NixOS configuration failed to parse before mounting: {message}"
            )));
        }

        Ok(CheckResult::Pass(
            "NixOS configuration overlay structure is valid".into(),
        ))
    }
}

#[cfg(test)]
mod tests;
