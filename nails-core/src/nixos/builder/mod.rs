//! NixOS profile builder implementation
//!
//! Contains the core build methods for `NixOSBuilder`.

mod switch;

use super::NixOSBuilder;
use super::{selected_nixos_configuration_fragment, split_flake_ref};
use crate::error::{NailsError, Result};

impl NixOSBuilder {
    /// Build the hidden NixOS system toplevel explicitly and return its store path.
    ///
    /// Runs `nix build <ref>#nixosConfigurations.<name>.config.system.build.toplevel`
    /// with an `--out-link` on [`profile_path`](NixOSBuilder), which lives on the
    /// hidden `/nix` upper while the overlays are mounted. The out-link is a Nix GC
    /// root, so the built closure survives on the hidden volume and a later
    /// activation can switch to it without rebuilding. The resulting store path
    /// (`/nix/store/…-nixos-system-*`) is read from `--print-out-paths`, falling
    /// back to reading the out-link.
    ///
    /// Flake-only: a legacy configuration has no `nixosConfigurations` attribute,
    /// so [`build_and_switch`](NixOSBuilder::build_and_switch) builds and activates
    /// it in one step instead.
    pub fn build_toplevel(&self) -> Result<String> {
        let installable = self.toplevel_installable()?;
        let out_link = self.profile_path.to_string_lossy().into_owned();

        tracing::info!(
            installable = %installable,
            out_link = %out_link,
            "Building the hidden NixOS system toplevel"
        );

        let (success, stdout, stderr) = self.executor.execute_nix(
            &[
                "build",
                &installable,
                "--out-link",
                &out_link,
                "--print-out-paths",
                "--no-update-lock-file",
                "--impure",
            ],
            self.should_clear_nix_path(),
        )?;

        if !success {
            // Hand the raw nix output back as a NixOSError so the caller classifies
            // it exactly as it does a build+switch failure.
            return Err(NailsError::NixOSError(combine_output(&stderr, &stdout)));
        }

        self.resolve_built_toplevel(&stdout)
    }

    /// The `nix build` installable for the hidden system toplevel.
    fn toplevel_installable(&self) -> Result<String> {
        if !self.is_flake() {
            return Err(NailsError::NixOSError(
                "an explicit toplevel build is only supported for flake configurations".into(),
            ));
        }
        let flake_arg = self.effective_flake_arg();
        let (base_ref, explicit_fragment) = split_flake_ref(&flake_arg);
        let (name, _is_explicit) = selected_nixos_configuration_fragment(explicit_fragment)?;
        Ok(format!(
            "{base_ref}#nixosConfigurations.{name}.config.system.build.toplevel"
        ))
    }

    /// Resolve the built toplevel store path from `nix build` output, falling back
    /// to reading the out-link symlink.
    fn resolve_built_toplevel(&self, stdout: &str) -> Result<String> {
        if let Some(path) = stdout
            .lines()
            .map(str::trim)
            .rfind(|line| line.starts_with("/nix/store/"))
        {
            return Ok(path.to_string());
        }

        match std::fs::read_link(&self.profile_path) {
            Ok(target) => Ok(target.to_string_lossy().into_owned()),
            Err(e) => Err(NailsError::NixOSError(format!(
                "the hidden NixOS toplevel built but its store path could not be determined \
                 (out-link {}: {})",
                self.profile_path.display(),
                e
            ))),
        }
    }

    /// The flake reference and configuration name that feed the config
    /// fingerprint, so a changed flake ref or attribute name forces a rebuild.
    ///
    /// For a legacy configuration the flake "ref" is the config directory path and
    /// there is no attribute name.
    pub(crate) fn fingerprint_inputs(&self) -> (Option<String>, Option<String>) {
        if !self.is_flake() {
            return (Some(self.config_path.to_string_lossy().into_owned()), None);
        }
        let flake_arg = self.effective_flake_arg();
        let config_name = split_flake_ref(&flake_arg).1.map(str::to_string);
        (Some(flake_arg), config_name)
    }
}

/// Prefer stderr, then stdout, then a placeholder for a failed nix invocation.
fn combine_output(stderr: &str, stdout: &str) -> String {
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    "nix build returned a non-zero exit status without diagnostic output".to_string()
}
