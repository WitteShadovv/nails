//! NixOS profile switch/activation methods for `NixOSBuilder`.

use crate::error::{NailsError, Result};
use crate::nixos::is_non_fatal_switch_failure;
use crate::nixos::{NixOSBuildMode, NixOSBuilder, SwitchAction};
use std::path::PathBuf;

fn prefer_stderr(stderr: &str, stdout: &str) -> String {
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }

    let stdout = stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }

    "command returned a non-zero exit status without diagnostic output".to_string()
}

impl NixOSBuilder {
    /// Activate an already-built system toplevel for the running session.
    ///
    /// Runs the toplevel's own `bin/switch-to-configuration` with the
    /// non-installing [`SwitchAction`] (`test`), so the bootloader, ESP and EFI
    /// NVRAM are never touched. `store_path` is a `/nix/store/…-nixos-system-*`
    /// path — the result of [`build_toplevel`](NixOSBuilder::build_toplevel) or a
    /// cached one reused on the fast path.
    ///
    /// Unit-restart failures that `switch-to-configuration` reports but that do not
    /// mean the configuration failed to apply are treated as non-fatal, matching
    /// [`build_and_switch`].
    pub fn switch_to_toplevel(&self, store_path: &str, action: SwitchAction) -> Result<()> {
        let switch_script = PathBuf::from(store_path).join("bin/switch-to-configuration");

        tracing::info!(
            toplevel = %store_path,
            action = action.as_arg(),
            "Switching to the hidden NixOS system toplevel"
        );

        let (success, stdout, stderr) = self
            .executor
            .execute_switch_to_configuration(&switch_script, action)?;

        if !success {
            if is_non_fatal_switch_failure(&stderr, &stdout) {
                tracing::warn!(
                    stderr = %stderr.trim(),
                    stdout = %stdout.trim(),
                    "switch-to-configuration reported non-fatal unit restart failures; continuing"
                );
                return Ok(());
            }

            return Err(NailsError::NixOSError(format!(
                "switch-to-configuration {} failed: {}",
                action.as_arg(),
                prefer_stderr(&stderr, &stdout)
            )));
        }

        Ok(())
    }

    /// Combined build + switch via `nixos-rebuild test` (legacy, non-flake path).
    ///
    /// The flake path builds the toplevel explicitly
    /// ([`build_toplevel`](NixOSBuilder::build_toplevel)) and switches to it; a
    /// legacy configuration has no `nixosConfigurations` attribute to build a
    /// toplevel from, so it is built and activated in one step here:
    ///
    /// `nixos-rebuild test -I nixos-config=<path>`
    pub fn build_and_switch(&self) -> Result<()> {
        let (success, stdout, stderr) = match &self.build_mode {
            NixOSBuildMode::Flake => {
                let flake_arg = self.effective_flake_arg();
                self.executor.execute_nixos_rebuild(
                    &[
                        "test",
                        "--flake",
                        &flake_arg,
                        "--no-update-lock-file",
                        "--impure",
                    ],
                    self.should_clear_nix_path(),
                )?
            }
            NixOSBuildMode::Legacy { config_path } => {
                let arg = format!("nixos-config={}", config_path.display());
                self.executor
                    .execute_nixos_rebuild(&["test", "-I", &arg], self.should_clear_nix_path())?
            }
        };

        if !success {
            if is_non_fatal_switch_failure(&stderr, &stdout) {
                tracing::warn!(
                    stderr = %stderr.trim(),
                    stdout = %stdout.trim(),
                    "nixos-rebuild test reported non-fatal unit restart failures; continuing activation"
                );
                return Ok(());
            }

            return Err(NailsError::NixOSError(format!(
                "nixos-rebuild test failed: {}",
                prefer_stderr(&stderr, &stdout)
            )));
        }

        Ok(())
    }
}
