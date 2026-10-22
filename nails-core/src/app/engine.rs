// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Building a [`NailsManager`] with the NixOS build target an operation would
//! pick, shared by readiness and activation so neither can report a different
//! target than the other.

use std::path::PathBuf;

use crate::{Config, HostTarget, NailsManager, NixOSBuilder, RealFilesystem, RuntimeEnv};

/// Build a [`NailsManager`] with the NixOS build target activation would pick
/// for the same configuration.
///
/// The host is detected once here and the build target is then asked of that
/// host's platform backend: on NixOS that is overlay-only (no builder) →
/// explicit `config.nixos_flake` → a flake in the hidden volume → the decoy's
/// own `/etc/nixos/flake.nix` (refused: no builder, and the build-target check
/// fails) → a legacy `/etc/nixos/configuration.nix` or system profile → no
/// NixOS; a host without a declarative config layer has no build target at all.
/// Activation, readiness and the `nixos-build-target` check all go through this
/// one discovery on the same host profile, so none of them can report a
/// different build target than the others. A failed detection leaves no profile,
/// and discovery then runs the NixOS cascade as it always has.
pub fn build_nixos_manager(
    config: Config,
    state_path: PathBuf,
    overlay_only: bool,
    env: &RuntimeEnv,
) -> NailsManager<RealFilesystem> {
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

/// The builder of a build target. Overlay-only, no target and the refused decoy
/// flake get none.
pub fn nixos_builder_for(target: HostTarget) -> Option<NixOSBuilder> {
    match target {
        HostTarget::OverlayOnly | HostTarget::None | HostTarget::DecoyFlake { .. } => None,
        HostTarget::ExplicitFlake(flake_ref) => Some(NixOSBuilder::new_with_flake_ref(flake_ref)),
        HostTarget::Flake(dir) => Some(NixOSBuilder::new(dir)),
        HostTarget::Legacy(path) => Some(NixOSBuilder::new_legacy(path)),
    }
}

#[cfg(test)]
mod tests {
    use super::nixos_builder_for;
    use crate::HostTarget;
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
}
