// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Building a [`NailsManager`] with the NixOS build target an operation would
//! pick, shared by readiness and activation so neither can report a different
//! target than the other.

use std::path::PathBuf;

use crate::platform::HostProfile;
use crate::{
    Config, Filesystem, HostTarget, NailsManager, NixOSBuilder, RealFilesystem, RuntimeEnv,
};

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
/// different build target than the others. A detection that fails leaves the
/// profile of a host NAILS cannot tell ([`HostProfile::undetected`]): the
/// platform gate of activation refuses it, and the platform row of `check`
/// fails, naming the error.
pub fn build_nixos_manager(
    config: Config,
    state_path: PathBuf,
    overlay_only: bool,
    env: &RuntimeEnv,
) -> NailsManager<RealFilesystem> {
    let mut manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    detect_or_refuse(&mut manager);

    let target = manager
        .discover_host_target(overlay_only)
        .unwrap_or(HostTarget::None);
    if let Some(builder) = nixos_builder_for(target) {
        manager.set_nixos_builder(builder);
    }
    manager
}

/// Detect the host of `manager`; one whose detection fails is kept as a host
/// NAILS refuses, never as one without a profile, which the platform gate
/// would let pass.
fn detect_or_refuse<F: Filesystem>(manager: &mut NailsManager<F>) {
    if let Err(error) = manager.initialize_platform() {
        tracing::debug!(%error, "platform detection failed; the host is refused");
        manager.set_host_profile(HostProfile::undetected(&error));
    }
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

    /// A host whose detection failed is refused by the platform gate and the
    /// platform row, naming the error, where it used to be one without a
    /// profile, which the gate let pass.
    #[test]
    fn a_host_that_cannot_be_detected_is_refused() {
        use crate::preflight::{PlatformCheck, PreFlightCheck};
        let error = crate::NailsError::io(
            "/etc/os-release",
            std::io::Error::from(std::io::ErrorKind::Other),
        );
        let profile = super::HostProfile::undetected(&error);
        let reason = "NAILS cannot tell which platform this is: /etc/os-release: other error";
        match profile.require_supported() {
            Err(crate::NailsError::UnsupportedPlatform { reason: refused }) => {
                assert_eq!(refused, reason);
            }
            other => panic!("{other:?}"),
        }
        let row = PreFlightCheck::<crate::MockFilesystem>::run(
            &PlatformCheck::new(profile),
            &crate::MockFilesystem::new(),
        )
        .unwrap();
        assert_eq!(row, crate::preflight::CheckResult::fail(reason));
    }

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
