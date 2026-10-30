// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One build-target discovery, shared by every path that needs it.
//!
//! Historically the cascade was copied into `activate`, into the `check`
//! manager builder, and into the `nixos-build-target` pre-flight check, and the
//! copies drifted. Auto-discovery is now a question put to the host's
//! [`Platform`] backend ([`Platform::discover_build_target`]): the NixOS backend
//! runs the one probe cascade ([`super::nixos::discover_nixos_target`]), every
//! other backend discovers nothing. [`discover_host_target`] picks the backend
//! from the detected [`HostProfile`], so activation, `check`/`--dry-run` and the
//! pre-flight check all derive the same answer from the same profile.

use std::path::{Path, PathBuf};

use super::{HostProfile, NixOsPlatform, Platform, platform_for};
use crate::Result;
use crate::filesystem::Filesystem;

/// The declarative build target activation would select, resolved once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTarget {
    /// `--overlay-only`: no NixOS build or switch at all.
    OverlayOnly,
    /// An explicit flake reference from `--flake` or config `nixos_flake`.
    ExplicitFlake(String),
    /// A flake directory holding `flake.nix`: the hidden flake in
    /// `<hidden_volume_root>/nixos`.
    Flake(PathBuf),
    /// The decoy's own flake (`/etc/nixos/flake.nix`), found with no hidden
    /// flake: activation refuses it. A build of it reads only the decoy's
    /// files, so neither the hidden module nor the hidden hardware
    /// configuration would be part of the hidden system.
    DecoyFlake {
        /// The decoy's flake directory.
        dir: PathBuf,
        /// The hidden volume root: where a hidden flake goes (`nixos/`) and
        /// where the hidden module lives (`config/nixos/configuration.nix`).
        hidden_volume_root: PathBuf,
    },
    /// A legacy `configuration.nix` build (also the choice when only the system
    /// profile is present, matching activation).
    Legacy(PathBuf),
    /// No declarative build target: the host has no config layer, or none was
    /// found. Activation proceeds overlay-only.
    None,
}

/// Resolve the build target through an explicit platform backend.
///
/// In order: `overlay_only` short-circuits to [`HostTarget::OverlayOnly`]; an
/// explicit flake reference (the operator's own choice) is honoured on every
/// host, unless it names the decoy's own `/etc/nixos` flake or a directory
/// below it, compared by device and inode, in any reading Nix may make of it
/// (a path, `path:`, or a URL that reads local files such as `git+file:`,
/// `hg+file:` or `file:`, percent-encoded or not, with a query, a `dir`
/// parameter, `.` or `..` components or through the repository's `.git`
/// directory, and the path relative to the working directory Nix reads a
/// reference it cannot parse as a URL as), which is the refused
/// [`HostTarget::DecoyFlake`]; otherwise the backend's auto-discovery
/// answers. A lookup that fails other than for a missing file is an error.
/// Tests pass a
/// [`FakePlatform`](super::FakePlatform) here to pin the discovered target
/// without staging any host files.
pub fn discover_with_platform<F: Filesystem>(
    platform: &dyn Platform<F>,
    fs: &F,
    hidden_volume_root: &Path,
    explicit_flake: Option<&str>,
    overlay_only: bool,
) -> Result<HostTarget> {
    if overlay_only {
        return Ok(HostTarget::OverlayOnly);
    }
    if let Some(flake_ref) = explicit_flake {
        if let Some(dir) = super::nixos::explicit_decoy_flake(fs, flake_ref)? {
            return Ok(HostTarget::DecoyFlake {
                dir,
                hidden_volume_root: hidden_volume_root.to_path_buf(),
            });
        }
        return Ok(HostTarget::ExplicitFlake(flake_ref.to_string()));
    }
    platform.discover_build_target(fs, hidden_volume_root)
}

/// Resolve the build target for the detected host.
///
/// The backend is chosen from `profile` by [`platform_for`]. When no profile was
/// detected (`None`: detection failed, or a caller skipped it) the NixOS backend
/// answers, which keeps the historical behaviour where discovery always probed
/// the NixOS locations.
pub fn discover_host_target<F: Filesystem>(
    fs: &F,
    profile: Option<&HostProfile>,
    hidden_volume_root: &Path,
    explicit_flake: Option<&str>,
    overlay_only: bool,
) -> Result<HostTarget> {
    match profile {
        Some(profile) => {
            let backend = platform_for::<F>(profile);
            discover_with_platform(
                backend.as_ref(),
                fs,
                hidden_volume_root,
                explicit_flake,
                overlay_only,
            )
        }
        None => discover_with_platform(
            &NixOsPlatform,
            fs,
            hidden_volume_root,
            explicit_flake,
            overlay_only,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use crate::platform::{FakePlatform, PlatformKind};

    const HIDDEN_ROOT: &str = "/mnt/hidden";

    fn profile(kind: PlatformKind) -> HostProfile {
        FakePlatform::new(kind).host_profile()
    }

    #[test]
    fn overlay_only_short_circuits_every_backend() {
        let fs = MockFilesystem::new();
        for kind in [
            PlatformKind::NixOs,
            PlatformKind::Fhs,
            PlatformKind::Unsupported,
        ] {
            let target = discover_host_target(
                &fs,
                Some(&profile(kind)),
                Path::new(HIDDEN_ROOT),
                Some("ignored#ref"),
                true,
            )
            .unwrap();
            assert_eq!(target, HostTarget::OverlayOnly, "{kind:?}");
        }
    }

    #[test]
    fn fake_platform_pins_the_target_regardless_of_host_files() {
        // Every NixOS location is present, yet the fake's pinned answer wins: the
        // backend, not the filesystem, decides.
        let fs = crate::platform::nixos::tests_support::full_nixos_host();
        let fake = FakePlatform::nixos()
            .with_build_target(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix")));
        let target =
            discover_with_platform(&fake, &fs, Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(
            target,
            HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix"))
        );
    }

    #[test]
    fn explicit_flake_wins_over_the_discovered_target() {
        let fs = MockFilesystem::new();
        let fake = FakePlatform::nixos().with_build_target(HostTarget::None);
        let target =
            discover_with_platform(&fake, &fs, Path::new(HIDDEN_ROOT), Some("gh:me/cfg"), false)
                .unwrap();
        assert_eq!(target, HostTarget::ExplicitFlake("gh:me/cfg".into()));
    }

    /// A host without a config layer auto-discovers nothing, even when NixOS
    /// files happen to be present (Nix installed on Debian, a stray
    /// `/etc/nixos`). An explicit flake reference is still reported as given, so
    /// its validation is unchanged on every host.
    #[test]
    fn hosts_without_a_config_layer_discover_nothing() {
        let fs = crate::platform::nixos::tests_support::full_nixos_host();
        for kind in [PlatformKind::Fhs, PlatformKind::Unsupported] {
            let hidden = Path::new(HIDDEN_ROOT);
            let target =
                discover_host_target(&fs, Some(&profile(kind)), hidden, None, false).unwrap();
            assert_eq!(target, HostTarget::None, "{kind:?}");

            let target =
                discover_host_target(&fs, Some(&profile(kind)), hidden, Some("gh:me/cfg"), false)
                    .unwrap();
            assert_eq!(
                target,
                HostTarget::ExplicitFlake("gh:me/cfg".into()),
                "{kind:?}"
            );
        }
    }

    /// A detected NixOS host and an undetected host run the same cascade, so a
    /// failed detection never changes the target on a real NixOS machine.
    #[test]
    fn nixos_profile_and_undetected_host_agree() {
        let fs = crate::platform::nixos::tests_support::full_nixos_host();
        let nixos = discover_host_target(
            &fs,
            Some(&profile(PlatformKind::NixOs)),
            Path::new(HIDDEN_ROOT),
            None,
            false,
        )
        .unwrap();
        let undetected =
            discover_host_target(&fs, None, Path::new(HIDDEN_ROOT), None, false).unwrap();
        assert_eq!(nixos, undetected);
        assert_eq!(nixos, HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos")));
    }
}
