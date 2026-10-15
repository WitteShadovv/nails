// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The NixOS backend: the project's first-class platform.
//!
//! It carries the one NixOS build-target discovery cascade
//! ([`discover_nixos_target`]) and the config layer.

use std::path::{Path, PathBuf};

use super::{ConfigLayer, HostTarget, NixOsConfigLayer, Platform, PlatformKind};
use crate::Result;
use crate::constants::NIXOS_SYSTEM_PROFILE_BIN;
use crate::filesystem::Filesystem;

/// Legacy NixOS configuration, probed when no flake is found.
const LEGACY_CONFIG: &str = "/etc/nixos/configuration.nix";
/// The decoy's own flake directory.
const ETC_FLAKE_DIR: &str = "/etc/nixos";
/// Newest-generation system profile; its mere presence means the host is NixOS.
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";

/// Directories NixOS exposes host tools under.
pub(crate) const NIXOS_COMMAND_DIRS: &[&str] = &[NIXOS_SYSTEM_PROFILE_BIN, "/run/wrappers/bin"];

/// The NixOS build-target discovery cascade: the single implementation.
///
/// Run when no explicit flake is configured. In order:
///
/// 1. a `flake.nix` in `<hidden_volume_root>/nixos`.
/// 2. a `flake.nix` in `/etc/nixos`: the decoy's own flake, which
///    [`HostTarget::DecoyFlake`] reports for refusal. Built from the decoy's
///    files, it could not import the hidden module (the decoy's `/etc/nixos`
///    must not name the hidden volume), and the legacy configuration beside it
///    would be built without the flake's inputs.
/// 3. a legacy `/etc/nixos/configuration.nix`, or a present system profile.
/// 4. otherwise [`HostTarget::None`].
///
/// Every probe goes through the [`Filesystem`] trait so the result is
/// deterministic under test. Callers reach this through
/// [`Platform::discover_build_target`] (see
/// [`discover_host_target`](super::discover_host_target)) rather than directly,
/// so a non-NixOS host never runs it.
pub(crate) fn discover_nixos_target<F: Filesystem>(
    fs: &F,
    hidden_volume_root: &Path,
) -> Result<HostTarget> {
    let hidden_flake_dir = hidden_volume_root.join("nixos");
    if fs.path_exists(&hidden_flake_dir.join("flake.nix"))? {
        return Ok(HostTarget::Flake(hidden_flake_dir));
    }

    let etc_flake_dir = PathBuf::from(ETC_FLAKE_DIR);
    if fs.path_exists(&etc_flake_dir.join("flake.nix"))? {
        return Ok(HostTarget::DecoyFlake {
            dir: etc_flake_dir,
            hidden_volume_root: hidden_volume_root.to_path_buf(),
        });
    }

    let legacy_config = PathBuf::from(LEGACY_CONFIG);
    if fs.path_exists(&legacy_config)? || fs.path_exists(Path::new(SYSTEM_PROFILE))? {
        return Ok(HostTarget::Legacy(legacy_config));
    }

    Ok(HostTarget::None)
}

/// The decoy's own flake directory when `flake_ref` names it and `/etc/nixos`
/// holds a flake: a local reference (an absolute path, `path:`, `git+file:`
/// or `file:`, or a relative one) whose directory is `/etc/nixos` once both
/// are resolved, so `/etc/nixos/`, `path:/etc/nixos?…` and a link to the
/// directory name it too. Naming it explicitly is no way around the refusal
/// [`HostTarget::DecoyFlake`] carries.
pub(crate) fn explicit_decoy_flake<F: Filesystem>(fs: &F, flake_ref: &str) -> Option<PathBuf> {
    let (base, _) = crate::nixos::split_flake_ref(flake_ref);
    let dir = local_flake_path(base)?;
    let etc = Path::new(ETC_FLAKE_DIR);
    if !fs.path_exists(&etc.join("flake.nix")).unwrap_or(false) {
        return None;
    }
    (resolved(fs, &dir) == resolved(fs, etc)).then(|| etc.to_path_buf())
}

/// The directory a local flake reference names; `None` for a remote one.
fn local_flake_path(base: &str) -> Option<PathBuf> {
    for scheme in ["git+file:", "file:"] {
        if let Some(rest) = base.strip_prefix(scheme) {
            let (path, _) = rest.split_once('?').unwrap_or((rest, ""));
            // `git+file:///etc/nixos`: an empty authority before the path.
            let path = path.strip_prefix("//").unwrap_or(path);
            return path.starts_with('/').then(|| PathBuf::from(path));
        }
    }
    crate::nixos::resolve_local_flake_dir(base).ok().flatten()
}

/// `path` with its links resolved where it can be, and with `.` components
/// and a trailing slash dropped.
fn resolved<F: Filesystem>(fs: &F, path: &Path) -> PathBuf {
    fs.canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .components()
        .collect()
}

/// First-class NixOS backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct NixOsPlatform;

impl<F: Filesystem> Platform<F> for NixOsPlatform {
    fn kind(&self) -> PlatformKind {
        PlatformKind::NixOs
    }

    fn host_command_dirs(&self) -> &'static [&'static str] {
        NIXOS_COMMAND_DIRS
    }

    fn config_layer(&self) -> Option<Box<dyn ConfigLayer<F>>>
    where
        F: 'static,
    {
        Some(Box::new(NixOsConfigLayer))
    }

    fn discover_build_target(&self, fs: &F, hidden_volume_root: &Path) -> Result<HostTarget> {
        discover_nixos_target(fs, hidden_volume_root)
    }
}

/// Shared NixOS host fixtures for the platform module's own tests.
#[cfg(test)]
pub(super) mod tests_support {
    use crate::filesystem::{MockFilesystem, PathKind};

    /// A mock host where every discovery location is present: the hidden-volume
    /// flake (under `/mnt/hidden`), the `/etc/nixos` flake, the legacy
    /// configuration and the system profile.
    pub(in crate::platform) fn full_nixos_host() -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/mnt/hidden/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        fs
    }
}

/// The discovery cascade, exercised against NixOS host fixtures. These are the
/// only `/etc/nixos` discovery fixtures: callers (manager, pre-flight, CLI) pin
/// the target with a `FakePlatform` instead.
#[cfg(test)]
mod discovery_tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    const HIDDEN_ROOT: &str = "/mnt/hidden";

    fn discover(fs: &MockFilesystem) -> HostTarget {
        Platform::discover_build_target(&NixOsPlatform, fs, Path::new(HIDDEN_ROOT)).unwrap()
    }

    #[test]
    fn explicit_flake_wins_over_probes() {
        let fs = tests_support::full_nixos_host();
        let target = super::super::discover_with_platform(
            &NixOsPlatform,
            &fs,
            Path::new(HIDDEN_ROOT),
            Some("gh:me/cfg#host"),
            false,
        )
        .unwrap();
        assert_eq!(
            target,
            HostTarget::ExplicitFlake("gh:me/cfg#host".to_string())
        );
    }

    #[test]
    fn hidden_volume_flake_preferred() {
        let fs = tests_support::full_nixos_host();
        assert_eq!(
            discover(&fs),
            HostTarget::Flake(PathBuf::from("/mnt/hidden/nixos"))
        );
    }

    /// The decoy's own flake is reported for refusal, never built, and the
    /// legacy configuration beside it (which the flake imports) is not taken
    /// instead.
    #[test]
    fn etc_flake_without_a_hidden_flake_is_the_refused_decoy_flake() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        assert_eq!(
            discover(&fs),
            HostTarget::DecoyFlake {
                dir: PathBuf::from("/etc/nixos"),
                hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
            }
        );
    }

    /// The decoy's own flake named explicitly, in each spelling Nix accepts
    /// for it, is the refused decoy flake; another directory is not, and
    /// neither is `/etc/nixos` without a flake in it.
    #[test]
    fn the_decoy_flake_named_explicitly_is_the_refused_decoy_flake() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        fs.create_symlink(Path::new("/etc/nixos"), Path::new("/srv/config"))
            .unwrap();
        for spelling in [
            "/etc/nixos#host",
            "/etc/nixos/#host",
            "/etc/./nixos",
            "path:/etc/nixos?lastModified=1#host",
            "git+file:///etc/nixos?ref=main#host",
            "git+file:/etc/nixos#host",
            "/srv/config#host",
        ] {
            let target = super::super::discover_with_platform(
                &NixOsPlatform,
                &fs,
                Path::new(HIDDEN_ROOT),
                Some(spelling),
                false,
            )
            .unwrap();
            assert_eq!(
                target,
                HostTarget::DecoyFlake {
                    dir: PathBuf::from("/etc/nixos"),
                    hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
                },
                "{spelling}"
            );
        }
        for other in [
            "/mnt/hidden/nixos#host",
            "/etc/nixos2#host",
            "github:me/cfg#host",
        ] {
            assert_eq!(explicit_decoy_flake(&fs, other), None, "{other}");
        }
        assert_eq!(
            explicit_decoy_flake(&MockFilesystem::new(), "/etc/nixos#host"),
            None,
            "no flake in /etc/nixos"
        );
    }

    #[test]
    fn legacy_config_when_present() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        assert_eq!(
            discover(&fs),
            HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
        );
    }

    /// The agreement case: with only the system profile present, every path must
    /// resolve to the same legacy target activation uses — no drift between
    /// activate, `--dry-run`/`check`, and the `nixos-build-target` pre-flight.
    #[test]
    fn only_system_profile_resolves_to_legacy() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        assert_eq!(
            discover(&fs),
            HostTarget::Legacy(PathBuf::from("/etc/nixos/configuration.nix"))
        );
    }

    #[test]
    fn nothing_found_is_none() {
        assert_eq!(discover(&MockFilesystem::new()), HostTarget::None);
    }
}
