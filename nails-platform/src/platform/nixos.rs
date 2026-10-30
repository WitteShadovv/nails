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
/// 1. a `flake.nix` in `<hidden_volume_root>/nixos`, unless that directory is
///    a link to `/etc/nixos`: the decoy's own flake then, as in step 2.
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
    match hidden_flake(fs, hidden_volume_root) {
        HiddenFlake::Present => return Ok(HostTarget::Flake(hidden_volume_root.join("nixos"))),
        HiddenFlake::DecoyFlake => {
            return Ok(HostTarget::DecoyFlake {
                dir: PathBuf::from(ETC_FLAKE_DIR),
                hidden_volume_root: hidden_volume_root.to_path_buf(),
            });
        }
        HiddenFlake::Missing => {}
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

/// What `<hidden_volume_root>/nixos` holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenFlake {
    /// No flake.
    Missing,
    /// A flake of its own.
    Present,
    /// The decoy's own flake: the directory resolves to `/etc/nixos`, through
    /// a link.
    DecoyFlake,
}

/// What `<hidden_volume_root>/nixos` holds: a flake of its own, none, or the
/// decoy's own flake through a link, which is no way around the refusal
/// [`HostTarget::DecoyFlake`] carries.
pub fn hidden_flake<F: Filesystem>(fs: &F, hidden_volume_root: &Path) -> HiddenFlake {
    let dir = hidden_volume_root.join("nixos");
    if !fs.path_exists(&dir.join("flake.nix")).unwrap_or(false) {
        HiddenFlake::Missing
    } else if is_decoy_flake_dir(fs, &dir) {
        HiddenFlake::DecoyFlake
    } else {
        HiddenFlake::Present
    }
}

/// The decoy's own flake directory when `flake_ref`, read against the
/// working directory, names it or a directory below it while `/etc/nixos`
/// holds a flake ([`names_decoy_flake`]). Naming it explicitly is no way
/// around the refusal [`HostTarget::DecoyFlake`] carries.
///
/// # Errors
///
/// The working directory, which Nix reads a relative reference against, or a
/// file that decides the answer, cannot be looked at.
pub(crate) fn explicit_decoy_flake<F: Filesystem>(
    fs: &F,
    flake_ref: &str,
) -> Result<Option<PathBuf>> {
    let cwd = std::env::current_dir().map_err(|error| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "could not read the working directory, which Nix reads a flake reference against: \
             {error}"
        ),
    })?;
    Ok(names_decoy_flake(fs, flake_ref, &cwd)?.then(|| PathBuf::from(ETC_FLAKE_DIR)))
}

/// Whether `flake_ref`, read against the working directory `cwd`, names the
/// decoy's own flake or a directory below it while `/etc/nixos` holds a
/// flake. Every reading counts ([`crate::nixos::flake_ref_readings`]): what
/// NAILS reads a local reference as (`/etc/nixos/`, `path:/etc?dir=nixos`,
/// `git+file:///etc/nixos/.git`, `hg+file:///etc/nixos`, the percent-encoded
/// `path:/etc/%6Eixos`), whether it exists or not, and the path relative to
/// `cwd` that Nix reads a reference it cannot parse as
/// (`git+file://../../etc/nixos`, `github:/../../etc/nixos`), where it
/// exists. A directory counts by what it is, not by its name: when it, or a
/// directory above it, has the device and inode of `/etc/nixos`, so a link
/// and a bind mount count (impermanence's `/persist/etc/nixos`). A directory
/// below counts because Nix builds the flake above a directory that holds
/// none, and a flake on the decoy is no hidden flake anyway.
///
/// # Errors
///
/// Only a missing `flake.nix` means `/etc/nixos` holds no flake: another
/// error looking it up, or looking at a directory on the way, is one, so
/// the reference is refused rather than passed.
pub(crate) fn names_decoy_flake<F: Filesystem>(
    fs: &F,
    flake_ref: &str,
    cwd: &Path,
) -> Result<bool> {
    let etc = Path::new(ETC_FLAKE_DIR);
    if fs.inode(&etc.join("flake.nix"))?.is_none() {
        return Ok(false);
    }
    let decoy = identity(fs, etc)?.ok_or_else(|| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!("{ETC_FLAKE_DIR} holds a flake.nix, but cannot be looked at itself"),
    })?;
    let (base, _) = crate::nixos::split_flake_ref(flake_ref);
    let readings = crate::nixos::flake_ref_readings(base, cwd);
    for dir in &readings.local {
        if at_or_below(fs, dir, decoy)? {
            return Ok(true);
        }
    }
    for dir in &readings.fallback {
        if identity(fs, dir)?.is_some() && at_or_below(fs, dir, decoy)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the file `path` leads to is, its links followed: its device and its
/// inode, or `None` when nothing is there.
fn identity<F: Filesystem>(fs: &F, path: &Path) -> Result<Option<(u64, u64)>> {
    let path = fs.canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let Some(inode) = fs.inode(&path)? else {
        return Ok(None);
    };
    Ok(Some((fs.device_id(&path)?, inode)))
}

/// Whether `path`, or a directory above it, is the file whose identity is
/// `decoy`.
fn at_or_below<F: Filesystem>(fs: &F, path: &Path, decoy: (u64, u64)) -> Result<bool> {
    for dir in path.ancestors() {
        if identity(fs, dir)? == Some(decoy) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `/etc/nixos` holds a flake and `dir` is that directory once both
/// are resolved.
fn is_decoy_flake_dir<F: Filesystem>(fs: &F, dir: &Path) -> bool {
    let etc = Path::new(ETC_FLAKE_DIR);
    fs.path_exists(&etc.join("flake.nix")).unwrap_or(false)
        && resolved(fs, dir) == resolved(fs, etc)
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
        fs.mock_set_path_type("/etc/nixos", PathKind::Dir);
        fs.mock_set_path_type("/etc/nixos/flake.nix", PathKind::File);
        fs.mock_set_path_type("/etc/nixos/configuration.nix", PathKind::File);
        fs.mock_set_path_type("/nix/var/nix/profiles/system", PathKind::Dir);
        fs
    }
}

#[cfg(test)]
#[path = "nixos_tests.rs"]
mod discovery_tests;
