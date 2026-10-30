// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The NixOS backend: the project's first-class platform.
//!
//! It carries the one NixOS build-target discovery cascade
//! ([`discover_nixos_target`]) and the config layer.

use std::path::{Component, Path, PathBuf};

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
///    would be built without the flake's inputs. Only a missing `flake.nix`
///    means none: another error looking at it is one.
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
    match hidden_flake(fs, hidden_volume_root)? {
        HiddenFlake::Present => return Ok(HostTarget::Flake(hidden_volume_root.join("nixos"))),
        HiddenFlake::DecoyFlake => {
            return Ok(HostTarget::DecoyFlake {
                dir: PathBuf::from(ETC_FLAKE_DIR),
                hidden_volume_root: hidden_volume_root.to_path_buf(),
            });
        }
        HiddenFlake::Missing => {}
    }

    // Only a missing flake.nix means the decoy holds no flake: another error
    // looking at it refuses, as it does for a named reference.
    let etc_flake_dir = PathBuf::from(ETC_FLAKE_DIR);
    if fs.inode(&etc_flake_dir.join("flake.nix"))?.is_some() {
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
    /// The decoy's own flake: the directory is `/etc/nixos` or a directory
    /// below it, by device and inode, through a link or a bind mount.
    DecoyFlake,
}

/// What `<hidden_volume_root>/nixos` holds: a flake of its own, none, or the
/// decoy's own flake, which is no way around the refusal
/// [`HostTarget::DecoyFlake`] carries. The directory is the decoy's flake
/// when it, the target of a link on its way, or a directory above either has
/// the device and inode of `/etc/nixos` while that holds a flake, so a link
/// to `/etc/nixos` or below it and a bind mount of it count.
///
/// # Errors
///
/// Only a missing `flake.nix`, here or in `/etc/nixos`, means no flake:
/// another error looking at one, or at a directory on the way, is one, so
/// discovery refuses rather than takes the directory for a flake of its own.
pub fn hidden_flake<F: Filesystem>(fs: &F, hidden_volume_root: &Path) -> Result<HiddenFlake> {
    let dir = hidden_volume_root.join("nixos");
    if fs.inode(&dir.join("flake.nix"))?.is_none() {
        return Ok(HiddenFlake::Missing);
    }
    let decoy = match decoy_flake_identity(fs)? {
        Some(decoy) => at_or_below(fs, &dir, decoy)?,
        None => false,
    };
    Ok(if decoy {
        HiddenFlake::DecoyFlake
    } else {
        HiddenFlake::Present
    })
}

/// The decoy's own flake directory when `flake_ref`, read against the
/// working directory, names it or a directory below it while `/etc/nixos`
/// holds a flake ([`names_decoy_flake`]). Naming it explicitly is no way
/// around the refusal [`HostTarget::DecoyFlake`] carries.
///
/// # Errors
///
/// The working directory, which Nix reads a relative reference against, or a
/// file that decides the answer, cannot be looked at. A plain remote
/// reference (`github:owner/repo`), which Nix takes for a URL and never reads
/// as a path, needs no working directory.
pub(crate) fn explicit_decoy_flake<F: Filesystem>(
    fs: &F,
    flake_ref: &str,
) -> Result<Option<PathBuf>> {
    let (base, _) = crate::nixos::split_flake_ref(flake_ref);
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) if crate::nixos::is_remote_flake_ref(base) => return Ok(None),
        Err(error) => {
            return Err(crate::NailsError::NixOSPreflightError {
                category: "configuration",
                message: format!(
                    "could not read the working directory, which Nix reads a flake reference \
                     against: {error}"
                ),
            });
        }
    };
    Ok(names_decoy_flake(fs, flake_ref, &cwd)?.then(|| PathBuf::from(ETC_FLAKE_DIR)))
}

/// Whether `flake_ref`, read against the working directory `cwd`, names the
/// decoy's own flake or a directory below it while `/etc/nixos` holds a
/// flake. These readings count ([`crate::nixos::flake_ref_readings`]), each
/// as written, its links and `..` resolved by the kernel as Nix resolves a
/// path and `git+file:` (`/var/run/../etc/nixos`), and with `.` and `..`
/// applied by the text as Nix applies them to `path:`: what NAILS reads a
/// local reference as (`/etc/nixos/`, `path:/etc?dir=nixos`,
/// `git+file:///etc/nixos/.git`, `hg+file:///etc/nixos`, the percent-encoded
/// `path:/etc/%6Eixos`), whether it exists or not, and the path relative to
/// `cwd` that Nix reads a reference it cannot parse as
/// (`git+file://../../etc/nixos`, `github:/../../etc/nixos`), where it
/// exists. A directory counts by what it is, not by its name: when it, or a
/// directory above it or above the target of a link on its way, has the
/// device and inode of `/etc/nixos`, so a link and a bind mount count
/// (impermanence's `/persist/etc/nixos`). A directory below counts because
/// Nix builds the flake above a directory that holds none, and a flake on
/// the decoy is no hidden flake anyway.
///
/// # Errors
///
/// Only a missing `flake.nix` means `/etc/nixos` holds no flake: another
/// error looking it up, or looking at a directory on the way, is one, so
/// the reference is refused rather than passed. For a plain remote
/// reference, which Nix takes for a URL and never reads as a path, an error
/// looking at its reading as a path does not count.
pub(crate) fn names_decoy_flake<F: Filesystem>(
    fs: &F,
    flake_ref: &str,
    cwd: &Path,
) -> Result<bool> {
    names_flake_in(fs, flake_ref, cwd, Path::new(ETC_FLAKE_DIR))
}

/// [`names_decoy_flake`] for the decoy's flake in `decoy_dir`, which the
/// tests point at a scratch tree.
fn names_flake_in<F: Filesystem>(
    fs: &F,
    flake_ref: &str,
    cwd: &Path,
    decoy_dir: &Path,
) -> Result<bool> {
    let Some(decoy) = flake_identity(fs, decoy_dir)? else {
        return Ok(false);
    };
    let (base, _) = crate::nixos::split_flake_ref(flake_ref);
    let readings = crate::nixos::flake_ref_readings(base, cwd);
    for dir in &readings.local {
        if at_or_below(fs, dir, decoy)? {
            return Ok(true);
        }
    }
    let remote = crate::nixos::is_remote_flake_ref(base);
    for dir in &readings.fallback {
        let reached = identity(fs, dir).and_then(|found| match found {
            Some(_) => at_or_below(fs, dir, decoy),
            None => Ok(false),
        });
        match reached {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(_) if remote => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// The device and inode of `/etc/nixos` while it holds a flake; `None` when
/// it holds none ([`flake_identity`]).
fn decoy_flake_identity<F: Filesystem>(fs: &F) -> Result<Option<(u64, u64)>> {
    flake_identity(fs, Path::new(ETC_FLAKE_DIR))
}

/// The device and inode of the directory `dir` while it holds a flake;
/// `None` when it holds none. Only a missing `flake.nix` means none: another
/// error looking at it, or at `dir`, is one.
fn flake_identity<F: Filesystem>(fs: &F, dir: &Path) -> Result<Option<(u64, u64)>> {
    if fs.inode(&dir.join("flake.nix"))?.is_none() {
        return Ok(None);
    }
    identity(fs, dir)?
        .map(Some)
        .ok_or_else(|| crate::NailsError::NixOSPreflightError {
            category: "configuration",
            message: format!(
                "{} holds a flake.nix, but cannot be looked at itself",
                dir.display()
            ),
        })
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
/// `decoy`, the links on its way followed: each directory of `path` that
/// exists counts with its target and every directory above that target, so
/// a link to a directory below `/etc/nixos` leads below it, as Nix follows
/// it, and a directory above the link counts too, as Nix looks for a flake
/// above a directory that holds none. A `..` left in `path` is the kernel's
/// to apply, so the directories the text names before the last one are not
/// above `path`: `/etc/nixos/../nixos2` is `/etc/nixos2`, beside it.
fn at_or_below<F: Filesystem>(fs: &F, path: &Path, decoy: (u64, u64)) -> Result<bool> {
    let count = path.components().count();
    let floor = path
        .components()
        .rev()
        .position(|component| component == Component::ParentDir)
        .map_or(1, |from_end| count - from_end);
    let within = |dir: &&Path| dir.components().count() >= floor;
    for dir in path.ancestors().take_while(within) {
        if fs.inode(dir)?.is_none() {
            continue;
        }
        let target = fs.canonicalize(dir)?;
        for above in target.ancestors() {
            if identity(fs, above)? == Some(decoy) {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
