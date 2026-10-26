// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Check-time advice about cryptsetup's Argon2id / tcrypt limitation.
//!
//! VeraCrypt 1.26.29 can derive a volume's header key with Argon2id instead of
//! PBKDF2 (the "Argon2" entry in its KDF list), but no released cryptsetup can
//! open such a tcrypt volume: the support landed on cryptsetup's development
//! branch in June 2026 and is in no tag through 2.8.8 (September 2026). NAILS
//! opens VeraCrypt hidden volumes with cryptsetup, so a volume made with
//! Argon2id never becomes a mapping the backend check can inspect, and nothing
//! outside the encrypted header reveals which algorithm it used. A volume made
//! this way simply fails to open, as if the password were wrong.
//!
//! So the advice is keyed on the *installed* cryptsetup version rather than on
//! the current backend: while the host's cryptsetup cannot open Argon2id, it
//! tells the operator to keep PBKDF2 when making a VeraCrypt volume. The trap
//! lasts for years on the LTS decoys, which do not get a newer cryptsetup once
//! released. `docs/backends.md` keeps the dated note with the version table.
//!
//! # Reading the version without a trace
//!
//! The check never runs `cryptsetup --version`, and never reads the binary.
//! Running it would read the decoy's `cryptsetup` and, under the default
//! `relatime`, stamp its access time with the time of every `nails check` and
//! activation: the very tell the residue catalog lists for encryption tooling
//! (`backend-tooling`, "a cryptsetup binary read recently says encrypted
//! volumes were opened"), and one that would undo the advice to run the backend
//! tools from another machine or a live medium. The version comes instead from
//! what names it: the store path the NixOS system profile links `cryptsetup`
//! to, whose name carries the version (resolving the link reads no file, and
//! its links lie in `/run` and in the store, which NixOS mounts read-only), or
//! the package database, dpkg's `status` or pacman's `local` directory, read
//! with `O_NOATIME` ([`crate::packages`]). The kernel grants `O_NOATIME` on a
//! file the caller does not own only to root, so a check that is not running
//! as root skips the advice rather than read the database the plain way and
//! stamp its access time. A host whose version none of these names (rpm's database, which is
//! not a format read here, or a cryptsetup built by hand) skips it as well.
//!
//! # Keeping it current
//!
//! Two constants record what has been reviewed: [`NEWEST_REVIEWED_CRYPTSETUP`]
//! and [`FIRST_RELEASE_OPENING_ARGON2ID`]. When a new cryptsetup release
//! appears, bump the first and, if its notes say it opens Argon2id tcrypt
//! volumes, set the second to that release. A compile-time assertion then fails
//! until both are updated together, which is the prompt to refresh this advice
//! and the dated note.

use crate::packages::{dpkg, pacman};
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::fmt;
use std::path::{Path, PathBuf};

/// Where the per-backend guidance lives, named in the advice.
const BACKENDS_DOC: &str = "docs/backends.md";

/// The NixOS system profile's `cryptsetup` link, relative to the root. It
/// points into the store path of the package, whose name carries the version.
const NIXOS_PROFILE_CRYPTSETUP: &str = "run/current-system/sw/bin/cryptsetup";

/// The Nix store, relative to the root.
const NIX_STORE: &str = "nix/store";

/// The Debian package that ships the `cryptsetup` binary.
const DPKG_PACKAGE: &str = "cryptsetup-bin";

/// The name of the cryptsetup package in the Nix store and in pacman's
/// database.
const PACKAGE: &str = "cryptsetup";

/// Why the advice is skipped on a check that is not running as root.
const UNPRIVILEGED_SKIP: &str = "Skipping the VeraCrypt Argon2id advice: only a check running as \
     root reads the installed cryptsetup version, from the package database, without updating \
     its access time";

/// The newest cryptsetup release reviewed against this advice: 2.8.8
/// (September 2026), whose `lib/tcrypt/tcrypt.c` has no Argon2id support. Bump
/// it when a newer release is reviewed; see the [module docs](self).
const NEWEST_REVIEWED_CRYPTSETUP: CryptsetupVersion = CryptsetupVersion::new(2, 8, 8);

/// The first cryptsetup release able to open a VeraCrypt / tcrypt volume whose
/// header key is derived with Argon2id.
///
/// `None` while no release carries it: the support landed on cryptsetup's
/// development branch on 2026-06-28 but is in no tag through 2.8.8. Set it to
/// the release that ships the support; [`argon2id_advice`] then stops firing
/// on a host new enough to open such a volume, and the compile-time tripwire
/// below fails until [`NEWEST_REVIEWED_CRYPTSETUP`] is updated with it.
const FIRST_RELEASE_OPENING_ARGON2ID: Option<CryptsetupVersion> = None;

/// A cryptsetup release version, `major.minor.patch`, ordered as semver.
///
/// The field order makes the derived `Ord` compare major first, then minor,
/// then patch, which is the ordering cryptsetup releases follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CryptsetupVersion {
    /// Major component (`2` in `2.7.5`).
    pub major: u16,
    /// Minor component (`7` in `2.7.5`).
    pub minor: u16,
    /// Patch component (`5` in `2.7.5`).
    pub patch: u16,
}

impl CryptsetupVersion {
    /// A version from its three components.
    const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// `self >= other`, in a `const fn` so the compile-time tripwire below can
    /// compare versions (the derived `Ord` operators are not `const`).
    const fn at_least(self, other: CryptsetupVersion) -> bool {
        if self.major != other.major {
            return self.major > other.major;
        }
        if self.minor != other.minor {
            return self.minor > other.minor;
        }
        self.patch >= other.patch
    }
}

impl fmt::Display for CryptsetupVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse the version from `cryptsetup --version` output (`cryptsetup 2.7.5`),
/// tolerating a bare `2.7.5` and trailing build text. `None` when no leading
/// `major` number can be read.
pub fn parse_cryptsetup_version(text: &str) -> Option<CryptsetupVersion> {
    let text = text.trim();
    let text = text
        .strip_prefix("cryptsetup")
        .map_or(text, str::trim_start);
    let token = text.split_whitespace().next()?;
    let mut parts = token.split('.').map(leading_number);
    let major = parts.next().flatten()?;
    let minor = parts.next().flatten().unwrap_or(0);
    let patch = parts.next().flatten().unwrap_or(0);
    Some(CryptsetupVersion {
        major,
        minor,
        patch,
    })
}

/// The leading run of ASCII digits of `component` as a number, so a packaging
/// suffix (`5-2`, `8~rc1`) keeps only its numeric head.
fn leading_number(component: &str) -> Option<u16> {
    let digits: String = component.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Whether `version` can open a VeraCrypt / tcrypt volume made with Argon2id,
/// given the first release that carries the support.
const fn opens_argon2id_tcrypt(
    version: CryptsetupVersion,
    first: Option<CryptsetupVersion>,
) -> bool {
    match first {
        Some(first) => version.at_least(first),
        None => false,
    }
}

/// Compile-time tripwire: the newest reviewed cryptsetup release must
/// still be unable to open an Argon2id tcrypt volume. The day a reviewed
/// release opens them — [`FIRST_RELEASE_OPENING_ARGON2ID`] set at or below
/// [`NEWEST_REVIEWED_CRYPTSETUP`] — this fails to compile, which is the prompt
/// to refresh this advice and the dated note in `docs/backends.md`.
const _: () = assert!(!opens_argon2id_tcrypt(
    NEWEST_REVIEWED_CRYPTSETUP,
    FIRST_RELEASE_OPENING_ARGON2ID
));

/// The advice for the installed cryptsetup `version` (`None` when it could not
/// be read): always an informational pass, never a warning. It carries the
/// PBKDF2 advisory while the host cannot open Argon2id volumes, and a note of
/// support once a release can.
pub fn argon2id_advice(version: Option<CryptsetupVersion>) -> CheckResult {
    advice(version, FIRST_RELEASE_OPENING_ARGON2ID)
}

/// [`argon2id_advice`] against an explicit first-supporting release, so the
/// support-confirming branch can be tested while the real constant is still
/// `None`.
fn advice(version: Option<CryptsetupVersion>, first: Option<CryptsetupVersion>) -> CheckResult {
    match version {
        None => CheckResult::Pass(
            "Skipping the VeraCrypt Argon2id advice: could not read the installed cryptsetup \
             version from the NixOS system profile or the dpkg or pacman database"
                .into(),
        ),
        Some(version) if opens_argon2id_tcrypt(version, first) => CheckResult::Pass(format!(
            "cryptsetup {version} can open a VeraCrypt volume whose header key uses Argon2id"
        )),
        Some(version) => CheckResult::Pass(format!(
            "If you use VeraCrypt: the installed cryptsetup {version} cannot open a volume whose \
             header key is derived with Argon2id (the \"Argon2\" entry in VeraCrypt 1.26.29 and \
             newer), and nothing outside the encrypted header shows which algorithm it used. Make \
             both the outer and the hidden VeraCrypt volume with PBKDF2: keep VeraCrypt's default \
             key-derivation function, or pick any entry other than Argon2. See {BACKENDS_DOC}."
        )),
    }
}

/// The installed cryptsetup's version under `root`, from what names it without
/// running or reading the binary (see the [module docs](self)): the NixOS
/// system profile's link, which comes first as it does in the tool search
/// path, then dpkg's database, then pacman's. `None` when none of them names
/// it. Every one of them is whatever the decoy's disk holds; the
/// `cryptsetup_version` fuzz target drives this with hostile ones.
pub fn installed_cryptsetup_version<F: Filesystem>(
    fs: &F,
    root: &Path,
) -> Option<CryptsetupVersion> {
    nix_profile_version(fs, root)
        .or_else(|| dpkg_version(&dpkg::read_status(fs, root).ok()??))
        .or_else(|| pacman_version(&pacman::read_local(fs, root).ok()??))
}

/// The version in the name of the store path the NixOS system profile's
/// `cryptsetup` resolves into (`/nix/store/<hash>-cryptsetup-2.8.6-bin/...`).
fn nix_profile_version<F: Filesystem>(fs: &F, root: &Path) -> Option<CryptsetupVersion> {
    let target = fs.canonicalize(&root.join(NIXOS_PROFILE_CRYPTSETUP)).ok()?;
    let store_path = target.strip_prefix(root.join(NIX_STORE)).ok()?;
    let name = store_path.components().next()?.as_os_str().to_str()?;
    let (_hash, package) = name.split_once('-')?;
    package_version(package)
}

/// The version of a `cryptsetup-<version>[-<suffix>]` package name, as the Nix
/// store writes it in a store path's name; `None` for another package's name,
/// such as `cryptsetup-nuke-password-1.0-1`.
fn package_version(name: &str) -> Option<CryptsetupVersion> {
    let version = name.strip_prefix(PACKAGE)?.strip_prefix('-')?;
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    parse_cryptsetup_version(without_epoch(version))
}

/// A package version without the epoch Debian and pacman put before a colon
/// (`2:2.7.5-2` is upstream `2.7.5`).
fn without_epoch(version: &str) -> &str {
    version.split_once(':').map_or(version, |(_, rest)| rest)
}

/// The version of [`DPKG_PACKAGE`] among the `packages` dpkg's `status` file
/// records, the first with its files on disk; `None` when it records none.
fn dpkg_version(packages: &[dpkg::Package]) -> Option<CryptsetupVersion> {
    packages
        .iter()
        .filter(|package| package.name == DPKG_PACKAGE && package.files_present())
        .find_map(|package| parse_cryptsetup_version(without_epoch(package.version.as_deref()?)))
}

/// The version of cryptsetup among the `packages` of pacman's database
/// (the entry `cryptsetup-2.8.1-1`).
fn pacman_version(packages: &[pacman::Package]) -> Option<CryptsetupVersion> {
    packages
        .iter()
        .filter(|package| package.name == PACKAGE)
        .find_map(|package| parse_cryptsetup_version(without_epoch(&package.version)))
}

/// Pre-flight advice (never a failure) about cryptsetup's Argon2id limitation,
/// keyed on the installed cryptsetup version.
#[derive(Debug, Clone)]
pub struct CryptsetupArgon2idCheck {
    /// The root of the system whose cryptsetup is asked about; `/` outside
    /// tests.
    root: PathBuf,
    /// Whether the check runs as root, the only caller the kernel lets read the
    /// package database with `O_NOATIME`.
    privileged: bool,
}

impl CryptsetupArgon2idCheck {
    /// The check of the running system, as the current process.
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
            privileged: nix::unistd::geteuid().is_root(),
        }
    }
}

impl Default for CryptsetupArgon2idCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Filesystem> PreFlightCheck<F> for CryptsetupArgon2idCheck {
    fn name(&self) -> &'static str {
        "cryptsetup-argon2id"
    }

    fn description(&self) -> &'static str {
        "Advises when the installed cryptsetup cannot open VeraCrypt Argon2id volumes"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        if !self.privileged {
            return Ok(CheckResult::Pass(UNPRIVILEGED_SKIP.into()));
        }
        let version = installed_cryptsetup_version(fs, &self.root);
        Ok(argon2id_advice(version))
    }
}

#[cfg(test)]
mod tests;
