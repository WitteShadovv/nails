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
//! with `O_NOATIME`. The kernel grants `O_NOATIME` on a file the caller does
//! not own only to root, so a check that is not running as root skips the
//! advice rather than read the database the plain way and stamp its access
//! time. A host whose version none of these names (rpm's database, which is
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

/// dpkg's record of every package (Debian, Ubuntu), relative to the root.
const DPKG_STATUS: &str = "var/lib/dpkg/status";

/// The Debian package that ships the `cryptsetup` binary.
const DPKG_PACKAGE: &str = "cryptsetup-bin";

/// pacman's database of installed packages (Arch), relative to the root: one
/// `<name>-<version>-<release>` directory each.
const PACMAN_LOCAL: &str = "var/lib/pacman/local";

/// The name of the cryptsetup package in the Nix store and in pacman's
/// database.
const PACKAGE: &str = "cryptsetup";

/// The dpkg package states in which a package's files are on disk.
const DPKG_FILES_PRESENT: &[&str] = &[
    "installed",
    "triggers-pending",
    "triggers-awaited",
    "half-configured",
    "unpacked",
];

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
/// it.
fn installed_version<F: Filesystem>(fs: &F, root: &Path) -> Option<CryptsetupVersion> {
    nix_profile_version(fs, root)
        .or_else(|| {
            let status = fs.read_file_bytes(&root.join(DPKG_STATUS)).ok()?;
            dpkg_version(&String::from_utf8_lossy(&status))
        })
        .or_else(|| pacman_version(fs, root))
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
/// store and pacman write it; `None` for another package's name, such as
/// `cryptsetup-nuke-password-1.0-1`.
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

/// The version of [`DPKG_PACKAGE`] that dpkg's `status` file records with its
/// files on disk; `None` when it records none.
fn dpkg_version(status: &str) -> Option<CryptsetupVersion> {
    status.split("\n\n").find_map(|stanza| {
        let field = |name: &str| {
            stanza.lines().find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .map(str::trim)
            })
        };
        let present = field("Status")
            .and_then(|status| status.split_whitespace().next_back())
            .is_some_and(|state| DPKG_FILES_PRESENT.contains(&state));
        if field("Package") != Some(DPKG_PACKAGE) || !present {
            return None;
        }
        parse_cryptsetup_version(without_epoch(field("Version")?))
    })
}

/// The version in the name of pacman's database entry for cryptsetup
/// (`cryptsetup-2.8.1-1`).
fn pacman_version<F: Filesystem>(fs: &F, root: &Path) -> Option<CryptsetupVersion> {
    fs.list_directory(&root.join(PACMAN_LOCAL))
        .ok()?
        .iter()
        .filter_map(|entry| entry.file_name()?.to_str())
        .find_map(package_version)
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
        Ok(argon2id_advice(installed_version(fs, &self.root)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    /// The cryptsetup each supported decoy ships, from the version table in
    /// docs/backends.md plus the Fedora and Arch releases, checked on
    /// 2026-10-19. Every entry must still draw the advice, because no release
    /// here opens Argon2id.
    const SUPPORTED_DECOY_CRYPTSETUP: &[(&str, &str)] = &[
        ("Ubuntu 24.04", "2.7.0"),
        ("Debian 13", "2.7.5"),
        ("Ubuntu 26.04", "2.8.4"),
        ("NixOS 26.05", "2.8.6"),
        ("NixOS unstable", "2.8.8"),
        ("Fedora 45", "2.8.8"),
        ("Arch", "2.8.8"),
    ];

    fn version(text: &str) -> CryptsetupVersion {
        parse_cryptsetup_version(text).expect("a version")
    }

    #[test]
    fn parses_the_version_cryptsetup_prints() {
        assert_eq!(
            version("cryptsetup 2.7.5\n"),
            CryptsetupVersion::new(2, 7, 5)
        );
        assert_eq!(version("cryptsetup 2.7.5"), CryptsetupVersion::new(2, 7, 5));
        // A bare version, and a Debian-style packaging suffix on the patch.
        assert_eq!(version("2.8.8"), CryptsetupVersion::new(2, 8, 8));
        assert_eq!(
            version("cryptsetup 2.7.5-2"),
            CryptsetupVersion::new(2, 7, 5)
        );
        // Missing components default to zero.
        assert_eq!(version("cryptsetup 2.8"), CryptsetupVersion::new(2, 8, 0));
        assert_eq!(version("cryptsetup 3"), CryptsetupVersion::new(3, 0, 0));
    }

    #[test]
    fn rejects_output_without_a_version() {
        assert_eq!(parse_cryptsetup_version(""), None);
        assert_eq!(parse_cryptsetup_version("cryptsetup"), None);
        assert_eq!(parse_cryptsetup_version("no version here"), None);
    }

    #[test]
    fn version_ordering_is_semver() {
        assert!(version("2.7.5") < version("2.8.0"));
        assert!(version("2.8.4") < version("2.8.8"));
        assert!(version("2.8.8") < version("2.9.0"));
        assert!(version("2.10.0") > version("2.9.9"));
    }

    #[test]
    fn at_least_is_inclusive_semver_comparison() {
        // `at_least` is `self >= other`, compared major first, then minor, then
        // patch. Each pair below puts one component in charge of the answer,
        // including the inclusive patch tie, so flipping a branch's comparison
        // to `<` or `==` changes a result here. (Turning the major or minor `>`
        // into `>=` is an equivalent mutant: that branch runs only when the
        // component differs, where `>=` and `>` agree, so no test can catch it.)

        // A version is at least itself (the inclusive patch tie).
        assert!(version("2.8.8").at_least(version("2.8.8")));

        // The major decides first, over a larger minor and patch on the other
        // side.
        assert!(version("3.0.0").at_least(version("2.9.9")));
        assert!(!version("2.9.9").at_least(version("3.0.0")));

        // With equal majors, the minor decides, over a larger patch.
        assert!(version("2.9.0").at_least(version("2.8.9")));
        assert!(!version("2.8.9").at_least(version("2.9.0")));

        // With equal major and minor, the patch decides, and a lower one is
        // not enough.
        assert!(version("2.8.8").at_least(version("2.8.7")));
        assert!(!version("2.8.7").at_least(version("2.8.8")));
    }

    #[test]
    fn an_unknown_version_skips_the_advice() {
        let result = argon2id_advice(None);
        assert!(result.is_pass(), "{result:?}");
        assert!(result.message().contains("could not read"));
    }

    #[test]
    fn every_supported_decoy_cryptsetup_gets_the_argon2id_advice() {
        // Fixture tripwire: this fails the day a decoy ships a cryptsetup that
        // opens Argon2id and FIRST_RELEASE_OPENING_ARGON2ID is set to record
        // it. When it fails, revisit this advice and the dated note in
        // docs/backends.md.
        for (decoy, release) in SUPPORTED_DECOY_CRYPTSETUP {
            let result = argon2id_advice(Some(version(release)));
            assert!(result.is_pass(), "{decoy} ({release}): {result:?}");
            assert!(!result.is_fail(), "the advice never blocks: {decoy}");
            let message = result.message();
            assert!(message.contains(*release), "{decoy}: {message}");
            assert!(message.contains("Argon2"), "{decoy}: {message}");
            assert!(message.contains("PBKDF2"), "{decoy}: {message}");
            assert!(message.contains(BACKENDS_DOC), "{decoy}: {message}");
        }
    }

    #[test]
    fn the_newest_reviewed_cryptsetup_release_still_draws_the_advice() {
        // The boolean is guarded at compile time (see the tripwire assertion);
        // here we confirm the advice itself still draws the PBKDF2 note (an
        // informational pass, not a warning) for that release.
        let result = argon2id_advice(Some(NEWEST_REVIEWED_CRYPTSETUP));
        assert!(result.is_pass(), "{result:?}");
        assert!(result.message().contains("PBKDF2"), "{result:?}");
    }

    #[test]
    fn the_advice_lifts_once_a_release_opens_argon2id() {
        // Both branches are informational passes; they are told apart by their
        // message. Exercised against an explicit first-supporting release while
        // the real constant is still `None`.
        let first = CryptsetupVersion::new(2, 9, 0);
        let supported = advice(Some(version("2.9.0")), Some(first));
        assert!(supported.is_pass(), "{supported:?}");
        assert!(supported.message().contains("can open"));

        // A release below the boundary still carries the PBKDF2 advisory.
        let older = advice(Some(version("2.8.8")), Some(first));
        assert!(older.is_pass(), "{older:?}");
        assert!(older.message().contains("PBKDF2"));
    }

    /// A dpkg `status` file with `cryptsetup-bin` in `state` at `version`,
    /// between two other packages, as dpkg writes it.
    fn dpkg_status(state: &str, version: &str) -> String {
        format!(
            "Package: libcryptsetup12\nStatus: install ok installed\nPriority: optional\n\
             Architecture: amd64\nMulti-Arch: same\nSource: cryptsetup\nVersion: 2:2.6.1-4\n\
             Description: disk encryption support - shared library\n libcryptsetup provides \
             an interface.\n\n\
             Package: cryptsetup-bin\nStatus: install ok {state}\nPriority: optional\n\
             Section: admin\nInstalled-Size: 470\nArchitecture: amd64\nSource: cryptsetup\n\
             Version: {version}\nConfig-Version: 2:1.0.0-1\n\
             Description: disk encryption support - command line tools\n Cryptsetup provides \
             an interface.\n\n\
             Package: cryptsetup-nuke-password\nStatus: install ok installed\nVersion: 5\n"
        )
    }

    #[test]
    fn reads_the_version_dpkg_records() {
        for (version, expected) in [
            ("2:2.7.5-2", CryptsetupVersion::new(2, 7, 5)),
            ("2:2.7.0-1ubuntu4.2", CryptsetupVersion::new(2, 7, 0)),
            ("2:2.8.4-1ubuntu1", CryptsetupVersion::new(2, 8, 4)),
            ("2.8.0~rc1-1", CryptsetupVersion::new(2, 8, 0)),
        ] {
            assert_eq!(
                dpkg_version(&dpkg_status("installed", version)),
                Some(expected),
                "{version}"
            );
        }
        // Files left on disk count; a removed package does not.
        assert!(dpkg_version(&dpkg_status("triggers-pending", "2:2.7.5-2")).is_some());
        assert_eq!(
            dpkg_version(&dpkg_status("config-files", "2:2.7.5-2")),
            None
        );
        assert_eq!(
            dpkg_version(&dpkg_status("not-installed", "2:2.7.5-2")),
            None
        );
        // The library's version is not the tool's, and a status without the
        // tool names none.
        assert_eq!(dpkg_version(""), None);
        assert_eq!(
            dpkg_version(
                "Package: libcryptsetup12\nStatus: install ok installed\nVersion: 2:2.7.5-2\n"
            ),
            None
        );
    }

    #[test]
    fn reads_the_version_a_package_name_carries() {
        assert_eq!(
            package_version("cryptsetup-2.8.6-bin"),
            Some(CryptsetupVersion::new(2, 8, 6))
        );
        assert_eq!(
            package_version("cryptsetup-2.8.1-1"),
            Some(CryptsetupVersion::new(2, 8, 1))
        );
        assert_eq!(
            package_version("cryptsetup-1:2.8.1-1"),
            Some(CryptsetupVersion::new(2, 8, 1))
        );
        // Another package whose name starts the same.
        for other in [
            "cryptsetup-nuke-password-1.0-1",
            "cryptsetupx-2.8.1-1",
            "cryptsetup",
            "lvm2-2.03.35-1",
        ] {
            assert_eq!(package_version(other), None, "{other}");
        }
    }

    #[test]
    fn reads_the_version_from_the_nixos_store_path() {
        let fs = MockFilesystem::new();
        fs.create_symlink(
            Path::new(
                "/nix/store/00000000000000000000000000000000-cryptsetup-2.8.6-bin/bin/cryptsetup",
            ),
            Path::new("/run/current-system/sw/bin/cryptsetup"),
        )
        .unwrap();
        assert_eq!(
            installed_version(&fs, Path::new("/")),
            Some(CryptsetupVersion::new(2, 8, 6))
        );
    }

    #[test]
    fn reads_the_version_from_pacmans_database() {
        let fs = MockFilesystem::new();
        let local = Path::new("/var/lib/pacman/local");
        fs.mock_set_directory_contents(
            local,
            [
                "cryptsetup-nuke-password-1.0-1",
                "cryptsetup-2.8.1-1",
                "lvm2-2.03.35-1",
            ]
            .iter()
            .map(|name| local.join(name))
            .collect(),
        );
        assert_eq!(
            installed_version(&fs, Path::new("/")),
            Some(CryptsetupVersion::new(2, 8, 1))
        );
    }

    #[test]
    fn nothing_that_names_the_version_skips_the_advice() {
        let check = CryptsetupArgon2idCheck {
            root: PathBuf::from("/"),
            privileged: true,
        };
        let result = check.run(&MockFilesystem::new()).unwrap();
        assert!(result.is_pass(), "{result:?}");
        assert!(result.message().contains("could not read"), "{result:?}");
    }

    #[test]
    fn a_check_as_root_gives_the_advice_from_the_package_database() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/var/lib/dpkg/status",
            &dpkg_status("installed", "2:2.7.5-2"),
        );
        let check = CryptsetupArgon2idCheck {
            root: PathBuf::from("/"),
            privileged: true,
        };
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
        assert!(result.message().contains("cryptsetup 2.7.5"), "{result:?}");
        assert!(result.message().contains("PBKDF2"), "{result:?}");
    }

    #[test]
    fn a_check_not_running_as_root_skips_the_advice() {
        // Without root the kernel refuses O_NOATIME on the database, and a
        // plain read would stamp its access time, so it is not read at all.
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/var/lib/dpkg/status",
            &dpkg_status("installed", "2:2.7.5-2"),
        );
        let check = CryptsetupArgon2idCheck {
            root: PathBuf::from("/"),
            privileged: false,
        };
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass(), "{result:?}");
        assert_eq!(result.message(), UNPRIVILEGED_SKIP);
        assert!(!result.message().contains("2.7.5"), "{result:?}");
    }

    #[test]
    fn the_check_leaves_the_access_times_of_the_tool_and_the_database() {
        use crate::RealFilesystem;
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, SystemTime};

        // A decoy whose cryptsetup binary and dpkg database were last read
        // long ago, so a plain read under relatime would stamp them now.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let binary = root.join("usr/sbin/cryptsetup");
        let status = root.join("var/lib/dpkg/status");
        for (path, content) in [
            (&binary, "\x7fELF cryptsetup 2.7.5".to_string()),
            (&status, dpkg_status("installed", "2:2.7.5-2")),
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
            let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
            std::fs::File::open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_accessed(old))
                .unwrap();
        }
        fn atime(path: &Path) -> (i64, i64) {
            let meta = std::fs::metadata(path).unwrap();
            (meta.atime(), meta.atime_nsec())
        }
        let before = (atime(&binary), atime(&status));

        let check = CryptsetupArgon2idCheck {
            root: root.to_path_buf(),
            privileged: true,
        };
        let result = check.run(&RealFilesystem).unwrap();
        assert!(result.message().contains("cryptsetup 2.7.5"), "{result:?}");
        assert_eq!(
            (atime(&binary), atime(&status)),
            before,
            "the check must not change an access time"
        );
    }

    #[test]
    fn the_check_names_itself() {
        let check = CryptsetupArgon2idCheck::new();
        assert_eq!(
            <CryptsetupArgon2idCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "cryptsetup-argon2id"
        );
        assert!(
            <CryptsetupArgon2idCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("Argon2id")
        );
    }

    #[test]
    fn the_advice_never_blocks_activation() {
        // The PBKDF2 advisory (every real version today), the support note and
        // the skipped case are all passes, hence non-failures: the check is
        // advice, so it can never refuse.
        assert!(!argon2id_advice(None).is_fail());
        assert!(!argon2id_advice(Some(version("2.7.5"))).is_fail());
        assert!(
            !advice(
                Some(version("2.9.0")),
                Some(CryptsetupVersion::new(2, 9, 0))
            )
            .is_fail()
        );
    }
}
