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
//! # Keeping it current
//!
//! Two constants record what has been reviewed: [`NEWEST_REVIEWED_CRYPTSETUP`]
//! and [`FIRST_RELEASE_OPENING_ARGON2ID`]. When a new cryptsetup release
//! appears, bump the first and, if its notes say it opens Argon2id tcrypt
//! volumes, set the second to that release. A compile-time assertion then fails
//! until both are updated together, which is the prompt to refresh this advice
//! and the dated note.

use crate::preflight::{CheckResult, PreFlightCheck};
use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};
use crate::{Filesystem, Result};
use std::fmt;
use std::time::Duration;

/// Where the per-backend guidance lives, named in the advice.
const BACKENDS_DOC: &str = "docs/backends.md";

/// How long `cryptsetup --version` may run: a local tool that prints and exits.
const CRYPTSETUP_VERSION_BUDGET: Duration = Duration::from_secs(10);

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
            "Skipping the VeraCrypt Argon2id advice: could not read the cryptsetup version".into(),
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

/// Read the installed cryptsetup version with `cryptsetup --version`. Any
/// failure (tool absent, non-zero exit, unparsable output, a test runtime that
/// refuses host commands) yields `None`, which the advice treats as "unknown".
fn detect_version(runner: &dyn ProcessRunner) -> Option<CryptsetupVersion> {
    let command = ProcessCommand::tool("cryptsetup")
        .arg("--version")
        .deadline(CRYPTSETUP_VERSION_BUDGET);
    let (ok, stdout, _) = runner.run_text(&command).ok()?;
    ok.then(|| parse_cryptsetup_version(&stdout)).flatten()
}

/// Pre-flight advice (never a failure) about cryptsetup's Argon2id limitation,
/// keyed on the installed cryptsetup version.
#[derive(Debug, Clone, Default)]
pub struct CryptsetupArgon2idCheck;

impl<F: Filesystem> PreFlightCheck<F> for CryptsetupArgon2idCheck {
    fn name(&self) -> &'static str {
        "cryptsetup-argon2id"
    }

    fn description(&self) -> &'static str {
        "Advises when the installed cryptsetup cannot open VeraCrypt Argon2id volumes"
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        Ok(argon2id_advice(detect_version(&RealProcessRunner)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NailsError;
    use crate::filesystem::MockFilesystem;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

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

    #[test]
    fn detect_version_reads_the_tool_output() {
        let runner = OneShotRunner::ok("cryptsetup 2.7.5\n");
        assert_eq!(
            detect_version(&runner),
            Some(CryptsetupVersion::new(2, 7, 5))
        );
    }

    #[test]
    fn detect_version_is_none_on_failure_or_junk() {
        assert_eq!(detect_version(&OneShotRunner::ok("not a version")), None);
        assert_eq!(detect_version(&OneShotRunner::failed()), None);
        assert_eq!(detect_version(&OneShotRunner::refused()), None);
    }

    #[test]
    fn the_check_names_itself() {
        let check = CryptsetupArgon2idCheck;
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

    /// A one-call [`ProcessRunner`] stub for the version probe.
    struct OneShotRunner(Result<Output>);

    impl OneShotRunner {
        fn ok(stdout: &str) -> Self {
            Self(Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            }))
        }

        fn failed() -> Self {
            Self(Ok(Output {
                status: ExitStatus::from_raw(1 << 8),
                stdout: Vec::new(),
                stderr: b"cryptsetup: boom\n".to_vec(),
            }))
        }

        fn refused() -> Self {
            Self(Err(NailsError::InvalidState("refused".into())))
        }
    }

    impl ProcessRunner for OneShotRunner {
        fn run(&self, _command: &ProcessCommand) -> Result<Output> {
            match &self.0 {
                Ok(output) => Ok(output.clone()),
                Err(_) => Err(NailsError::InvalidState("refused".into())),
            }
        }
    }
}
