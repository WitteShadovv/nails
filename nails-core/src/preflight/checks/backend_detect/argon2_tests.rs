// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the check-time advice about cryptsetup's Argon2id limitation.

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
