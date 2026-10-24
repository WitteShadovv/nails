// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
