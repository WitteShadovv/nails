// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The installed cryptsetup's version, which the Argon2id advice reads from
//! what names it on the decoy instead of running the tool: dpkg's `status`
//! file, the entries of pacman's `local` database and the name of the store
//! path the NixOS system profile links `cryptsetup` to.
//!
//! The input is dpkg's status file. Its lines that can be file names are also
//! the entries of pacman's database, and the first of them the store path's
//! name. The target checks that a version read comes from what names
//! cryptsetup and is printed back and read again unchanged, and that another
//! package's stanza after the status, or its entry before the others, changes
//! nothing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::{Filesystem, MockFilesystem};
use nails_core::preflight::checks::backend_detect::{
    CryptsetupVersion, installed_cryptsetup_version, parse_cryptsetup_version,
};
use std::path::Path;

/// dpkg's record of every package.
const DPKG_STATUS: &str = "/var/lib/dpkg/status";

/// pacman's database of installed packages, one entry per package.
const PACMAN_LOCAL: &str = "/var/lib/pacman/local";

/// The NixOS system profile's `cryptsetup`.
const NIXOS_PROFILE_CRYPTSETUP: &str = "/run/current-system/sw/bin/cryptsetup";

/// A stanza of a package whose name starts like the one read.
const OTHER_STANZA: &str =
    "\n\nPackage: cryptsetup-bin-dbg\nStatus: install ok installed\nVersion: 2:9.9.9-1\n";

/// An entry of a package whose name starts like the one read.
const OTHER_ENTRY: &str = "cryptsetup-nuke-password-1.0-1";

fuzz_target!(|data: &[u8]| {
    let status = String::from_utf8_lossy(data);

    let from_dpkg = with_dpkg(&status);
    if let Some(version) = from_dpkg {
        assert!(status.contains("cryptsetup-bin"), "{status:?}");
        reads_back(version);
    }
    assert_eq!(
        with_dpkg(&format!("{status}{OTHER_STANZA}")),
        from_dpkg,
        "{status:?}"
    );

    let names: Vec<&str> = status.lines().filter(|line| is_file_name(line)).collect();
    let from_pacman = with_pacman(&names);
    if let Some(version) = from_pacman {
        assert!(
            names.iter().any(|name| name.starts_with("cryptsetup-")),
            "{names:?}"
        );
        reads_back(version);
    }
    let behind_another: Vec<&str> = std::iter::once(OTHER_ENTRY)
        .chain(names.iter().copied())
        .collect();
    assert_eq!(with_pacman(&behind_another), from_pacman, "{names:?}");

    if let Some(name) = names.first()
        && let Some(version) = with_store_path(name)
    {
        assert!(
            name.split_once('-')
                .is_some_and(|(_, package)| package.starts_with("cryptsetup-")),
            "{name:?}"
        );
        reads_back(version);
    }
});

/// Whether `line` can be the name of an entry in a directory.
fn is_file_name(line: &str) -> bool {
    !line.is_empty() && line != "." && line != ".." && !line.contains(['/', '\0'])
}

/// A version prints as `major.minor.patch` and reads back the same.
fn reads_back(version: CryptsetupVersion) {
    assert_eq!(
        parse_cryptsetup_version(&version.to_string()),
        Some(version)
    );
}

/// The version read from a decoy whose only record of cryptsetup is dpkg's
/// `status`.
fn with_dpkg(status: &str) -> Option<CryptsetupVersion> {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(DPKG_STATUS, status);
    installed_cryptsetup_version(&fs, Path::new("/"))
}

/// The version read from a decoy whose only record of cryptsetup is pacman's
/// database, holding `names`.
fn with_pacman(names: &[&str]) -> Option<CryptsetupVersion> {
    let fs = MockFilesystem::new();
    let local = Path::new(PACMAN_LOCAL);
    fs.mock_set_directory_contents(local, names.iter().map(|name| local.join(name)).collect());
    installed_cryptsetup_version(&fs, Path::new("/"))
}

/// The version read from a decoy whose only record of cryptsetup is the
/// profile's link into the store path `name`.
fn with_store_path(name: &str) -> Option<CryptsetupVersion> {
    let fs = MockFilesystem::new();
    let target = Path::new("/nix/store").join(name).join("bin/cryptsetup");
    fs.create_symlink(&target, Path::new(NIXOS_PROFILE_CRYPTSETUP))
        .expect("the mock links any path");
    installed_cryptsetup_version(&fs, Path::new("/"))
}
