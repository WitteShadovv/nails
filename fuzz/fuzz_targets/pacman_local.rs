// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! pacman's database of installed packages, which NAILS lists on the decoy
//! and in hidden sessions' copy of it: one `<name>-<version>-<release>`
//! directory per package.
//!
//! The input's lines are the database's entries. The target checks that each
//! entry splits into the name and the version libalpm's `_alpm_splitname()`
//! gives (`fuzz/src/alpm.rs`), that the package's entry name is the entry it
//! came from, and that a listing of the database through the filesystem
//! gives the packages of the entries in their order.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_base::packages::pacman::{self, parse_entry};
use nails_fuzz::alpm::splitname;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let entries: Vec<&str> = text.split('\n').filter(|line| is_file_name(line)).collect();

    for entry in &entries {
        let package = parse_entry(entry);
        assert_eq!(
            package
                .as_ref()
                .map(|package| (package.name.as_bytes(), package.version.as_bytes())),
            splitname(entry.as_bytes()),
            "{entry:?}"
        );
        if let Some(package) = package {
            assert_eq!(package.entry(), *entry);
        }
    }

    let fs = MockFilesystem::new();
    let local = Path::new("/var/lib/pacman/local");
    fs.mock_set_directory_contents(
        local,
        entries.iter().map(|entry| local.join(entry)).collect(),
    );
    let listed = pacman::read_local(&fs, Path::new("/")).expect("the mock lists");
    let expected: Vec<pacman::Package> = entries
        .iter()
        .filter_map(|entry| parse_entry(entry))
        .collect();
    assert_eq!(listed, Some(expected));
});

/// Whether `line` can be the name of an entry in a directory.
fn is_file_name(line: &str) -> bool {
    !line.is_empty() && line != "." && line != ".." && !line.contains(['/', '\0'])
}
