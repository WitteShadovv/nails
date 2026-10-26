// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! dpkg's status file, which NAILS reads on the decoy and in hidden
//! sessions' copy of it, and the names of the files in dpkg's `info`
//! directory, whose owners tell which packages a hidden session changed.
//!
//! The input is the status file; its lines are also names of `info`
//! entries. The target checks that:
//!
//! - where dpkg accepts the file at its stanza layer (`fuzz/src/dpkg.rs`)
//!   and it ends with a newline, as every file dpkg writes does, NAILS reads
//!   each stanza's package, architecture, version and state from the fields
//!   dpkg reads, and leaves out exactly the stanzas where one of them goes on
//!   over a second line (dpkg checks a value's syntax, which the model does
//!   not, and refuses such a value). A file with Ctrl+Z in it is not
//!   compared: dpkg ends a line there and keeps the byte in the value, which
//!   NAILS reads as any other character;
//! - a stanza after the file changes nothing of what is read before it, and
//!   is read itself;
//! - the packages read, written back as dpkg writes them, read the same, and
//!   so does the file read through the filesystem;
//! - an `info` entry's owner is its name up to its last dot, with the
//!   architecture after a colon.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_base::packages::dpkg::{self, Package, State, info_owner, parse_status};
use nails_fuzz::dpkg::{Field, stanzas};
use std::path::Path;

/// A stanza of a package of its own, written after the input.
const OTHER: &str = "Package: other-package\nStatus: install ok installed\nVersion: 1.0-1\n";

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let packages = parse_status(&text);

    if (text.is_empty() || text.ends_with('\n'))
        && !text.contains('\x1a')
        && let Some(stanzas) = stanzas(&text)
    {
        let expected: Vec<Package> = stanzas.iter().filter_map(|stanza| kept(stanza)).collect();
        assert_eq!(packages, expected, "{text:?}");
    }

    for package in &packages {
        assert!(!package.name.is_empty());
        assert!(text.contains(&package.name), "{package:?}");
    }

    let more = parse_status(&format!("{text}\n\n{OTHER}"));
    assert_eq!(more[..more.len() - 1], packages[..], "{text:?}");
    assert_eq!(more.last(), parse_status(OTHER).first(), "{text:?}");

    let written = write(&packages);
    assert_eq!(parse_status(&written), packages, "{written:?}");

    let fs = MockFilesystem::new();
    fs.mock_set_file_content("/var/lib/dpkg/status", &text);
    assert_eq!(
        dpkg::read_status(&fs, Path::new("/")).expect("the mock reads"),
        Some(packages)
    );

    for line in text.split('\n') {
        if let Some((name, arch)) = info_owner(line) {
            let (owner, what) = line.rsplit_once('.').expect("an owner ends at a dot");
            assert!(!what.is_empty() && !name.is_empty() && !name.contains(':'));
            match arch {
                Some(arch) => assert_eq!(owner, format!("{name}:{arch}")),
                None => assert_eq!(owner, name),
            }
        }
    }
});

/// What NAILS keeps of a stanza dpkg reads: `None` when a kept field's
/// value goes on over a second line.
fn kept(stanza: &[Field]) -> Option<Package> {
    let field = |name: &str| {
        stanza
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.value.as_str())
    };
    let kept = [
        field("Package"),
        field("Architecture"),
        field("Version"),
        field("Status"),
    ];
    if kept.iter().flatten().any(|value| value.contains('\n')) {
        return None;
    }
    let [name, architecture, version, status] = kept;
    let present = |value: Option<&str>| value.filter(|v| !v.is_empty()).map(str::to_string);
    Some(Package {
        name: name?.to_string(),
        architecture: present(architecture),
        version: present(version),
        state: status
            .and_then(|status| {
                status
                    .split([' ', '\t', '\x0b', '\x0c', '\r'])
                    .rfind(|word| !word.is_empty())
            })
            .and_then(State::parse),
    })
}

/// `packages` as dpkg writes them, each stanza with a field NAILS does not
/// keep running over two lines.
fn write(packages: &[Package]) -> String {
    packages
        .iter()
        .map(|package| {
            let mut stanza = format!("Package: {}\n", package.name);
            if let Some(state) = package.state {
                stanza.push_str(&format!("Status: install ok {}\n", state.as_str()));
            }
            stanza.push_str("Description: a package\n that does something\n");
            if let Some(architecture) = &package.architecture {
                stanza.push_str(&format!("Architecture: {architecture}\n"));
            }
            if let Some(version) = &package.version {
                stanza.push_str(&format!("Version: {version}\n"));
            }
            stanza
        })
        .collect::<Vec<_>>()
        .join("\n")
}
