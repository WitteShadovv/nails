// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The systemd configuration NAILS reads to judge a decoy: logind's lid and
//! idle actions, where journald keeps the journal, systemd-coredump and
//! sleep. NAILS has to read these files exactly as the daemons do: a
//! difference makes a decoy that writes a journal or a core dump to its disk
//! look safe.
//!
//! The input is up to three files, separated by NULs: the main file in
//! `/etc/systemd`, a drop-in `50-local.conf` in `/etc` and a drop-in
//! `10-vendor.conf` in `/usr/lib`. A vendor main file and a vendor
//! `50-local.conf` are always there too: the first is shadowed by the main
//! file in `/etc`, the second by the drop-in of the same name when the input
//! has one. Every input serves as `logind.conf`, `journald.conf`,
//! `coredump.conf` and `sleep.conf`. The target checks that the assignments
//! NAILS resolves for each are the ones the daemon applies (the model in
//! `nails_fuzz::systemd_conf`), in order.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_core::preflight::checks::systemd_conf::section_assignments;
use nails_fuzz::systemd_conf::{Verdict, read_files};
use std::path::{Path, PathBuf};

/// The configurations NAILS reads, with the section it reads in each.
const CONFIGS: [(&str, &str); 4] = [
    ("logind.conf", "Login"),
    ("journald.conf", "Journal"),
    ("coredump.conf", "Coredump"),
    ("sleep.conf", "Sleep"),
];

/// The vendor files a file in `/etc` shadows.
const VENDOR: &str = "[Login]\nHandleLidSwitch=hibernate\nIdleAction=suspend\n\
                      [Journal]\nStorage=persistent\n[Coredump]\nStorage=external\n\
                      [Sleep]\nAllowSuspend=yes\n";

fuzz_target!(|data: &[u8]| {
    let parts = nails_fuzz::parts(data, 3);
    let local = parts.get(1).map(String::as_str);
    let vendor = parts.get(2).map(String::as_str);
    // The order the daemon reads them in: the main file found first, then
    // the drop-ins sorted by name, each name from the first directory.
    let mut files = vec![parts[0].as_str()];
    files.extend(vendor);
    files.push(local.unwrap_or(VENDOR));

    for (name, section) in CONFIGS {
        let fs = stage(name, &parts[0], local, vendor);
        // Every staged file is a regular one and the main file is in /etc,
        // which every release reads, so the configuration is read.
        let read: Vec<(String, String)> =
            section_assignments(&fs, Path::new("/"), name, section, None)
                .expect("a configuration of regular files is read")
                .into_iter()
                .map(|assignment| (assignment.key, assignment.value))
                .collect();
        // systemd strips its WHITESPACE, " \t\n\r", around both.
        let stripped = |text: &str| text.trim_matches([' ', '\t', '\n', '\r']).len() == text.len();
        for (key, value) in &read {
            assert!(!key.is_empty() && !key.contains('='), "{key:?}");
            assert!(stripped(key) && stripped(value), "{key:?}={value:?}");
        }
        if let Verdict::Read(expected) = read_files(&files, section) {
            assert_eq!(read, expected.assignments, "[{section}] of {name}");
        }
    }
});

/// A system with `name`'s files: the main file and the drop-ins.
fn stage(name: &str, main: &str, local: Option<&str>, vendor: Option<&str>) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(&format!("/etc/systemd/{name}"), main);
    fs.mock_set_file_content(&format!("/usr/lib/systemd/{name}"), VENDOR);
    let etc_dir = PathBuf::from(format!("/etc/systemd/{name}.d"));
    let lib_dir = PathBuf::from(format!("/usr/lib/systemd/{name}.d"));
    let mut etc = Vec::new();
    if let Some(text) = local {
        let path = etc_dir.join("50-local.conf");
        fs.mock_set_file_content(&path.to_string_lossy(), text);
        etc.push(path);
    }
    let mut lib = Vec::new();
    if let Some(text) = vendor {
        let path = lib_dir.join("10-vendor.conf");
        fs.mock_set_file_content(&path.to_string_lossy(), text);
        lib.push(path);
    }
    let shadowed = lib_dir.join("50-local.conf");
    fs.mock_set_file_content(&shadowed.to_string_lossy(), VENDOR);
    lib.push(shadowed);
    fs.mock_set_directory_contents(&etc_dir, etc);
    fs.mock_set_directory_contents(&lib_dir, lib);
    fs
}
