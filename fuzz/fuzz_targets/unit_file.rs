// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A decoy's systemd unit file, which the session reads to decide the mount,
//! swap and automount units outside the fstab. NAILS has to read a unit as
//! systemd's `config_parse()` does: a disk mount misread as a RAM filesystem
//! would be left to the hidden systemd, which would mount the disk
//! read-write.
//!
//! The input is the unit file. The target checks that reading it never
//! panics, that every assignment has a key that is not empty and holds no
//! `=`, with key and value stripped, and that for every section NAILS reads
//! the assignments are the ones systemd applies (the model in
//! `nails_fuzz::systemd_conf`), in order. A file systemd stops reading at a
//! line it refuses never loads as a unit, so NAILS must refuse it whole, and
//! so must it a header some systemd releases refuse.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_fuzz::systemd_conf::{Verdict, read_files};
use nails_session::session::mount_units::unit_file::{self, UnitFile};

/// The sections NAILS reads from a mount, swap or automount unit.
const SECTIONS: [&str; 4] = ["Unit", "Mount", "Swap", "Automount"];

fuzz_target!(|data: &[u8]| {
    if let Ok(unit) = unit_file::parse(data) {
        check(&unit);
    }
    // The model reads text: compare the two on the input as UTF-8.
    let text = String::from_utf8_lossy(data);
    let read = unit_file::parse(text.as_bytes());
    if let Ok(unit) = &read {
        check(unit);
    }
    for section in SECTIONS {
        match read_files(&[&text], section) {
            Verdict::Undecided => assert!(read.is_err(), "[{section}] read: {read:?}"),
            Verdict::Read(expected) if expected.stopped => {
                assert!(read.is_err(), "systemd stops reading [{section}]: {read:?}");
            }
            Verdict::Read(expected) => {
                let unit = read.as_ref().expect("a unit systemd reads to its end");
                let assignments: Vec<(String, String)> = unit
                    .assignments
                    .iter()
                    .filter(|(s, ..)| s == section)
                    .map(|(_, key, value)| (key.clone(), value.clone()))
                    .collect();
                assert_eq!(assignments, expected.assignments, "[{section}]");
            }
        }
    }
});

/// The invariants of every unit read.
fn check(unit: &UnitFile) {
    // systemd strips its WHITESPACE, " \t\n\r", around both.
    let stripped = |text: &str| text.trim_matches([' ', '\t', '\n', '\r']).len() == text.len();
    for (section, key, value) in &unit.assignments {
        assert!(!section.is_empty(), "{section:?}");
        assert!(!key.is_empty() && !key.contains('='), "{key:?}");
        assert!(stripped(key) && stripped(value), "{key:?}={value:?}");
    }
}
