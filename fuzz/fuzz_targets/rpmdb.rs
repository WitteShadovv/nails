// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! rpm's database, `rpmdb.sqlite` and its write-ahead log, which the decoy's
//! disk or a hidden session holds, read by NAILS's own SQLite reader and its
//! reader of rpm's headers.
//!
//! The input's first four bytes (little-endian) give the length of the log,
//! which follows them; the rest is the database file. The whole input is also
//! read as one header. The target checks that:
//!
//! - neither reader panics, whatever the bytes;
//! - a database read twice gives the same packages, and read through the
//!   filesystem (in pieces) the same as from memory;
//! - its packages judged against themselves follow, and judged against no
//!   package, with every difference a hidden session's own, follow too;
//! - each directory its packages record, resolved through the links they
//!   record, is a path shorter than `PATH_MAX` with no link on its way: it
//!   resolves to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_base::packages::rpm::{self, Files, Links, parse_database, parse_header};
use nails_core::session::package_drift::{Verdict, judge_rpm, rpm_differing};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);

    let (wal, file) = match data.get(..4) {
        Some(len) => {
            let len = u32::from_le_bytes(len.try_into().unwrap()) as usize;
            let rest = &data[4..];
            let len = len.min(rest.len());
            (Some(&rest[..len]), &rest[len..])
        }
        None => (None, data),
    };
    let Ok(packages) = parse_database(file, wal) else {
        return;
    };
    assert_eq!(parse_database(file, wal).as_ref(), Ok(&packages));

    let fs = MockFilesystem::new();
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let database = "/rpm/rpmdb.sqlite";
    fs.mock_set_file_bytes(database, file);
    fs.mock_set_modified_time(std::path::Path::new(database), time.into());
    let log = wal.filter(|wal| !wal.is_empty()).map(|wal| {
        let path = "/rpm/rpmdb.sqlite-wal";
        fs.mock_set_file_bytes(path, wal);
        fs.mock_set_modified_time(std::path::Path::new(path), time.into());
        PathBuf::from(path)
    });
    let files = Files {
        database: PathBuf::from(database),
        wal: log,
        journal: None,
    };
    assert_eq!(
        rpm::read_packages(&fs, &files, &mut rpm::Budget::default())
            .ok()
            .as_ref(),
        Some(&packages)
    );

    assert_eq!(
        judge_rpm(&packages, &packages, &BTreeSet::new()),
        Verdict::Follows { own: 0 }
    );
    let every: BTreeSet<_> = rpm_differing(&packages, &[]).into_keys().collect();
    assert!(matches!(
        judge_rpm(&packages, &[], &every),
        Verdict::Follows { .. }
    ));

    let Ok(links) = Links::of(&packages, &mut rpm::Budget::default()) else {
        return;
    };
    for dir in packages.iter().flat_map(|package| &package.dirs) {
        if let Ok(path) = links.resolve(dir) {
            assert!(path.len() < rpm::PATH_MAX, "{path}");
            assert_eq!(links.resolve(&path).as_ref(), Ok(&path), "{dir}");
        }
    }
});
