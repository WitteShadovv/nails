// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `package-drift` row over the decoy's package databases and what hidden
//! sessions' upper holds of them, which a hidden session writes as it likes.
//!
//! The input is five parts apart by NUL bytes: the decoy's dpkg `status`,
//! hidden sessions' copy of it, the names in the upper's copy of dpkg's
//! `info` directory (one a line), the decoy's pacman entries and the upper's
//! (one a line; a line that starts with `!` is a deletion, a whiteout). The
//! target checks that:
//!
//! - a record judged against itself follows, whatever hidden sessions
//!   changed, and judged both ways it names the same packages with the two
//!   sides swapped;
//! - a hidden session that changed every package keeps none drifted: each
//!   difference is its own;
//! - a pacman package listed twice has a version on both sides, one listed
//!   without its files none in hidden sessions, and each is one a hidden
//!   session changed;
//! - the row through the filesystem is a pass or a warning, never a refusal,
//!   and its warning is the advisory an entry shows.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::MockFilesystem;
use nails_base::packages::dpkg::{self, parse_status};
use nails_base::packages::pacman::{self, parse_entry};
use nails_core::preflight::{CheckResult, PreFlightCheck};
use nails_core::session::Layout;
use nails_core::session::package_drift::{
    Change, Drift, PackageDriftCheck, Verdict, advisory, judge_dpkg, judge_pacman,
};
use nails_fuzz::parts;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ROOT: &str = "/decoy";
const HIDDEN: &str = "/hidden";

fuzz_target!(|data: &[u8]| {
    let parts = parts(data, 5);
    let part = |i: usize| parts.get(i).map_or("", String::as_str);
    let (decoy, hidden) = (parse_status(part(0)), parse_status(part(1)));
    let owners: BTreeSet<(String, Option<String>)> = part(2)
        .split('\n')
        .filter_map(dpkg::info_owner)
        .map(|(name, arch)| (name.to_string(), arch.map(str::to_string)))
        .collect();

    assert_eq!(
        judge_dpkg(&decoy, &decoy, &owners),
        Verdict::Follows { own: Some(0) }
    );
    let forth = stale(&judge_dpkg(&decoy, &hidden, &owners));
    let back = stale(&judge_dpkg(&hidden, &decoy, &owners));
    let swapped: Vec<Change> = back
        .iter()
        .map(|change| Change {
            name: change.name.clone(),
            decoy: change.hidden.clone(),
            hidden: change.decoy.clone(),
        })
        .collect();
    assert_eq!(forth, swapped);

    let differing = stale(&judge_dpkg(&decoy, &hidden, &BTreeSet::new())).len();
    let everyone: BTreeSet<(String, Option<String>)> = decoy
        .iter()
        .chain(&hidden)
        .map(|package| (package.name.clone(), None))
        .collect();
    assert_eq!(
        judge_dpkg(&decoy, &hidden, &everyone),
        Verdict::Follows {
            own: Some(differing)
        }
    );

    let decoy_local: Vec<pacman::Package> = part(3).split('\n').filter_map(parse_entry).collect();
    let (mut kept, mut removed) = (Vec::new(), Vec::new());
    for line in part(4).split('\n') {
        match line.strip_prefix('!') {
            Some(entry) => removed.extend(parse_entry(entry)),
            None => kept.extend(parse_entry(line)),
        }
    }
    assert_eq!(judge_pacman(&decoy_local, &[], &[]), Verdict::Shared);
    if let Verdict::Drifted(Drift::Merged {
        twice,
        removed: gone,
    }) = judge_pacman(&decoy_local, &kept, &removed)
    {
        let changed: BTreeSet<&str> = kept
            .iter()
            .chain(&removed)
            .map(|package| package.name.as_str())
            .collect();
        for change in &twice {
            assert!(
                change.decoy.is_some() && change.hidden.is_some(),
                "{change:?}"
            );
            assert!(changed.contains(change.name.as_str()), "{change:?}");
        }
        for change in &gone {
            assert!(
                change.decoy.is_some() && change.hidden.is_none(),
                "{change:?}"
            );
            assert!(changed.contains(change.name.as_str()), "{change:?}");
        }
    }

    let fs = filesystem(&parts, &kept, &removed);
    let check = PackageDriftCheck::new(PathBuf::from(ROOT), PathBuf::from(HIDDEN));
    let result = PreFlightCheck::<MockFilesystem>::run(&check.as_privileged(true), &fs)
        .expect("the row never errors");
    let shown = advisory(
        &fs,
        Path::new(ROOT),
        &Layout::new(Path::new(HIDDEN)),
        Some(&[]),
        false,
    );
    match result {
        CheckResult::Pass(_) => assert_eq!(shown, None),
        CheckResult::Warn(text) => {
            assert_eq!(shown.map(|advisory| advisory.text()), Some(text));
        }
        other => panic!("the row refused: {other:?}"),
    }
});

/// The packages a dpkg verdict names as drifted, none for any other verdict.
fn stale(verdict: &Verdict) -> Vec<Change> {
    match verdict {
        Verdict::Drifted(Drift::Stale(changes)) => changes.clone(),
        Verdict::Follows { .. } => Vec::new(),
        other => panic!("dpkg's judge gave {other:?}"),
    }
}

/// A decoy with the input's databases, and hidden sessions with its copies
/// in the root upper.
fn filesystem(
    parts: &[String],
    kept: &[pacman::Package],
    removed: &[pacman::Package],
) -> MockFilesystem {
    let part = |i: usize| parts.get(i).map_or("", String::as_str);
    let fs = MockFilesystem::new();
    let upper = Path::new(HIDDEN).join("root/upper");
    fs.mock_add_file(&format!("{ROOT}/var/lib/dpkg/status"), part(0));
    if parts.len() > 1 {
        fs.mock_add_file(
            &upper.join("var/lib/dpkg/status").display().to_string(),
            part(1),
        );
    }
    let info = upper.join("var/lib/dpkg/info");
    fs.mock_set_directory_contents(
        &info,
        part(2)
            .split('\n')
            .filter(|name| is_file_name(name))
            .map(|name| info.join(name))
            .collect(),
    );
    let local = Path::new(ROOT).join("var/lib/pacman/local");
    fs.mock_set_path_type(&local.display().to_string(), nails_base::PathKind::Dir);
    fs.mock_set_directory_contents(
        &local,
        part(3)
            .split('\n')
            .filter(|name| is_file_name(name))
            .map(|name| local.join(name))
            .collect(),
    );
    let upper_local = upper.join("var/lib/pacman/local");
    if !kept.is_empty() || !removed.is_empty() {
        fs.mock_set_path_type(
            &upper_local.display().to_string(),
            nails_base::PathKind::Dir,
        );
    }
    let mut entries = Vec::new();
    for package in kept {
        entries.push(upper_local.join(package.entry()));
    }
    for package in removed {
        let path = upper_local.join(package.entry());
        fs.mock_set_whiteout(&path.display().to_string());
        entries.push(path);
    }
    fs.mock_set_directory_contents(&upper_local, entries);
    fs
}

/// Whether `line` can be the name of an entry in a directory.
fn is_file_name(line: &str) -> bool {
    !line.is_empty() && line != "." && line != ".." && !line.contains(['/', '\0'])
}
