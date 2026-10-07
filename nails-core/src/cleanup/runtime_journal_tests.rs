// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The runtime journal scrub (`/run/log/journal`): journal files go, the
//! directories journald rotates into stay.

use super::manager::CleanupManager;
use super::types::{CleanupConfig, CleanupMode, CleanupReport};
use crate::filesystem::{PathKind, RealFilesystem};
use crate::{Filesystem, MockFilesystem};
use std::path::{Path, PathBuf};

fn scrubber<F: Filesystem>(fs: F) -> CleanupManager<F> {
    CleanupManager::new(fs, CleanupConfig::default(), CleanupMode::default())
}

/// A mock store with one machine directory holding `files`.
fn mock_store(machine: &str, files: &[&str]) -> (MockFilesystem, PathBuf, Vec<PathBuf>) {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/run/log/journal", PathKind::Dir);
    let machine_dir = PathBuf::from("/run/log/journal").join(machine);
    fs.mock_set_path_type(machine_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_directory_contents(Path::new("/run/log/journal"), vec![machine_dir.clone()]);
    let files: Vec<PathBuf> = files.iter().map(|name| machine_dir.join(name)).collect();
    for file in &files {
        fs.mock_set_path_type(file.to_str().unwrap(), PathKind::File);
    }
    fs.mock_set_directory_contents(&machine_dir, files.clone());
    (fs, machine_dir, files)
}

#[test]
fn scrub_runtime_journal_removes_journal_files_and_keeps_the_machine_directory() {
    let (fs, machine_dir, files) = mock_store("0a1b2c3d", &["system.journal"]);

    let mut report = CleanupReport::new(CleanupMode::default());
    scrubber(fs.clone()).scrub_runtime_journal(&mut report);

    assert!(
        report
            .cleaned_items
            .iter()
            .any(|item| item.contains("0a1b2c3d/system.journal")),
        "the removed journal file should be recorded: {:?}",
        report.cleaned_items
    );
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    assert!(
        !fs.path_exists(&files[0]).unwrap(),
        "the journal file must be gone"
    );
    assert!(
        fs.path_exists(&machine_dir).unwrap(),
        "the machine directory journald rotates into must be kept"
    );
}

#[test]
fn scrub_runtime_journal_is_a_noop_when_the_store_is_absent() {
    let fs = MockFilesystem::new();
    let mut report = CleanupReport::new(CleanupMode::default());
    scrubber(fs).scrub_runtime_journal(&mut report);

    assert!(report.cleaned_items.is_empty());
    assert!(report.errors.is_empty());
}

#[test]
fn scrub_runtime_journal_records_a_removal_failure() {
    let (fs, _machine_dir, files) = mock_store("deadbeef", &["system.journal"]);
    fs.mock_set_remove_should_fail(files[0].to_str().unwrap(), true);

    let mut report = CleanupReport::new(CleanupMode::default());
    scrubber(fs).scrub_runtime_journal(&mut report);

    assert!(
        report.errors.iter().any(|e| e.contains("deadbeef")),
        "a failed removal must be recorded: {:?}",
        report.errors
    );
}

/// Regression for the Ubuntu 24.04 smoke run: the scrub removed
/// `/run/log/journal/<machine-id>` itself, journald's next rotation failed with
/// "Failed to create new runtime journal: No such file or directory", and the
/// next `systemd-run` timed out. Against a real directory tree the scrub must
/// delete every journal file (active, archived, unclean `~`, per-user and
/// per-namespace) and leave the store root, the machine and namespace
/// directories, unrelated files and symlinks in place.
#[test]
fn scrub_runtime_journal_keeps_the_directory_layout_journald_expects() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().join("run/log/journal");
    let machine = root.join("0123456789abcdef0123456789abcdef");
    let namespace = root.join("0123456789abcdef0123456789abcdef.hidden");
    std::fs::create_dir_all(&machine).unwrap();
    std::fs::create_dir_all(&namespace).unwrap();

    let journal_files = [
        machine.join("system.journal"),
        machine.join("system@0005e3b1c2d4a6f8-1b2c3d4e5f607182.journal"),
        machine.join("user-1000.journal"),
        machine.join("system@0005e3b1c2d4a6f8-1b2c3d4e5f607183.journal~"),
        namespace.join("system.journal"),
    ];
    for file in &journal_files {
        std::fs::write(file, b"LPKSHHRH hidden session record").unwrap();
    }
    let unrelated = machine.join("notes.txt");
    std::fs::write(&unrelated, b"not a journal").unwrap();
    let outside = temp.path().join("elsewhere.journal");
    std::fs::write(&outside, b"must survive").unwrap();
    let link = machine.join("link.journal");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let mut report = CleanupReport::new(CleanupMode::default());
    scrubber(RealFilesystem).scrub_runtime_journal_at(&root, &mut report);

    assert!(report.errors.is_empty(), "{:?}", report.errors);
    for file in &journal_files {
        assert!(!file.exists(), "{} must be removed", file.display());
    }
    assert!(root.is_dir(), "the store root must be kept");
    assert!(machine.is_dir(), "the machine directory must be kept");
    assert!(namespace.is_dir(), "the namespace directory must be kept");
    assert!(unrelated.exists(), "a non-journal file is left alone");
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "a symlink is never followed or removed"
    );
    assert!(
        outside.exists(),
        "a symlink target outside the store survives"
    );
    assert_eq!(report.cleaned_items.len(), journal_files.len());

    // journald can open its next runtime file where it expects it.
    std::fs::write(machine.join("system.journal"), b"").expect("rotation target is creatable");
}
