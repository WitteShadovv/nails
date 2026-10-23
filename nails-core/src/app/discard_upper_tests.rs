// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `discard-upper` operation (the CLI's `discard`).

use super::*;
use std::path::PathBuf;

fn discard_rooted_at(root: &Path) -> ReadyDiscard {
    let config = Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..Config::test_default()
    };
    prepare(&RuntimeEnv::default(), config)
}

#[test]
fn apply_deletes_exactly_the_directories_and_files_the_plan_names() {
    let root = tempfile::tempdir().unwrap();
    // A hidden directory copy and a hidden file, both named by the plan.
    let removed_dir = root.path().join("root/upper/home");
    std::fs::create_dir_all(removed_dir.join("alice")).unwrap();
    let removed_file = root.path().join("root/upper/motd");
    std::fs::create_dir_all(removed_file.parent().unwrap()).unwrap();
    std::fs::write(&removed_file, b"decoy banner").unwrap();
    // An unrelated sibling the plan does not name: it must survive.
    let kept = root.path().join("root/upper/etc");
    std::fs::create_dir_all(&kept).unwrap();

    let ready = discard_rooted_at(root.path());
    let plan = ResetUpperPlan {
        target: PathBuf::from("/home"),
        removals: vec![removed_dir.clone(), removed_file.clone()],
        resets_nix_store: false,
    };

    ready.apply(&plan).unwrap();

    // The stub (`Ok(())`) would leave all three in place; the real apply
    // removes precisely the two the plan names and nothing else.
    assert!(!removed_dir.exists(), "the named directory was not removed");
    assert!(!removed_file.exists(), "the named file was not removed");
    assert!(kept.exists(), "an unnamed sibling must be left untouched");
}

#[test]
fn apply_of_an_empty_plan_removes_nothing_and_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let untouched = root.path().join("root/upper/home");
    std::fs::create_dir_all(&untouched).unwrap();

    let ready = discard_rooted_at(root.path());
    let plan = ResetUpperPlan {
        target: PathBuf::from("/home"),
        removals: Vec::new(),
        resets_nix_store: false,
    };

    ready.apply(&plan).unwrap();

    assert!(untouched.exists(), "an empty plan must delete nothing");
}
