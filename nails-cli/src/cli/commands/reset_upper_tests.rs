// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `reset-upper` prompt and its cancel.

use super::*;
use std::path::PathBuf;

fn plan(target: &str, removals: &[&str]) -> nails_core::ResetUpperPlan {
    nails_core::ResetUpperPlan {
        target: PathBuf::from(target),
        removals: removals.iter().map(PathBuf::from).collect(),
        resets_nix_store: target == "/nix",
    }
}

/// Run the confirmation with `answer` typed, returning the verdict and the
/// text shown.
fn confirm(plan: &nails_core::ResetUpperPlan, answer: &[u8]) -> (bool, String) {
    let mut out = Vec::new();
    let verdict = confirm_reset(
        &OutputSettings::default(),
        plan,
        &mut out,
        &mut std::io::Cursor::new(answer),
    );
    (verdict, String::from_utf8(out).unwrap())
}

#[test]
fn the_prompt_lists_every_removal_before_asking() {
    let plan = plan(
        "/srv/data",
        &[
            "/mnt/data/root/upper/srv/data",
            "/mnt/data/root/mounts/srv-data",
        ],
    );
    let (_, shown) = confirm(&plan, b"n\n");
    assert_eq!(
        shown,
        "\u{26a0} This permanently deletes the hidden upper for /srv/data.\n\
         \x20   remove /mnt/data/root/upper/srv/data\n\
         \x20   remove /mnt/data/root/mounts/srv-data\n\
         \x20   Continue? [y/N]: "
    );
}

#[test]
fn resetting_nix_warns_about_the_store_and_database() {
    let (_, shown) = confirm(&plan("/nix", &["/mnt/data/root/upper/nix"]), b"\n");
    assert!(
        shown.contains("WARNING: resetting /nix drops the hidden Nix database"),
        "{shown}"
    );
}

#[test]
fn only_yes_in_any_case_confirms_the_reset() {
    let plan = plan("/srv/data", &["/mnt/data/root/upper/srv/data"]);
    for answer in ["y\n", "YES\n", "  Yes  \n"] {
        assert!(confirm(&plan, answer.as_bytes()).0, "{answer:?}");
    }
    for answer in ["\n", "n\n", "yep\n", ""] {
        assert!(!confirm(&plan, answer.as_bytes()).0, "{answer:?}");
    }
    // Input that is not UTF-8 is a read error, and declines.
    assert!(!confirm(&plan, b"\xff\n").0);
}
