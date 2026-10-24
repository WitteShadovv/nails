// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `discard` prompt and its cancel.

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
    let verdict = confirm_discard(
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
fn discarding_nix_warns_about_the_store_and_database() {
    let (_, shown) = confirm(&plan("/nix", &["/mnt/data/root/upper/nix"]), b"\n");
    assert!(
        shown.contains("WARNING: discarding /nix drops the hidden Nix database"),
        "{shown}"
    );
}

#[test]
fn only_yes_in_any_case_confirms_the_discard() {
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

/// An answer other than yes reads as `activate`'s cancel: the neutral notice
/// after the prompt, no error, and exit 130. A yes goes on without one.
#[test]
fn a_declined_discard_is_a_neutral_notice_and_exits_130() {
    let plan = plan("/srv/data", &["/mnt/data/root/upper/srv/data"]);
    let ask = |answer: &[u8]| {
        let mut err = Vec::new();
        let status = confirm_or_cancel(
            &OutputSettings::default(),
            &plan,
            &mut err,
            &mut std::io::Cursor::new(answer),
        );
        (status, String::from_utf8(err).unwrap())
    };
    for answer in ["n\n", "\n", ""] {
        let (status, shown) = ask(answer.as_bytes());
        assert_eq!(status, Some(ExitStatus::Cancelled), "{answer:?}");
        assert!(
            shown.ends_with("Continue? [y/N]: \u{25cb} Discard cancelled; nothing was removed.\n"),
            "{shown}"
        );
        assert!(!shown.contains("error:"), "{shown}");
    }
    let (status, shown) = ask(b"y\n");
    assert_eq!(status, None);
    assert!(!shown.contains("cancelled"), "{shown}");
}

/// The lock's attach gate takes the decoy-storage override only when the
/// operator gave `--allow-decoy-storage`, as `activate` takes it.
#[test]
fn the_decoy_storage_override_reaches_the_attach_gate_only_when_given() {
    let args = |allow_decoy_storage| DiscardArgs {
        target: PathBuf::from("/system-update"),
        yes: true,
        allow_decoy_storage,
    };
    assert_eq!(allow(&args(false)), nails_core::hidden_root::Allow::Nothing);
    assert_eq!(
        allow(&args(true)),
        nails_core::hidden_root::Allow::DecoyStorage
    );
}
