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

/// The prompt as it is shown before the answer.
fn prompt(plan: &nails_core::ResetUpperPlan) -> String {
    let mut out = Vec::new();
    write_prompt(&OutputSettings::default(), plan, &mut out);
    String::from_utf8(out).unwrap()
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
    assert_eq!(
        prompt(&plan),
        "\u{26a0} This permanently deletes the hidden upper for /srv/data.\n\
         \x20   remove /mnt/data/root/upper/srv/data\n\
         \x20   remove /mnt/data/root/mounts/srv-data\n\
         \x20   Continue? [y/N]: "
    );
}

#[test]
fn discarding_nix_warns_about_the_store_and_database() {
    let shown = prompt(&plan("/nix", &["/mnt/data/root/upper/nix"]));
    assert!(
        shown.contains("WARNING: discarding /nix drops the hidden Nix database"),
        "{shown}"
    );
}

/// An answer other than yes reads as `activate`'s cancel: the neutral notice
/// after the prompt, no error, and exit 130. Ctrl+C at the prompt is one too,
/// its notice on a line of its own. A yes goes on without one.
#[test]
fn a_declined_or_interrupted_discard_is_a_neutral_notice_and_exits_130() {
    let plan = plan("/srv/data", &["/mnt/data/root/upper/srv/data"]);
    let ask = |answer: Answer| {
        let mut err = Vec::new();
        let status = confirm_or_cancel(&OutputSettings::default(), &plan, &mut err, || answer);
        (status, String::from_utf8(err).unwrap())
    };
    let notice = "\u{25cb} Discard cancelled; nothing was removed.\n";
    for (answer, ending) in [
        (Answer::No, format!("Continue? [y/N]: {notice}")),
        (Answer::Cancelled, format!("Continue? [y/N]: \n{notice}")),
    ] {
        let (status, shown) = ask(answer);
        assert_eq!(status, Some(ExitStatus::Cancelled), "{answer:?}");
        assert!(shown.ends_with(&ending), "{answer:?}: {shown}");
        assert!(!shown.contains("error:"), "{shown}");
    }
    let (status, shown) = ask(Answer::Yes);
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
