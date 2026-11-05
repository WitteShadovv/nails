// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Kani's proofs of the activation step order: the run order that
//! [`ACTIVATION_PHASES`] lists, and the numbers [`numbering`] gives the steps an
//! activation shows (`[3/6] Applying the mount policy...`).
//!
//! Only `cargo kani` compiles this file (`just kani`, weekly in CI); the normal
//! build and test leave it out. A proof takes every phase, as `kani::any()`
//! makes any value of the enum and not only the values the table lists, and
//! both kinds of activation, one that builds a hidden NixOS system and one that
//! does not. Nothing is stubbed. The loops run over the nine phases, and Kani
//! checks that ten unwindings are enough for each of them.
//!
//! Not covered: that the entry (`nails_session::session::entry`) reports each
//! phase once, in this order, when it starts it, and what a reporter does with
//! the numbers. The proofs are about the table and the numbering alone.

use super::{ACTIVATION_PHASES, ActivationPhase, numbering};

/// Whether `phase` runs in an activation that builds a hidden system
/// (`building`) or in one that does not.
fn runs(phase: ActivationPhase, building: bool) -> bool {
    building || !phase.builds()
}

/// The place of `phase` in the run order.
fn place(phase: ActivationPhase) -> usize {
    ACTIVATION_PHASES
        .iter()
        .position(|&listed| listed == phase)
        .expect("every phase is in the run order")
}

/// How many of the phases from place `from` up to, not including, place `to`
/// run.
fn running(building: bool, from: usize, to: usize) -> usize {
    ACTIVATION_PHASES[from..to]
        .iter()
        .filter(|&&phase| runs(phase, building))
        .count()
}

/// The run order lists every phase, and each once.
#[kani::proof]
#[kani::unwind(10)]
fn the_run_order_lists_every_phase_once() {
    let phase: ActivationPhase = kani::any();
    let listed = ACTIVATION_PHASES
        .iter()
        .filter(|&&listed| listed == phase)
        .count();
    assert_eq!(listed, 1, "a phase is listed once");
}

/// The run order keeps what the entry puts first for a reason.
#[kani::proof]
#[kani::unwind(10)]
fn the_run_order_keeps_the_entry_s_reasons() {
    use ActivationPhase::{
        ActivateSystem, Arm, BuildSystem, KeepClosure, MaskUnits, MountPolicy, Overlay, Runtime,
        WayBack,
    };
    // The runtime directory, the plan and the transition drop-in come before
    // anything is mounted at the next root: an activation stopped later leaves
    // an unarmed next root, which any soft-reboot disarms.
    assert_eq!(place(Runtime), 0, "the runtime comes first");
    // The policy mounts the decoy's filesystems inside the root overlay.
    assert!(
        place(Overlay) < place(MountPolicy),
        "the overlay before the policy"
    );
    // A separate /nix must be in place before anything reads the next root's
    // store.
    assert!(
        place(MountPolicy) < place(BuildSystem),
        "the policy before the build"
    );
    // The closure is kept on the hidden volume before anything runs from it.
    assert!(place(BuildSystem) < place(KeepClosure), "built, then kept");
    assert!(
        place(KeepClosure) < place(ActivateSystem),
        "kept, then activated"
    );
    // The masks are decided on the units of the hidden generation, and the way
    // back checks its init: both come with the build.
    assert!(
        place(ActivateSystem) < place(MaskUnits),
        "the build before the masks"
    );
    assert!(
        place(ActivateSystem) < place(WayBack),
        "the build before the way back"
    );
    // The switch is armed last, once everything it switches into is in place.
    assert_eq!(
        place(Arm),
        ACTIVATION_PHASES.len() - 1,
        "the switch is armed last"
    );
}

/// The steps an activation shows are numbered from 1 to the number of phases
/// it runs, in run order, each phase that runs once and none skipped; a build
/// phase of an activation that builds nothing is no step and gets 0.
#[kani::proof]
#[kani::unwind(10)]
fn the_steps_are_numbered_one_to_total_in_run_order() {
    let building: bool = kani::any();
    let first: ActivationPhase = kani::any();
    let second: ActivationPhase = kani::any();
    let (first_index, total) = numbering(first, building);
    let (second_index, second_total) = numbering(second, building);

    // One total per activation: the number of phases it runs.
    assert_eq!(total, second_total, "one total per activation");
    assert_eq!(
        total as usize,
        running(building, 0, ACTIVATION_PHASES.len()),
        "the total counts the phases that run"
    );
    assert_eq!(numbering(ActivationPhase::Runtime, building), (1, total));
    assert_eq!(numbering(ActivationPhase::Arm, building), (total, total));

    if !runs(first, building) {
        assert_eq!(first_index, 0, "a phase that does not run is no step");
        return;
    }
    assert!(
        (1..=total).contains(&first_index),
        "a step's number lies between 1 and the total"
    );
    kani::cover!(
        runs(second, building) && place(first) < place(second),
        "two steps in run order"
    );
    if runs(second, building) && place(first) < place(second) {
        // Later in the run order, a larger number, larger by exactly the
        // number of phases that run from the first up to the second.
        assert!(first_index < second_index, "numbered in run order");
        assert_eq!(
            (second_index - first_index) as usize,
            running(building, place(first), place(second)),
            "no number skipped or repeated"
        );
    }
}
