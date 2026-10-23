// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `activate` operation.

use super::*;
use crate::hidden_root::{Allow, Refusal, RefusalKind};
use crate::manager::EnterOptions;
use crate::nixos::NixOSBuilder;
use crate::platform::FakePlatform;
use crate::{Config, NailsManager, RealFilesystem};
use std::path::PathBuf;

/// A bare manager whose hidden volume and state file live under `dir`. The
/// live probe still reads the real machine, which is never a hidden NAILS
/// overlay during the tests, so the session view is the decoy.
fn manager_at(dir: &Path) -> NailsManager<RealFilesystem> {
    let hidden = dir.to_path_buf();
    let config = Config {
        hidden_volume_root: hidden.clone(),
        state_file_path: hidden.join("state.json"),
        log_path: hidden.join("logs"),
        ..Config::test_default()
    };
    let state_path = config.state_file_path.clone();
    NailsManager::new(RealFilesystem, config, state_path)
}

/// A ready activation over `manager`, with the given override state.
fn ready(
    manager: NailsManager<RealFilesystem>,
    options: EnterOptions,
    accepted: Option<Refusal>,
    warning: Option<String>,
) -> ReadyActivation {
    ReadyActivation {
        manager,
        options,
        accepted,
        warning,
    }
}

#[test]
fn enter_options_carries_every_activate_flag_through() {
    // Each CLI flag must map to its entry option; the stubbed
    // `Default::default()` would drop all four to false.
    let options = ActivateOptions {
        overlay_only: true,
        allow_persistent_decoy: true,
        allow_decoy_storage: true,
        allow_discards: true,
    };
    let entry = options.enter_options();
    assert!(entry.overlay_only, "overlay_only -> overlay_only");
    assert!(
        entry.allow_persistent_decoy,
        "allow_persistent_decoy -> allow_persistent_decoy"
    );
    assert!(
        entry.allow_decoy_storage,
        "allow_decoy_storage -> allow_decoy_storage"
    );
    assert!(entry.allow_discards, "allow_discards -> allow_discards");
}

#[test]
fn enter_options_leaves_every_flag_off_when_none_are_set() {
    // The complementary boundary: with no flags the entry options stay
    // false, so a `Default::default()` stub cannot masquerade as the real
    // mapping by matching only the all-false case.
    let entry = ActivateOptions::default().enter_options();
    assert!(!entry.overlay_only);
    assert!(!entry.allow_persistent_decoy);
    assert!(!entry.allow_decoy_storage);
    assert!(!entry.allow_discards);
}

#[test]
fn allow_reflects_the_decoy_storage_override() {
    // The lock's allowance is the one the entry options ask for. With the
    // override set it must be `DecoyStorage`; the `Default::default()` stub
    // would collapse it to `Nothing` and let the lock refuse a decoy-storage
    // root the operator accepted.
    let dir = tempfile::tempdir().unwrap();
    let options = EnterOptions {
        allow_decoy_storage: true,
        ..Default::default()
    };
    let ready = ready(manager_at(dir.path()), options, None, None);
    assert_eq!(ready.allow(), Allow::DecoyStorage);
}

#[test]
fn allow_is_nothing_without_the_override() {
    let dir = tempfile::tempdir().unwrap();
    let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
    assert_eq!(ready.allow(), Allow::Nothing);
}

#[test]
fn warning_returns_the_stored_sentence_verbatim() {
    // The accessor hands the front end the exact attach-gate warning. The
    // stubs (`None`, `Some("")`, `Some("xyzzy")`) all return something other
    // than the stored sentence, so an exact-match assertion kills them.
    let dir = tempfile::tempdir().unwrap();
    let sentence = "--allow-decoy-storage: using /mnt/hidden although it lives on the decoy's disk"
        .to_string();
    let ready = ready(
        manager_at(dir.path()),
        EnterOptions::default(),
        None,
        Some(sentence.clone()),
    );
    assert_eq!(ready.warning(), Some(sentence.as_str()));
}

#[test]
fn warning_is_none_when_the_gate_raised_none() {
    let dir = tempfile::tempdir().unwrap();
    let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
    assert_eq!(ready.warning(), None);
}

#[test]
fn accepted_returns_the_overridden_refusal() {
    // The confirmation prompt repeats the refusal the operator overrode.
    // The stub returns `None`, which would drop the refusal from the prompt.
    let dir = tempfile::tempdir().unwrap();
    let refusal = Refusal::new(RefusalKind::SameDeviceAsRoot, Path::new("/mnt/hidden"));
    let ready = ready(
        manager_at(dir.path()),
        EnterOptions::default(),
        Some(refusal.clone()),
        None,
    );
    assert_eq!(ready.accepted(), Some(&refusal));
}

#[test]
fn accepted_is_none_when_nothing_was_overridden() {
    let dir = tempfile::tempdir().unwrap();
    let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
    assert!(ready.accepted().is_none());
}

#[test]
fn a_missing_state_file_is_trusted() {
    // No state file legitimately means inactive, not unknown, so the state
    // can be trusted. The `false` stub would refuse here, and dropping the
    // `!` would report the known state as untrusted.
    let dir = tempfile::tempdir().unwrap();
    let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
    assert!(
        ready.is_state_trusted(),
        "a missing state file reads as inactive, which is trusted"
    );
}

#[test]
fn a_corrupt_state_file_is_not_trusted() {
    // An unparseable state file leaves the real state unknown, so activation
    // must refuse. The `true` stub would wrongly trust it, and dropping the
    // `!` would wrongly trust the unknown state.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("state.json"), b"this is not json").unwrap();
    let ready = ready(manager_at(dir.path()), EnterOptions::default(), None, None);
    assert!(
        !ready.is_state_trusted(),
        "a corrupt state file is unknown, which must not be trusted"
    );
}

#[test]
fn builds_hidden_system_when_a_nixos_target_is_configured() {
    // On a NixOS host with a build target and no --overlay-only, the entry
    // builds a hidden system; the `false` stub would hide the build step.
    let dir = tempfile::tempdir().unwrap();
    let mut manager = manager_at(dir.path());
    manager.set_host_profile(FakePlatform::nixos().host_profile());
    manager.set_nixos_builder(NixOSBuilder::new_legacy(PathBuf::from(
        "/etc/nixos/configuration.nix",
    )));
    let ready = ready(manager, EnterOptions::default(), None, None);
    assert!(
        ready.builds_hidden_system(),
        "a configured NixOS target builds a hidden system"
    );
}

#[test]
fn builds_no_hidden_system_under_overlay_only() {
    // --overlay-only runs the decoy's own system under the overlay, so no
    // hidden system is built even with a NixOS target configured; the `true`
    // stub would claim a build that never happens.
    let dir = tempfile::tempdir().unwrap();
    let mut manager = manager_at(dir.path());
    manager.set_host_profile(FakePlatform::nixos().host_profile());
    manager.set_nixos_builder(NixOSBuilder::new_legacy(PathBuf::from(
        "/etc/nixos/configuration.nix",
    )));
    let options = EnterOptions {
        overlay_only: true,
        ..Default::default()
    };
    let ready = ready(manager, options, None, None);
    assert!(
        !ready.builds_hidden_system(),
        "overlay-only builds no hidden system"
    );
}
