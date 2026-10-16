// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Argument parsing tests for the activate and deactivate commands

use super::args::{ActivateArgs, DeactivateArgs};
use super::*;

fn activate(args: &[&str]) -> ActivateArgs {
    let cli = Cli::try_parse_checked_from(["nails", "activate"].iter().chain(args)).unwrap();
    match cli.command {
        Commands::Activate(args) => args,
        _ => panic!("Expected Activate command"),
    }
}

fn deactivate(args: &[&str]) -> DeactivateArgs {
    let cli = Cli::try_parse_checked_from(["nails", "deactivate"].iter().chain(args)).unwrap();
    match cli.command {
        Commands::Deactivate(args) => args,
        _ => panic!("Expected Deactivate command"),
    }
}

fn refused(command: &str, args: &[&str]) -> bool {
    Cli::try_parse_checked_from(["nails", command].iter().chain(args)).is_err()
}

#[test]
fn activate_defaults_to_prompting_with_preflight() {
    assert_eq!(activate(&[]), ActivateArgs::default());
}

#[test]
fn activate_accepts_its_flags() {
    let args = activate(&[
        "-y",
        "--no-preflight",
        "--overlay-only",
        "--accept-persistent-decoy",
    ]);
    assert!(args.yes && args.no_preflight && args.overlay_only && args.accept_persistent_decoy);
    assert_eq!(
        activate(&["--nixos-flake", "/mnt/data/nixos#my-host"])
            .nixos_flake
            .as_deref(),
        Some("/mnt/data/nixos#my-host")
    );
    assert!(activate(&["--dry-run"]).dry_run);
}

#[test]
fn the_live_overlay_flags_are_gone() {
    for flags in [
        &["--session", "keep"][..],
        &["--pivot", "allow"][..],
        &["--risky-services", "skip"][..],
        &["--terminate-processes"][..],
    ] {
        assert!(refused("activate", flags), "{flags:?}");
    }
    assert!(refused("deactivate", &["--no-clear-history"]));
    assert!(refused("emergency", &["--lock-backend"]));
    assert!(refused("reapply", &[]));
}

#[test]
fn nixos_flake_conflicts_with_overlay_only() {
    assert!(refused(
        "activate",
        &["--overlay-only", "--nixos-flake", "/x#y"]
    ));
}

#[test]
fn deactivate_accepts_yes_and_poweroff() {
    assert_eq!(deactivate(&[]), DeactivateArgs::default());
    let args = deactivate(&["-y", "--poweroff"]);
    assert!(args.yes && args.poweroff);
}
