// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `reconcile_state` against a real mount table, in a private user + mount
//! namespace (see `crate::test_support`).
//!
//! The orchestration tests arm `reconcile_mounts_override` with a hand-built
//! `NailsMounts`. Here nothing is injected: the overlays are mounted with the
//! production mount code, the state file is written to a hidden root on a
//! scratch tmpfs, and the manager discovers the NAILS mounts from
//! `/proc/self/mountinfo` exactly as it does on a host.

use crate::config::Config;
use crate::filesystem::{Filesystem, RealFilesystem};
use crate::manager::NailsManager;
use crate::state::{DegradedKind, EffectiveState};
use crate::test_support::{Rerun, ScratchTmpfs};
use crate::{StateFile, SystemState};
use chrono::Utc;
use std::path::{Path, PathBuf};

/// Mount a NAILS overlay on `target` (its own lower, as NAILS mounts it) with
/// its upper and work directories under `hidden`.
fn mount_overlay(hidden: &Path, target: &Path, name: &str) {
    std::fs::create_dir_all(target).unwrap();
    let upper = hidden.join(format!("overlays/{name}/upper"));
    let work = hidden.join(format!("overlays/{name}/work"));
    std::fs::create_dir_all(&upper).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    RealFilesystem
        .mount_overlay(&[target], &upper, &work, target)
        .expect("mount the overlay");
}

fn save(state_path: &Path, hidden: &Path, state: SystemState) {
    StateFile {
        state,
        ..StateFile::default()
    }
    .save_with_custom_root(state_path, hidden)
    .expect("save the state file");
}

fn active(overlays: &[&PathBuf]) -> SystemState {
    SystemState::Active {
        activated_at: Utc::now(),
        overlays: overlays.iter().map(|p| (*p).clone()).collect(),
        decoy_writers: Vec::new(),
    }
}

fn sorted(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort();
    paths
}

#[test]
fn reconcile_reads_live_missing_and_shadowed_overlays_from_the_kernel() {
    let _ = Rerun::new(crate::test_path!(
        reconcile_reads_live_missing_and_shadowed_overlays_from_the_kernel
    ))
    .in_user_mount_ns()
    .run(|| {
        let scratch = ScratchTmpfs::new("");
        let root = scratch.path().canonicalize().unwrap();
        let hidden = root.join("hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        let state_path = hidden.join("state.json");
        let home = root.join("home");
        let store = root.join("nix/store");
        let nix = root.join("nix");

        mount_overlay(&hidden, &home, "home");
        // The /nix shape: an overlay on /nix/store, then one on /nix that
        // shadows it. The shadowed one is still mounted and still NAILS's.
        mount_overlay(&hidden, &store, "store");
        mount_overlay(&hidden, &nix, "nix");
        assert!(
            !RealFilesystem.is_overlay_mounted(&store).unwrap(),
            "the /nix overlay hides the store overlay from a path lookup"
        );

        let config = Config {
            hidden_volume_root: hidden.clone(),
            state_file_path: state_path.clone(),
            ..Config::test_default()
        };
        let manager = NailsManager::new(RealFilesystem, config, state_path.clone());
        let reconcile = || manager.reconcile_state().expect("reconcile");

        save(&state_path, &hidden, active(&[&home, &store, &nix]));
        assert_eq!(
            reconcile(),
            EffectiveState::VerifiedActive {
                overlays: vec![home.clone(), store.clone(), nix.clone()]
            },
            "every recorded overlay is in the kernel's table, the shadowed one too"
        );

        RealFilesystem.unmount(&home, false).unwrap();
        match reconcile() {
            EffectiveState::Degraded {
                kind: DegradedKind::ActiveOverlaysMissing,
                reason,
                remaining,
            } => {
                assert!(reason.contains(&home.display().to_string()), "{reason}");
                assert_eq!(sorted(remaining), vec![nix.clone(), store.clone()]);
            }
            other => panic!("a missing overlay degrades the session: {other:?}"),
        }

        save(&state_path, &hidden, SystemState::Inactive);
        match reconcile() {
            EffectiveState::Degraded {
                kind: DegradedKind::InactiveMountsLive,
                remaining,
                ..
            } => assert_eq!(sorted(remaining), vec![nix.clone(), store.clone()]),
            other => panic!("live overlays under an inactive state: {other:?}"),
        }

        RealFilesystem.unmount(&nix, false).unwrap();
        RealFilesystem.unmount(&store, false).unwrap();
        assert_eq!(reconcile(), EffectiveState::Inactive);
    });
}
