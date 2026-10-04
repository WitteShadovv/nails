// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `current_state`, `update_state`, `verify_overlay_status` and reset-upper.

use super::*;

// ========== current_state() ==========

#[test]
fn test_current_state_lazy_loads_on_first_access() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path);

    // Verify state not loaded yet
    {
        let cached = manager.cached_state.borrow();
        assert!(cached.is_none());
    }

    // First call should load state
    let state = manager.current_state().expect("Should return state");

    // Verify state is now cached
    {
        let cached = manager.cached_state.borrow();
        assert!(cached.is_some());
    }

    // Should be Inactive (default for missing file)
    assert_eq!(state, SystemState::Inactive);
}

#[test]
fn test_current_state_uses_cache_on_subsequent_calls() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // First call loads and caches
    let state1 = manager.current_state().expect("Should return state");

    // Modify file on disk (to verify cache is used, not re-read)
    let different_state = StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
            decoy_writers: Vec::new(),
        },
        ..StateFile::default()
    };
    let json = serde_json::to_string_pretty(&different_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Second call should use cache (not re-read file)
    let state2 = manager.current_state().expect("Should return state");

    // Both should be Inactive (from cache, not re-reading modified file)
    assert_eq!(state1, state2);
    assert_eq!(state2, SystemState::Inactive);
}

#[test]
fn test_current_state_missing_file_returns_inactive() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let nonexistent_path = temp_dir.path().join("nonexistent.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, nonexistent_path);

    // Should return Inactive (safe default)
    let state = manager.current_state().expect("Should return state");
    assert_eq!(state, SystemState::Inactive);
}

#[test]
fn test_current_state_malformed_file_returns_inactive() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let malformed_path = temp_dir.path().join("malformed.json");

    // Write invalid JSON
    std::fs::write(&malformed_path, "{ invalid json syntax").unwrap();

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, malformed_path);

    // Should return Inactive (safe default)
    let state = manager.current_state().expect("Should return state");
    assert_eq!(state, SystemState::Inactive);
}

// ========== update_state() ==========

#[test]
fn test_update_state_valid_transition_succeeds() {
    // Use /tmp for testing (bypass hidden volume check for unit tests)
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file in temp (simulating hidden volume)
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Valid transition: Inactive -> Activating
    let result = manager.update_state(SystemState::Activating {
        started_at: Utc::now(),
    });
    assert!(result.is_ok());

    // Verify state was updated
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Activating { .. }));
}

#[test]
fn test_update_state_invalid_transition_returns_error() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Invalid transition: Inactive -> Active (must go through Activating)
    let result = manager.update_state(SystemState::Active {
        activated_at: Utc::now(),
        overlays: vec![],
        decoy_writers: Vec::new(),
    });
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_update_state_saves_to_disk() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Update state
    manager
        .update_state(SystemState::Activating {
            started_at: Utc::now(),
        })
        .unwrap();

    // Verify file was written (by loading directly)
    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Activating { .. }));
}

#[test]
fn test_update_state_updates_cache() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Update state
    manager
        .update_state(SystemState::Activating {
            started_at: Utc::now(),
        })
        .unwrap();

    // Verify cache was updated
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Activating { .. }));
}

// ========== verify_overlay_status() ==========

#[test]
fn test_verify_overlay_status_active_with_mounted_overlays_ok() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();

    // Set up mounted overlay
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Active state file with mounted overlay
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        },
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should succeed
    let result = manager.verify_overlay_status();
    assert!(result.is_ok());
}

#[test]
fn test_verify_overlay_status_active_with_missing_overlay_error() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    // Overlay is NOT mounted

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Active state file claiming overlay is mounted
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        },
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should fail (state claims mounted but it's not)
    let result = manager.verify_overlay_status();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_verify_overlay_status_inactive_with_mounted_overlay_error() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();

    // Set up overlay as actually mounted
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Inactive state file but with overlay still tracked
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Inactive,
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should fail (state claims Inactive but overlay is mounted)
    let result = manager.verify_overlay_status();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_verify_overlay_status_transitional_state_skipped() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();

    // Set up overlay as NOT mounted (potential mismatch if we were strict)
    fs.mock_set_mounted(Path::new("/home"), false);

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Activating state (transitional) - verification should skip
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Activating {
            started_at: Utc::now(),
        },
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should succeed (transitional states are skipped - line 751)
    let result = manager.verify_overlay_status();
    assert!(
        result.is_ok(),
        "Transitional state verification should succeed (skip check)"
    );
}

// ========== reset-upper ==========

/// Build a manager over a MockFilesystem with a real temp hidden root and the
/// given state. Returns the temp dir (kept alive), the hidden root path, a
/// clone of the mock (shared state, for seeding), and the manager.
fn reset_upper_setup(
    state: SystemState,
) -> (
    tempfile::TempDir,
    PathBuf,
    MockFilesystem,
    NailsManager<MockFilesystem>,
) {
    let dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden_root).expect("create hidden root");
    let state_path = hidden_root.join("state.json");

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let fs = MockFilesystem::new();
    let mut manager = NailsManager::new(fs.clone(), config, state_path);
    manager.force_state(state).expect("force state");
    (dir, hidden_root, fs, manager)
}

#[test]
fn test_reset_upper_refuses_when_active() {
    let (_dir, _hidden_root, _fs, manager) = reset_upper_setup(SystemState::Active {
        activated_at: Utc::now(),
        overlays: vec![PathBuf::from("/home")],
        decoy_writers: Vec::new(),
    });

    let err = manager
        .plan_reset_upper(Path::new("/home"))
        .expect_err("reset-upper must refuse while Active");
    assert!(matches!(err, NailsError::InvalidState(_)), "got {err:?}");
}

#[test]
fn test_reset_upper_refuses_when_target_mounted() {
    let (_dir, _hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    fs.mock_set_mounted(Path::new("/home"), true);

    let err = manager
        .plan_reset_upper(Path::new("/home"))
        .expect_err("reset-upper must refuse a mounted target");
    assert!(matches!(err, NailsError::InvalidState(_)), "got {err:?}");
}

#[test]
fn test_reset_upper_plan_alone_removes_nothing() {
    let (_dir, hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    let upper = hidden_root.join("home");
    let work = hidden_root.join(".work").join("home");
    fs.mock_set_path_exists(upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(work.to_str().unwrap(), true);

    // Planning (the step before a declined prompt) must not delete anything.
    let plan = manager.plan_reset_upper(Path::new("/home")).expect("plan");
    assert!(plan.upper_exists && plan.work_exists);
    assert!(fs.path_exists(&upper).unwrap());
    assert!(fs.path_exists(&work).unwrap());
}

#[test]
fn test_reset_upper_removes_upper_and_work() {
    let (_dir, hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    let upper = hidden_root.join("home");
    let work = hidden_root.join(".work").join("home");
    fs.mock_set_path_exists(upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(work.to_str().unwrap(), true);

    let plan = manager.plan_reset_upper(Path::new("/home")).expect("plan");
    assert_eq!(plan.upper, upper);
    assert_eq!(plan.work, work);
    assert_eq!(plan.removals(), vec![upper.as_path(), work.as_path()]);
    assert!(!plan.resets_nix_store);

    manager.apply_reset_upper(&plan).expect("apply");
    assert!(!fs.path_exists(&upper).unwrap(), "upper should be removed");
    assert!(!fs.path_exists(&work).unwrap(), "work should be removed");
}

#[test]
fn test_reset_upper_skips_absent_directories() {
    let (_dir, hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    let upper = hidden_root.join("srv");

    // Neither upper nor work exists: the plan is empty and apply is a no-op.
    let plan = manager.plan_reset_upper(Path::new("/srv")).expect("plan");
    assert!(plan.is_empty());
    assert!(plan.removals().is_empty());
    manager.apply_reset_upper(&plan).expect("apply");
    assert!(!fs.path_exists(&upper).unwrap());
}

#[test]
fn test_reset_upper_flags_nix_store() {
    let (_dir, _hidden_root, _fs, manager) = reset_upper_setup(SystemState::Inactive);
    let plan = manager.plan_reset_upper(Path::new("/nix")).expect("plan");
    assert!(
        plan.resets_nix_store,
        "resetting /nix must flag the Nix store warning"
    );
}

// ========== reconcile_state() ==========

#[test]
fn test_reconcile_state_resets_stale_active_keeping_build_metadata() {
    use crate::state::{EffectiveState, test_boot_id};

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    // Save an Active state stamped with a previous boot id, carrying cached build
    // metadata that must survive the reset.
    {
        let _boot = test_boot_id::arm(Some("boot-previous"));
        let state = StateFile {
            state: SystemState::Active {
                decoy_writers: Vec::new(),
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            platform: Some(crate::state::PlatformState::nixos(Some(
                "gen-abc".to_string(),
            ))),
            config_fingerprint: Some("fp-123".to_string()),
            ..StateFile::default()
        };
        state
            .save_with_custom_root(&state_path, hidden_root)
            .unwrap();
    }

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let manager = NailsManager::new(MockFilesystem::new(), config, state_path.clone());

    // Reconcile under a different boot id: the state is stale and is reset.
    let effective = {
        let _boot = test_boot_id::arm(Some("boot-current"));
        manager.reconcile_state().expect("reconcile")
    };
    assert_eq!(effective, EffectiveState::StaleFromPreviousBoot);

    // The on-disk state is reset to Inactive but keeps the build metadata.
    let reloaded = StateFile::load(&state_path).expect("reload");
    assert_eq!(reloaded.state, SystemState::Inactive);
    assert!(reloaded.overlay_status.is_empty());
    assert_eq!(reloaded.hidden_toplevel(), Some("gen-abc"));
    assert_eq!(reloaded.config_fingerprint.as_deref(), Some("fp-123"));
}

#[test]
fn test_reconcile_state_reports_degraded_without_resetting() {
    use crate::state::EffectiveState;

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    // Active in the current boot recording an overlay that is not actually
    // mounted -> degraded, which must never be auto-reset.
    let state = StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        ..StateFile::default()
    };
    state
        .save_with_custom_root(&state_path, hidden_root)
        .unwrap();

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let manager = NailsManager::new(MockFilesystem::new(), config, state_path.clone());

    // No mount override: the real (empty of NAILS overlays) table is consulted, so
    // /home is not an owned overlay and the state is degraded.
    let effective = manager.reconcile_state().expect("reconcile");
    assert!(matches!(effective, EffectiveState::Degraded { .. }));

    // The state is left untouched (still Active).
    let reloaded = StateFile::load(&state_path).expect("reload");
    assert!(reloaded.state.is_active());
}

// ========== update_state table vs SystemState methods (exhaustive 5x5) ==========
//
// `update_state` keeps its own hand-written transition table, separate from the
// `SystemState` transition methods in `state/transitions.rs`. The two can drift.
// These tests pin both to one canonical 5x5 policy so a change to either side
// that is not reflected in the other fails here.

/// The five `SystemState` variants, in the order the canonical table indexes
/// them. Timestamps are fixed so the diagonal (same value for `from` and `to`)
/// compares equal and exercises the idempotent branch of `update_state`.
fn sample_states() -> [SystemState; 5] {
    let t = Utc::now();
    [
        SystemState::Inactive,
        SystemState::Activating { started_at: t },
        SystemState::Active {
            activated_at: t,
            overlays: vec![],
            decoy_writers: Vec::new(),
        },
        SystemState::Deactivating { started_at: t },
        SystemState::Degraded {
            since: t,
            reason: "pinned".into(),
            remaining_mounts: vec![],
        },
    ]
}

/// Canonical transition policy, indexed `[from][to]` over
/// `[Inactive, Activating, Active, Deactivating, Degraded]`.
///
/// Every `true` is justified by a `SystemState` transition method (and the
/// agreement tests below assert that justification holds):
/// - `Inactive -> Activating`          `begin_activation`
/// - `Activating -> Active`            `complete_activation`
/// - `Active -> Deactivating`          `begin_deactivation`
/// - `Deactivating -> Inactive`        `complete_deactivation`
/// - `Degraded|Inactive -> Inactive`   `recover`
/// - `{Activating,Active,Deactivating,Degraded} -> Degraded`  `enter_degraded`
/// - the diagonal                      idempotent re-save of the same state
///
/// `Inactive -> Degraded` is intentionally `false`: `enter_degraded` is an
/// infallible constructor the rollback paths call from a live state, never from
/// Inactive (nothing has been torn down), and `update_state` is the authority on
/// what may be persisted. `trigger_emergency` is likewise outside this table: it
/// drives straight to Inactive from any state through `force_state`, not through
/// `update_state`.
const CANONICAL_TRANSITIONS: [[bool; 5]; 5] = [
    //        to: In     Ag     Av     De     Dg
    /* In */
    [true, true, false, false, false],
    /* Ag */ [false, true, true, false, true],
    /* Av */ [false, false, true, true, true],
    /* De */ [true, false, false, true, true],
    /* Dg */ [true, false, false, false, true],
];

/// Build a manager whose persisted state is `from`, ready for an `update_state`
/// attempt. Uses a real temp dir as the hidden-volume root so the state file
/// saves pass the on-volume check.
fn manager_in_state(temp: &std::path::Path, from: &SystemState) -> NailsManager<MockFilesystem> {
    let state_path = temp.join("state.json");
    let config = Config {
        hidden_volume_root: temp.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(MockFilesystem::new(), config, state_path);
    manager
        .force_state(from.clone())
        .expect("force_state seeds the starting state");
    manager
}

#[test]
fn update_state_table_matches_canonical_policy() {
    let states = sample_states();
    for (i, from) in states.iter().enumerate() {
        for (j, to) in states.iter().enumerate() {
            let temp = tempfile::tempdir().expect("temp dir");
            let mut manager = manager_in_state(temp.path(), from);
            let accepted = manager.update_state(to.clone()).is_ok();
            assert_eq!(
                accepted, CANONICAL_TRANSITIONS[i][j],
                "update_state accepted={accepted} for {from:?} -> {to:?}, \
                 canonical policy says {}",
                CANONICAL_TRANSITIONS[i][j]
            );
        }
    }
}

#[test]
fn transition_methods_agree_with_canonical_policy() {
    use SystemState::{Activating, Active, Deactivating, Degraded, Inactive};

    let states = sample_states();
    let idx = |s: &SystemState| match s {
        Inactive => 0,
        Activating { .. } => 1,
        Active { .. } => 2,
        Deactivating { .. } => 3,
        Degraded { .. } => 4,
    };

    for from in &states {
        let i = idx(from);

        // Fallible methods: Ok exactly where the canonical table says so, and the
        // produced variant is the expected target column.
        let begin_act = from.begin_activation();
        assert_eq!(begin_act.is_ok(), CANONICAL_TRANSITIONS[i][1] && i == 0);
        if let Ok(next) = begin_act {
            assert_eq!(idx(&next), 1);
        }

        let complete_act = from.complete_activation(vec![], Vec::new());
        assert_eq!(complete_act.is_ok(), CANONICAL_TRANSITIONS[i][2] && i == 1);
        if let Ok(next) = complete_act {
            assert_eq!(idx(&next), 2);
        }

        let begin_deact = from.begin_deactivation();
        assert_eq!(begin_deact.is_ok(), CANONICAL_TRANSITIONS[i][3] && i == 2);
        if let Ok(next) = begin_deact {
            assert_eq!(idx(&next), 3);
        }

        let complete_deact = from.complete_deactivation();
        assert_eq!(
            complete_deact.is_ok(),
            CANONICAL_TRANSITIONS[i][0] && i == 3
        );
        if let Ok(next) = complete_deact {
            assert_eq!(idx(&next), 0);
        }

        // recover: Ok from Inactive and Degraded, always landing on Inactive, and
        // both are Inactive-column trues in the table.
        let recovered = from.recover();
        let recover_ok = matches!(from, Inactive | Degraded { .. });
        assert_eq!(recovered.is_ok(), recover_ok);
        if let Ok(next) = recovered {
            assert_eq!(idx(&next), 0);
            assert!(CANONICAL_TRANSITIONS[i][0]);
        }

        // enter_degraded: infallible and always yields Degraded; the table marks
        // the Degraded column true for every live state but false for Inactive,
        // the one deliberate divergence from this permissive constructor.
        let degraded = from.enter_degraded("pinned".into(), vec![]);
        assert_eq!(idx(&degraded), 4);
        assert_eq!(CANONICAL_TRANSITIONS[i][4], i != 0);

        // trigger_emergency: infallible, always Inactive, applied through
        // force_state rather than this table.
        let emergency = from.trigger_emergency().expect("emergency always succeeds");
        assert_eq!(idx(&emergency), 0);
    }
}
