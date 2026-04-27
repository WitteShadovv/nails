// Performance benchmarks for NAILS
//
// Validates RQ2: 2-5 second switching performance
// Exercises real code paths: config creation, state serialization,
// state persistence, manager construction, and status queries.

use chrono::Utc;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nails_core::{
    CleanupConfig, Config, ConfigBuilder, DeactivationMode, DeactivationOrchestrator,
    MockFilesystem, NailsManager, OverlayInfo, StateFile, StatusCommand, SystemState,
};
use std::collections::HashMap;
use std::hint::black_box;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn create_subsequent_activation_manager() -> Arc<Mutex<NailsManager<MockFilesystem>>> {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.keep();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        },
        ..StateFile::default()
    };
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)))
}

fn create_status_command() -> StatusCommand<MockFilesystem> {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.keep();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: hidden_root.join("home-upper"),
            work_dir: hidden_root.join("home-work"),
            mounted_at: Utc::now(),
        },
    );
    fs.mock_set_mounted(Path::new("/home"), true);

    let state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status,
        ..StateFile::default()
    };
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    StatusCommand::new(fs, config, state_path)
}

fn create_emergency_orchestrator() -> DeactivationOrchestrator<MockFilesystem> {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.keep();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();

    let safe_home = hidden_root.join("safe-home");
    std::fs::create_dir_all(&safe_home).unwrap();
    unsafe {
        std::env::set_var("HOME", &safe_home);
    }

    let profiles_dir = hidden_root.join("profiles");
    let system_profile = profiles_dir.join("system-1-link");
    let switch_script = system_profile.join("bin/switch-to-configuration");
    std::fs::create_dir_all(switch_script.parent().unwrap()).unwrap();
    std::fs::write(&switch_script, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&switch_script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&switch_script, perms).unwrap();
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", profiles_dir.join("system"));
    }
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(profiles_dir.to_str().unwrap(), "directory");
    fs.mock_set_directory_contents(&profiles_dir, vec![system_profile.clone()]);
    fs.mock_set_path_exists(switch_script.to_str().unwrap(), true);
    fs.mock_set_path_type(switch_script.to_str().unwrap(), "file");

    let history_path = safe_home.join(".bash_history");
    fs.mock_set_path_exists(history_path.to_str().unwrap(), true);
    fs.mock_set_path_type(history_path.to_str().unwrap(), "file");
    fs.mock_set_file_content(history_path.to_str().unwrap(), "nails emergency\n");

    let mut overlay_status = HashMap::new();
    for target in ["/home", "/etc"] {
        let overlay_path = PathBuf::from(target);
        fs.mock_set_overlay_mounted(&overlay_path, true);
        overlay_status.insert(
            overlay_path.clone(),
            OverlayInfo {
                mount_path: overlay_path.clone(),
                lower_dir: PathBuf::from("/"),
                upper_dir: hidden_root
                    .join(target.trim_start_matches('/'))
                    .join("upper"),
                work_dir: hidden_root
                    .join(target.trim_start_matches('/'))
                    .join("work"),
                mounted_at: Utc::now(),
            },
        );
    }

    StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    DeactivationOrchestrator::new(manager, CleanupConfig::default())
        .with_mode(DeactivationMode::Emergency)
        .with_decoy_profile_restore(false)
}

/// Benchmark Config::default() creation
fn benchmark_config_default(c: &mut Criterion) {
    c.bench_function("config_default", |b| {
        b.iter(|| black_box(Config::default()));
    });
}

/// Benchmark ConfigBuilder fluent API
fn benchmark_config_builder(c: &mut Criterion) {
    c.bench_function("config_builder", |b| {
        b.iter(|| {
            black_box(
                ConfigBuilder::new()
                    .hidden_volume_path(PathBuf::from("/mnt/hidden-volume"))
                    .clear_history(true)
                    .default_verbosity("info")
                    .build()
                    .unwrap(),
            )
        });
    });
}

/// Benchmark StateFile default creation
fn benchmark_state_default(c: &mut Criterion) {
    c.bench_function("state_file_default", |b| {
        b.iter(|| black_box(StateFile::default()));
    });
}

/// Benchmark StateFile JSON serialization (round-trip)
fn benchmark_state_serialization(c: &mut Criterion) {
    let state = StateFile::default();

    c.bench_function("state_serialize_json", |b| {
        b.iter(|| {
            let json = serde_json::to_string(black_box(&state)).unwrap();
            black_box(json);
        });
    });

    let json = serde_json::to_string_pretty(&state).unwrap();
    c.bench_function("state_deserialize_json", |b| {
        b.iter(|| {
            let parsed: StateFile = serde_json::from_str(black_box(&json)).unwrap();
            black_box(parsed);
        });
    });
}

/// Benchmark StateFile save + load round-trip to temp directory
fn benchmark_state_save_load(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let state_path = tmp.path().join("state.json");
    let root = tmp.path().to_string_lossy().to_string();

    c.bench_function("state_save_load_roundtrip", |b| {
        b.iter(|| {
            let state = StateFile::default();
            state.save(&state_path, &root).unwrap();
            let loaded = StateFile::load(&state_path).unwrap();
            black_box(loaded);
        });
    });
}

/// Benchmark NailsManager construction with MockFilesystem
fn benchmark_manager_construction(c: &mut Criterion) {
    c.bench_function("manager_new_mock", |b| {
        b.iter(|| {
            let fs = MockFilesystem::new();
            let config = Config::default();
            let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
            let manager = NailsManager::new(fs, config, state_path);
            black_box(manager);
        });
    });
}

/// Benchmark status query (current_state) on a freshly created manager
fn benchmark_status_query(c: &mut Criterion) {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let tmp = tempfile::tempdir().unwrap();
    let state_path = tmp.path().join("state.json");
    let manager = NailsManager::new(fs, config, state_path);

    c.bench_function("status_query_current_state", |b| {
        b.iter(|| {
            let state = manager.current_state().unwrap();
            black_box(state);
        });
    });
}

/// Benchmark direct status command execution against persisted active state.
fn benchmark_status_command(c: &mut Criterion) {
    let command = create_status_command();

    c.bench_function("status", |b| {
        b.iter(|| {
            let report = command.run().unwrap();
            black_box(report);
        });
    });
}

/// Benchmark subsequent activation via the idempotent fast path.
fn benchmark_activate_subsequent(c: &mut Criterion) {
    c.bench_function("activate_subsequent", |b| {
        b.iter_batched(
            create_subsequent_activation_manager,
            |manager| NailsManager::activate(black_box(manager), true).unwrap(),
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark emergency cleanup orchestration without host-destructive side effects.
fn benchmark_emergency(c: &mut Criterion) {
    c.bench_function("emergency_cleanup", |b| {
        b.iter_batched(
            create_emergency_orchestrator,
            |orchestrator| {
                let report = orchestrator.run().unwrap();
                black_box(report);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark SystemState transitions
fn benchmark_state_transitions(c: &mut Criterion) {
    c.bench_function("state_transition_inactive_to_activating", |b| {
        b.iter(|| {
            let state = SystemState::Inactive;
            let activating = state.begin_activation().unwrap();
            black_box(activating);
        });
    });

    c.bench_function("state_transition_full_cycle", |b| {
        b.iter(|| {
            let state = SystemState::Inactive;
            let activating = state.begin_activation().unwrap();
            let active = activating.complete_activation(vec![]).unwrap();
            let deactivating = active.begin_deactivation().unwrap();
            let inactive = deactivating.complete_deactivation().unwrap();
            black_box(inactive);
        });
    });
}

/// Benchmark overlay target computation with MockFilesystem
fn benchmark_overlay_targets(c: &mut Criterion) {
    let fs = MockFilesystem::new();
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
        PathBuf::from("/run"),
        PathBuf::from("/opt"),
        PathBuf::from("/srv"),
    ]);
    let config = Config::default();

    c.bench_function("build_overlay_targets", |b| {
        b.iter(|| {
            let targets = nails_core::build_overlay_targets(&fs, &config).unwrap();
            black_box(targets);
        });
    });
}

/// Benchmark exclusion filter
fn benchmark_exclusion_filter(c: &mut Criterion) {
    let dirs: Vec<PathBuf> = (0..50)
        .map(|i| PathBuf::from(format!("/dir-{}", i)))
        .collect();
    let exclusions: Vec<PathBuf> = (0..10)
        .map(|i| PathBuf::from(format!("/dir-{}", i * 5)))
        .collect();

    c.bench_function("apply_exclusion_filter_50dirs", |b| {
        b.iter(|| {
            let filtered =
                nails_core::apply_exclusion_filter(black_box(dirs.clone()), black_box(&exclusions));
            black_box(filtered);
        });
    });
}

criterion_group!(
    benches,
    benchmark_config_default,
    benchmark_config_builder,
    benchmark_state_default,
    benchmark_state_serialization,
    benchmark_state_save_load,
    benchmark_manager_construction,
    benchmark_status_query,
    benchmark_status_command,
    benchmark_activate_subsequent,
    benchmark_emergency,
    benchmark_state_transitions,
    benchmark_overlay_targets,
    benchmark_exclusion_filter,
);
criterion_main!(benches);
