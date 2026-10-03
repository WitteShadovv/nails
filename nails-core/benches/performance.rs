// Micro-benchmarks of nails-core code paths: config creation, state
// serialization and persistence, manager construction, status queries, the
// idempotent activation fast path and the emergency orchestration.
//
// Every filesystem operation outside the state file goes through
// MockFilesystem, so these numbers say nothing about real switching time; the
// E2E performance test measures that. They exist to catch relative
// regressions: the scheduled workflow compares each run with the previous
// one's baseline.

use chrono::Utc;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nails_core::filesystem::PathKind;
use nails_core::{
    CleanupConfig, Config, ConfigBuilder, DeactivationMode, DeactivationOrchestrator,
    MockFilesystem, NailsManager, OverlayInfo, StateFile, StatusCommand, SystemState,
};
use std::collections::HashMap;
use std::hint::black_box;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

/// A benchmark subject together with the temporary hidden root it reads from.
///
/// Owning the `TempDir` removes the tree when the fixture is dropped, so a
/// run leaves nothing behind in the system temp directory. Fields drop in
/// declaration order: the subject goes before the directory it points into.
struct Fixture<T> {
    subject: T,
    _hidden_root: TempDir,
}

fn subsequent_activation_fixture() -> Fixture<NailsManager<MockFilesystem>> {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            decoy_writers: Vec::new(),
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

    Fixture {
        subject: NailsManager::new(fs, config, state_path),
        _hidden_root: temp_dir,
    }
}

fn status_command_fixture() -> Fixture<StatusCommand<MockFilesystem>> {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
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
            decoy_writers: Vec::new(),
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

    Fixture {
        subject: StatusCommand::new(fs, config, state_path),
        _hidden_root: temp_dir,
    }
}

#[allow(unsafe_code)]
fn emergency_fixture() -> Fixture<(NailsManager<MockFilesystem>, DeactivationOrchestrator)> {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();

    let safe_home = hidden_root.join("safe-home");
    std::fs::create_dir_all(&safe_home).unwrap();
    // SAFETY: Criterion runs the setup on the bench's only thread, so nothing
    // reads the environment concurrently.
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
    // SAFETY: as for HOME above.
    unsafe {
        std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", profiles_dir.join("system"));
    }
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_directory_contents(&profiles_dir, vec![system_profile.clone()]);
    fs.mock_set_path_exists(switch_script.to_str().unwrap(), true);
    fs.mock_set_path_type(switch_script.to_str().unwrap(), PathKind::File);

    let history_path = safe_home.join(".bash_history");
    fs.mock_set_path_exists(history_path.to_str().unwrap(), true);
    fs.mock_set_path_type(history_path.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(history_path.to_str().unwrap(), "nails emergency\n");

    let mut overlay_status = HashMap::new();
    for target in ["/home", "/etc"] {
        let overlay_path = PathBuf::from(target);
        fs.mock_set_overlay_mounted(&overlay_path, true);
        overlay_status.insert(
            overlay_path.clone(),
            OverlayInfo {
                mount_method: Default::default(),
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
            decoy_writers: Vec::new(),
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

    let manager = NailsManager::new(fs, config, state_path);
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default())
        .with_mode(DeactivationMode::Emergency)
        .with_decoy_profile_restore(false);
    Fixture {
        subject: (manager, orchestrator),
        _hidden_root: temp_dir,
    }
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
                    .hidden_volume_root(PathBuf::from("/mnt/hidden-volume"))
                    .clear_history(true)
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
    let fixture = status_command_fixture();

    c.bench_function("status", |b| {
        b.iter(|| {
            let report = fixture.subject.run().unwrap();
            black_box(report);
        });
    });
}

/// Benchmark subsequent activation via the idempotent fast path.
///
/// The routine hands its fixture back so Criterion drops it, and with it the
/// temporary tree, after the timed section rather than inside it.
fn benchmark_activate_subsequent(c: &mut Criterion) {
    c.bench_function("activate_subsequent", |b| {
        b.iter_batched(
            subsequent_activation_fixture,
            |mut fixture| {
                black_box(fixture.subject.activate(true)).unwrap();
                fixture
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmark emergency cleanup orchestration without host-destructive side effects.
///
/// As above, the fixture is returned so its temporary tree is removed outside
/// the timed section.
fn benchmark_emergency(c: &mut Criterion) {
    c.bench_function("emergency_cleanup", |b| {
        b.iter_batched(
            emergency_fixture,
            |mut fixture| {
                let (manager, orchestrator) = &mut fixture.subject;
                let report = orchestrator.run(manager).unwrap();
                black_box(report);
                fixture
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
            let active = activating.complete_activation(vec![], vec![]).unwrap();
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

/// Short, fixed sampling. The run is compared with the previous one rather
/// than read on its own, so a stable sample count matters more than a tight
/// confidence interval, and the whole suite stays around a minute.
fn criterion_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(20)
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets =
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
        benchmark_exclusion_filter
}
criterion_main!(benches);
