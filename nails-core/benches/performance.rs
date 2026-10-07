// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

// Micro-benchmarks of nails-core code paths: config creation, state
// serialization and persistence, manager construction and the status report.
//
// Every filesystem operation outside the state file goes through
// MockFilesystem, so these numbers say nothing about real switching time; the
// E2E performance test measures that. They exist to catch relative
// regressions: the scheduled workflow compares each run with the previous
// one's baseline.

use criterion::{Criterion, criterion_group, criterion_main};
use nails_core::session::SessionView;
use nails_core::{Config, ConfigBuilder, MockFilesystem, NailsManager, StateFile, StatusCommand};
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

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
                    .minimum_space_mb(500)
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

/// Benchmark the status report on the plain decoy against a persisted state.
fn benchmark_status_command(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let state_path = tmp.path().join("state.json");
    StateFile::default()
        .save(&state_path, &tmp.path().to_string_lossy())
        .unwrap();
    let config = Config {
        hidden_volume_root: tmp.path().to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::default()
    };
    let command = StatusCommand::new(MockFilesystem::new(), config, state_path);

    c.bench_function("status", |b| {
        b.iter(|| {
            let report = command
                .report(&SessionView::Decoy, &[], chrono::Utc::now())
                .unwrap();
            black_box(report);
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
        benchmark_status_command
}
criterion_main!(benches);
