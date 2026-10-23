// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The shipped `emergency` printers, run for real: the test binary runs again
//! in a child process for one case and prints what `emergency` prints, so the
//! parent reads the child's stdout without redirecting its own descriptors,
//! which the threaded test run shares.

use super::*;
use std::path::PathBuf;
use std::time::Duration;

const SUBPROCESS_TEST_NAME: &str =
    "cli::commands::emergency::print_tests::subprocess_print_entrypoint";

/// What the real printer prints for `case`, run in a child process.
fn printed(case: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture", "--quiet"])
        .env("NAILS_EMERGENCY_PRINT_CASE", case)
        .output()
        .expect("failed to run the emergency printer subprocess")
}

/// A hot-path report for `side` with the mounts still below `/run/nextroot`,
/// built on a simulated run (nothing acts) with no phases or timings, so what
/// it prints is the same in every process.
fn report(side: Side, remaining: &[&str]) -> HotReport {
    let dir = tempfile::tempdir().unwrap();
    let host = emergency::Host {
        run: dir.path().join("run"),
        nextroot: dir.path().join("run/nextroot"),
        runtime_dir: dir.path().join("run/overlay-runtime"),
        cgroup_root: dir.path().join("cgroup"),
        protected_pids: Vec::new(),
        act: false,
    };
    let mut report = emergency::run(None, &host, Finish::Return);
    report.side = side;
    report.remaining = remaining.iter().map(PathBuf::from).collect();
    report.phases.clear();
    report.elapsed = Duration::ZERO;
    report
}

/// A run that found no session: nothing to tear down, exit 0.
fn clean() -> HotReport {
    report(Side::None, &[])
}

/// A decoy-side cleanup that left a mount below `/run/nextroot`: a degraded
/// teardown, exit 7.
fn degraded() -> HotReport {
    report(Side::Decoy, &["/run/nextroot/stuck"])
}

fn quiet() -> OutputSettings {
    OutputSettings {
        verbosity: nails_core::Verbosity::Quiet,
        ascii: true,
        ..OutputSettings::default()
    }
}

#[test]
fn subprocess_print_entrypoint() {
    let Ok(case) = std::env::var("NAILS_EMERGENCY_PRINT_CASE") else {
        return;
    };
    let loud = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    match case.as_str() {
        "json-clean" => print_json(&clean()),
        "json-degraded" => print_json(&degraded()),
        "human-clean" => render_human(&loud, &clean()),
        "quiet-clean" => render_human(&quiet(), &clean()),
        "quiet-degraded" => render_human(&quiet(), &degraded()),
        other => panic!("unknown emergency printer case: {other}"),
    }
    crate::cli::output::flush_stdio();
    crate::cli::chokepoint::exit_process(0);
}

/// The lines the child printed on stdout, without the blank lines and the test
/// harness's own `running 1 test` header.
fn stdout_lines(case: &str) -> Vec<String> {
    let output = printed(case);
    assert!(output.status.success(), "{case}: {output:?}");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("running "))
        .map(str::to_string)
        .collect()
}

/// The one envelope the shipped `--json` printer prints for `case`, checked
/// against the committed `emergency` schema.
fn printed_envelope(case: &str) -> serde_json::Value {
    let lines = stdout_lines(case);
    assert_eq!(lines.len(), 1, "{case}: one envelope line: {lines:?}");
    let value: serde_json::Value = serde_json::from_str(&lines[0])
        .unwrap_or_else(|e| panic!("{case}: not JSON ({e}): {lines:?}"));
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/emergency.schema.json");
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("compile the emergency schema");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{case}: {errors:?}: {value}");
    value
}

/// A clean run is one `ok` envelope that names the command and the side.
#[test]
fn the_json_printer_reports_a_clean_run_as_ok() {
    assert_eq!(app::exit_status(&clean()), ExitStatus::Ok);
    let value = printed_envelope("json-clean");
    assert_eq!(value["command"], "emergency", "{value}");
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(value["data"]["side"], "none", "{value}");
}

/// A degraded teardown (mounts left below `/run/nextroot`) is not `ok`: a
/// reader that keys on `ok` must not take it for a clean way back.
#[test]
fn the_json_printer_reports_a_degraded_run_as_not_ok() {
    assert_eq!(app::exit_status(&degraded()), ExitStatus::DegradedReboot);
    let value = printed_envelope("json-degraded");
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["data"]["side"], "decoy", "{value}");
    assert_eq!(
        value["data"]["remaining_mounts"],
        serde_json::json!(["/run/nextroot/stuck"]),
        "{value}"
    );
}

/// Without `--quiet` the report is printed, a clean one included.
#[test]
fn the_human_printer_prints_a_clean_report() {
    assert_eq!(
        stdout_lines("human-clean"),
        vec!["[PASS] No hidden session: nothing to tear down".to_string()]
    );
}

/// `--quiet` silences a clean run only.
#[test]
fn the_quiet_human_printer_prints_nothing_for_a_clean_run() {
    assert_eq!(stdout_lines("quiet-clean"), Vec::<String>::new());
}

/// `--quiet` never silences a degraded run: the mounts left behind are still
/// named.
#[test]
fn the_quiet_human_printer_still_reports_a_degraded_run() {
    assert_eq!(
        stdout_lines("quiet-degraded"),
        vec![
            "[PASS] Removed what an interrupted activation left in /run".to_string(),
            "  ! still mounted: /run/nextroot/stuck".to_string(),
        ]
    );
}
