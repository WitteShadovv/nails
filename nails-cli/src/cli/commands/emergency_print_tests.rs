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

/// A return from the hidden root whose way back is enqueued (exit 0), but
/// which could not mark a backend device to close: it stays open.
fn left_open() -> HotReport {
    let mut report = report(Side::Hidden, &[]);
    report.dispatched = Some(Finish::Return);
    report.deferred = vec![
        ("hidden-crypt".to_string(), false),
        ("hidden-loop".to_string(), true),
    ];
    report
}

/// A return from the hidden root whose way back is enqueued: exit 0.
fn returned() -> HotReport {
    let mut report = report(Side::Hidden, &[]);
    report.dispatched = Some(Finish::Return);
    report
}

/// Why a way back is bound to power off over the link `tunl0` the kernel
/// keeps once a session loads `ipip`.
fn bound_over_tunl0() -> Option<PowerOffReason> {
    power_off_reason(&nails_teardown::whole_root::network::Foreseen {
        kernel_kept: vec!["tunl0".to_string()],
        ..Default::default()
    })
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
        "json-left-open" => print_json(&left_open()),
        "human-clean" => render_human(&loud, &clean(), None),
        "quiet-clean" => render_human(&quiet(), &clean(), None),
        "quiet-degraded" => render_human(&quiet(), &degraded(), None),
        "quiet-left-open" => render_human(&quiet(), &left_open(), None),
        "human-return" => render_human(&loud, &returned(), None),
        "human-return-bound" => render_human(&loud, &returned(), bound_over_tunl0().as_ref()),
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

/// A device left open does not make the way back fail: it is `ok`, and the
/// data names the device apart from the one that is closing.
#[test]
fn the_json_printer_names_a_device_left_open() {
    assert_eq!(app::exit_status(&left_open()), ExitStatus::Ok);
    let value = printed_envelope("json-left-open");
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(
        value["data"]["backend_left_open"],
        serde_json::json!(["hidden-crypt"]),
        "{value}"
    );
    assert_eq!(
        value["data"]["backend_closing"],
        serde_json::json!(["hidden-loop"]),
        "{value}"
    );
}

/// `--quiet` never silences a run that left a backend device open, though
/// its way back is enqueued and it exits 0: the device is still named.
#[test]
fn the_quiet_human_printer_still_names_a_device_left_open() {
    let lines = stdout_lines("quiet-left-open");
    assert_eq!(
        lines.first().map(String::as_str),
        Some("[PASS] Returning to the decoy: hidden processes killed, soft-reboot under way"),
        "{lines:?}"
    );
    assert!(
        lines.contains(&format!(
            "  ! {}",
            crate::cli::output::deactivate::backend_left_open_warning("hidden-crypt")
        )),
        "{lines:?}"
    );
}

/// A return ends with where the machine ends: at the decoy's login screen, or
/// off when the way back cannot undo what it sets out to; off, and why, where
/// it is bound to power off instead.
#[test]
fn the_human_printer_says_where_a_return_ends() {
    let lines = stdout_lines("human-return");
    assert_eq!(
        lines.last().map(String::as_str),
        Some(
            "  The decoy starts at its own login screen; log in there with the decoy password (a \
             display manager set to log an account in automatically logs it in again, as at \
             boot). The machine powers off instead if a link, MAC address, rule or table the way \
             back sets out to undo is still the session's afterwards."
        ),
        "{lines:?}"
    );
    let lines = stdout_lines("human-return-bound");
    assert_eq!(
        lines.last().map(String::as_str),
        Some(
            "  The way back cannot delete tunl0, which the kernel keeps: the machine powers off \
             instead of returning to the decoy."
        ),
        "{lines:?}"
    );
}
