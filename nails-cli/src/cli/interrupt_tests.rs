// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The cancel envelope a signal prints under `--json`, seen from outside: a
//! child test process starts the watcher, signals itself and is judged by its
//! real stdout and exit code.

use crate::cli::output::envelope::{Envelope, EnvelopePrint};
use crate::cli::output::test_support::{envelope, stdout_lines};

const SUBPROCESS_TEST_NAME: &str = "cli::interrupt::tests::subprocess_interrupt_entrypoint";

/// Run `case` of [`subprocess_interrupt_entrypoint`] in a child process.
fn run_subprocess(case: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture", "--quiet"])
        .env("NAILS_INTERRUPT_SUBPROCESS_CASE", case)
        .output()
        .expect("failed to run the interrupt subprocess test")
}

/// Start the watcher for `status`, print the command's own envelope first when
/// the case says so, then send this process SIGINT, as Ctrl+C does.
#[test]
fn subprocess_interrupt_entrypoint() {
    let Ok(case) = std::env::var("NAILS_INTERRUPT_SUBPROCESS_CASE") else {
        return;
    };
    super::report_signals_as_cancel("status");
    match case.as_str() {
        "signal-first" => {}
        "result-first" => {
            Envelope::success("status", serde_json::json!({"place": "decoy"})).print();
        }
        other => panic!("unknown interrupt subprocess case: {other}"),
    }
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGINT).expect("raise SIGINT");
    // The watcher ends the process at once when it prints; otherwise the
    // command runs on and ends as it would have.
    std::thread::sleep(std::time::Duration::from_millis(500));
    crate::cli::chokepoint::exit_process(0);
}

/// A signal before the result is the one cancel envelope, with no data, and
/// exit 130.
#[test]
fn a_signal_before_the_result_is_the_one_cancel_envelope() {
    let output = run_subprocess("signal-first");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 1, "one envelope: {output:?}");
    let value = envelope("status", &lines[0]);
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "cancelled", "{value}");
    assert_eq!(value["error"]["message"], super::INTERRUPTED, "{value}");
    assert!(value.get("data").is_none(), "{value}");
    assert_eq!(output.status.code(), Some(130), "{output:?}");
}

/// A signal once the command's own envelope is out adds no second one and
/// leaves the exit code to the command.
#[test]
fn a_signal_after_the_result_changes_nothing() {
    let output = run_subprocess("result-first");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 1, "one envelope: {output:?}");
    let value: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}
