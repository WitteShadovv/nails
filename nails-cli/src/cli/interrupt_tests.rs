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

/// Start the watcher for `status`, then send this process SIGINT, as Ctrl+C
/// does, before or after the command's own envelope as the case says.
#[test]
fn subprocess_interrupt_entrypoint() {
    let Ok(case) = std::env::var("NAILS_INTERRUPT_SUBPROCESS_CASE") else {
        return;
    };
    use nix::sys::signal::{Signal, raise};
    super::report_signals_as_cancel("status");
    let result = || Envelope::success("status", serde_json::json!({"place": "decoy"})).print();
    let ctrl_c = || raise(Signal::SIGINT).expect("raise SIGINT");
    // The watcher ends the process at once when it prints; otherwise the
    // command runs on and ends as it would have.
    let run_on = || std::thread::sleep(std::time::Duration::from_millis(500));
    match case.as_str() {
        "signal-first" => {
            ctrl_c();
            run_on();
        }
        "result-first" => {
            result();
            ctrl_c();
            run_on();
        }
        // The handler has run when `raise` returns, so the result comes after
        // the signal but before the watcher thread could print, as a command
        // whose child the same Ctrl+C killed reports its failure at once.
        "result-right-after" => {
            ctrl_c();
            result();
        }
        other => panic!("unknown interrupt subprocess case: {other}"),
    }
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

/// A result printed after the signal, even before the watcher thread woke,
/// gives way to the cancel: still exactly one envelope, the cancel, with exit
/// 130, never the result and never no envelope at all.
#[test]
fn a_result_right_after_the_signal_gives_way_to_the_cancel() {
    let output = run_subprocess("result-right-after");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 1, "one envelope: {output:?}");
    let value = envelope("status", &lines[0]);
    assert_eq!(value["error"]["code"], "cancelled", "{value}");
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
