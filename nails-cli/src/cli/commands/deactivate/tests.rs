// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `deactivate` ends the hidden session in a power-off. No test here powers
//! anything off: the lock step's handle and its power-off are stand-ins that
//! print [`ENQUEUED`] where the power-off would be enqueued.

use crate::cli::args::DeactivateArgs;
use crate::cli::output::test_support::{envelope, stdout_lines};
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};
use nails_core::NailsError;
use nails_core::app::deactivate::{Prepared, ReadyDeactivation};
use std::path::Path;

fn json() -> OutputSettings {
    OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    }
}

const SUBPROCESS_TEST_NAME: &str =
    "cli::commands::deactivate::tests::subprocess_deactivate_entrypoint";

/// What the stand-in for the power-off prints on stdout when it runs: the
/// moment the power-off would be enqueued.
const ENQUEUED: &str = "<the power-off is enqueued here>";

/// Run `case` of [`subprocess_deactivate_entrypoint`] in a child process, so
/// the test sees its real stdout and exit code.
fn run_subprocess(case: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture", "--quiet"])
        .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", case)
        .output()
        .expect("failed to run deactivate subprocess test")
}

/// The error the power-off returns when systemd refuses it.
fn refused() -> NailsError {
    NailsError::InvalidState("systemctl could not enqueue poweroff.target".to_string())
}

/// The check of the handle that leaves while a program blocks shutdown.
fn blocked_check(_: &()) -> Result<(), NailsError> {
    Err(NailsError::InvalidState(
        "apt blocks shutdown (Installing, PID 4242): the switch would cut it short. Let it \
         finish, then try again"
            .to_string(),
    ))
}

/// A check of the handle that leaves, as a stand-in for its own.
type Check = fn(&()) -> Result<(), NailsError>;

/// The check of the handle that leaves where nothing holds the power-off.
fn no_refusal(_: &()) -> Result<(), NailsError> {
    Ok(())
}

/// Report a deactivation through a stand-in for the power-off that prints
/// [`ENQUEUED`] and then succeeds or fails, as the case says, and exit with
/// the status.
#[test]
fn subprocess_deactivate_entrypoint() {
    let Ok(case) = std::env::var("NAILS_DEACTIVATE_SUBPROCESS_CASE") else {
        return;
    };
    let ascii = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let yes = DeactivateArgs {
        yes: true,
        poweroff: false,
    };
    if let Some((settings, args)) = match case.as_str() {
        "human-ready" => Some((ascii, yes)),
        "json-ready" => Some((json(), yes)),
        "json-ready-poweroff" => Some((
            json(),
            DeactivateArgs {
                yes: true,
                poweroff: true,
            },
        )),
        "json-ready-unconfirmed" => Some((json(), DeactivateArgs::default())),
        _ => None,
    } {
        let root = tempfile::tempdir().unwrap();
        // A stand-in for the lock step and the power-off: what the operator
        // reads up to it.
        let status = super::deactivate_prepared_with(
            &settings,
            &args,
            Prepared::Ready(Box::new(ready_at(root.path()))),
            |_ready| {
                super::leave_and_report(&settings, &mut (), no_refusal, |_| {
                    crate::cli::output::println_tolerating_broken_pipe(ENQUEUED);
                    Ok(())
                })
            },
        );
        // The exit runs no destructor: remove the scratch tree first.
        drop(root);
        crate::cli::chokepoint::exit_process(status.code());
    }
    let (settings, check, outcome): (_, Check, _) = match case.as_str() {
        "json-enqueued" => (json(), no_refusal, Ok(())),
        "json-refused" => (json(), no_refusal, Err(refused())),
        "human-enqueued" => (ascii, no_refusal, Ok(())),
        "human-refused" => (ascii, no_refusal, Err(refused())),
        "human-blocked" => (ascii, blocked_check, Ok(())),
        "json-blocked" => (json(), blocked_check, Ok(())),
        other => panic!("unknown deactivate subprocess case: {other}"),
    };
    let status = super::leave_and_report(&settings, &mut (), check, |_| {
        crate::cli::output::println_tolerating_broken_pipe(ENQUEUED);
        outcome
    });
    crate::cli::chokepoint::exit_process(status.code());
}

/// A deactivation ready to end a hidden session, with its hidden volume and
/// its state file below `root`.
fn ready_at(root: &Path) -> ReadyDeactivation {
    let config = nails_core::Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..nails_core::Config::test_default()
    };
    ReadyDeactivation::for_test(config)
}

/// The lines a person reads of the session's end, up to the power-off.
fn ending_lines() -> Vec<String> {
    vec![
        format!("[PASS] {}", super::ENDING_LINES[0]),
        super::ENDING_LINES[1].to_string(),
    ]
}

/// A person reads that the machine powers off, and nothing of a return,
/// before the power-off, which stops the terminal; under `--json` the one
/// envelope says the power-off, with or without `--poweroff`.
#[test]
fn a_person_reads_that_the_machine_powers_off() {
    let output = run_subprocess("human-ready");
    let mut expected = ending_lines();
    expected.push(ENQUEUED.to_string());
    assert_eq!(stdout_lines(&output), expected, "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(!text.contains("return"), "{text}");
    assert!(!text.contains("login screen"), "{text}");
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    for case in ["json-ready", "json-ready-poweroff"] {
        let output = run_subprocess(case);
        let lines = stdout_lines(&output);
        assert_eq!(lines.len(), 2, "{case}: {output:?}");
        assert_eq!(lines[0], ENQUEUED, "{case}: {output:?}");
        let value = envelope("deactivate", &lines[1]);
        assert_eq!(value["ok"], true, "{value}");
        assert_eq!(
            value["data"],
            serde_json::json!({"status": "poweroff_requested"}),
            "{case}: {value}"
        );
        assert_eq!(output.status.code(), Some(0), "{case}: {output:?}");
    }
}

/// Without `-y` off a terminal a ready deactivation is refused before it
/// asks or leaves: the one envelope is `needs_confirmation`, exit 2.
#[test]
fn an_unconfirmed_deactivation_off_a_terminal_is_refused_before_anything() {
    let output = run_subprocess("json-ready-unconfirmed");
    assert!(output.stderr.is_empty(), "{output:?}");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 1, "one envelope: {output:?}");
    let value = envelope("deactivate", &lines[0]);
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "needs_confirmation", "{value}");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// Past the question the real lock step runs, and its attach gate refuses a
/// hidden root that is no mount point, as `activate` refuses it: exit 4,
/// with nothing written there and nothing left.
#[test]
fn the_lock_step_refuses_a_hidden_root_that_is_no_mount_point() {
    let root = tempfile::tempdir().unwrap();
    let status = super::lock_and_leave(&json(), ready_at(root.path()));
    assert_eq!(status, ExitStatus::PreflightRefused);
    let left: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

/// Under `--json` a power-off that cannot be enqueued is the only envelope on
/// stdout: printed after the attempt, `ok` false with the error, exit 1. No
/// success envelope comes first for a reader of the first line to trust.
#[test]
fn a_power_off_that_fails_is_the_only_envelope() {
    let output = run_subprocess("json-refused");
    let lines = stdout_lines(&output);
    assert_eq!(
        lines.len(),
        2,
        "the stand-in's line, one envelope: {output:?}"
    );
    assert_eq!(lines[0], ENQUEUED, "{output:?}");
    let value = envelope("deactivate", &lines[1]);
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "invalid_state", "{value}");
    assert_eq!(value["error"]["next"]["command"], "emergency", "{value}");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

/// An enqueued power-off is one success envelope, printed once it is
/// enqueued.
#[test]
fn an_enqueued_power_off_is_one_envelope_printed_after_it() {
    let output = run_subprocess("json-enqueued");
    let lines = stdout_lines(&output);
    assert_eq!(
        lines.len(),
        2,
        "the stand-in's line, one envelope: {output:?}"
    );
    assert_eq!(lines[0], ENQUEUED, "{output:?}");
    let value = envelope("deactivate", &lines[1]);
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(value["data"]["status"], "poweroff_requested", "{value}");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

/// A program that blocks shutdown refuses the power-off before anything is
/// printed: a person reads the refusal alone, on stderr, and under `--json`
/// it is the one envelope.
#[test]
fn a_blocked_power_off_is_refused_before_its_banner() {
    let output = run_subprocess("human-blocked");
    assert!(stdout_lines(&output).is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("apt blocks shutdown (Installing, PID 4242)"),
        "{stderr}"
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let output = run_subprocess("json-blocked");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 1, "one envelope: {output:?}");
    let value = envelope("deactivate", &lines[0]);
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "invalid_state", "{value}");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

/// Only a refused check exits 4: a program that blocks shutdown, and every
/// power-off that fails, exit 1.
#[test]
fn only_a_refused_check_exits_as_a_refusal() {
    let check =
        NailsError::PreFlightCheckFailed(vec![("some-check".to_string(), "off".to_string(), None)]);
    assert_eq!(super::error_status(&check), ExitStatus::PreflightRefused);
    for error in [blocked_check(&()).unwrap_err(), refused()] {
        assert_eq!(super::error_status(&error), ExitStatus::Failed, "{error}");
    }
}

/// A person reads the result before the power-off, which stops the terminal,
/// however it goes; a failure to enqueue it follows on stderr.
#[test]
fn a_person_reads_the_result_before_the_power_off() {
    for (case, code) in [("human-enqueued", 0), ("human-refused", 1)] {
        let output = run_subprocess(case);
        let mut expected = ending_lines();
        expected.push(ENQUEUED.to_string());
        assert_eq!(stdout_lines(&output), expected, "{case}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.contains("error: systemctl could not enqueue poweroff.target"),
            code == 1,
            "{case}: {stderr}"
        );
        assert_eq!(output.status.code(), Some(code), "{case}: {output:?}");
    }
}

/// Outside a hidden session deactivate refuses before it asks, locks or
/// leaves, with `-y --poweroff` as without. The probe's verdict is given here
/// rather than read from the host: on a host in a hidden session the real
/// command would power the host off.
#[test]
fn outside_a_hidden_session_deactivate_refuses_with_invalid_state() {
    for args in [
        DeactivateArgs::default(),
        DeactivateArgs {
            yes: true,
            poweroff: true,
        },
    ] {
        let status = super::deactivate_prepared(&json(), &args, Prepared::NotHidden);
        assert_eq!(status, ExitStatus::InvalidState, "{args:?}");
    }
}

/// The prompt as it is shown before the answer.
fn prompt() -> String {
    let settings = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let mut out = Vec::new();
    super::write_prompt(&settings, &mut out);
    String::from_utf8(out).unwrap()
}

#[test]
fn the_prompt_says_the_session_ends_in_a_power_off_before_asking() {
    assert_eq!(
        prompt(),
        "[WARN] This ends the hidden session and powers off the machine now.\n\
         \x20   Every hidden program closes. Unsaved work is lost.\n\
         \x20   Continue? [y/N]: "
    );
}

/// An answer other than yes reads as `activate`'s cancel: the neutral notice
/// after the prompt, no error, and exit 130. Ctrl+C at the prompt is one too,
/// and so is the end of the input, each with its notice on a line of its own,
/// since no Enter ended the prompt's. A yes goes on without one.
#[test]
fn a_declined_or_interrupted_deactivation_is_a_neutral_notice_and_exits_130() {
    use crate::cli::commands::prompt::Answer;
    let ask = |answer: Answer| {
        let mut err = Vec::new();
        let status = super::confirm_or_cancel(&OutputSettings::default(), &mut err, || answer);
        (status, String::from_utf8(err).unwrap())
    };
    let notice = "\u{25cb} Deactivation cancelled; nothing was changed.\n";
    for (answer, ending) in [
        (Answer::No, format!("Continue? [y/N]: {notice}")),
        (Answer::Cancelled, format!("Continue? [y/N]: \n{notice}")),
        (Answer::EndOfInput, format!("Continue? [y/N]: \n{notice}")),
    ] {
        let (status, shown) = ask(answer);
        assert_eq!(status, Some(ExitStatus::Cancelled), "{answer:?}");
        assert!(shown.ends_with(&ending), "{answer:?}: {shown}");
        assert!(!shown.contains("error:"), "{shown}");
    }
    let (status, shown) = ask(Answer::Yes);
    assert_eq!(status, None);
    assert!(!shown.contains("cancelled"), "{shown}");
}
