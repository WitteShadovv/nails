// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::execute;
use crate::cli::args::DeactivateArgs;
use crate::cli::output::test_support::{envelope, stdout_lines};
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};
use nails_core::NailsError;
use nails_core::app::deactivate::Prepared;
use nails_core::session::{LeaveReport, LeaveTo};

fn json() -> OutputSettings {
    OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    }
}

const SUBPROCESS_TEST_NAME: &str =
    "cli::commands::deactivate::tests::subprocess_deactivate_entrypoint";

/// What the stand-in for the way back prints on stdout when it runs: the
/// moment the soft-reboot would be enqueued.
const ENQUEUED: &str = "<the way back is enqueued here>";

/// Run `case` of [`subprocess_deactivate_entrypoint`] in a child process, so
/// the test sees its real stdout and exit code.
fn run_subprocess(case: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture", "--quiet"])
        .env("NAILS_DEACTIVATE_SUBPROCESS_CASE", case)
        .output()
        .expect("failed to run deactivate subprocess test")
}

/// Why the probe found no way back in a hidden root without its plan.
const WITHOUT_PLAN: &str = "no session plan in /run (upper /mnt/data/root/upper)";

/// The error the way back returns when systemd refuses the soft-reboot.
fn refused() -> NailsError {
    NailsError::InvalidState("systemctl could not enqueue soft-reboot.target".to_string())
}

/// Report a way back through a stand-in for it that prints [`ENQUEUED`] and
/// then succeeds or fails, as the case says, and exit with the status.
#[test]
fn subprocess_deactivate_entrypoint() {
    let Ok(case) = std::env::var("NAILS_DEACTIVATE_SUBPROCESS_CASE") else {
        return;
    };
    let ascii = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    if let Some(settings) = match case.as_str() {
        "json-without-way-back" => Some(json()),
        "human-without-way-back" => Some(ascii),
        _ => None,
    } {
        // No -y: a prompt would refuse off a terminal with exit 2 first.
        let status = super::deactivate_prepared(
            &settings,
            &DeactivateArgs::default(),
            Prepared::WayBackUnknown(WITHOUT_PLAN.to_string()),
        );
        crate::cli::chokepoint::exit_process(status.code());
    }
    let (settings, to, outcome) = match case.as_str() {
        "json-enqueued" => (json(), LeaveTo::Poweroff, Ok(LeaveReport::default())),
        "json-refused" => (json(), LeaveTo::Decoy, Err(refused())),
        "human-enqueued" => (ascii, LeaveTo::Decoy, Ok(LeaveReport::default())),
        "human-refused" => (ascii, LeaveTo::Decoy, Err(refused())),
        other => panic!("unknown deactivate subprocess case: {other}"),
    };
    let status = super::leave_and_report(&settings, to, |_| {
        crate::cli::output::println_tolerating_broken_pipe(ENQUEUED);
        outcome
    });
    crate::cli::chokepoint::exit_process(status.code());
}

/// Under `--json` a way back that cannot be enqueued is the only envelope on
/// stdout: printed after the attempt, `ok` false with the error, exit 1. No
/// success envelope comes first for a reader of the first line to trust.
#[test]
fn a_way_back_that_fails_is_the_only_envelope() {
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

/// An enqueued way back is one success envelope, printed once it is enqueued.
#[test]
fn an_enqueued_way_back_is_one_envelope_printed_after_it() {
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

/// A person reads the result before the switch, which stops the terminal,
/// however the switch goes; a failure to enqueue it follows on stderr.
#[test]
fn a_person_reads_the_result_before_the_way_back() {
    for (case, code) in [("human-enqueued", 0), ("human-refused", 1)] {
        let output = run_subprocess(case);
        assert_eq!(
            stdout_lines(&output),
            [
                "[PASS] Ending the hidden session: soft-rebooting back to the decoy",
                "  The decoy starts at its own login screen in a few seconds (a display manager \
                 set to log an account in automatically logs it in again, as at boot).",
                ENQUEUED,
            ],
            "{case}: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.contains("error: systemctl could not enqueue soft-reboot.target"),
            code == 1,
            "{case}: {stderr}"
        );
        assert_eq!(output.status.code(), Some(code), "{case}: {output:?}");
    }
}

/// In a hidden root without its plan there is no way back: under `--json`
/// the one envelope is the refusal, before any prompt, with the power-off as
/// the next step (a plain emergency finds no plan and does nothing).
#[test]
fn without_a_way_back_the_refusal_is_the_one_envelope() {
    let output = run_subprocess("json-without-way-back");
    let lines = stdout_lines(&output);
    assert_eq!(lines.len(), 1, "one envelope: {output:?}");
    let value = envelope("deactivate", &lines[0]);
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["error"]["code"], "invalid_state", "{value}");
    assert_eq!(
        value["error"]["next"]["command"], "emergency --poweroff",
        "{value}"
    );
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(WITHOUT_PLAN)),
        "{value}"
    );
    assert!(value.get("data").is_none(), "{value}");
    assert_eq!(output.status.code(), Some(6), "{output:?}");
}

/// A person is told before anything is asked or printed as done: no prompt,
/// no line that says the session is ending, only the error with the power-off.
#[test]
fn without_a_way_back_a_person_gets_the_refusal_and_no_prompt() {
    use nails_core::next_step::{NextStep, sudo_line};
    let output = run_subprocess("human-without-way-back");
    assert!(stdout_lines(&output).is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "error: in the hidden root without a way back: {WITHOUT_PLAN}\n  Power off to end \
             the session: `{}`",
            sudo_line(NextStep::EmergencyPoweroff)
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("Continue?"), "{stderr}");
    assert_eq!(output.status.code(), Some(6), "{output:?}");
}

#[test]
fn outside_a_hidden_session_deactivate_refuses_with_invalid_state() {
    // The test process runs on its host's own root, never in a hidden root.
    let config = tempfile::tempdir().unwrap();
    let missing = config.path().join("absent.toml");
    for args in [
        DeactivateArgs::default(),
        DeactivateArgs {
            yes: true,
            poweroff: true,
        },
    ] {
        let status = execute(
            &json(),
            &nails_core::RuntimeEnv::default(),
            &args,
            Some(&missing),
        );
        assert_eq!(status, ExitStatus::InvalidState, "{args:?}");
    }
}

/// The prompt as it is shown before the answer.
fn prompt(poweroff: bool) -> String {
    let settings = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let mut out = Vec::new();
    super::write_prompt(&settings, poweroff, &mut out);
    String::from_utf8(out).unwrap()
}

#[test]
fn the_prompt_says_where_the_session_ends_before_asking() {
    assert_eq!(
        prompt(false),
        "[WARN] This ends the hidden session and returns to the decoy now.\n\
         \x20   Every hidden program is closed; unsaved work is lost.\n\
         \x20   Continue? [y/N]: "
    );
    assert!(
        prompt(true).starts_with("[WARN] This ends the hidden session and powers off now.\n"),
        "{}",
        prompt(true)
    );
}

/// An answer other than yes reads as `activate`'s cancel: the neutral notice
/// after the prompt, no error, and exit 130. Ctrl+C at the prompt is one too,
/// its notice on a line of its own. A yes goes on without one.
#[test]
fn a_declined_or_interrupted_deactivation_is_a_neutral_notice_and_exits_130() {
    use crate::cli::commands::prompt::Answer;
    let ask = |answer: Answer| {
        let mut err = Vec::new();
        let status =
            super::confirm_or_cancel(&OutputSettings::default(), false, &mut err, || answer);
        (status, String::from_utf8(err).unwrap())
    };
    let notice = "\u{25cb} Deactivation cancelled; nothing was changed.\n";
    for (answer, ending) in [
        (Answer::No, format!("Continue? [y/N]: {notice}")),
        (Answer::Cancelled, format!("Continue? [y/N]: \n{notice}")),
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
