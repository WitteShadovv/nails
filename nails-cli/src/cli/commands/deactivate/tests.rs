// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::execute;
use crate::cli::args::DeactivateArgs;
use crate::cli::output::test_support::{envelope, stdout_lines};
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};
use nails_core::NailsError;
use nails_core::app::deactivate::{Prepared, ReadyDeactivation};
use nails_core::session::{LeaveReport, LeaveTo};
use std::path::Path;

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
    let yes = DeactivateArgs {
        yes: true,
        poweroff: false,
    };
    // Which of the network tools the way back's last step runs on a machine
    // without Wi-Fi are where it looks.
    let (all, only_nft): (&[&str], &[&str]) = (&["ip", "nft"], &["nft"]);
    if let Some((settings, args, tools)) = match case.as_str() {
        "human-ready-without-ip" => Some((ascii, yes, only_nft)),
        "human-ready-without-tools" => Some((ascii, yes, &[][..])),
        "human-ready-with-tools" => Some((ascii, yes, all)),
        "json-ready-without-ip" => Some((json(), yes, only_nft)),
        "json-ready-without-tools" => Some((json(), yes, &[][..])),
        "json-ready-with-tools" => Some((json(), yes, all)),
        "json-ready-poweroff" => Some((
            json(),
            DeactivateArgs {
                yes: true,
                poweroff: true,
            },
            &[][..],
        )),
        "json-ready-unconfirmed" => Some((json(), DeactivateArgs::default(), &[][..])),
        _ => None,
    } {
        let root = tempfile::tempdir().unwrap();
        for tool in tools {
            put(root.path(), &format!("usr/bin/{tool}"));
        }
        // A stand-in for the lock step and the way back: what the operator
        // reads up to the switch.
        let status = super::deactivate_prepared_with(
            &settings,
            &args,
            Prepared::Ready(Box::new(ready_at(root.path()))),
            |_ready, to, warnings| {
                super::leave_and_report(&settings, to, warnings, |_| {
                    crate::cli::output::println_tolerating_broken_pipe(ENQUEUED);
                    Ok(LeaveReport::default())
                })
            },
        );
        // The exit runs no destructor: remove the scratch tree first.
        drop(root);
        crate::cli::chokepoint::exit_process(status.code());
    }
    let (settings, to, outcome) = match case.as_str() {
        "json-enqueued" => (json(), LeaveTo::Poweroff, Ok(LeaveReport::default())),
        "json-refused" => (json(), LeaveTo::Decoy, Err(refused())),
        "json-left-open" => (json(), LeaveTo::Decoy, Ok(left_open())),
        "human-enqueued" => (ascii, LeaveTo::Decoy, Ok(LeaveReport::default())),
        "human-refused" => (ascii, LeaveTo::Decoy, Err(refused())),
        "human-left-open" => (ascii, LeaveTo::Decoy, Ok(left_open())),
        other => panic!("unknown deactivate subprocess case: {other}"),
    };
    // The warning given before the question rides along in the envelope.
    let warnings = if case.ends_with("left-open") {
        vec![EARLIER_WARNING.to_string()]
    } else {
        Vec::new()
    };
    let status = super::leave_and_report(&settings, to, warnings, |_| {
        crate::cli::output::println_tolerating_broken_pipe(ENQUEUED);
        outcome
    });
    crate::cli::chokepoint::exit_process(status.code());
}

/// A warning given before the question.
const EARLIER_WARNING: &str = "The return finds no `ip` (iproute2) in the hidden session's system \
                               directories";

/// Put an empty file at `path` below `root`.
fn put(root: &Path, path: &str) {
    let file = root.join(path);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, "").unwrap();
}

/// A deactivation ready to leave a hidden session whose decoy runs no NixOS,
/// with its hidden volume, its state file and the root the way back's last
/// step runs in, where it looks for its network tools, all below `root`.
fn ready_at(root: &Path) -> ReadyDeactivation {
    use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
    let plan = serde_json::json!({
        "version": PLAN_VERSION,
        "hidden_root": "/mnt/data",
        "upper": "/mnt/data/root/upper",
        "work": "/mnt/data/root/work",
        "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
        "decoy": {"init": "/sbin/init"},
        "hidden": {"init": "/sbin/init"},
    });
    let config = nails_core::Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..nails_core::Config::test_default()
    };
    let plan = Plan::from_json(&plan.to_string()).expect("a minimal plan");
    ReadyDeactivation::for_test(config, plan, root)
}

/// What a person reads before the question when the way back's last step
/// finds no `ip` in a hidden root whose decoy runs no NixOS.
fn no_ip_warning() -> String {
    use nails_core::next_step::{NextStep, sudo_line};
    format!(
        "The return finds no `ip` (iproute2) in the hidden session's system directories, so the \
         virtual links the session made, the MAC addresses it changed and the policy-routing \
         rules it added stay on the decoy until power-off. `{}` leaves none of them.",
        sudo_line(NextStep::DeactivatePoweroff)
    )
}

/// What a person reads before the question when the way back's last step
/// finds no `nft` in a hidden root whose decoy runs no NixOS.
fn no_nft_warning() -> String {
    use nails_core::next_step::{NextStep, sudo_line};
    format!(
        "The return finds no `nft` (nftables) in the hidden session's system directories, so the \
         nftables tables the session added stay on the decoy until power-off (a VPN app's table \
         that blocks all traffic outside its tunnel keeps the decoy offline). `{}` leaves none \
         of them.",
        sudo_line(NextStep::DeactivatePoweroff)
    )
}

/// The lines a person reads of a return to the decoy, up to the switch.
const RETURN_LINES: [&str; 3] = [
    "[PASS] Ending the hidden session: soft-rebooting back to the decoy",
    "  The decoy starts at its own login screen in a few seconds (a display manager set to log \
     an account in automatically logs it in again, as at boot).",
    ENQUEUED,
];

/// A person reads that the return leaves the session's network state on the
/// decoy where its last step finds no `ip`, or no `nft`, one line each on
/// the question's stream before the lines of the return; where it finds both
/// there is nothing to read.
#[test]
fn a_person_reads_the_network_tool_warnings_before_the_return() {
    for (case, warned) in [
        ("human-ready-without-ip", vec![no_ip_warning()]),
        (
            "human-ready-without-tools",
            vec![no_ip_warning(), no_nft_warning()],
        ),
        ("human-ready-with-tools", Vec::new()),
    ] {
        let output = run_subprocess(case);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let expected: Vec<String> = warned
            .iter()
            .map(|warning| format!("[WARN] {warning}"))
            .collect();
        assert_eq!(stderr.lines().collect::<Vec<_>>(), expected, "{case}");
        assert_eq!(stdout_lines(&output), RETURN_LINES, "{case}: {output:?}");
        assert_eq!(output.status.code(), Some(0), "{case}: {output:?}");
    }
}

/// Under `--json` nothing is written before the question: the one envelope
/// carries the warnings in `warnings` where the return finds no `ip` or no
/// `nft`, and has no `warnings` where it finds both or for a power-off,
/// after which the decoy starts afresh.
#[test]
fn the_envelope_carries_the_network_tool_warnings() {
    for (case, status, warnings) in [
        (
            "json-ready-without-ip",
            "return_requested",
            Some(serde_json::json!([no_ip_warning()])),
        ),
        (
            "json-ready-without-tools",
            "return_requested",
            Some(serde_json::json!([no_ip_warning(), no_nft_warning()])),
        ),
        ("json-ready-with-tools", "return_requested", None),
        ("json-ready-poweroff", "poweroff_requested", None),
    ] {
        let output = run_subprocess(case);
        assert!(output.stderr.is_empty(), "{case}: {output:?}");
        let lines = stdout_lines(&output);
        assert_eq!(
            lines.len(),
            2,
            "the stand-in's line, one envelope: {output:?}"
        );
        assert_eq!(lines[0], ENQUEUED, "{case}: {output:?}");
        let value = envelope("deactivate", &lines[1]);
        assert_eq!(value["ok"], true, "{case}: {value}");
        assert_eq!(value["data"]["status"], status, "{case}: {value}");
        assert_eq!(
            value["data"].get("warnings"),
            warnings.as_ref(),
            "{case}: {value}"
        );
        assert_eq!(output.status.code(), Some(0), "{case}: {output:?}");
    }
}

/// Without `-y` off a terminal a ready deactivation is refused before it
/// warns, asks or leaves: the one envelope is `needs_confirmation`, exit 2.
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
    let status = super::lock_and_leave(&json(), ready_at(root.path()), LeaveTo::Decoy, Vec::new());
    assert_eq!(status, ExitStatus::PreflightRefused);
    assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
}

/// A way back that marked one backend device to close and not the other.
fn left_open() -> LeaveReport {
    LeaveReport {
        deferred: vec![
            ("hidden-crypt".to_string(), false),
            ("hidden-loop".to_string(), true),
        ],
        unmounted: Vec::new(),
    }
}

/// A backend device the way back could not mark to close is named in the one
/// envelope, after the warning given before the question: `ok`, exit 0.
#[test]
fn a_device_left_open_is_named_in_the_envelope() {
    let output = run_subprocess("json-left-open");
    let lines = stdout_lines(&output);
    assert_eq!(
        lines.len(),
        2,
        "the stand-in's line, one envelope: {output:?}"
    );
    let value = envelope("deactivate", &lines[1]);
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(value["data"]["status"], "return_requested", "{value}");
    assert_eq!(
        value["data"]["backend_left_open"],
        serde_json::json!(["hidden-crypt"]),
        "{value}"
    );
    assert_eq!(
        value["data"]["warnings"],
        serde_json::json!([
            EARLIER_WARNING,
            crate::cli::output::deactivate::backend_left_open_warning("hidden-crypt"),
        ]),
        "{value}"
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

/// A person reads a device left open after the lines that come before the
/// switch, once the way back is enqueued.
#[test]
fn a_person_reads_a_device_left_open_after_the_enqueue() {
    let output = run_subprocess("human-left-open");
    let lines = stdout_lines(&output);
    assert_eq!(
        lines[2..],
        [
            ENQUEUED.to_string(),
            format!(
                "[WARN] {}",
                crate::cli::output::deactivate::backend_left_open_warning("hidden-crypt")
            ),
        ],
        "{output:?}"
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

/// The warnings come before the question, one marked line each, on the
/// question's stream.
#[test]
fn the_warnings_are_written_before_the_question() {
    let settings = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let mut out = Vec::new();
    super::write_warnings(
        &settings,
        &["first".to_string(), "second".to_string()],
        &mut out,
    );
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "[WARN] first\n[WARN] second\n"
    );
    let mut none = Vec::new();
    super::write_warnings(&settings, &[], &mut none);
    assert!(none.is_empty());
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
        assert_eq!(stdout_lines(&output), RETURN_LINES, "{case}: {output:?}");
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
