// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The process-exit chokepoint and the panic hook.

use crate::cli::output::ExitStatus;
use crate::cli::output::envelope::{ErrorBody, error_envelope, print_envelope_line};

/// The process-exit chokepoint.
///
/// `main` turns a handler's [`crate::cli::output::ExitStatus`] into a
/// [`std::process::ExitCode`] and returns it, so this is the only place in the
/// binary that exits the process directly: the early dispatch of `emergency`
/// and `transition` (which run before clap), a signal reported as a cancel
/// under `--json` ([`crate::cli::interrupt`], from the envelope slot that
/// prints it) and the test-harness subprocess entrypoints use it to end the
/// process with a code.
pub(crate) fn exit_process(code: u8) -> ! {
    std::process::exit(i32::from(code));
}

/// Install a panic hook that keeps source paths off stderr.
///
/// The default hook prints `thread '…' panicked at <crate>/<file>:<line>` to
/// stderr, and a panic payload can carry a hidden-root path. This hook sends
/// the full payload and location only through `tracing` (whose only sink for
/// this target is the hidden-root file log, for the commands that write one:
/// the console layer leaves it out) and prints a single neutral line, with no
/// path, crate name or payload, to stderr. It deliberately does not chain to
/// the previous hook.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        tracing::error!(target: crate::cli::logging::PANIC_TARGET, detail = %info, "aborted by an internal error");
        // Pipe-safe: the terminal may already be gone (an emergency kills it).
        crate::cli::output::eprintln_tolerating_broken_pipe(PANIC_NOTICE);
    }));
}

/// What a panic tells the operator, on stderr and as the `--json` error: no
/// path, crate name or payload.
const PANIC_NOTICE: &str = "A fatal internal error occurred; the operation was aborted.";

/// Run `run`, the whole of `main` after the early dispatch, and turn a panic
/// that unwinds out of it into the documented failure instead of the runtime's
/// exit 101, a code outside the table: exit 1, and under `--json` the one
/// envelope, the error `internal_error`, unless the command already printed
/// its envelope.
///
/// A panic is caught only once it has unwound to here, so the guards on the
/// way (a state lock, a rollback) have run as they would have. Whether the
/// run was under `--json`, and the command it was, are read from the
/// arguments, as for a usage error: a panic can come before the parsed
/// arguments exist.
pub fn exit_code_catching_panics(
    run: impl FnOnce() -> std::process::ExitCode,
) -> std::process::ExitCode {
    catching_panics(&crate::cli::main_guard::invocation_args(), run)
}

/// [`exit_code_catching_panics`] for the arguments `args`.
fn catching_panics(
    args: &[std::ffi::OsString],
    run: impl FnOnce() -> std::process::ExitCode,
) -> std::process::ExitCode {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(code) => code,
        Err(_) => {
            if args.iter().any(|arg| arg == "--json") {
                let command = crate::cli::main_guard::command_from_argv(args);
                let error = ErrorBody::new("internal_error", PANIC_NOTICE);
                print_envelope_line(&error_envelope(command, error).to_line());
            }
            crate::cli::output::flush_stdio();
            ExitStatus::Failed.to_exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::output::envelope::{Envelope, EnvelopePrint};
    use crate::cli::output::test_support::{envelope, stdout_lines};

    const SUBPROCESS_TEST_NAME: &str = "cli::chokepoint::tests::subprocess_panic_entrypoint";

    /// Run `case` of [`subprocess_panic_entrypoint`] in a child process.
    fn run_subprocess(case: &str) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture", "--quiet"])
            .env("NAILS_PANIC_SUBPROCESS_CASE", case)
            .output()
            .expect("failed to run the panic subprocess test")
    }

    /// Run the case inside [`catching_panics`], for `status` run with or
    /// without `--json`, and exit with what it returns, as `main` does.
    #[test]
    fn subprocess_panic_entrypoint() {
        let Ok(case) = std::env::var("NAILS_PANIC_SUBPROCESS_CASE") else {
            return;
        };
        install_panic_hook();
        let json: [std::ffi::OsString; 2] = ["--json".into(), "status".into()];
        let plain: [std::ffi::OsString; 1] = ["status".into()];
        let code = match case.as_str() {
            "json" => catching_panics(&json, || panic!("a payload naming /mnt/data")),
            "plain" => catching_panics(&plain, || panic!("a payload naming /mnt/data")),
            "after-the-envelope" => catching_panics(&json, || {
                Envelope::success("status", serde_json::json!({"place": "decoy"})).print();
                panic!("a payload naming /mnt/data")
            }),
            "no-panic" => catching_panics(&json, || ExitStatus::SuccessWithWarnings.to_exit_code()),
            other => panic!("unknown panic subprocess case: {other}"),
        };
        let status = if code == ExitStatus::Failed.to_exit_code() {
            ExitStatus::Failed
        } else {
            ExitStatus::SuccessWithWarnings
        };
        exit_process(status.code());
    }

    /// Under `--json` a panic is the one envelope, the error `internal_error`
    /// of the command, and exit 1, a code of the table; the payload stays off
    /// both streams.
    #[test]
    fn a_panic_under_json_is_the_internal_error_envelope_and_exit_1() {
        let output = run_subprocess("json");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let lines = stdout_lines(&output);
        assert_eq!(lines.len(), 1, "one envelope: {output:?}");
        let value = envelope("status", &lines[0]);
        assert_eq!(value["ok"], false, "{value}");
        assert_eq!(value["error"]["code"], "internal_error", "{value}");
        assert_eq!(value["error"]["message"], PANIC_NOTICE, "{value}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(PANIC_NOTICE), "{stderr}");
        assert!(!format!("{output:?}").contains("/mnt/data"), "{output:?}");
    }

    /// Without `--json` a panic prints nothing on stdout and exits 1 too.
    #[test]
    fn a_panic_without_json_exits_1_with_the_notice_only() {
        let output = run_subprocess("plain");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(stdout_lines(&output).is_empty(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(PANIC_NOTICE),
            "{output:?}"
        );
    }

    /// A panic after the command printed its envelope adds no second one.
    #[test]
    fn a_panic_after_the_envelope_adds_none() {
        let output = run_subprocess("after-the-envelope");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let lines = stdout_lines(&output);
        assert_eq!(lines.len(), 1, "one envelope: {output:?}");
        let value: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(value["ok"], true, "{value}");
    }

    /// A run that does not panic keeps its own exit code.
    #[test]
    fn a_run_without_a_panic_keeps_its_code() {
        let output = run_subprocess("no-panic");
        assert_eq!(output.status.code(), Some(9), "{output:?}");
        assert!(stdout_lines(&output).is_empty(), "{output:?}");
    }
}
