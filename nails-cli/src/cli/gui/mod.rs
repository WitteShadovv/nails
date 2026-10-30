// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails gui`: open the window, with the engine's root helper behind it.
//!
//! The launcher is the one root step of the window: `sudo <root>/nails gui`
//! from a terminal on the decoy, or the same line in a terminal of the hidden
//! session. It runs as root only long enough to:
//!
//! 1. resolve the operator ([`TargetUser`], `PKEXEC_UID` before `SUDO_UID`)
//!    and refuse root as the window's account;
//! 2. pass the gate ([`gate`]): in the hidden session the window always opens;
//!    on the decoy only where the decoy keeps no persistent record and the
//!    desktop's trace test has passed. The gate runs before anything starts a
//!    toolkit or connects to a session bus, so a refusal leaves no more than
//!    the line the privilege tool logged;
//! 3. find the operator's runtime directory in RAM ([`runtime_dir`]) and make
//!    the window a directory of its own in it, for its home and every XDG
//!    base directory;
//! 4. start both ends of one socket pair ([`spawn`]): `<root>/nails helper
//!    --stdio`, still root, on one end, and the window's program
//!    (`<root>/gui/bin/nails-gui`) on the other, dropped to the operator with
//!    the environment of [`window_env`] and nothing else.
//!
//! Both start a session of their own, so the terminal the line was typed in
//! can close, and its shell be killed (activation kills it last, before the
//! switch), without a hangup or a group signal reaching either. The helper
//! catches SIGHUP besides. The launcher does not wait for them: its prompt
//! comes back at once, and the window and its helper talk over the pair from
//! the hello handshake on, which refuses a window of another release.
//!
//! The command is built only with the `gui` cargo feature, like the helper.

mod gate;
mod runtime_dir;
mod spawn;
mod window_env;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use nails_core::RuntimeEnv;
use nails_core::target_user::TargetUser;
use serde::Serialize;

use crate::cli::output::envelope::{Envelope, EnvelopePrint, ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// The `command` of this command's envelopes.
pub(crate) const COMMAND: &str = "gui";

/// Where the window's program lies, relative to the directory of the engine.
const WINDOW_PROGRAM: &str = "gui/bin/nails-gui";

/// Why the window did not open: the exit status and the error to report.
#[derive(Debug)]
pub(crate) struct Refusal {
    status: ExitStatus,
    body: ErrorBody,
}

impl Refusal {
    fn new(status: ExitStatus, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ErrorBody::new(code, message),
        }
    }
}

/// What `--json` reports once both processes run.
#[derive(Debug, Serialize)]
struct Opened {
    /// The root helper's process id.
    helper_pid: u32,
    /// The window's process id.
    window_pid: u32,
}

/// The launcher's global options that the helper takes too.
#[derive(Debug, Clone, Copy)]
pub struct HelperOptions<'a> {
    /// `--config`.
    pub config: Option<&'a Path>,
    /// `--no-log-file`.
    pub no_log_file: bool,
}

/// Open the window, or say why it does not open.
pub fn execute(
    settings: &OutputSettings,
    env: &RuntimeEnv,
    options: HelperOptions<'_>,
) -> ExitStatus {
    match open(env, options) {
        Ok(opened) => {
            if settings.is_json() {
                Envelope::success(COMMAND, opened).print();
            }
            ExitStatus::Ok
        }
        Err(refusal) => report_error(settings.is_json(), COMMAND, refusal.status, refusal.body),
    }
}

fn open(env: &RuntimeEnv, options: HelperOptions<'_>) -> Result<Opened, Refusal> {
    let engine = std::env::current_exe().map_err(|error| {
        Refusal::new(
            ExitStatus::Failed,
            "launch_failed",
            format!("the engine cannot find its own file: {error}"),
        )
    })?;
    let operator = operator(env, &engine)?;
    gate::admit(env, options.config, &engine)?;
    let program = window_program(&engine)?;
    let runtime = runtime_dir::find(env, &operator)?;
    let own_dir = runtime_dir::make_own_dir(&runtime, &operator)?;
    let window = spawn::Window {
        program,
        account: nails_core::process::run::Account {
            uid: operator.uid,
            gid: operator.gid,
        },
        vars: window_env::vars(&env.inherited, &runtime, &own_dir),
    };
    let (helper_pid, window_pid) =
        spawn::start(&engine, &helper_args(options), window).map_err(|error| {
            Refusal::new(
                ExitStatus::Failed,
                "launch_failed",
                format!("the window could not be started: {error}"),
            )
        })?;
    tracing::info!(helper_pid, window_pid, "the window and its helper run");
    Ok(Opened {
        helper_pid,
        window_pid,
    })
}

/// The operator the window runs as: never root.
fn operator(env: &RuntimeEnv, engine: &Path) -> Result<TargetUser, Refusal> {
    let operator = TargetUser::resolve_with(env)
        .map_err(|error| Refusal::new(ExitStatus::Config, "no_operator", error.to_string()))?;
    refuse_root(operator, engine)
}

/// `operator`, unless it is root: the window runs as the account that asked
/// for it, and a root login has none to drop to.
fn refuse_root(operator: TargetUser, engine: &Path) -> Result<TargetUser, Refusal> {
    if operator.uid == 0 {
        return Err(Refusal::new(
            ExitStatus::Config,
            "operator_is_root",
            format!(
                "The window never runs as root, and it was asked for from the root account.\n\
                 Start it from your own account: {}",
                gui_line(engine)
            ),
        ));
    }
    Ok(operator)
}

/// The line that opens the window with `engine`.
pub(crate) fn gui_line(engine: &Path) -> String {
    format!(
        "sudo {} {COMMAND}",
        nails_core::next_step::shell_word(engine.as_os_str())
    )
}

/// The window's launcher in the hidden session for `engine`, when the window's
/// program lies beside it: what an activation writes into the hidden root, a
/// menu entry that runs the window and the polkit action of the helper the
/// window then starts through pkexec.
pub(crate) fn hidden_launcher(engine: &Path) -> Option<nails_core::session::WindowLauncher> {
    let window = window_program(engine).ok()?;
    Some(nails_core::session::WindowLauncher {
        engine: engine.to_path_buf(),
        window,
    })
}

/// The window's program beside `engine`, which must be a file.
fn window_program(engine: &Path) -> Result<PathBuf, Refusal> {
    let program = engine
        .parent()
        .unwrap_or(Path::new("/"))
        .join(WINDOW_PROGRAM);
    match std::fs::metadata(&program) {
        Ok(meta) if meta.is_file() => Ok(program),
        Ok(_) => Err(window_missing(&program, "it is not a file")),
        Err(error) => Err(window_missing(&program, &error.to_string())),
    }
}

fn window_missing(program: &Path, why: &str) -> Refusal {
    Refusal::new(
        ExitStatus::Failed,
        "window_missing",
        format!(
            "The window is not installed beside the engine: {} ({why}).",
            program.display()
        ),
    )
}

/// The helper's command line: the launcher's own `--config` and
/// `--no-log-file`, so both ends read the same configuration.
fn helper_args(options: HelperOptions<'_>) -> Vec<OsString> {
    let mut args = Vec::new();
    if options.no_log_file {
        args.push(OsString::from("--no-log-file"));
    }
    if let Some(config) = options.config {
        args.push(OsString::from("--config"));
        args.push(config.as_os_str().to_owned());
    }
    args.extend(["helper", "--stdio"].map(OsString::from));
    args
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
