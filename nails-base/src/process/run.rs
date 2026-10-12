// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! External Program Execution
//!
//! nails starts external programs through a [`ProcessRunner`]. The real
//! runner is the one place that decides:
//!
//! - **which binary runs**: host tools resolve to an absolute path from a fixed
//!   list of system directories ([`SYSTEM_TOOL_DIRS`]) instead of the caller's
//!   `PATH`, which can point into user-writable profiles while nails runs as
//!   root;
//! - **whether it may run at all**: commands are refused in test and test-like
//!   runtimes unless they opt in, so a test that reaches the real runner gets
//!   an error instead of stopping services or signalling host processes;
//! - **what environment it inherits**: the child starts from a *cleared*
//!   environment (see [below](#environment)), never the caller's;
//! - **how the child starts**: stdin is closed and stdout/stderr are captured;
//! - **how long it may run**: a command may carry a [deadline](ProcessCommand::deadline).
//!
//! # Environment
//!
//! nails runs as root, so a child must not inherit variables a lower-privileged
//! caller could have set. Every child is started with [`env_clear`] and then
//! given only:
//!
//! - a fixed `PATH` ([`SYSTEM_TOOL_DIRS`]), so the child resolves *its own*
//!   helpers from the same root-owned directories the runner resolves from,
//!   never from a user profile on the caller's `PATH`;
//! - the caller's `LANG`, `LC_*` and `TERM`, which affect only locale and
//!   terminal rendering and never tool resolution or a trust decision;
//! - any variable a call site adds with [`ProcessCommand::allow_env`]. The only
//!   use today is `NIX_PATH` for channel-based `nixos-rebuild`; a flake build
//!   never allows it, so the caller's channel search path cannot steer
//!   evaluation. `NIX_*` variables are *not* inherited otherwise.
//!
//! [`env_clear`]: std::process::Command::env_clear
//!
//! # Deadlines
//!
//! A command runs in one of two modes:
//!
//! - **Streaming** (the default, no deadline): the command runs to completion.
//!   This is the only safe mode for `nixos-rebuild build/test` and
//!   `switch-to-configuration` — killing a half-finished switch would leave the
//!   system in an undefined state — so those must never carry a deadline. For a
//!   long step that must not be killed, [`ProcessRunner::run_streaming`] runs it
//!   to completion while calling back with the elapsed time at a fixed interval,
//!   so the call site can report "still building, 2m10s" without ever bounding
//!   the command.
//! - **Deadline** ([`ProcessCommand::deadline`]): used for probes and
//!   idempotent control commands (`systemctl is-active`, `nix store ping`,
//!   reboot dispatch, …). The child is spawned in its own process group; if the
//!   budget elapses the whole group is killed and [`NailsError::Timeout`] is
//!   returned. Killing the group — not just the immediate child — stops any
//!   helper the command forked. A D-state (uninterruptible) descendant cannot be
//!   removed by any signal, so a deadline cannot recover from one; it still
//!   reaps the direct child and reports the timeout. Named budgets for the known
//!   call sites live in this module (e.g. [`SYSTEMCTL_PROBE_BUDGET`]).
//!
//! Call sites describe a command with [`ProcessCommand`]; unit tests substitute
//! a recording runner.

use crate::{NailsError, Result};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Directories searched, in order, for [`Program::Tool`].
///
/// The NixOS system profile comes first, then the FHS locations used by
/// Debian, Ubuntu and most other distributions. All of them are root-owned on
/// a sane host.
pub const SYSTEM_TOOL_DIRS: &[&str] = &[
    crate::constants::NIXOS_SYSTEM_PROFILE_BIN,
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// How often [`ProcessCommand::deadline`] checks whether the child has exited.
///
/// Small enough that a probe returns promptly once its command finishes, large
/// enough that waiting out a full budget costs only a handful of wakeups.
const DEADLINE_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Budgets for external *control* commands that run under a deadline.
///
/// These bound probes and idempotent emergency-path commands only. None of them
/// may wrap `nixos-rebuild build/test` or `switch-to-configuration`, which run
/// in the default (no-deadline) mode: a deadline that killed a half-finished
/// switch would leave the system in an undefined state. Call sites pass the
/// matching budget to [`ProcessCommand::deadline`].
///
/// `systemctl is-active` and other read-only probes.
pub const SYSTEMCTL_PROBE_BUDGET: Duration = Duration::from_secs(10);
/// `systemctl start/stop/daemon-reload` and other state changes.
pub const SYSTEMCTL_ACTION_BUDGET: Duration = Duration::from_secs(30);
/// `nix store ping` reachability check.
pub const NIX_STORE_PING_BUDGET: Duration = Duration::from_secs(5);
/// `loginctl` session probes.
pub const LOGINCTL_BUDGET: Duration = Duration::from_secs(10);
/// `ldd` shared-library resolution.
pub const LDD_BUDGET: Duration = Duration::from_secs(10);
/// `cp` of an overlay snapshot, which can be large.
pub const COPY_BUDGET: Duration = Duration::from_secs(300);
/// Stopping one of NAILS' own helper units during a teardown, so a wedged stop
/// never holds the teardown up.
pub const UNIT_STOP_BUDGET: Duration = Duration::from_secs(5);
/// Dispatching a reboot (`systemctl reboot`, `reboot`).
pub const REBOOT_DISPATCH_BUDGET: Duration = Duration::from_secs(10);

/// How often [`ProcessRunner::run_streaming`] reports progress for a long step.
///
/// Build and switch steps have no deadline, so this only governs how often the
/// operator is told the step is still alive; 30 s is frequent enough to reassure
/// without flooding the log.
pub const BUILD_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

/// The executable a [`ProcessCommand`] starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// A host tool such as `systemctl`, resolved from [`SYSTEM_TOOL_DIRS`].
    Tool(&'static str),
    /// A binary looked up on the caller's `PATH`, or on the command's
    /// [search path](ProcessCommand::search_path) when one is set. Not found on
    /// the caller's `PATH`, it is looked up in [`SYSTEM_TOOL_DIRS`] as well: a
    /// systemd unit (a panic key, `systemd-run`) starts nails with a minimal
    /// `PATH` that, on NixOS, holds none of the Nix tools.
    ///
    /// Used where resolving from the caller's `PATH` is correct rather than a
    /// hijack risk: the Nix toolchain (`nix`, `nixos-rebuild`), whose VM tests
    /// substitute stub builds by prepending a directory to `PATH`, and the
    /// login-time `notify-send` dispatch, which runs in the operator's own login
    /// session (so their `PATH` is theirs to choose). The backend watcher's
    /// immediate alert runs as root from a system unit instead and resolves
    /// `notify-send` as a [`Program::Tool`].
    CallerPath(&'static str),
    /// An exact executable, such as a system generation's
    /// `switch-to-configuration` script.
    Exact(PathBuf),
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tool(name) | Self::CallerPath(name) => f.write_str(name),
            Self::Exact(path) => write!(f, "{}", path.display()),
        }
    }
}

/// One external command: the program, its arguments and environment changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCommand {
    program: Program,
    args: Vec<OsString>,
    allowed_env: Vec<OsString>,
    session_env: Vec<(OsString, OsString)>,
    search_path: Option<OsString>,
    allowed_in_test_runtime: bool,
    timeout: Option<Duration>,
}

impl ProcessCommand {
    /// A command that runs `program` with no arguments.
    pub fn new(program: Program) -> Self {
        Self {
            program,
            args: Vec::new(),
            allowed_env: Vec::new(),
            session_env: Vec::new(),
            search_path: None,
            allowed_in_test_runtime: false,
            timeout: None,
        }
    }

    /// A command running the host tool `name`; see [`Program::Tool`].
    pub fn tool(name: &'static str) -> Self {
        Self::new(Program::Tool(name))
    }

    /// A command running `name` from the caller's `PATH`; see
    /// [`Program::CallerPath`].
    pub fn caller_path(name: &'static str) -> Self {
        Self::new(Program::CallerPath(name))
    }

    /// A command running the executable at `path`.
    pub fn exact(path: impl Into<PathBuf>) -> Self {
        Self::new(Program::Exact(path.into()))
    }

    /// Appends one argument.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Appends several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_os_string()));
        self
    }

    /// Passes `key` from the caller's environment through to the child.
    ///
    /// The child otherwise starts from a cleared environment plus the fixed
    /// allowlist (see the [module docs](self#environment)); this adds one more
    /// variable to it when the caller holds it. Use it only for a concrete,
    /// documented need — today just `NIX_PATH` for a channel-based
    /// `nixos-rebuild`. It cannot override the fixed `PATH`.
    pub fn allow_env(mut self, key: impl AsRef<OsStr>) -> Self {
        self.allowed_env.push(key.as_ref().to_os_string());
        self
    }

    /// Sets `key` to an explicit `value` in the child's environment.
    ///
    /// Unlike [`allow_env`](Self::allow_env), which passes a variable through
    /// from the caller only when it holds it, this writes a value the call site
    /// computed. It exists for the one case where a root command must reach a
    /// *different* account's session: `notify-send`, which needs
    /// `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS` and the display variables
    /// pointed at the operator's session rather than root's. The value is applied
    /// on top of the cleared, allowlisted environment (see the
    /// [module docs](self#environment)) and cannot override the fixed `PATH`,
    /// which is always set last.
    pub fn set_env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.session_env
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Resolves a [`Program::CallerPath`] program from `dirs`, a `PATH`-style
    /// list, instead of the caller's `PATH`.
    ///
    /// This changes only where the executable is found: the child still starts
    /// with the fixed `PATH`, and other kinds of [`Program`] ignore it. Tests use
    /// it to point a command at stub binaries without changing the process
    /// environment that every other test thread shares.
    pub fn search_path(mut self, dirs: impl Into<OsString>) -> Self {
        self.search_path = Some(dirs.into());
        self
    }

    /// Lets the command run in test and test-like runtimes.
    ///
    /// Commands are refused there by default because most of them act on the
    /// running host. Opt in only for commands whose effects stay inside paths
    /// the caller chose, or that tests deliberately point at stubs.
    pub fn allow_in_test_runtime(mut self) -> Self {
        self.allowed_in_test_runtime = true;
        self
    }

    /// Runs the command under a deadline of `budget`.
    ///
    /// The real runner spawns the child in its own process group; if the budget
    /// elapses it kills the whole group and returns [`NailsError::Timeout`]. Use
    /// it only for probes and idempotent control commands — never for
    /// `nixos-rebuild build/test` or `switch-to-configuration` (see the module
    /// documentation). The named budgets in this module (e.g.
    /// [`SYSTEMCTL_PROBE_BUDGET`]) are the intended arguments.
    pub fn deadline(mut self, budget: Duration) -> Self {
        self.timeout = Some(budget);
        self
    }
}

impl fmt::Display for ProcessCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {}", arg.to_string_lossy())?;
        }
        Ok(())
    }
}

/// Starts external programs.
pub trait ProcessRunner {
    /// Runs `command` to completion and returns its exit status and output.
    ///
    /// A non-zero exit is not an error; callers inspect [`Output::status`].
    fn run(&self, command: &ProcessCommand) -> Result<Output>;

    /// Runs `command` and returns whether it succeeded, with stdout and
    /// stderr decoded lossily as UTF-8.
    fn run_text(&self, command: &ProcessCommand) -> Result<(bool, String, String)> {
        let output = self.run(command)?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }

    /// Runs `command` to completion, reporting elapsed progress while it runs.
    ///
    /// Unlike [`run`](Self::run), this never applies a deadline and never kills
    /// the child: it is for long steps that must finish or fail on their own —
    /// `nixos-rebuild build/test` and `switch-to-configuration` — where killing a
    /// half-finished switch would leave the system in an undefined state. While
    /// the child runs, `on_progress` is called about every `progress_interval`
    /// with the total elapsed time and the most recent non-empty stderr line seen
    /// so far (`None` until one arrives), so a caller can show the operator that a
    /// slow step is still alive and what it is currently doing.
    ///
    /// The default implementation ignores progress and defers to
    /// [`run`](Self::run); the real runner overrides it, and a recording mock
    /// inherits the default so tests need not model timing.
    fn run_streaming(
        &self,
        command: &ProcessCommand,
        progress_interval: Duration,
        on_progress: &mut dyn FnMut(Duration, Option<&str>),
    ) -> Result<Output> {
        let _ = (progress_interval, on_progress);
        self.run(command)
    }

    /// [`run_streaming`](Self::run_streaming) with the output decoded lossily as
    /// UTF-8, the streaming counterpart of [`run_text`](Self::run_text).
    fn run_streaming_text(
        &self,
        command: &ProcessCommand,
        progress_interval: Duration,
        on_progress: &mut dyn FnMut(Duration, Option<&str>),
    ) -> Result<(bool, String, String)> {
        let output = self.run_streaming(command, progress_interval, on_progress)?;
        Ok((
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

/// Runner that starts real processes on the host.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealProcessRunner;

impl ProcessRunner for RealProcessRunner {
    fn run(&self, command: &ProcessCommand) -> Result<Output> {
        if !command.allowed_in_test_runtime && crate::runtime_safety::should_skip_host_interaction()
        {
            return Err(NailsError::InvalidState(format!(
                "Refusing to run {} from a test/test-like runtime context; use a mock process runner or executor instead",
                command.program
            )));
        }

        let executable = resolve(&command.program, command.search_path.as_deref())?;
        tracing::debug!("Running {} ({})", command, executable.display());

        match command.timeout {
            None => run_to_completion(&executable, command),
            Some(budget) => run_with_deadline(&executable, command, budget),
        }
    }

    fn run_streaming(
        &self,
        command: &ProcessCommand,
        progress_interval: Duration,
        on_progress: &mut dyn FnMut(Duration, Option<&str>),
    ) -> Result<Output> {
        if !command.allowed_in_test_runtime && crate::runtime_safety::should_skip_host_interaction()
        {
            return Err(NailsError::InvalidState(format!(
                "Refusing to run {} from a test/test-like runtime context; use a mock process runner or executor instead",
                command.program
            )));
        }

        debug_assert!(
            command.timeout.is_none(),
            "streaming mode must never carry a deadline: build/switch run to completion"
        );

        let executable = resolve(&command.program, command.search_path.as_deref())?;
        tracing::debug!("Streaming {} ({})", command, executable.display());
        run_streaming_to_completion(&executable, command, progress_interval, on_progress)
    }
}

/// Builds the `std::process::Command` shared by both run modes: the resolved
/// executable, the arguments, and the cleared, allowlisted environment.
fn base_command(executable: &Path, command: &ProcessCommand) -> std::process::Command {
    let mut child = std::process::Command::new(executable);
    child.args(&command.args);
    apply_environment(
        &mut child,
        command,
        &crate::runtime_env::current().inherited,
    );
    reset_child_oom_score(&mut child);
    child
}

/// Reset a child's `oom_score_adj` to the neutral `0` before it execs.
///
/// A mutating command lowers its own `oom_score_adj` to survive memory pressure,
/// and that bias is inherited by every child. That is the wrong default for the
/// children — the nix evaluator in particular should stay a normal OOM candidate
/// so the kernel kills it rather than something critical — so each child resets
/// itself to the neutral score. The write runs in the forked child just before
/// `exec`; it is best-effort and any error is ignored, because failing to reset
/// the score must never prevent the child from running.
#[allow(unsafe_code)]
fn reset_child_oom_score(child: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure only performs an async-signal-safe `write(2)` to a
    // `/proc` file through libc and ignores the result. It allocates nothing and
    // touches no shared state, so it is safe to run between fork and exec.
    unsafe {
        child.pre_exec(|| {
            use nix::libc;
            let bytes = b"0\n";
            let path = c"/proc/self/oom_score_adj";
            let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::write(fd, bytes.as_ptr().cast(), bytes.len());
                libc::close(fd);
            }
            Ok(())
        });
    }
}

/// Clears the child's environment and rebuilds it from the allowlist.
///
/// See the [module docs](self#environment): a fixed `PATH`, the caller's
/// locale/terminal variables, and any key the command opted in with
/// [`ProcessCommand::allow_env`]. `inherited` is the caller's environment as
/// captured in the startup snapshot (the runner passes the installed one);
/// nothing else of the caller's reaches the child.
fn apply_environment(
    child: &mut std::process::Command,
    command: &ProcessCommand,
    inherited: &crate::runtime_env::InheritedVars,
) {
    child.env_clear();
    for (key, value) in inherited.iter() {
        if is_allowlisted_env(key) || command.allowed_env.iter().any(|allowed| allowed == key) {
            child.env(key, value);
        }
    }
    // Explicit, call-site-computed values (e.g. the operator's session bus for
    // `notify-send`) override anything the allowlist let through.
    for (key, value) in &command.session_env {
        child.env(key, value);
    }
    // Set last so neither an `allow_env("PATH")` nor a `set_env("PATH", …)` can
    // redirect the child onto a caller-chosen search path.
    child.env("PATH", SYSTEM_TOOL_DIRS.join(":"));
}

/// Whether `key` is always passed through to a child.
///
/// Only `LANG`, `LC_*` and `TERM`: locale and terminal rendering, which never
/// decide which binary runs or whether to trust something. Everything else is
/// dropped unless a call site allows it explicitly.
fn is_allowlisted_env(key: &OsStr) -> bool {
    key.to_str()
        .is_some_and(|key| key == "LANG" || key == "TERM" || key.starts_with("LC_"))
}

/// Wraps a spawn/`wait` failure with the executable path for context.
fn start_failed(executable: &Path, err: std::io::Error) -> NailsError {
    NailsError::io(
        executable,
        std::io::Error::new(
            err.kind(),
            format!("failed to start {}: {}", executable.display(), err),
        ),
    )
}

/// Runs the command to completion (the default, no-deadline mode).
fn run_to_completion(executable: &Path, command: &ProcessCommand) -> Result<Output> {
    base_command(executable, command)
        .output()
        .map_err(|err| start_failed(executable, err))
}

/// Runs the command under `budget`, killing its whole process group on expiry.
fn run_with_deadline(
    executable: &Path,
    command: &ProcessCommand,
    budget: Duration,
) -> Result<Output> {
    let mut child = base_command(executable, command)
        // Own process group so the deadline tears down the whole tree, not just
        // the immediate child.
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| start_failed(executable, err))?;

    // Drain stdout/stderr on their own threads: a child that fills a pipe buffer
    // while we wait would otherwise deadlock, never exiting and never letting us
    // read it.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Output {
                    status,
                    stdout: collect(stdout),
                    stderr: collect(stderr),
                });
            }
            Ok(None) => {}
            Err(err) => return Err(start_failed(executable, err)),
        }

        if start.elapsed() >= budget {
            // The child may have exited during the final sleep; prefer its real
            // result over a spurious timeout.
            if let Ok(Some(status)) = child.try_wait() {
                return Ok(Output {
                    status,
                    stdout: collect(stdout),
                    stderr: collect(stderr),
                });
            }
            kill_group(&mut child);
            // The killed group closes the pipes, so the reader threads finish;
            // the captured output is discarded on timeout.
            let _ = collect(stdout);
            let _ = collect(stderr);
            return Err(NailsError::Timeout {
                command: command.to_string(),
                budget,
            });
        }

        std::thread::sleep(DEADLINE_POLL_INTERVAL.min(budget));
    }
}

/// Runs the command to completion, reporting progress and never killing it.
///
/// Used only for `nixos-rebuild build/test` and `switch-to-configuration`, which
/// must not be interrupted; `on_progress` is called with the total elapsed time
/// and the most recent non-empty stderr line roughly every `progress_interval`
/// so the operator sees a slow step is alive and what it is doing. Output is
/// drained on reader threads to avoid a pipe-buffer deadlock, as in the deadline
/// path; the stderr drain also records its last non-empty line so the callback
/// can surface it without disturbing the full buffer kept for classification.
fn run_streaming_to_completion(
    executable: &Path,
    command: &ProcessCommand,
    progress_interval: Duration,
    on_progress: &mut dyn FnMut(Duration, Option<&str>),
) -> Result<Output> {
    let mut child = base_command(executable, command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| start_failed(executable, err))?;

    let stdout = drain(child.stdout.take());
    let last_line: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let stderr = drain_tracking_last_line(child.stderr.take(), Arc::clone(&last_line));

    let start = Instant::now();
    let mut last_report = start;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Output {
                    status,
                    stdout: collect(stdout),
                    stderr: collect(stderr),
                });
            }
            Ok(None) => {}
            Err(err) => return Err(start_failed(executable, err)),
        }

        if last_report.elapsed() >= progress_interval {
            let snapshot = last_line.lock().ok().and_then(|guard| guard.clone());
            on_progress(start.elapsed(), snapshot.as_deref());
            last_report = Instant::now();
        }

        std::thread::sleep(DEADLINE_POLL_INTERVAL);
    }
}

pub(crate) use crate::timing::format_elapsed;

/// Reads a child pipe to EOF on a background thread.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<Vec<u8>> {
    let mut pipe = pipe.expect("stdout/stderr were piped for the deadline path");
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = pipe.read_to_end(&mut buffer);
        buffer
    })
}

/// Reads a child pipe to EOF on a background thread, collecting the full byte
/// buffer and, as a side channel, publishing the most recent non-empty line into
/// `last_line` so the progress callback can show what the step is currently
/// doing. The full buffer is unchanged, so failure classification still sees
/// every byte.
fn drain_tracking_last_line<R: Read + Send + 'static>(
    pipe: Option<R>,
    last_line: Arc<Mutex<Option<String>>>,
) -> JoinHandle<Vec<u8>> {
    let pipe = pipe.expect("stderr was piped for the streaming path");
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut buffer: Vec<u8> = Vec::new();
        let mut line: Vec<u8> = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    buffer.extend_from_slice(&line);
                    let text = String::from_utf8_lossy(&line);
                    let trimmed = text.trim();
                    if !trimmed.is_empty()
                        && let Ok(mut guard) = last_line.lock()
                    {
                        *guard = Some(trimmed.to_owned());
                    }
                }
                Err(_) => break,
            }
        }
        buffer
    })
}

/// The longest a build line is allowed to be when folded into a progress
/// heartbeat, so a single pathological line cannot dominate the output.
const PROGRESS_LINE_MAX: usize = 120;

/// Formats one progress heartbeat for a long step: `still <activity>, <elapsed>`,
/// with the most recent build line appended when one is available. The build
/// line is trimmed to [`PROGRESS_LINE_MAX`] characters on a char boundary so a
/// very long line cannot swamp the heartbeat.
pub(crate) fn progress_line(activity: &str, elapsed: Duration, last_line: Option<&str>) -> String {
    let base = format!("still {activity}, {}", format_elapsed(elapsed));
    match last_line {
        Some(line) if !line.trim().is_empty() => format!("{base} — {}", truncate_line(line.trim())),
        _ => base,
    }
}

/// Resolves which build line a heartbeat may surface, given whether stderr is an
/// interactive terminal.
///
/// The most recent build line is useful live feedback under a spinner on a TTY,
/// but it is raw tool output: on a pipe, in the journal, or from a detached
/// worker it adds nothing a human is watching and only widens the activity
/// fingerprint if the stream is ever captured. Off a terminal the heartbeat
/// therefore keeps only the neutral `still <activity>, <elapsed>` form.
fn heartbeat_last_line(last_line: Option<&str>, stderr_is_tty: bool) -> Option<&str> {
    if stderr_is_tty { last_line } else { None }
}

/// Formats a long-step heartbeat for the current output context, folding in the
/// most recent build line only when stderr is an interactive terminal (see
/// [`heartbeat_last_line`]). Long-step call sites use this rather than
/// [`progress_line`] directly so the TTY gate is applied in exactly one place.
pub(crate) fn heartbeat_line(activity: &str, elapsed: Duration, last_line: Option<&str>) -> String {
    progress_line(
        activity,
        elapsed,
        heartbeat_last_line(last_line, std::io::stderr().is_terminal()),
    )
}

/// Returns `line` unchanged, or its first [`PROGRESS_LINE_MAX`] characters with a
/// trailing ellipsis, never splitting a multi-byte character.
fn truncate_line(line: &str) -> String {
    if line.chars().count() <= PROGRESS_LINE_MAX {
        return line.to_owned();
    }
    let kept: String = line
        .chars()
        .take(PROGRESS_LINE_MAX.saturating_sub(1))
        .collect();
    format!("{kept}…")
}

/// Joins a [`drain`] thread, yielding what it read (empty if it panicked).
fn collect(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

/// Sends `SIGKILL` to the child's whole process group, then reaps the child.
///
/// `child` was spawned with `process_group(0)`, so it leads a new group whose
/// PGID equals its PID; signalling that group reaches every descendant that has
/// not escaped it with its own `setsid`. A D-state descendant survives — no
/// signal can remove one.
fn kill_group(child: &mut std::process::Child) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let group = Pid::from_raw(child.id() as i32);
    let _ = killpg(group, Signal::SIGKILL);
    let _ = child.wait();
}

/// Resolves `program` to the absolute path that is executed. A
/// [`Program::CallerPath`] is looked up in `search_path` when it is given and
/// on the caller's `PATH` otherwise.
fn resolve(program: &Program, search_path: Option<&OsStr>) -> Result<PathBuf> {
    match program {
        Program::Tool(name) => find_executable(name, SYSTEM_TOOL_DIRS.iter().map(Path::new))
            .ok_or_else(|| {
                not_found(
                    name,
                    format!("{} not found in {}", name, SYSTEM_TOOL_DIRS.join(", ")),
                )
            }),
        Program::CallerPath(name) => {
            let (path, searched) = match search_path {
                Some(dirs) => (dirs.to_os_string(), "the search path"),
                // The caller's `PATH` from the installed startup snapshot.
                None => (
                    crate::runtime_env::current()
                        .path
                        .clone()
                        .unwrap_or_default(),
                    "PATH",
                ),
            };
            // Relative entries would make the result depend on the working
            // directory, so only absolute ones are searched.
            let dirs: Vec<PathBuf> = std::env::split_paths(&path)
                .filter(|dir| dir.is_absolute())
                .collect();
            let on_path = find_executable(name, dirs.iter().map(PathBuf::as_path));
            // The caller's PATH first, so a test's stubs still win; then the
            // root-owned system directories, for a caller with a minimal PATH.
            let fallback = || {
                search_path
                    .is_none()
                    .then(|| find_executable(name, SYSTEM_TOOL_DIRS.iter().map(Path::new)))
                    .flatten()
            };
            on_path.or_else(fallback).ok_or_else(|| {
                let also = if search_path.is_none() {
                    format!(" or in {}", SYSTEM_TOOL_DIRS.join(", "))
                } else {
                    String::new()
                };
                not_found(name, format!("{name} not found on {searched}{also}"))
            })
        }
        Program::Exact(path) => Ok(path.clone()),
    }
}

/// First `dir/name` that is an executable file nails is willing to run.
///
/// A candidate must be a regular file with an execute bit set; when nails runs as
/// root the candidate must additionally pass the root-trust check
/// ([`is_trusted_executable`](super::host_commands::is_trusted_executable)),
/// so a tampered binary on the search path is never spawned with full privilege.
/// The trust check shares one implementation with [`HostCommands`](super::host_commands::HostCommands).
fn find_executable<'a>(name: &str, dirs: impl IntoIterator<Item = &'a Path>) -> Option<PathBuf> {
    use super::host_commands::{is_executable_file, is_trusted_executable, running_as_root};

    let enforce_trust = running_as_root();
    dirs.into_iter()
        .map(|dir| dir.join(name))
        .find(|candidate| {
            is_executable_file(candidate) && (!enforce_trust || is_trusted_executable(candidate))
        })
}

/// A `NotFound` error naming the `program` that could not be resolved.
fn not_found(program: &str, message: String) -> NailsError {
    NailsError::io(
        program,
        std::io::Error::new(std::io::ErrorKind::NotFound, message),
    )
}

#[cfg(test)]
mod mock;
#[cfg(test)]
pub(crate) use mock::{MockProcessRunner, assert_refused_in_test_runtime, exited};

#[cfg(test)]
mod tests;
