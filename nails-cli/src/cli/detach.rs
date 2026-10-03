use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use nails_core::constants::{
    ENV_DETACHED, ENV_DISPLAY_MANAGER, ENV_FORCE_DETACH, ENV_LOGIND_AVAILABLE, ENV_SESSION_ID,
    ENV_SKIP_DETACH, ENV_TARGET_UID, ENV_TARGET_USER,
};
use nails_core::process::{ProcessCommand, ProcessRunner, RealProcessRunner, SYSTEM_TOOL_DIRS};
use nails_core::{
    NailsError, RealSessionCommandExecutor, SessionContext, SessionKind, detect_session_context,
};

/// The NixOS setuid-wrapper directory, prepended to the detached worker's search
/// path ahead of [`SYSTEM_TOOL_DIRS`]. Not part of [`SYSTEM_TOOL_DIRS`] because
/// the process runner resolves its own tools without the wrappers.
const WRAPPERS_BIN: &str = "/run/wrappers/bin";

/// Description applied to every detached transient unit.
///
/// `systemd-run` otherwise derives the unit's description (and, without an
/// explicit `--unit`, its name) from the command line, so PID 1 would log the
/// hidden-root binary path and the `activate`/`deactivate` verb into the decoy
/// journal. A fixed, generic description keeps the activate and deactivate
/// workers indistinguishable from any other transient maintenance unit, and
/// omitting `--unit` lets systemd auto-name them `run-u<NNN>.service` with no
/// product string at all.
const NEUTRAL_UNIT_DESCRIPTION: &str = "System maintenance task";

/// Opt-in debug escape hatch: send the detached worker's stdout/stderr to the
/// journal instead of discarding it.
///
/// Off by default, the hidden-root file log is the worker's only sink, so
/// nothing identifying reaches the decoy journal before `/var` is overlaid. An
/// operator who needs to debug a failing handoff can set this to route the
/// worker's streams back to the journal.
const DETACH_DEBUG_JOURNAL_ENV: &str = "NAILS_DETACH_DEBUG_JOURNAL";

// Test-only override hooks. Compiled in only under the `test-hooks` feature (and
// this crate's own `cfg(test)` builds), so a shipped binary neither reads them
// nor carries the strings.
#[cfg(any(test, feature = "test-hooks"))]
const SYSTEMD_RUN_OVERRIDE_ENV: &str = "NAILS_SYSTEMD_RUN_PATH";
#[cfg(any(test, feature = "test-hooks"))]
const SHELL_CLEANUP_PROTECTED_PIDS_ENV: &str = "NAILS_SHELL_CLEANUP_PROTECTED_PIDS";

/// The process-exit chokepoint.
///
/// `main` turns a handler's [`crate::cli::output::ExitStatus`] into a
/// [`std::process::ExitCode`] and returns it, so this is the only place in the
/// binary that exits the process directly: the detach parent below hands off to
/// a transient service and leaves, and the test-harness subprocess entrypoints
/// reuse it to terminate the child with a handler's code.
pub(crate) fn exit_process(code: u8) -> ! {
    std::process::exit(i32::from(code));
}

/// Install a panic hook that keeps source paths out of the decoy journal.
///
/// The default hook prints `thread '…' panicked at <crate>/<file>:<line>` to
/// stderr. For a detached worker whose stderr is wired to the journal that would
/// leak the crate layout, and a panic payload can carry a hidden-root path. This
/// hook instead sends the full payload and location only through `tracing`
/// (whose active sink is the hidden-root file log for the commands that write
/// one) and prints a single neutral line, with no path, crate name or payload,
/// to stderr. It deliberately does not chain to the previous hook, so the
/// default path-bearing line is never emitted.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        tracing::error!(target: "panic", detail = %info, "aborted by an internal error");
        eprintln!("A fatal internal error occurred; the operation was aborted.");
    }));
}

/// Choose where the detached worker's stdout/stderr go.
///
/// Defaults to discarding both so the hidden-root file log is the only sink and
/// nothing identifying reaches the decoy journal; the journal is used only when
/// the debug escape hatch is set.
fn apply_worker_stdio(cmd: &mut Command) {
    if env::var_os(DETACH_DEBUG_JOURNAL_ENV).is_some() {
        cmd.arg("--property=StandardOutput=journal");
        cmd.arg("--property=StandardError=journal");
    } else {
        cmd.arg("--property=StandardOutput=null");
        cmd.arg("--property=StandardError=null");
    }
}

fn maybe_exit_after_detach(
    mut cmd: Command,
    report_success: impl FnOnce(),
) -> Result<(), NailsError> {
    let output = cmd
        .output()
        .map_err(|e| NailsError::InvalidState(format!("Failed to execute systemd-run: {}", e)))?;

    if !output.status.success() {
        return Err(NailsError::InvalidState(format!(
            "systemd-run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    report_success();

    exit_process(0);
}

/// Report a successful activation handoff to the detached worker.
///
/// Under `--json` the parent emits one final success envelope whose
/// `data.status` is `"detached"`; otherwise it prints the follow-up command
/// with the absolute binary path so the operator can check progress after the
/// session restarts.
fn report_session_detach(exe_path: &Path, json: bool) {
    if json {
        #[derive(serde::Serialize)]
        struct DetachedData {
            status: &'static str,
        }
        crate::cli::output::envelope::Envelope::success(
            "activate",
            DetachedData { status: "detached" },
        )
        .print();
    } else {
        eprintln!("Detached to background via systemd transient service.");
        eprintln!("Activation continues in the background after your session restarts.");
        eprintln!(
            "Run 'sudo {} status' to check progress.",
            exe_path.display()
        );
    }
}

fn should_skip_detach() -> bool {
    env::var_os(ENV_SKIP_DETACH).is_some()
}

/// The `journalctl --relinquish-var` command run before a detach handoff.
///
/// Resolved through [`nails_core::process::Program::Tool`], so it comes from the
/// same fixed, root-owned system directories the process runner uses, never from
/// the caller's `PATH`.
fn journal_relinquish_command() -> ProcessCommand {
    ProcessCommand::tool("journalctl").arg("--relinquish-var")
}

/// Hand the persistent journal back to volatile storage before detaching.
///
/// `journalctl --relinquish-var` makes journald stop writing to the on-disk
/// `/var/log/journal` and buffer to the volatile `/run/log/journal` instead, so
/// nothing lands on the persistent decoy journal between this handoff and the
/// point the detached worker overlays `/var`. Best-effort and deliberately
/// ordered before the `systemd-run` spawn below: a host without a persistent
/// journal (or without journald, or a test runtime where the runner refuses host
/// commands) simply has nothing to relinquish.
fn relinquish_journal_before_detach() {
    if let Err(err) = RealProcessRunner.run(&journal_relinquish_command()) {
        tracing::debug!(%err, "journalctl --relinquish-var before detach was skipped");
    }
}

/// Resolve the `systemd-run` program to execute for a detach handoff.
///
/// Shipped builds always use the real `systemd-run`. Test and E2E builds instead
/// honour `NAILS_SYSTEMD_RUN_PATH` (a fake recorder) or `NAILS_UNSAFE_REAL_OPS=1`
/// (an explicit opt-in to the real binary), and otherwise refuse to start a
/// transient unit at all — so a bare `cargo test` can never spawn one even though
/// the hooks are compiled in.
#[cfg(any(test, feature = "test-hooks"))]
fn systemd_run_program() -> Result<OsString, NailsError> {
    if let Some(path) = env::var_os(SYSTEMD_RUN_OVERRIDE_ENV) {
        return Ok(path);
    }

    if env::var("NAILS_UNSAFE_REAL_OPS").unwrap_or_default() == "1" {
        return Ok(OsString::from("systemd-run"));
    }

    Err(NailsError::InvalidState(format!(
        "Refusing to start transient systemd units from a test runtime; set {} to a fake systemd-run, set {}=1 to bypass detach, or set NAILS_UNSAFE_REAL_OPS=1 to allow real host operations",
        SYSTEMD_RUN_OVERRIDE_ENV, ENV_SKIP_DETACH
    )))
}

#[cfg(not(any(test, feature = "test-hooks")))]
fn systemd_run_program() -> Result<OsString, NailsError> {
    Ok(OsString::from("systemd-run"))
}

/// Forward the operator's identity across the `systemd-run` boundary so the
/// detached worker acts for the same account this invocation did.
///
/// This is the one place that turns the raw escalation environment into NAILS's
/// own identity variables: it resolves the operator once through
/// [`nails_core::TargetUser`] — the single source of truth for who NAILS acts on
/// behalf of — and forwards the resolved numeric uid and login name as
/// `NAILS_TARGET_UID` / `NAILS_TARGET_USER`. The detached worker then reads only
/// those; the escalation variables themselves are not preserved across the
/// transient-unit boundary. When no operator can be resolved (detach may run
/// before any escalation context is established) nothing is forwarded and the
/// worker resolves for itself.
fn set_target_identity_from_environment(cmd: &mut Command) {
    if let Ok(user) = nails_core::TargetUser::resolve() {
        cmd.arg(format!("--setenv={}={}", ENV_TARGET_UID, user.uid));
        cmd.arg(format!("--setenv={}={}", ENV_TARGET_USER, user.name));
    }
}

/// Forward the test-only protected-PID handoff across the `systemd-run` boundary.
///
/// Nothing sets `NAILS_SHELL_CLEANUP_PROTECTED_PIDS` in production, so this is a
/// no-op in shipped builds; the tests use it to inject the PIDs that shell
/// cleanup must spare.
#[cfg(any(test, feature = "test-hooks"))]
fn propagate_shell_cleanup_protection(cmd: &mut Command) {
    if let Some(protected) = env::var_os(SHELL_CLEANUP_PROTECTED_PIDS_ENV) {
        cmd.arg(format!(
            "--setenv={}={}",
            SHELL_CLEANUP_PROTECTED_PIDS_ENV,
            protected.to_string_lossy()
        ));
    }
}

#[cfg(not(any(test, feature = "test-hooks")))]
fn propagate_shell_cleanup_protection(_cmd: &mut Command) {}

fn is_already_detached() -> bool {
    env::var_os(ENV_DETACHED).is_some()
}

/// Build the fixed `PATH` for the detached worker unit.
///
/// The worker re-execs this binary as root, so whatever `PATH` the unit carries
/// decides which tools that root process resolves by name. Deriving it from the
/// caller's `PATH` would let a lower-privileged invoker's profile directories
/// steer a root child, which is exactly the hijack this item removes. The result
/// is therefore a fixed, root-owned search path, independent of the invoking
/// environment: the NixOS setuid wrappers (`/run/wrappers/bin`, not part of
/// [`SYSTEM_TOOL_DIRS`]) first, then the same root-owned directories the process
/// runner itself resolves [`nails_core::process::Program::Tool`] from.
fn detached_path_env() -> OsString {
    let mut dirs: Vec<PathBuf> = Vec::with_capacity(SYSTEM_TOOL_DIRS.len() + 1);
    dirs.push(PathBuf::from(WRAPPERS_BIN));
    dirs.extend(SYSTEM_TOOL_DIRS.iter().map(PathBuf::from));

    env::join_paths(&dirs).unwrap_or_else(|_| {
        // Every member is a static, colon- and NUL-free path, so `join_paths`
        // cannot fail in practice; joining the same dirs by hand keeps the result
        // total without re-spelling the search path as a literal.
        OsString::from(
            dirs.iter()
                .map(|dir| dir.to_string_lossy())
                .collect::<Vec<_>>()
                .join(":"),
        )
    })
}

/// Detach using systemd-run to create a transient service in system.slice.
///
/// Creates a proper one-shot service that runs independently of any user session.
pub fn maybe_detach_for_session_kill(
    kill_session: bool,
    args: &[OsString],
    session_ctx: Option<&SessionContext>,
    json: bool,
) -> Result<(), NailsError> {
    // Testing override: allow tests to bypass actual detaching/spawn.
    if should_skip_detach() {
        return Ok(());
    }

    // Only detach when a session kill is requested and we look like a GUI session.
    if !kill_session {
        return Ok(());
    }

    // Prevent recursion - if already detached, just continue.
    if is_already_detached() {
        return Ok(());
    }

    // Allow integration tests or users to force detaching for safety.
    let force_detach = env::var_os(ENV_FORCE_DETACH).is_some();

    if !force_detach {
        // Prefer logind-aware detection to avoid detaching from TTY/SSH.
        if let Some(ctx) = session_ctx {
            if ctx.kind != SessionKind::GraphicalUser {
                return Ok(());
            }
        } else if let Ok(ctx) = detect_session_context(&RealSessionCommandExecutor) {
            if ctx.kind != SessionKind::GraphicalUser {
                return Ok(());
            }
        } else {
            // If detection fails, fall back to env markers.
            if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
                return Ok(());
            }
        }
    }

    // Get the current binary path
    let exe_path = std::env::current_exe().map_err(|e| {
        NailsError::InvalidState(format!("Failed to get current executable path: {}", e))
    })?;

    // Relinquish the persistent journal before handing off, so journald is not
    // still writing to the base /var/log/journal while the worker prepares to
    // overlay /var.
    relinquish_journal_before_detach();

    // Build systemd-run command.
    //
    // No --scope flag creates a proper transient service, and no --unit lets
    // systemd auto-name it `run-u<NNN>.service` so the product name never reaches
    // the journal; the neutral --description hides the hidden-root command line.
    let mut cmd = Command::new(systemd_run_program()?);
    cmd.arg("--slice=system.slice")
        .arg("--same-dir") // Keep current working directory
        .arg("--collect") // Clean up unit after it finishes
        .arg("--quiet")
        .arg(format!("--description={NEUTRAL_UNIT_DESCRIPTION}"))
        // Survive an OOM kill of a child (e.g. the nix evaluator): with the
        // default DefaultOOMPolicy=stop, a cgroup OOM kill of any process in the
        // unit would stop the whole transient service and abandon the activation
        // mid-flight. `continue` keeps the unit — and the nails worker driving the
        // rollback — alive so the kill is survivable.
        .arg("--property=OOMPolicy=continue");

    // Set environment variables for the service
    cmd.arg(format!("--setenv={}=1", ENV_DETACHED));
    cmd.arg("--setenv=XDG_SESSION_ID="); // Clear session tracking

    // Give the worker a fixed, root-owned PATH so the root child resolves its
    // tools from system directories, not from the caller's PATH. No NIX_*
    // variable is forwarded: the hidden build is a flake build run with
    // `--impure`, which ignores NIX_PATH, and forwarding the caller's Nix
    // configuration would let it steer evaluation inside the root worker.
    cmd.arg(format!(
        "--setenv=PATH={}",
        detached_path_env().to_string_lossy()
    ));

    if let Some(ctx) = session_ctx
        && ctx.kind == SessionKind::GraphicalUser
    {
        if let Some(ref session_id) = ctx.session_id {
            cmd.arg(format!("--setenv={}={}", ENV_SESSION_ID, session_id));
        }
        if let Some(ref dm) = ctx.display_manager {
            cmd.arg(format!("--setenv={}={}", ENV_DISPLAY_MANAGER, dm));
        }
        if let Some(uid) = ctx.target_uid {
            cmd.arg(format!("--setenv={}={}", ENV_TARGET_UID, uid));
        }
        if let Some(ref user) = ctx.target_user {
            cmd.arg(format!("--setenv={}={}", ENV_TARGET_USER, user));
        }
        cmd.arg(format!(
            "--setenv={}={}",
            ENV_LOGIND_AVAILABLE,
            if ctx.logind_available { "1" } else { "0" }
        ));
    }

    set_target_identity_from_environment(&mut cmd);

    // Discard the worker's streams by default so nothing identifying reaches the
    // decoy journal; the hidden-root file log is the sink.
    apply_worker_stdio(&mut cmd);

    // Add the command to execute
    cmd.arg("--");
    cmd.arg(&exe_path);
    cmd.args(args.iter().skip(1));

    // Execute systemd-run
    maybe_exit_after_detach(cmd, || report_session_detach(&exe_path, json))
}

/// Detach deactivation to a transient service so shell cleanup cannot kill the caller.
pub fn maybe_detach_for_deactivation() -> Result<(), NailsError> {
    if should_skip_detach() || is_already_detached() {
        return Ok(());
    }

    // Deactivation should run synchronously in the invoking context by default.
    // Detached transient services are opt-in only.
    let force_detach = env::var_os(ENV_FORCE_DETACH).is_some();
    if !force_detach {
        return Ok(());
    }

    let exe_path = std::env::current_exe().map_err(|e| {
        NailsError::InvalidState(format!("Failed to get current executable path: {}", e))
    })?;

    let argv: Vec<OsString> = std::env::args_os().collect();

    // Relinquish the persistent journal before handing off (see the session-kill
    // path above for the rationale).
    relinquish_journal_before_detach();

    // No --unit (systemd auto-names `run-u<NNN>.service`) and a neutral
    // --description keep the product name and hidden-root command line out of the
    // journal.
    let mut cmd = Command::new(systemd_run_program()?);
    cmd.arg("--slice=system.slice")
        .arg("--collect")
        .arg("--quiet")
        .arg(format!("--description={NEUTRAL_UNIT_DESCRIPTION}"))
        // Survive an OOM kill of a child so a teardown unit is never abandoned
        // half-done; see the activation path above for the rationale.
        .arg("--property=OOMPolicy=continue")
        .arg("--working-directory=/")
        .arg(format!("--setenv={}=1", ENV_DETACHED))
        .arg("--setenv=XDG_SESSION_ID=")
        .arg(format!(
            "--setenv=PATH={}",
            detached_path_env().to_string_lossy()
        ));

    // Discard the worker's streams by default; the hidden-root file log is the
    // sink. Must precede the `--` separator below.
    apply_worker_stdio(&mut cmd);

    cmd.arg("--").arg(&exe_path).args(argv.iter().skip(1));

    set_target_identity_from_environment(&mut cmd);
    propagate_shell_cleanup_protection(&mut cmd);

    maybe_exit_after_detach(cmd, || {
        eprintln!("Detached to background via systemd transient service.");
        eprintln!("Handoff complete; deactivation continues in background.");
    })
}

/// Run an external backend-close command as a journal-free detached transient
/// unit.
///
/// Used for the emergency `[emergency] close_command` opt-in: a backend that is
/// not device-mapper based (so deferred `dmsetup` removal cannot reach it) is
/// closed by an explicit argv, with no shell. It runs through the same
/// `systemd-run` handoff the activate/deactivate workers use so its streams are
/// discarded (`StandardOutput`/`StandardError=null`) and PID 1 logs only the
/// neutral unit description — the command line, which may name the backend, never
/// reaches the decoy journal. Unlike the worker handoffs this does not re-exec
/// NAILS and does not exit the process: it dispatches the unit and returns, so
/// the caller can report the result and continue the teardown.
///
/// The debug escape hatch is deliberately not honoured here: the close command's
/// argv can carry a backend path, so its streams are always discarded regardless
/// of `NAILS_DETACH_DEBUG_JOURNAL`.
pub fn run_detached_close_command(argv: &[String]) -> Result<(), NailsError> {
    if argv.is_empty() {
        return Err(NailsError::InvalidState(
            "close_command is empty; nothing to run".to_string(),
        ));
    }

    let mut cmd = Command::new(systemd_run_program()?);
    cmd.arg("--slice=system.slice")
        .arg("--collect")
        .arg("--quiet")
        .arg(format!("--description={NEUTRAL_UNIT_DESCRIPTION}"))
        .arg("--working-directory=/")
        .arg(format!(
            "--setenv=PATH={}",
            detached_path_env().to_string_lossy()
        ))
        // Always discard the streams: the close command's argv may name the
        // backend, so the debug journal escape hatch must not reroute it.
        .arg("--property=StandardOutput=null")
        .arg("--property=StandardError=null")
        .arg("--");
    cmd.args(argv);

    let output = cmd.output().map_err(|e| {
        NailsError::InvalidState(format!("Failed to execute the close command: {}", e))
    })?;

    if !output.status.success() {
        return Err(NailsError::InvalidState(format!(
            "close command transient unit failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
