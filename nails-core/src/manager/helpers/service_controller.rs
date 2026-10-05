// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::command_cache::{command_failed_error, runner_error_to_io, systemctl_command};
use crate::process::run::{
    NIX_STORE_PING_BUDGET, ProcessCommand, ProcessRunner, RealProcessRunner, systemctl_budget,
};

#[cfg(test)]
use std::path::Path;

/// Run a prepared command through the shared runner, translating its error into
/// the `io::Error` these helpers speak.
fn run_command(
    command: &ProcessCommand,
) -> std::result::Result<std::process::Output, std::io::Error> {
    RealProcessRunner.run(command).map_err(runner_error_to_io)
}

/// A per-call deadline bounded by what remains in the outer retry loop.
///
/// Capping at `cap` keeps each attempt short, while capping at the remaining loop
/// time keeps a single attempt from outliving the loop's own budget — so one hung
/// `is-active` or `store ping` can never freeze the loop. The small floor lets a
/// nearly-expired loop still issue one real attempt.
fn per_call_deadline(
    loop_deadline: std::time::Instant,
    cap: std::time::Duration,
) -> std::time::Duration {
    loop_deadline
        .saturating_duration_since(std::time::Instant::now())
        .min(cap)
        .max(std::time::Duration::from_millis(50))
}

/// Test-only recorder for service lifecycle actions.
///
/// In a test or runtime-safety context the real `systemctl` calls are skipped,
/// so there is otherwise no way to observe that a restart happened. This
/// per-thread log lets unit tests assert that teardown and rollback paths
/// restart the services they must (e.g. nix-daemon and journald) in the right
/// order. Deactivation and rollback run synchronously on the calling thread.
#[cfg(test)]
pub(crate) mod recorder {
    use std::cell::RefCell;

    thread_local! {
        static ACTIONS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn record(action: impl Into<String>) {
        ACTIONS.with(|actions| actions.borrow_mut().push(action.into()));
    }

    /// Take and clear the recorded actions for the current thread.
    pub(crate) fn drain() -> Vec<String> {
        ACTIONS.with(|actions| std::mem::take(&mut *actions.borrow_mut()))
    }
}

fn run_systemctl(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    run_command(
        &systemctl_command()
            .to_process_command(args)
            .deadline(systemctl_budget(args)),
    )
}

/// Parse the unit names from `systemctl list-units … --no-legend --plain`
/// output: the first whitespace-separated column of each non-empty line.
fn parse_active_units(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Run `journalctl` with the given arguments through the shared runner.
///
/// Resolved through the trust-checked host-tool resolver at call time: the
/// journal control verbs run after `/var` is overlaid but `journalctl` itself
/// lives outside `/var` (the system profile on NixOS, `/usr/bin` on an FHS
/// host), so no pre-overlay cache is needed. Bounded by a short deadline so a
/// hung flush cannot freeze activation.
fn run_journalctl(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    let path = super::command_cache::nixos_tool_path("journalctl");
    run_command(
        &ProcessCommand::exact(path)
            .args(args)
            .deadline(std::time::Duration::from_secs(30)),
    )
}

/// The cached `nix` command, resolved against the pre-overlay store when set.
fn nix_command(args: &[&str]) -> ProcessCommand {
    let path = super::NIX_COMMAND_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| super::command_cache::nixos_tool_path("nix"));
    ProcessCommand::exact(path).args(args)
}

/// Start the daemon. No deadline: `nix-daemon --daemon` daemonises and returns,
/// and bounding the launch of the daemon itself serves no purpose.
fn run_nix_daemon(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    let path = super::NIX_DAEMON_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| super::command_cache::nixos_tool_path("nix-daemon"));
    run_command(&ProcessCommand::exact(path).args(args))
}

fn ensure_systemctl_success(args: &[&str]) -> std::result::Result<(), std::io::Error> {
    let output = run_systemctl(args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_failed_error(
            &format!("systemctl {}", args.join(" ")),
            &output,
        ))
    }
}

fn io_context_error(context: &str, err: std::io::Error) -> std::io::Error {
    std::io::Error::new(err.kind(), format!("{context}: {err}"))
}

fn wait_for_nix_daemon_ping(
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> std::result::Result<(), std::io::Error> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last_error = None;

    while std::time::Instant::now() < deadline {
        // Each ping is bounded strictly below the loop budget, so a hung daemon
        // cannot freeze the loop: a timed-out ping is just a failed attempt.
        let ping = nix_command(&[
            "--extra-experimental-features",
            "nix-command",
            "store",
            "ping",
            "--store",
            "daemon",
        ])
        .deadline(per_call_deadline(deadline, NIX_STORE_PING_BUDGET));

        match run_command(&ping) {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(command_failed_error(
                    "nix --extra-experimental-features nix-command store ping --store daemon",
                    &output,
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => last_error = Some(err),
            Err(err) => return Err(err),
        }
        std::thread::sleep(poll_interval);
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timed out waiting for nix-daemon ping to succeed",
        )
    }))
}

fn list_process_ids_by_comm(process_name: &str) -> std::result::Result<Vec<i32>, std::io::Error> {
    let mut pids = Vec::new();

    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_string_lossy().parse::<i32>().ok() else {
            continue;
        };

        let comm_path = entry.path().join("comm");
        let Ok(comm) = std::fs::read_to_string(&comm_path) else {
            continue;
        };

        if comm.trim() == process_name {
            pids.push(pid);
        }
    }

    Ok(pids)
}

fn terminate_processes_by_comm(process_name: &str) -> std::result::Result<(), std::io::Error> {
    let pids = list_process_ids_by_comm(process_name)?;
    if pids.is_empty() {
        return Ok(());
    }

    for pid in &pids {
        let result = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(*pid),
            nix::sys::signal::Signal::SIGTERM,
        );
        if let Err(err) = result
            && err != nix::errno::Errno::ESRCH
        {
            return Err(std::io::Error::other(format!(
                "failed to terminate process {pid} ({process_name}): {err}"
            )));
        }
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let remaining = list_process_ids_by_comm(process_name)?;
        if remaining.is_empty() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Timed out waiting for {process_name} to exit"),
    ))
}

fn wait_for_systemd_unit_active(
    unit: &str,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> std::result::Result<(), std::io::Error> {
    use crate::process::run::SYSTEMCTL_PROBE_BUDGET;

    let deadline = std::time::Instant::now() + timeout;
    let mut last_error = None;

    while std::time::Instant::now() < deadline {
        // Bound each probe strictly below the loop budget so a hung is-active
        // cannot freeze the loop; a timed-out probe is treated as not-yet-active.
        let probe = systemctl_command()
            .to_process_command(&["is-active", unit])
            .deadline(per_call_deadline(deadline, SYSTEMCTL_PROBE_BUDGET));

        match run_command(&probe) {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_error = Some(command_failed_error(
                    &format!("systemctl is-active {unit}"),
                    &output,
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => last_error = Some(err),
            Err(err) => return Err(err),
        }
        std::thread::sleep(poll_interval);
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("Timed out waiting for systemd unit {unit} to become active"),
        )
    }))
}

#[cfg(test)]
fn wait_for_unix_socket_ready(
    socket_path: &Path,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> std::result::Result<(), std::io::Error> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last_error = None;

    while std::time::Instant::now() < deadline {
        match std::os::unix::net::UnixStream::connect(socket_path) {
            Ok(_) => return Ok(()),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                last_error = Some(err);
                std::thread::sleep(poll_interval);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Timed out waiting for Unix socket readiness at {}",
                socket_path.display()
            ),
        )
    }))
}

/// Centralized socket-aware service lifecycle control.
///
/// All systemd service start/stop operations should go through this struct
/// to ensure consistent ordering: stop socket BEFORE service, start socket
/// to activate service.
pub(crate) struct ServiceController;

impl ServiceController {
    /// Returns true when running in a test or test-like context where
    /// host interaction (systemctl, etc.) should be skipped.
    fn should_skip() -> bool {
        crate::runtime_safety::should_skip_host_interaction()
    }

    /// Stop nix-daemon: stop socket first (prevents socket-activation restart),
    /// then stop the service. Best-effort — errors are logged but returned so
    /// callers can decide how to handle them.
    pub fn stop_nix_daemon() -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            #[cfg(test)]
            recorder::record("stop:nix-daemon");
            tracing::debug!(
                "Skipping nix-daemon stop commands in test/test-like context to avoid host interaction"
            );
            return Ok(());
        }

        tracing::info!("Stopping nix-daemon.socket...");
        let _ = run_systemctl(&["stop", "nix-daemon.socket"])?;

        tracing::info!("Stopping nix-daemon.service...");
        let _ = run_systemctl(&["stop", "nix-daemon.service"])?;

        terminate_processes_by_comm("nix-daemon")
            .map_err(|err| io_context_error("stopping lingering nix-daemon processes", err))?;

        Ok(())
    }

    pub fn start_nix_daemon_and_wait() -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            return Ok(());
        }

        // After overlaying /nix, systemd may report the nix-daemon service unit as
        // changed-on-disk. Starting the socket and letting socket activation bring
        // the daemon back avoids that false-negative while still proving the daemon
        // is active and serving requests from the overlaid view.
        tracing::debug!("Starting nix-daemon.socket");
        ensure_systemctl_success(&["start", "nix-daemon.socket"])
            .map_err(|err| io_context_error("starting nix-daemon.socket", err))?;
        wait_for_systemd_unit_active(
            "nix-daemon.socket",
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(100),
        )
        .map_err(|err| io_context_error("waiting for nix-daemon.socket to become active", err))?;

        if wait_for_nix_daemon_ping(
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(100),
        )
        .is_ok()
        {
            return Ok(());
        }

        tracing::warn!(
            "Socket activation did not yield a usable nix-daemon; falling back to manual daemon startup"
        );

        let _ = run_systemctl(&["stop", "nix-daemon.socket"]);
        let _ = run_systemctl(&["stop", "nix-daemon.service"]);
        let _ = run_systemctl(&["reset-failed", "nix-daemon.service", "nix-daemon.socket"]);

        let output = run_nix_daemon(&["--daemon"])
            .map_err(|err| io_context_error("starting nix-daemon manually", err))?;
        if !output.status.success() {
            return Err(io_context_error(
                "starting nix-daemon manually",
                command_failed_error("nix-daemon --daemon", &output),
            ));
        }

        wait_for_nix_daemon_ping(
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(100),
        )
        .map_err(|err| io_context_error("waiting for manual nix-daemon startup", err))?;

        Ok(())
    }

    /// Start a systemd service and its socket.
    ///
    /// The socket is started first so socket activation can bring the service up;
    /// a service with no `.socket` unit is expected and does not fail the call. A
    /// failure to start the *service* is returned rather than discarded, so a
    /// caller that cannot tolerate a dead service surfaces it; the best-effort
    /// recovery wrappers below log it and carry on.
    pub fn start_service_and_socket(service: &str) -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            #[cfg(test)]
            recorder::record(format!("start:{service}"));
            return Ok(());
        }

        let socket_name = format!("{service}.socket");
        tracing::debug!(service, "Starting {socket_name}");
        if let Err(err) = ensure_systemctl_success(&["start", socket_name.as_str()]) {
            // Not every service has a socket unit; a missing socket is normal and
            // only noted, since the service start below is what matters.
            tracing::debug!(service, %err, "socket start failed (service may have no socket unit)");
        }

        tracing::debug!(service, "Starting {service}");
        ensure_systemctl_success(&["start", service])
            .map_err(|err| io_context_error(&format!("starting {service}"), err))
    }

    /// Restart a service and its socket: stop the socket first (so socket
    /// activation cannot race the restart), stop the service, then start the
    /// socket and service again.
    ///
    /// Unlike [`start_service_and_socket`](Self::start_service_and_socket), this
    /// forces an *already-active* unit to tear down and reopen. systemd-journald
    /// re-homing relies on that: a plain `start` on the still-running journald is
    /// a no-op that leaves it holding the pre-overlay `/var/log/journal` file
    /// descriptors, so the hidden session's records keep landing on the decoy
    /// disk; a restart makes journald close those fds and reopen under the
    /// freshly mounted overlay.
    pub fn restart_service_and_socket(service: &str) -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            #[cfg(test)]
            {
                recorder::record(format!("stop:{service}.socket"));
                recorder::record(format!("stop:{service}"));
                recorder::record(format!("start:{service}.socket"));
                recorder::record(format!("start:{service}"));
            }
            return Ok(());
        }

        let socket_name = format!("{service}.socket");
        tracing::debug!(service, "Stopping {socket_name} before restart");
        let _ = run_systemctl(&["stop", socket_name.as_str()]);
        tracing::debug!(service, "Stopping {service} before restart");
        let _ = run_systemctl(&["stop", service]);

        Self::start_service_and_socket(service)
    }

    /// Hand the persistent journal back to volatile storage.
    ///
    /// `journalctl --relinquish-var` makes journald stop writing to the on-disk
    /// `/var/log/journal` and flush to the volatile `/run/log/journal` instead,
    /// so no further records land on the persistent decoy journal between here
    /// and the point `/var` is overlaid. Best-effort: a host without a persistent
    /// journal (or without journald) simply has nothing to relinquish.
    pub fn relinquish_journal_var() -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            #[cfg(test)]
            recorder::record("journalctl:relinquish-var");
            return Ok(());
        }

        run_journalctl(&["--relinquish-var"]).map(|_| ())
    }

    /// Flush volatile journal records into the persistent journal.
    ///
    /// Run after `/var` is overlaid and journald has reopened: `journalctl
    /// --flush` moves anything journald buffered in `/run/log/journal` into
    /// `/var/log/journal`, which now resolves into the overlay upper, so those
    /// records never touch the decoy disk.
    pub fn flush_journal() -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            #[cfg(test)]
            recorder::record("journalctl:flush");
            return Ok(());
        }

        run_journalctl(&["--flush"]).map(|_| ())
    }

    /// Rotate the active journal files so journald closes them.
    ///
    /// `journalctl --rotate` makes journald archive the journals it currently has
    /// open and start fresh ones. At teardown, after journald has been restarted
    /// onto the decoy `/var`, rotating forces it to close the active runtime files
    /// under `/run/log/journal` before they are removed, so the removal does not
    /// orphan inodes journald still holds open. Best-effort: a host without
    /// journald simply has nothing to rotate.
    pub fn rotate_journal() -> std::result::Result<(), std::io::Error> {
        if Self::should_skip() {
            #[cfg(test)]
            recorder::record("journalctl:rotate");
            return Ok(());
        }

        run_journalctl(&["--rotate"]).map(|_| ())
    }

    /// List every service unit the host already knows about, active or not.
    ///
    /// The union of `systemctl list-unit-files --type=service` (units with a unit
    /// file on disk) and `systemctl list-units --type=service --all` (every loaded
    /// unit, including inactive and transient ones). Activation takes this
    /// snapshot *before* the hidden switch: a unit counts as hidden-added only if
    /// it is active afterwards and was not known at all beforehand. Comparing
    /// presence rather than active state means a base service that merely
    /// restarts while the overlays settle — inactive for an instant, but loaded
    /// and backed by a decoy unit file — is never mistaken for one the hidden
    /// generation brought up. Returns an empty list where host interaction is
    /// skipped.
    pub fn list_known_units() -> Vec<String> {
        if Self::should_skip() {
            return Vec::new();
        }

        let mut known: Vec<String> = Vec::new();
        for args in [
            &[
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--plain",
                "--no-pager",
            ][..],
            &[
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--plain",
                "--no-pager",
            ][..],
        ] {
            if let Ok(output) = run_systemctl(args)
                && output.status.success()
            {
                for unit in parse_active_units(&output.stdout) {
                    if !known.contains(&unit) {
                        known.push(unit);
                    }
                }
            }
        }
        known
    }

    /// List the names of the currently active service units.
    ///
    /// Runs `systemctl list-units --type=service --state=active --no-legend
    /// --plain` and returns the first column (the unit name) of each line.
    /// Activation snapshots this before and after the hidden switch so emergency
    /// teardown knows exactly which units the hidden generation brought up.
    /// Returns an empty list in test/test-like contexts, where host interaction
    /// is skipped.
    pub fn list_active_units() -> Vec<String> {
        if Self::should_skip() {
            return Vec::new();
        }

        match run_systemctl(&[
            "list-units",
            "--type=service",
            "--state=active",
            "--no-legend",
            "--plain",
            "--no-pager",
        ]) {
            Ok(output) if output.status.success() => parse_active_units(&output.stdout),
            Ok(_) | Err(_) => Vec::new(),
        }
    }

    /// Stop a single unit, socket before service.
    ///
    /// The paired `<unit>.socket` is stopped first so socket activation does not
    /// bring the service straight back; a unit with no socket simply has that
    /// best-effort step do nothing. Returns whether the service stop succeeded.
    /// Used by emergency teardown to end the services the hidden configuration
    /// added without a full decoy switch.
    pub fn stop_unit(unit: &str) -> bool {
        if Self::should_skip() {
            #[cfg(test)]
            {
                recorder::record(format!("stop:{unit}.socket"));
                recorder::record(format!("stop:{unit}"));
            }
            return true;
        }

        let socket_name = format!("{unit}.socket");
        let _ = run_systemctl(&["stop", socket_name.as_str()]);
        match run_systemctl(&["stop", unit]) {
            Ok(output) => output.status.success(),
            Err(err) => {
                tracing::warn!(unit, %err, "failed to stop hidden-session unit");
                false
            }
        }
    }

    /// Best-effort restart of services that were stopped during overlay mounting
    /// when the mount ultimately fails. Starts both socket and service for each,
    /// logging — never propagating — a failure so teardown always completes.
    pub fn restart_services_after_failure(services: &[String]) {
        if Self::should_skip() {
            tracing::debug!(
                "Skipping service restart commands in test/test-like context to avoid host interaction"
            );
            return;
        }

        for service in services {
            if let Err(err) = Self::start_service_and_socket(service) {
                tracing::warn!(service, %err, "failed to restart service after overlay failure");
            }
        }
    }
}

/// Best-effort wrapper around [`ServiceController::start_service_and_socket`].
///
/// The recovery and teardown call sites must always run to completion, so this
/// logs a failed start instead of propagating it — the error is surfaced, not
/// silently dropped as it was before.
pub(crate) fn start_service_and_socket(service: &str) {
    if let Err(err) = ServiceController::start_service_and_socket(service) {
        tracing::warn!(service, %err, "failed to start service");
    }
}

/// Best-effort wrapper around [`ServiceController::restart_service_and_socket`].
///
/// Teardown and re-home call sites must always run to completion, so a failed
/// restart is logged, not propagated.
pub(crate) fn restart_service_and_socket(service: &str) {
    if let Err(err) = ServiceController::restart_service_and_socket(service) {
        tracing::warn!(service, %err, "failed to restart service");
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_active_units, wait_for_unix_socket_ready};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn parse_active_units_takes_the_first_column() {
        let stdout = b"hidden-app.service    loaded active running A hidden GUI app\n\
                       display-manager.service loaded active running Display Manager\n";
        assert_eq!(
            parse_active_units(stdout),
            vec![
                "hidden-app.service".to_string(),
                "display-manager.service".to_string(),
            ]
        );
    }

    #[test]
    fn parse_active_units_ignores_blank_lines() {
        assert!(parse_active_units(b"").is_empty());
        assert!(parse_active_units(b"\n   \n").is_empty());
    }

    /// Probe whether this environment permits binding Unix-domain sockets.
    ///
    /// Restricted sandboxes deny `bind(2)` (EPERM/EACCES), so the socket
    /// readiness tests skip rather than fail there; a normal host binds the
    /// probe successfully and the tests run.
    fn unix_sockets_available() -> bool {
        let Ok(dir) = tempfile::tempdir() else {
            return false;
        };
        UnixListener::bind(dir.path().join("probe.sock")).is_ok()
    }

    #[test]
    fn wait_for_unix_socket_ready_returns_when_listener_appears() {
        if !unix_sockets_available() {
            eprintln!(
                "skipping Unix-socket readiness test: binding Unix sockets is not permitted here"
            );
            return;
        }

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let socket_path = temp_dir.path().join("daemon.sock");
        let socket_path_clone = socket_path.clone();

        let listener_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let listener = UnixListener::bind(&socket_path_clone).expect("bind listener");
            let _ = listener.accept();
        });

        wait_for_unix_socket_ready(
            &socket_path,
            Duration::from_secs(2),
            Duration::from_millis(20),
        )
        .expect("socket should become ready");

        listener_thread
            .join()
            .expect("listener thread should finish");
    }

    #[test]
    fn wait_for_unix_socket_ready_times_out_when_socket_never_appears() {
        if !unix_sockets_available() {
            eprintln!(
                "skipping Unix-socket timeout test: binding Unix sockets is not permitted here"
            );
            return;
        }

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let socket_path: PathBuf = temp_dir.path().join("missing.sock");

        let err = wait_for_unix_socket_ready(
            &socket_path,
            Duration::from_millis(150),
            Duration::from_millis(20),
        )
        .expect_err("missing socket should time out");

        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
            ),
            "unexpected error kind: {err:?}"
        );
    }
}
