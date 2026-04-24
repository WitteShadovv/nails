use super::command_cache::{command_failed_error, systemctl_command};
use std::path::PathBuf;

#[cfg(test)]
use std::path::Path;

fn run_systemctl(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    systemctl_command().spawn_output(args)
}

fn run_nix_daemon(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    std::process::Command::new(
        super::NIX_DAEMON_PATH
            .get()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/run/current-system/sw/bin/nix-daemon")),
    )
    .args(args)
    .output()
}

fn run_nix(args: &[&str]) -> std::result::Result<std::process::Output, std::io::Error> {
    std::process::Command::new(
        super::NIX_COMMAND_PATH
            .get()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("/run/current-system/sw/bin/nix")),
    )
    .args(args)
    .output()
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
        let output = run_nix(&[
            "--extra-experimental-features",
            "nix-command",
            "store",
            "ping",
            "--store",
            "daemon",
        ])?;

        if output.status.success() {
            return Ok(());
        }

        last_error = Some(command_failed_error(
            "nix --extra-experimental-features nix-command store ping --store daemon",
            &output,
        ));
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
    let deadline = std::time::Instant::now() + timeout;
    let mut last_error = None;

    while std::time::Instant::now() < deadline {
        let output = run_systemctl(&["is-active", unit])?;
        if output.status.success() {
            return Ok(());
        }

        last_error = Some(command_failed_error(
            &format!("systemctl is-active {unit}"),
            &output,
        ));
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

    /// Start nix-daemon: start socket (which activates service on demand),
    /// then start the service directly as well. Best-effort.
    #[allow(dead_code)]
    pub fn start_nix_daemon() {
        Self::start_service_and_socket("nix-daemon");
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

    /// Restart nix-daemon: stop then start.
    #[allow(dead_code)]
    pub fn restart_nix_daemon() {
        let _ = Self::stop_nix_daemon();
        Self::start_nix_daemon();
    }

    /// Start a systemd service and its socket (socket first), best-effort.
    pub fn start_service_and_socket(service: &str) {
        if Self::should_skip() {
            return;
        }

        tracing::debug!(service, "Starting {}.socket", service);
        let socket_name = format!("{}.socket", service);
        let _ = run_systemctl(&["start", socket_name.as_str()]);

        tracing::debug!(service, "Starting {}", service);
        let _ = run_systemctl(&["start", service]);
    }

    /// Best-effort restart of services that were stopped during overlay mounting
    /// when the mount ultimately fails. Starts both socket and service for each.
    pub fn restart_services_after_failure(services: &[String]) {
        if Self::should_skip() {
            tracing::debug!(
                "Skipping service restart commands in test/test-like context to avoid host interaction"
            );
            return;
        }

        for service in services {
            Self::start_service_and_socket(service);
        }
    }
}

/// Legacy wrapper — delegates to [`ServiceController::start_service_and_socket`].
pub(crate) fn start_service_and_socket(service: &str) {
    ServiceController::start_service_and_socket(service);
}

#[cfg(test)]
mod tests {
    use super::wait_for_unix_socket_ready;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn wait_for_unix_socket_ready_returns_when_listener_appears() {
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
