//! The Nix-on-foreign `/nix` lifecycle.
//!
//! On a non-NixOS host that nonetheless has a `/nix` store — Nix installed on
//! Debian/Ubuntu — overlaying `/nix` still requires nix-daemon to be stopped
//! before the overlay (so it does not keep the pre-overlay store busy) and
//! restarted afterwards (so it serves from the overlaid view). None of the NixOS
//! security-model restoration applies here: there is no `/run/current-system`
//! generation to re-point and no boot-time read-only `/nix/store` bind to
//! recreate, so this module does *only* the daemon stop/start.
//!
//! The daemon is driven through the host's own `systemctl`, resolved from the
//! platform's command directories ([`host_command_dirs`]) rather than the NixOS
//! system-profile path, so the restart does not ENOENT on a Debian/Ubuntu host.
//!
//! This daemon cycle is a [`ServiceManager`] concern; it is kept here as a direct
//! `systemctl` sequence over the shared [`HostCommands`] resolver and process
//! runner because it predates that seam and rewiring it is deferred.
//!
//! [`host_command_dirs`]: super::Platform::host_command_dirs
//! [`ServiceManager`]: super::ServiceManager

use std::path::Path;

use crate::platform::HostCommands;
use crate::process::run::{ProcessCommand, ProcessRunner, RealProcessRunner, systemctl_budget};
use crate::{NailsError, Result};

/// Stop nix-daemon before `/nix` is overlaid on a non-NixOS host.
///
/// The socket is stopped first so socket-activation does not immediately bring
/// the daemon back, then the service. A missing unit is tolerated: on a host
/// where nix-daemon is not socket-activated the socket stop simply has no effect.
pub(crate) fn stop_nix_daemon(command_dirs: &[&'static str]) -> Result<()> {
    if crate::runtime_safety::should_skip_host_interaction() {
        #[cfg(test)]
        crate::manager::helpers::record_service_action("stop:nix-daemon");
        tracing::debug!("Skipping foreign nix-daemon stop in test/test-like context");
        return Ok(());
    }

    let systemctl = resolve_systemctl(command_dirs)?;
    // Best-effort on the socket; the service stop is what must take effect.
    let _ = run_systemctl(&systemctl, &["stop", "nix-daemon.socket"]);
    run_systemctl(&systemctl, &["stop", "nix-daemon.service"])
}

/// Restart nix-daemon after `/nix` has been overlaid on a non-NixOS host.
///
/// The socket is started first so socket activation can bring the service up,
/// then the service itself; a host with no socket unit still gets the service.
pub(crate) fn restart_nix_daemon(command_dirs: &[&'static str]) -> Result<()> {
    if crate::runtime_safety::should_skip_host_interaction() {
        #[cfg(test)]
        crate::manager::helpers::record_service_action("start:nix-daemon");
        tracing::debug!("Skipping foreign nix-daemon restart in test/test-like context");
        return Ok(());
    }

    let systemctl = resolve_systemctl(command_dirs)?;
    let _ = run_systemctl(&systemctl, &["start", "nix-daemon.socket"]);
    run_systemctl(&systemctl, &["start", "nix-daemon.service"])
}

/// Resolve the host's own `systemctl` from the platform command directories.
fn resolve_systemctl(command_dirs: &[&'static str]) -> Result<std::path::PathBuf> {
    HostCommands::new(command_dirs.iter().copied())
        .resolve("systemctl")
        .map_err(|err| {
            NailsError::NixOSError(format!(
                "Cannot resolve systemctl to manage nix-daemon on this host: {err}"
            ))
        })
}

fn run_systemctl(systemctl: &Path, args: &[&str]) -> Result<()> {
    let command = ProcessCommand::exact(systemctl)
        .args(args)
        .deadline(systemctl_budget(args));
    let output = RealProcessRunner.run(&command)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(NailsError::NixOSError(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}
