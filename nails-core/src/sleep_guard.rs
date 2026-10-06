// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Sleep guard: keep an active hidden session out of the hands of a suspend.
//!
//! When [`sleep_policy.mode`](crate::config::SleepPolicyConfig) is `block` or
//! `teardown`, activation starts this guard from the RAM-backed runtime copy as a
//! transient systemd unit (the same mechanism as the backend watcher). The guard
//! takes a logind inhibitor over the system D-Bus and holds it for the life of the
//! session:
//!
//! * **block** — a `sleep:idle` *block* inhibitor. logind refuses to suspend or
//!   idle-sleep while it is held, so a closed lid or an idle timeout cannot strand
//!   the hidden session resident in RAM. The inhibitor is released when the unit
//!   is stopped at deactivation (the process exits and the kernel drops the fd).
//! * **teardown** — a `sleep` *delay* inhibitor. logind lets the sleep begin but
//!   blocks it for up to `InhibitDelayMaxSec` (default 5s) after emitting
//!   `PrepareForSleep(true)`. In that window the guard runs the bounded emergency
//!   teardown, then releases the inhibitor so the sleep proceeds — the machine
//!   sleeps with the hidden session already torn down.
//!
//! # Threat model
//!
//! The unit name and the inhibitor's `who`/`why` strings are neutral: they appear
//! in `systemd-inhibit --list`, `systemctl` and the journal, so they must reveal
//! nothing about a hidden environment. Everything runs from the `/run` copy, so no
//! artifact is written to the decoy disk.
//!
//! # Testability
//!
//! The D-Bus paths need a live logind on the system bus and cannot run in the
//! unit-test sandbox (the bus socket is unavailable); they are exercised by the
//! end-to-end VM suite. Only [`run_guard`] with [`SleepPolicyMode::Warn`] (a
//! no-op) and the neutral-name invariant are checked here.

use crate::config::SleepPolicyMode;
use crate::{NailsError, Result};

/// Transient systemd unit name for the sleep guard.
///
/// Neutral for the same reason as the runtime-copy names: it shows up in
/// `systemctl` and the journal.
pub const SLEEP_GUARD_UNIT_NAME: &str = "overlay-runtime-power";

/// logind D-Bus service, object and interface.
const LOGIND_DESTINATION: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const LOGIND_MANAGER: &str = "org.freedesktop.login1.Manager";

/// Neutral `who` string recorded against the inhibitor.
const INHIBITOR_WHO: &str = "power-management";
/// Neutral `why` strings. They read as ordinary power-management, not as a hint
/// that something is being protected.
const INHIBITOR_WHY_BLOCK: &str = "A background task is in progress";
const INHIBITOR_WHY_DELAY: &str = "Finishing a background task before sleep";

/// The system bus logind is reached through, named in D-Bus errors.
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

/// Map any D-Bus error into a NailsError without leaking a backtrace.
fn dbus_error<E: std::fmt::Display>(context: &str, error: E) -> NailsError {
    NailsError::io(
        SYSTEM_BUS_SOCKET,
        std::io::Error::other(format!("{context}: {error}")),
    )
}

/// Run the sleep guard for the configured mode.
///
/// Blocks for the life of the session: `block` parks holding the inhibitor until
/// the process is stopped; `teardown` waits for the first `PrepareForSleep(true)`,
/// runs `on_prepare_for_sleep` (the bounded emergency teardown), releases the
/// inhibitor and returns. `warn` is a no-op. The `on_prepare_for_sleep` callback
/// is only invoked in `teardown` mode.
pub fn run_guard<F: FnOnce()>(mode: SleepPolicyMode, on_prepare_for_sleep: F) -> Result<()> {
    match mode {
        SleepPolicyMode::Warn => {
            tracing::debug!("Sleep policy is warn-only; the guard has nothing to do");
            Ok(())
        }
        SleepPolicyMode::Block => hold_block_inhibitor(),
        SleepPolicyMode::Teardown => wait_for_sleep_then(on_prepare_for_sleep),
    }
}

/// Connect to the system bus and build the logind Manager proxy.
fn logind_proxy(conn: &zbus::blocking::Connection) -> Result<zbus::blocking::Proxy<'static>> {
    zbus::blocking::Proxy::new(conn, LOGIND_DESTINATION, LOGIND_PATH, LOGIND_MANAGER)
        .map_err(|e| dbus_error("could not open the logind D-Bus proxy", e))
}

/// Take a sleep/idle *block* inhibitor and hold it until the process is stopped.
fn hold_block_inhibitor() -> Result<()> {
    let conn = zbus::blocking::Connection::system()
        .map_err(|e| dbus_error("could not connect to the system D-Bus", e))?;
    let proxy = logind_proxy(&conn)?;

    // The returned fd must stay open for the inhibitor to hold; it is released
    // when the process exits (unit stopped at deactivation).
    let _fd: zbus::zvariant::OwnedFd = proxy
        .call(
            "Inhibit",
            &("sleep:idle", INHIBITOR_WHO, INHIBITOR_WHY_BLOCK, "block"),
        )
        .map_err(|e| dbus_error("logind Inhibit (block) failed", e))?;

    tracing::info!(
        unit = SLEEP_GUARD_UNIT_NAME,
        "Holding a sleep/idle block inhibitor for the session"
    );

    // Park forever. The inhibitor lives exactly as long as this process; systemd
    // stops the unit at deactivation, which closes the fd and releases it.
    loop {
        std::thread::park();
    }
}

/// Take a sleep *delay* inhibitor, then on the first imminent sleep run
/// `on_prepare_for_sleep` within the delay window and release the inhibitor.
fn wait_for_sleep_then<F: FnOnce()>(on_prepare_for_sleep: F) -> Result<()> {
    let conn = zbus::blocking::Connection::system()
        .map_err(|e| dbus_error("could not connect to the system D-Bus", e))?;
    let proxy = logind_proxy(&conn)?;

    // Subscribe before taking the inhibitor so the PrepareForSleep signal can
    // never slip through between acquiring the lock and starting to listen.
    let mut signals = proxy
        .receive_signal("PrepareForSleep")
        .map_err(|e| dbus_error("could not subscribe to PrepareForSleep", e))?;

    let fd: zbus::zvariant::OwnedFd = proxy
        .call(
            "Inhibit",
            &("sleep", INHIBITOR_WHO, INHIBITOR_WHY_DELAY, "delay"),
        )
        .map_err(|e| dbus_error("logind Inhibit (delay) failed", e))?;

    tracing::info!(
        unit = SLEEP_GUARD_UNIT_NAME,
        "Holding a sleep delay inhibitor; waiting for the host to sleep"
    );

    for message in signals.by_ref() {
        let going_to_sleep: bool = message
            .body()
            .deserialize()
            .map_err(|e| dbus_error("could not read the PrepareForSleep signal", e))?;
        if going_to_sleep {
            tracing::warn!(
                "The host is about to sleep; running the bounded emergency teardown before it does"
            );
            on_prepare_for_sleep();
            // Release the delay inhibitor so the suspend proceeds now that the
            // hidden session is torn down.
            drop(fd);
            return Ok(());
        }
        // going_to_sleep == false is a resume notification; keep waiting.
    }

    // The signal stream ended without a sleep (bus closed): release and exit.
    drop(fd);
    Ok(())
}

/// Start the sleep guard as a transient systemd unit from the runtime copy.
///
/// Mirrors [`crate::runtime_copy::start_watch_unit`]: launched from the mirrored
/// executable under [`SLEEP_GUARD_UNIT_NAME`], with `--collect` so systemd reaps
/// the unit when it exits. Best-effort — a failure to start only means the session
/// runs without sleep protection, never that activation fails. Callers must gate
/// this on a non-test runtime; it performs a real host operation.
pub fn start_sleep_guard_unit() {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};

    let binary = crate::runtime_copy::binary_copy_path();
    let command = ProcessCommand::tool("systemd-run")
        .arg("--unit")
        .arg(SLEEP_GUARD_UNIT_NAME)
        .arg("--collect")
        .arg("--quiet")
        .arg(&binary)
        .arg("sleep-guard");

    match RealProcessRunner.run(&command) {
        Ok(output) if output.status.success() => {
            tracing::info!(unit = SLEEP_GUARD_UNIT_NAME, "Started the sleep guard");
        }
        Ok(output) => {
            tracing::warn!(
                unit = SLEEP_GUARD_UNIT_NAME,
                status = %output.status,
                "Could not start the sleep guard; the session runs without sleep protection"
            );
        }
        Err(e) => {
            tracing::warn!(
                unit = SLEEP_GUARD_UNIT_NAME,
                error = %e,
                "Could not start the sleep guard; the session runs without sleep protection"
            );
        }
    }
}

/// Stop the sleep guard's transient unit, best-effort.
///
/// Called by deactivation and emergency teardown. A guard that was never started
/// (warn mode, or a start that failed) makes `systemctl stop` a harmless no-op.
/// Callers must gate this on a non-test runtime; it performs a real host operation.
pub fn stop_sleep_guard_unit() {
    use crate::process::{ProcessCommand, ProcessRunner, RealProcessRunner};

    let own_unit = crate::process::cgroup_unit::own_service_unit();
    if !crate::process::cgroup_unit::may_stop_unit(own_unit.as_deref(), SLEEP_GUARD_UNIT_NAME) {
        // The teardown runs inside this very unit (the watcher's auto-emergency):
        // stopping it would SIGTERM the teardown. The unit ends on its own when
        // the process returns.
        tracing::info!(
            unit = SLEEP_GUARD_UNIT_NAME,
            "Not stopping the unit this teardown runs in"
        );
        return;
    }
    let command = ProcessCommand::tool("systemctl")
        .arg("stop")
        .arg(SLEEP_GUARD_UNIT_NAME)
        .deadline(crate::process::run::UNIT_STOP_BUDGET);
    let _ = RealProcessRunner.run(&command);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_name_is_neutral() {
        assert!(
            !SLEEP_GUARD_UNIT_NAME.to_ascii_lowercase().contains("nails"),
            "sleep-guard unit name {SLEEP_GUARD_UNIT_NAME:?} must be neutral"
        );
        assert!(!SLEEP_GUARD_UNIT_NAME.to_ascii_lowercase().contains("sleep"));
    }

    #[test]
    fn inhibitor_strings_reveal_nothing() {
        for text in [INHIBITOR_WHO, INHIBITOR_WHY_BLOCK, INHIBITOR_WHY_DELAY] {
            let lower = text.to_ascii_lowercase();
            assert!(!lower.contains("nails"));
            assert!(!lower.contains("hidden"));
        }
    }

    #[test]
    fn warn_mode_is_a_noop_and_never_runs_the_callback() {
        let mut called = false;
        run_guard(SleepPolicyMode::Warn, || called = true).unwrap();
        assert!(!called, "warn mode must not run the teardown callback");
    }
}
