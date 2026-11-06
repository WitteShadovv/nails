// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Sleep guard: keep an active hidden session out of the hands of a suspend.
//!
//! When [`sleep_policy.mode`](crate::config::SleepPolicyConfig) is `block` or
//! `teardown`, the entry installs this guard as one of the hidden session's
//! runtime units ([`crate::session::units`]), run from the RAM-backed copy of
//! the binary like the backend watcher. The guard
//! takes logind inhibitors over the system D-Bus and holds them for the life of
//! the session:
//!
//! * **block** — a `sleep:idle` *block* inhibitor, so logind refuses a suspend
//!   that is asked for (a sleep key, a desktop's or a user's `Suspend` call) or
//!   that an idle timeout starts. That alone does not cover the lid:
//!   logind ignores sleep inhibitors for the lid switch unless
//!   `LidSwitchIgnoreInhibited=no`, and the default is `yes`. So when the
//!   session's logind would sleep on a closed lid ([`LidSwitch::Take`]), the
//!   guard also takes a `handle-lid-switch` *block* inhibitor, which logind
//!   always honours: it then takes no action at all on a closed lid, neither
//!   the suspend nor a lock. When the lid action does not sleep (`lock`,
//!   `ignore`, `poweroff`), the guard leaves the lid to logind
//!   ([`LidSwitch::Leave`]) so that action still happens. Both inhibitors are
//!   released together when the unit is stopped at the way back (the process
//!   exits and the kernel closes the fds).
//! * **teardown** — a `sleep` *delay* inhibitor. logind honours delay
//!   inhibitors for every sleep, the lid switch's included: it emits
//!   `PrepareForSleep(true)` and holds the sleep back for up to
//!   `InhibitDelayMaxSec` (default 5s) while the inhibitor is held. In that
//!   window the guard runs the callback it is given, then releases the
//!   inhibitor. The `sleep-guard` command passes a teardown that powers the
//!   machine off, so the machine powers off instead of sleeping.
//!
//! When the guard cannot read its settings it cannot tell which of the two
//! modes the operator chose, so it does both ([`run_untold_guard`]): it holds
//! `block`'s inhibitors, so an ordinary sleep request is refused and nothing
//! powers off on its own, and `teardown`'s delay inhibitor, so a sleep that
//! starts anyway, forced past the block inhibitors (`systemctl suspend -i`),
//! powers the machine off first. No sleep then leaves the session in RAM.
//!
//! # Threat model
//!
//! The unit name and the inhibitors' `who`/`why` strings are neutral: they appear
//! in `systemd-inhibit --list`, `systemctl` and the journal, so they must reveal
//! nothing about a hidden environment. Everything runs from the `/run` copy, so no
//! artifact is written to the decoy disk.
//!
//! # Testability
//!
//! The unit tests run the guard against a fake logind on a private bus: the
//! inhibitors each mode takes, their release and the `PrepareForSleep`
//! handling. What logind then does on a closed lid is checked by the NixOS VM
//! test `session-sleep-guard`, which closes a virtual lid in a hidden session
//! in each mode.

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

/// Whether `block` also takes logind's handling of the lid switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LidSwitch {
    /// The lid action would sleep: take a `handle-lid-switch` block inhibitor,
    /// so logind does nothing on a closed lid.
    Take,
    /// The lid action does not sleep: leave it to logind.
    Leave,
}

/// Run the sleep guard for the configured mode.
///
/// Blocks for the life of the session: `block` parks holding its inhibitors
/// (the lid switch's too when `lid` is [`LidSwitch::Take`]) until the process
/// is stopped; `teardown` waits for the first `PrepareForSleep(true)`, runs
/// `on_prepare_for_sleep`, releases the inhibitor and returns. `warn` is a
/// no-op. The `on_prepare_for_sleep` callback is only invoked in `teardown`
/// mode, and `lid` only counts in `block` mode.
pub fn run_guard<F: FnOnce()>(
    mode: SleepPolicyMode,
    lid: LidSwitch,
    on_prepare_for_sleep: F,
) -> Result<()> {
    match mode {
        SleepPolicyMode::Warn => {
            tracing::debug!("Sleep policy is warn-only; the guard has nothing to do");
            Ok(())
        }
        SleepPolicyMode::Block => hold_block_inhibitors(lid),
        SleepPolicyMode::Teardown => wait_for_sleep_then(on_prepare_for_sleep),
    }
}

/// Run the guard of a session whose sleep policy cannot be read: it holds
/// what `block` holds (the sleep/idle block inhibitor, and the lid switch's
/// when `lid` is [`LidSwitch::Take`]), so an ordinary sleep request is
/// refused, and what `teardown` holds (the sleep delay inhibitor), so a
/// sleep forced past the block inhibitors runs `on_prepare_for_sleep` before
/// it happens, then releases the delay inhibitor and returns.
///
/// Either part is kept when the other cannot be taken: without the delay
/// inhibitor the guard parks holding the block ones, as `block` does, and
/// without the block one it waits for a sleep, as `teardown` does. When the
/// signal stream ends without a sleep, the block inhibitors stay held. An
/// error only when neither part can be taken.
pub fn run_untold_guard<F: FnOnce()>(lid: LidSwitch, on_prepare_for_sleep: F) -> Result<()> {
    let conn = system_bus()?;
    let proxy = logind_proxy(&conn)?;
    let blocking = take_block(&proxy, lid);
    let delay = take_delay(&proxy);
    let delay = match (delay, blocking.as_ref()) {
        (Ok(delay), _) => delay,
        (Err(e), Ok(blocking)) => {
            tracing::warn!(
                error = %e,
                "A sleep forced past the inhibitors can still suspend the session"
            );
            tracing::info!(
                unit = SLEEP_GUARD_UNIT_NAME,
                lid_switch = blocking.lid.is_some(),
                "Holding a sleep/idle block inhibitor for the session"
            );
            park();
        }
        (Err(e), Err(blocked)) => {
            tracing::warn!(error = %blocked, "The sleep/idle block inhibitor could not be taken");
            return Err(e);
        }
    };
    match &blocking {
        Ok(blocking) => tracing::info!(
            unit = SLEEP_GUARD_UNIT_NAME,
            lid_switch = blocking.lid.is_some(),
            "Holding the block and the delay inhibitors; a sleep that starts anyway powers off"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "A sleep request is not refused; a sleep powers the machine off instead"
        ),
    }
    let slept = await_sleep(delay, on_prepare_for_sleep);
    match (slept, blocking) {
        (Ok(true), _) => Ok(()),
        (ended, Ok(_blocking)) => {
            if let Err(e) = ended {
                tracing::warn!(error = %e, "No longer waiting for the host to sleep");
            }
            tracing::info!("Holding a sleep/idle block inhibitor for the session");
            park();
        }
        (ended, Err(_)) => ended.map(drop),
    }
}

/// Connect to the system bus.
fn system_bus() -> Result<zbus::blocking::Connection> {
    zbus::blocking::Connection::system()
        .map_err(|e| dbus_error("could not connect to the system D-Bus", e))
}

/// Connect to the system bus and build the logind Manager proxy.
fn logind_proxy(conn: &zbus::blocking::Connection) -> Result<zbus::blocking::Proxy<'static>> {
    zbus::blocking::Proxy::new(conn, LOGIND_DESTINATION, LOGIND_PATH, LOGIND_MANAGER)
        .map_err(|e| dbus_error("could not open the logind D-Bus proxy", e))
}

/// Park forever. The inhibitors live exactly as long as this process;
/// systemd stops the unit at deactivation, which closes the fds and
/// releases them.
fn park() -> ! {
    loop {
        std::thread::park();
    }
}

/// The block inhibitors `block` holds. The fds must stay open for the
/// inhibitors to hold; they are released together when the process exits
/// (unit stopped at deactivation).
struct Blocking {
    _sleep: zbus::zvariant::OwnedFd,
    lid: Option<zbus::zvariant::OwnedFd>,
}

/// Take the sleep/idle *block* inhibitor, and the lid switch's when `lid`
/// says so.
fn take_block(proxy: &zbus::blocking::Proxy<'static>, lid: LidSwitch) -> Result<Blocking> {
    let sleep: zbus::zvariant::OwnedFd = proxy
        .call(
            "Inhibit",
            &("sleep:idle", INHIBITOR_WHO, INHIBITOR_WHY_BLOCK, "block"),
        )
        .map_err(|e| dbus_error("logind Inhibit (block) failed", e))?;

    // logind ignores the sleep inhibitor above for a closed lid by default
    // (LidSwitchIgnoreInhibited=yes), but always honours this one.
    let lid = match lid {
        LidSwitch::Leave => None,
        LidSwitch::Take => match proxy.call(
            "Inhibit",
            &(
                "handle-lid-switch",
                INHIBITOR_WHO,
                INHIBITOR_WHY_BLOCK,
                "block",
            ),
        ) {
            Ok(fd) => Some(fd),
            Err(e) => {
                tracing::warn!(
                    error = %dbus_error("logind Inhibit (lid switch) failed", e),
                    "Closing the lid can still suspend the session"
                );
                None
            }
        },
    };
    Ok(Blocking { _sleep: sleep, lid })
}

/// Take the sleep/idle *block* inhibitor, and the lid switch's when `lid` says
/// so, and hold them until the process is stopped.
fn hold_block_inhibitors(lid: LidSwitch) -> Result<()> {
    let conn = system_bus()?;
    let proxy = logind_proxy(&conn)?;
    let blocking = take_block(&proxy, lid)?;
    tracing::info!(
        unit = SLEEP_GUARD_UNIT_NAME,
        lid_switch = blocking.lid.is_some(),
        "Holding a sleep/idle block inhibitor for the session"
    );
    park();
}

/// The delay inhibitor `teardown` holds, and the stream of `PrepareForSleep`
/// signals it waits on.
struct Delay {
    signals: zbus::blocking::proxy::SignalIterator<'static>,
    fd: zbus::zvariant::OwnedFd,
}

/// Subscribe to `PrepareForSleep` and take a sleep *delay* inhibitor:
/// subscribed first, so the signal can never slip through between acquiring
/// the lock and starting to listen.
fn take_delay(proxy: &zbus::blocking::Proxy<'static>) -> Result<Delay> {
    let signals = proxy
        .receive_signal("PrepareForSleep")
        .map_err(|e| dbus_error("could not subscribe to PrepareForSleep", e))?;
    let fd: zbus::zvariant::OwnedFd = proxy
        .call(
            "Inhibit",
            &("sleep", INHIBITOR_WHO, INHIBITOR_WHY_DELAY, "delay"),
        )
        .map_err(|e| dbus_error("logind Inhibit (delay) failed", e))?;
    Ok(Delay { signals, fd })
}

/// Wait on `delay` for the first imminent sleep, run `on_prepare_for_sleep`
/// within the delay window and release the inhibitor: `true` when a sleep
/// came, `false` when the signal stream ended first (the bus closed), which
/// releases the inhibitor too.
fn await_sleep<F: FnOnce()>(delay: Delay, on_prepare_for_sleep: F) -> Result<bool> {
    let Delay { mut signals, fd } = delay;
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
            return Ok(true);
        }
        // going_to_sleep == false is a resume notification; keep waiting.
    }
    drop(fd);
    Ok(false)
}

/// Take a sleep *delay* inhibitor, then on the first imminent sleep run
/// `on_prepare_for_sleep` within the delay window and release the inhibitor.
fn wait_for_sleep_then<F: FnOnce()>(on_prepare_for_sleep: F) -> Result<()> {
    let conn = system_bus()?;
    let proxy = logind_proxy(&conn)?;
    let delay = take_delay(&proxy)?;
    tracing::info!(
        unit = SLEEP_GUARD_UNIT_NAME,
        "Holding a sleep delay inhibitor; waiting for the host to sleep"
    );
    // The signal stream may end without a sleep (bus closed): the inhibitor
    // is released and the guard exits.
    await_sleep(delay, on_prepare_for_sleep).map(drop)
}

#[cfg(test)]
mod tests;
