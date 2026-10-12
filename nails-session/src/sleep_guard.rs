// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Sleep guard: keep an active hidden session out of the hands of a suspend.
//!
//! When [`sleep_policy.mode`](crate::config::SleepPolicyConfig) is `block` or
//! `teardown`, the entry installs this guard as one of the hidden session's
//! runtime units ([`crate::session::units`]), run from the RAM-backed copy of
//! the binary like the backend watcher. The guard
//! takes a logind inhibitor over the system D-Bus and holds it for the life of the
//! session:
//!
//! * **block** — a `sleep:idle` *block* inhibitor. logind refuses to suspend or
//!   idle-sleep while it is held, so a closed lid or an idle timeout cannot strand
//!   the hidden session resident in RAM. The inhibitor is released when the unit
//!   is stopped at the way back (the process exits and the kernel drops the fd).
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

#[cfg(test)]
mod tests {
    use super::*;
    use nails_base::test_support::{Rerun, skip_host};
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// The arguments of one `Inhibit` call: what, who, why, mode.
    type InhibitCall = [String; 4];

    /// A stand-in for logind's Manager object: it records each `Inhibit` call
    /// and answers with one end of a socket pair, keeping the other end, so
    /// the test sees the inhibitor released when the guard closes its fd.
    struct FakeLogind {
        calls: Arc<Mutex<Vec<InhibitCall>>>,
        kept: Arc<Mutex<Vec<UnixStream>>>,
        refuse: bool,
    }

    #[zbus::interface(name = "org.freedesktop.login1.Manager")]
    impl FakeLogind {
        fn inhibit(
            &self,
            what: String,
            who: String,
            why: String,
            mode: String,
        ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
            self.calls.lock().unwrap().push([what, who, why, mode]);
            if self.refuse {
                return Err(zbus::fdo::Error::AccessDenied("not allowed".into()));
            }
            let (ours, theirs) = UnixStream::pair().unwrap();
            ours.set_nonblocking(true).unwrap();
            self.kept.lock().unwrap().push(ours);
            Ok(std::os::fd::OwnedFd::from(theirs).into())
        }
    }

    /// A private bus run by `dbus-daemon`, with a fake logind on it, that
    /// `Connection::system()` reaches through `DBUS_SYSTEM_BUS_ADDRESS`.
    struct FakeSystemBus {
        daemon: std::process::Child,
        logind: zbus::blocking::Connection,
        calls: Arc<Mutex<Vec<InhibitCall>>>,
        kept: Arc<Mutex<Vec<UnixStream>>>,
        _dir: tempfile::TempDir,
    }

    impl FakeSystemBus {
        /// Start the bus and claim logind's name on it. Ends the (re-executed)
        /// test as a host skip when `dbus-daemon` is not installed.
        fn start(refuse: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("bus");
            let config = dir.path().join("bus.conf");
            std::fs::write(
                &config,
                format!(
                    "<busconfig><listen>unix:path={}</listen><auth>EXTERNAL</auth>\
                     <policy context=\"default\"><allow own=\"*\"/>\
                     <allow send_type=\"*\"/><allow receive_type=\"*\"/>\
                     </policy></busconfig>",
                    socket.display()
                ),
            )
            .unwrap();
            let mut daemon = match std::process::Command::new("dbus-daemon")
                .arg("--nofork")
                .arg("--print-address")
                .arg(format!("--config-file={}", config.display()))
                .stdout(std::process::Stdio::piped())
                .spawn()
            {
                Ok(daemon) => daemon,
                Err(e) => skip_host(&format!("no dbus-daemon on this host ({e})")),
            };
            // The address is printed once the bus listens.
            let mut address = String::new();
            let mut stdout = daemon.stdout.take().unwrap();
            let mut byte = [0u8; 1];
            while stdout.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
                address.push(byte[0] as char);
            }
            if address.is_empty() {
                skip_host("dbus-daemon could not start a bus on this host");
            }
            #[allow(unsafe_code)]
            // SAFETY: the re-executed child runs this one test on one thread,
            // and no other thread reads the environment yet.
            unsafe {
                std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", &address);
            }

            let calls = Arc::new(Mutex::new(Vec::new()));
            let kept = Arc::new(Mutex::new(Vec::new()));
            let logind = zbus::blocking::connection::Builder::address(address.as_str())
                .unwrap()
                .serve_at(
                    LOGIND_PATH,
                    FakeLogind {
                        calls: Arc::clone(&calls),
                        kept: Arc::clone(&kept),
                        refuse,
                    },
                )
                .unwrap()
                .name(LOGIND_DESTINATION)
                .unwrap()
                .build()
                .unwrap();
            Self {
                daemon,
                logind,
                calls,
                kept,
                _dir: dir,
            }
        }

        /// Wait for the guard's first `Inhibit` call and return it.
        fn await_inhibit(&self) -> InhibitCall {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(call) = self.calls.lock().unwrap().first() {
                    return call.clone();
                }
                assert!(Instant::now() < deadline, "the guard never called Inhibit");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        /// Whether the guard still holds the inhibitor fd it was handed.
        fn inhibitor_held(&self) -> bool {
            let mut kept = self.kept.lock().unwrap();
            let end = kept.first_mut().expect("an inhibitor was handed out");
            match end.read(&mut [0u8; 1]) {
                Ok(0) => false,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                other => panic!("unexpected read on the inhibitor: {other:?}"),
            }
        }

        fn prepare_for_sleep<B>(&self, body: &B)
        where
            B: zbus::export::serde::Serialize + zbus::zvariant::DynamicType,
        {
            self.logind
                .emit_signal(
                    None::<&str>,
                    LOGIND_PATH,
                    LOGIND_MANAGER,
                    "PrepareForSleep",
                    body,
                )
                .unwrap();
        }
    }

    impl Drop for FakeSystemBus {
        fn drop(&mut self) {
            let _ = self.daemon.kill();
            let _ = self.daemon.wait();
        }
    }

    /// Run the guard on a thread; its result arrives on the returned channel
    /// and each run of the teardown callback on the second one.
    fn spawn_guard(mode: SleepPolicyMode) -> (mpsc::Receiver<Result<()>>, mpsc::Receiver<()>) {
        let (result_tx, result_rx) = mpsc::channel();
        let (teardown_tx, teardown_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = run_guard(mode, move || teardown_tx.send(()).unwrap());
            let _ = result_tx.send(result);
        });
        (result_rx, teardown_rx)
    }

    /// Everything the (re-executed, single-test) process logs from now on.
    fn capture_log() -> Arc<Mutex<Vec<u8>>> {
        struct Tap(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Tap {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let tap = Arc::clone(&log);
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Tap(Arc::clone(&tap)))
            .init();
        log
    }

    /// Wait until the captured log contains `text`.
    fn await_log(log: &Mutex<Vec<u8>>, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !String::from_utf8_lossy(&log.lock().unwrap()).contains(text) {
            assert!(Instant::now() < deadline, "never logged {text:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The message of a guard error, which names the system bus socket.
    fn bus_error(result: Result<()>) -> String {
        match result {
            Err(NailsError::IoError { path, source }) => {
                assert_eq!(path, std::path::Path::new(SYSTEM_BUS_SOCKET));
                source.to_string()
            }
            other => panic!("expected a D-Bus error, got {other:?}"),
        }
    }

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

    #[test]
    fn an_unreachable_system_bus_fails_both_guarding_modes() {
        let _ = Rerun::new(nails_base::test_path!(
            an_unreachable_system_bus_fails_both_guarding_modes
        ))
        .run(|| {
            let dir = tempfile::tempdir().unwrap();
            let address = format!("unix:path={}", dir.path().join("missing").display());
            #[allow(unsafe_code)]
            // SAFETY: the re-executed child runs this one test on one thread.
            unsafe {
                std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", address);
            }

            for mode in [SleepPolicyMode::Block, SleepPolicyMode::Teardown] {
                let mut called = false;
                let message = bus_error(run_guard(mode, || called = true));
                assert!(
                    message.starts_with("could not connect to the system D-Bus"),
                    "{message}"
                );
                assert!(!called);
            }
        });
    }

    #[test]
    fn block_mode_holds_a_neutral_sleep_and_idle_block_inhibitor() {
        let _ = Rerun::new(nails_base::test_path!(
            block_mode_holds_a_neutral_sleep_and_idle_block_inhibitor
        ))
        .run(|| {
            let bus = FakeSystemBus::start(false);
            let (result, _teardown) = spawn_guard(SleepPolicyMode::Block);

            assert_eq!(
                bus.await_inhibit(),
                ["sleep:idle", INHIBITOR_WHO, INHIBITOR_WHY_BLOCK, "block"].map(String::from)
            );
            // The guard parks holding the inhibitor; it never returns on its own.
            assert!(
                result.recv_timeout(Duration::from_millis(200)).is_err(),
                "block mode must not return while the session runs"
            );
            assert!(bus.inhibitor_held());
        });
    }

    #[test]
    fn teardown_mode_runs_the_teardown_on_sleep_then_releases_the_inhibitor() {
        let _ = Rerun::new(nails_base::test_path!(
            teardown_mode_runs_the_teardown_on_sleep_then_releases_the_inhibitor
        ))
        .run(|| {
            let bus = FakeSystemBus::start(false);
            let (result, teardown) = spawn_guard(SleepPolicyMode::Teardown);

            assert_eq!(
                bus.await_inhibit(),
                ["sleep", INHIBITOR_WHO, INHIBITOR_WHY_DELAY, "delay"].map(String::from)
            );
            // A resume notification is not a sleep: keep waiting, keep holding.
            bus.prepare_for_sleep(&(false,));
            assert!(teardown.recv_timeout(Duration::from_millis(200)).is_err());
            assert!(bus.inhibitor_held());

            bus.prepare_for_sleep(&(true,));
            teardown
                .recv_timeout(Duration::from_secs(10))
                .expect("the teardown runs before the sleep");
            result
                .recv_timeout(Duration::from_secs(10))
                .expect("the guard returns after the teardown")
                .unwrap();
            assert!(
                !bus.inhibitor_held(),
                "the delay inhibitor is released so the sleep proceeds"
            );
            assert!(teardown.try_recv().is_err(), "the teardown runs once");
        });
    }

    #[test]
    fn teardown_mode_exits_without_a_teardown_when_the_bus_goes_away() {
        let _ = Rerun::new(nails_base::test_path!(
            teardown_mode_exits_without_a_teardown_when_the_bus_goes_away
        ))
        .run(|| {
            let log = capture_log();
            let mut bus = FakeSystemBus::start(false);
            let (result, teardown) = spawn_guard(SleepPolicyMode::Teardown);
            // The fake records the call before its reply leaves: wait until the
            // guard holds the fd, or the kill would fail the Inhibit call instead.
            await_log(&log, "Holding a sleep delay inhibitor");

            bus.daemon.kill().unwrap();
            bus.daemon.wait().unwrap();

            result
                .recv_timeout(Duration::from_secs(10))
                .expect("the guard returns once the signal stream ends")
                .unwrap();
            assert!(teardown.try_recv().is_err(), "no sleep, no teardown");
        });
    }

    #[test]
    fn a_malformed_prepare_for_sleep_signal_is_an_error() {
        let _ = Rerun::new(nails_base::test_path!(
            a_malformed_prepare_for_sleep_signal_is_an_error
        ))
        .run(|| {
            let bus = FakeSystemBus::start(false);
            let (result, teardown) = spawn_guard(SleepPolicyMode::Teardown);
            bus.await_inhibit();

            bus.prepare_for_sleep(&("soon",));

            let message = bus_error(
                result
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the guard gives up on an unreadable signal"),
            );
            assert!(
                message.starts_with("could not read the PrepareForSleep signal"),
                "{message}"
            );
            assert!(teardown.try_recv().is_err());
        });
    }

    #[test]
    fn a_refused_inhibitor_fails_both_guarding_modes() {
        let _ = Rerun::new(nails_base::test_path!(
            a_refused_inhibitor_fails_both_guarding_modes
        ))
        .run(|| {
            let _bus = FakeSystemBus::start(true);

            let message = bus_error(run_guard(SleepPolicyMode::Block, || {}));
            assert!(
                message.starts_with("logind Inhibit (block) failed"),
                "{message}"
            );
            assert!(message.contains("not allowed"), "{message}");

            let mut called = false;
            let message = bus_error(run_guard(SleepPolicyMode::Teardown, || called = true));
            assert!(
                message.starts_with("logind Inhibit (delay) failed"),
                "{message}"
            );
            assert!(!called);
        });
    }
}
