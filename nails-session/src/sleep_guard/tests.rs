// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the sleep guard, against a fake logind on a private bus.

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
    refuse: fn(&str) -> bool,
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
        let refused = (self.refuse)(&what);
        self.calls.lock().unwrap().push([what, who, why, mode]);
        if refused {
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
    /// Start the bus and claim logind's name on it; the fake refuses each
    /// `Inhibit` call whose `what` `refuse` picks. Ends the (re-executed)
    /// test as a host skip when `dbus-daemon` is not installed.
    fn start(refuse: fn(&str) -> bool) -> Self {
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
            let _ = daemon.kill();
            let _ = daemon.wait();
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
        self.await_inhibits(1).remove(0)
    }

    /// Wait for the guard's first `count` `Inhibit` calls and return them.
    fn await_inhibits(&self, count: usize) -> Vec<InhibitCall> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let calls = self.calls.lock().unwrap();
            if calls.len() >= count {
                return calls[..count].to_vec();
            }
            drop(calls);
            assert!(Instant::now() < deadline, "the guard never called Inhibit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Whether the guard still holds the first inhibitor fd it was handed.
    fn inhibitor_held(&self) -> bool {
        self.inhibitor_held_at(0)
    }

    /// Whether the guard still holds the `index`th inhibitor fd it was handed.
    fn inhibitor_held_at(&self, index: usize) -> bool {
        let mut kept = self.kept.lock().unwrap();
        let end = kept.get_mut(index).expect("an inhibitor was handed out");
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
fn spawn_guard(
    mode: SleepPolicyMode,
    lid: LidSwitch,
) -> (mpsc::Receiver<Result<()>>, mpsc::Receiver<()>) {
    let (result_tx, result_rx) = mpsc::channel();
    let (teardown_tx, teardown_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = run_guard(mode, lid, move || teardown_tx.send(()).unwrap());
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
    run_guard(SleepPolicyMode::Warn, LidSwitch::Take, || called = true).unwrap();
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
            let message = bus_error(run_guard(mode, LidSwitch::Take, || called = true));
            assert!(
                message.starts_with("could not connect to the system D-Bus"),
                "{message}"
            );
            assert!(!called);
        }
    });
}

#[test]
fn block_mode_holds_neutral_sleep_idle_and_lid_switch_block_inhibitors() {
    let _ = Rerun::new(nails_base::test_path!(
        block_mode_holds_neutral_sleep_idle_and_lid_switch_block_inhibitors
    ))
    .run(|| {
        let bus = FakeSystemBus::start(|_| false);
        let (result, _teardown) = spawn_guard(SleepPolicyMode::Block, LidSwitch::Take);

        assert_eq!(
            bus.await_inhibits(2),
            [
                ["sleep:idle", INHIBITOR_WHO, INHIBITOR_WHY_BLOCK, "block"].map(String::from),
                [
                    "handle-lid-switch",
                    INHIBITOR_WHO,
                    INHIBITOR_WHY_BLOCK,
                    "block"
                ]
                .map(String::from),
            ]
        );
        // The guard parks holding both; it never returns on its own.
        assert!(
            result.recv_timeout(Duration::from_millis(200)).is_err(),
            "block mode must not return while the session runs"
        );
        assert!(bus.inhibitor_held_at(0));
        assert!(bus.inhibitor_held_at(1));
    });
}

#[test]
fn block_mode_leaves_a_lid_switch_that_does_not_sleep_to_logind() {
    let _ = Rerun::new(nails_base::test_path!(
        block_mode_leaves_a_lid_switch_that_does_not_sleep_to_logind
    ))
    .run(|| {
        let log = capture_log();
        let bus = FakeSystemBus::start(|_| false);
        let (result, _teardown) = spawn_guard(SleepPolicyMode::Block, LidSwitch::Leave);

        await_log(&log, "Holding a sleep/idle block inhibitor");
        assert!(result.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(
            *bus.calls.lock().unwrap(),
            [["sleep:idle", INHIBITOR_WHO, INHIBITOR_WHY_BLOCK, "block"].map(String::from)]
        );
        assert!(bus.inhibitor_held());
    });
}

#[test]
fn a_refused_lid_switch_inhibitor_still_blocks_sleep() {
    let _ = Rerun::new(nails_base::test_path!(
        a_refused_lid_switch_inhibitor_still_blocks_sleep
    ))
    .run(|| {
        let log = capture_log();
        let bus = FakeSystemBus::start(|what| what == "handle-lid-switch");
        let (result, _teardown) = spawn_guard(SleepPolicyMode::Block, LidSwitch::Take);

        await_log(&log, "Closing the lid can still suspend the session");
        await_log(&log, "Holding a sleep/idle block inhibitor");
        assert!(result.recv_timeout(Duration::from_millis(200)).is_err());
        assert_eq!(bus.await_inhibits(2)[1][0], "handle-lid-switch");
        assert!(bus.inhibitor_held(), "the sleep/idle inhibitor stays held");
    });
}

#[test]
fn teardown_mode_runs_the_teardown_on_sleep_then_releases_the_inhibitor() {
    let _ = Rerun::new(nails_base::test_path!(
        teardown_mode_runs_the_teardown_on_sleep_then_releases_the_inhibitor
    ))
    .run(|| {
        let bus = FakeSystemBus::start(|_| false);
        let (result, teardown) = spawn_guard(SleepPolicyMode::Teardown, LidSwitch::Take);

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
        let mut bus = FakeSystemBus::start(|_| false);
        let (result, teardown) = spawn_guard(SleepPolicyMode::Teardown, LidSwitch::Take);
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
        let bus = FakeSystemBus::start(|_| false);
        let (result, teardown) = spawn_guard(SleepPolicyMode::Teardown, LidSwitch::Take);
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
        let _bus = FakeSystemBus::start(|_| true);

        let message = bus_error(run_guard(SleepPolicyMode::Block, LidSwitch::Take, || {}));
        assert!(
            message.starts_with("logind Inhibit (block) failed"),
            "{message}"
        );
        assert!(message.contains("not allowed"), "{message}");

        let mut called = false;
        let message = bus_error(run_guard(
            SleepPolicyMode::Teardown,
            LidSwitch::Take,
            || called = true,
        ));
        assert!(
            message.starts_with("logind Inhibit (delay) failed"),
            "{message}"
        );
        assert!(!called);
    });
}
