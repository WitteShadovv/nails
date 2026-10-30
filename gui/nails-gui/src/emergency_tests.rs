// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicU32;
use std::sync::mpsc::{Receiver, channel};

use super::*;
use nails_api::protocol::decode_request;

/// How long a test waits for the emergency's thread before it fails.
const PATIENCE: Duration = Duration::from_secs(20);

/// A short grace, so the tests that wait it out stay quick.
const GRACE: Duration = Duration::from_millis(300);

/// A stand-in for `systemctl`: a script that appends its arguments to a file
/// and then runs `then`, in a directory of its own removed with it.
struct FakePowerOff {
    dir: PathBuf,
}

impl FakePowerOff {
    fn new(then: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nails-gui-poweroff-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("systemctl");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\n{then}\n",
                dir.join("calls").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir }
    }

    fn fallback(&self) -> Fallback {
        Fallback {
            program: Some(self.dir.join("systemctl")),
            args: vec!["poweroff".into(), "--no-ask-password".into()],
            grace: GRACE,
            limit: Duration::from_secs(5),
        }
    }

    /// Each call's arguments.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for FakePowerOff {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An emergency on `fallback`, and what it reports.
fn started(fallback: Fallback) -> (Emergency, Receiver<Outcome>) {
    let (tell, heard) = channel();
    let emergency = Emergency::start(fallback, move |outcome| {
        let _ = tell.send(outcome);
    });
    (emergency, heard)
}

fn next(heard: &Receiver<Outcome>) -> Outcome {
    heard.recv_timeout(PATIENCE).expect("the emergency reports")
}

/// A pipe like the helper's: the window's end for the emergency, and the
/// helper's end, which gives up a read after [`PATIENCE`].
fn pipe() -> (HelperLine, UnixStream) {
    let (window, helper) = UnixStream::pair().unwrap();
    helper.set_read_timeout(Some(PATIENCE)).unwrap();
    (
        HelperLine {
            stream: window,
            writes: Arc::new(Mutex::new(())),
        },
        helper,
    )
}

/// The request the helper's end reads next.
fn read_request(helper: &UnixStream) -> Request {
    let mut line = String::new();
    BufReader::new(helper)
        .read_line(&mut line)
        .expect("the helper reads a line");
    decode_request(line.trim_end().as_bytes()).expect("a request the helper takes")
}

#[test]
fn the_request_is_one_the_helper_takes_and_asks_for_a_power_off() {
    let line = request_line();
    // The bytes the VM test `session-window-emergency` sends the real helper.
    assert_eq!(
        String::from_utf8(line.clone()).unwrap(),
        "{\"v\":1,\"id\":0,\"op\":{\"emergency\":{\"poweroff\":true,\"reboot\":false}}}\n"
    );
    assert_eq!(line.last(), Some(&b'\n'));
    let request = decode_request(&line[..line.len() - 1]).unwrap();
    assert_eq!(request.v, PROTOCOL_VERSION);
    assert_eq!(request.id, EMERGENCY_ID);
    assert_eq!(
        request.op,
        Op::Emergency(EmergencyArgs {
            poweroff: true,
            reboot: false
        })
    );
}

#[test]
fn firing_waits_for_nothing_and_fires_once() {
    // A session that never opens, and a power-off that takes its time:
    // firing still returns at once.
    let fake = FakePowerOff::new("sleep 2");
    let (emergency, heard) = started(fake.fallback());
    let start = Instant::now();
    assert!(emergency.fire());
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "it only signals"
    );
    assert!(emergency.fired());
    assert!(!emergency.fire(), "once");
    assert!(!emergency.clone().fire(), "a clone shares it");
    assert_eq!(next(&heard), Outcome::PowerOffAsked);
}

#[test]
fn the_helper_gets_the_request_and_a_window_still_here_after_the_grace_powers_off() {
    let fake = FakePowerOff::new("exit 0");
    let (emergency, heard) = started(fake.fallback());
    let (line, helper) = pipe();
    emergency.open(line);
    emergency.fire();
    assert_eq!(read_request(&helper).id, EMERGENCY_ID);
    assert_eq!(next(&heard), Outcome::HelperAsked);
    // The engine's emergency would have ended this window by now.
    assert_eq!(next(&heard), Outcome::PowerOffAsked);
    assert_eq!(fake.calls(), ["poweroff --no-ask-password"]);
}

#[test]
fn an_emergency_while_the_session_opens_waits_for_it_within_the_grace() {
    let fake = FakePowerOff::new("exit 0");
    let mut fallback = fake.fallback();
    fallback.grace = Duration::from_secs(5);
    let (emergency, heard) = started(fallback);
    emergency.fire();
    std::thread::sleep(Duration::from_millis(100));
    let (line, helper) = pipe();
    emergency.open(line);
    assert_eq!(read_request(&helper).id, EMERGENCY_ID);
    assert_eq!(next(&heard), Outcome::HelperAsked);
}

#[test]
fn without_a_session_it_powers_off_at_once() {
    let fake = FakePowerOff::new("exit 0");
    let mut fallback = fake.fallback();
    fallback.grace = Duration::from_secs(10);
    let (emergency, heard) = started(fallback);
    emergency.close();
    let start = Instant::now();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffAsked);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "no grace without a helper to wait for"
    );
    // A line offered once the session is over is not taken: it is dropped,
    // and nothing was written on it.
    let (line, helper) = pipe();
    emergency.open(line);
    let mut byte = [0u8; 1];
    assert_eq!(std::io::Read::read(&mut &helper, &mut byte).unwrap(), 0);
}

#[test]
fn a_session_that_never_opens_is_waited_for_only_the_grace() {
    let fake = FakePowerOff::new("exit 0");
    let (emergency, heard) = started(fake.fallback());
    let start = Instant::now();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffAsked);
    assert!(start.elapsed() >= GRACE);
}

#[test]
fn a_client_that_holds_the_pipe_past_the_grace_leaves_it_to_the_power_off() {
    let fake = FakePowerOff::new("exit 0");
    let (emergency, heard) = started(fake.fallback());
    let (line, helper) = pipe();
    let writes = Arc::clone(&line.writes);
    emergency.open(line);
    // The client is inside a write that does not end.
    let held = writes.lock().unwrap();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffAsked);
    drop(held);
    helper.set_nonblocking(true).unwrap();
    let mut byte = [0u8; 1];
    assert!(
        std::io::Read::read(&mut &helper, &mut byte).is_err(),
        "nothing was written into the client's request"
    );
}

#[test]
fn a_pipe_the_helper_does_not_read_is_not_waited_on() {
    let fake = FakePowerOff::new("exit 0");
    let (emergency, heard) = started(fake.fallback());
    let (line, _helper) = pipe();
    // Fill the pipe as a helper that stopped reading leaves it.
    let filler = line.stream.try_clone().unwrap();
    filler.set_nonblocking(true).unwrap();
    let chunk = [0u8; 4096];
    while std::io::Write::write(&mut &filler, &chunk).is_ok() {}
    emergency.open(line);
    let start = Instant::now();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffAsked);
    assert!(start.elapsed() < PATIENCE);
}

#[test]
fn a_power_off_that_hangs_is_given_up_on_and_none_found_is_no_power_off() {
    let fake = FakePowerOff::new("sleep 30");
    let mut fallback = fake.fallback();
    fallback.limit = Duration::from_millis(300);
    let (emergency, heard) = started(fallback);
    emergency.close();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffFailed);

    let (emergency, heard) = started(Fallback {
        program: None,
        ..fake.fallback()
    });
    emergency.close();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffFailed);

    let refused = FakePowerOff::new("exit 1");
    let (emergency, heard) = started(refused.fallback());
    emergency.close();
    emergency.fire();
    assert_eq!(next(&heard), Outcome::PowerOffFailed);
}

#[test]
fn the_systems_power_off_asks_logind_without_a_password_prompt() {
    let fallback = Fallback::system();
    assert_eq!(fallback.args, ["poweroff", "--no-ask-password"]);
    assert_eq!(fallback.grace, HELPER_GRACE);
    assert_eq!(fallback.limit, POWER_OFF_LIMIT);
    if let Some(program) = &fallback.program {
        assert!(program.ends_with("systemctl") && program.is_absolute());
    }
}

#[test]
fn the_grace_after_a_late_request_counts_from_the_request() {
    let fake = FakePowerOff::new("exit 0");
    let mut fallback = fake.fallback();
    fallback.grace = Duration::from_millis(400);
    let (tell, heard) = channel();
    let emergency = Emergency::start(fallback, move |outcome| {
        let _ = tell.send((outcome, Instant::now()));
    });
    emergency.fire();
    // The session opens late, shortly before the grace of the press runs
    // out, as one does once pkexec's password was typed.
    std::thread::sleep(Duration::from_millis(300));
    let (line, helper) = pipe();
    emergency.open(line);
    assert_eq!(read_request(&helper).id, EMERGENCY_ID);
    let (asked, written) = heard.recv_timeout(PATIENCE).expect("a report");
    assert_eq!(asked, Outcome::HelperAsked);
    let (off, later) = heard.recv_timeout(PATIENCE).expect("a report");
    assert_eq!(off, Outcome::PowerOffAsked);
    assert!(
        later - written >= Duration::from_millis(400),
        "a whole grace after the request: {:?}",
        later - written
    );
}

/// The names of this process's threads.
fn thread_names() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|task| std::fs::read_to_string(task.ok()?.path().join("comm")).ok())
        .map(|name| name.trim_end().to_string())
        .collect()
}

#[test]
fn its_thread_keeps_the_name_of_the_thread_that_starts_it() {
    let (before, after) = std::thread::spawn(|| {
        crate::process::name_neutrally().unwrap();
        let count = || {
            thread_names()
                .iter()
                .filter(|name| *name == "session")
                .count()
        };
        let before = count();
        let (_emergency, _heard) = started(Fallback {
            program: None,
            args: Vec::new(),
            grace: GRACE,
            limit: Duration::from_secs(1),
        });
        (before, count())
    })
    .join()
    .unwrap();
    assert_eq!(after, before + 1, "the emergency's thread is `session` too");
    assert!(!thread_names().iter().any(|name| name == "emergency"));
}
