// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The `nails-gui` binary itself: it names its versions, and started neither
//! by the launcher nor in a hidden session it opens nothing and names the
//! launcher's line instead.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use nails_api::protocol::{PROTOCOL_VERSION, RELEASE};

/// How long the window may take to answer before the test ends it and fails.
const LIMIT: Duration = Duration::from_secs(60);

/// Run `command` to its end within [`LIMIT`], or end it and fail.
fn finish(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the window starts");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("the window can be waited for") {
            break status;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the window did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

fn window() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nails-gui"));
    // No display to reach: a window that tried to open would fail, not hang.
    command
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("WAYLAND_SOCKET")
        .stdin(Stdio::null());
    command
}

#[test]
fn the_version_names_the_engine_release_and_the_protocol() {
    let output = finish(window().arg("--version"));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            "nails-gui {} for NAILS {RELEASE} (protocol {PROTOCOL_VERSION})\n",
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[test]
fn any_other_argument_is_a_usage_error() {
    for args in [
        vec!["--help"],
        vec!["--version", "x"],
        vec!["status"],
        vec!["--engine"],
    ] {
        let output = finish(window().args(&args));
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "usage: nails-gui [--version | --engine <path>]\n"
        );
    }
}

#[test]
fn an_engine_outside_a_hidden_session_of_its_volume_gets_no_pkexec() {
    // The test runs on no hidden session, so the menu entry's command opens
    // nothing: pkexec is never started, and the line names that engine.
    let output = finish(window().args(["--engine", "/mnt/data/nails"]));
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "The window opens from a terminal: sudo /mnt/data/nails gui\n"
    );
}

#[test]
fn outside_the_launcher_and_a_hidden_session_the_window_opens_nothing() {
    // The test binary lies in a build directory, not in `<root>/gui/bin`, and
    // its standard input is not a socket: there is no hidden session of its
    // volume to start pkexec in.
    let output = finish(&mut window());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "The window opens from a terminal: sudo <hidden volume>/nails gui\n"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn on_the_launchers_socket_the_window_tries_to_open_and_says_why_it_cannot() {
    // Standard input is one end of a pair, as the launcher hands it: the
    // window takes it and goes on to open, which fails here without a display
    // before anything is sent on the pair.
    let (window_end, mut helper_end) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_end.set_read_timeout(Some(LIMIT)).unwrap();
    let output = finish(window().stdin(Stdio::from(std::os::fd::OwnedFd::from(window_end))));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("The window could not open: "),
        "{stderr}"
    );
    // The window wrote nothing on its end of the pair, and closed it.
    let mut sent = Vec::new();
    std::io::Read::read_to_end(&mut helper_end, &mut sent).unwrap();
    assert!(sent.is_empty(), "{sent:?}");
}
