// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's program, `session` (the package `nails-gui`).
//!
//! - `session --version` names the window's version, the engine release it
//!   was built for and its protocol.
//! - `session` opens the window on the socket of the launcher (`sudo
//!   <root>/nails gui`), its standard input.
//! - `session --engine <root>/nails`, as the menu entry of a hidden session
//!   runs it, opens the window and starts that engine's helper through
//!   pkexec ([`nails_gui::launch`]). It first starts itself again as
//!   `session --engine -`, with the engine's path on standard input.
//!
//! Anywhere else it prints the launcher's line and exits with 2, before
//! anything connects to a display or a session bus. Whichever way it starts,
//! the process takes its neutral name first, and before the window opens it
//! limits itself; a menu entry's start first runs again on the launcher's
//! environment and starts pkexec before that ([`nails_gui::process`]).

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;

use nails_api::protocol::{PROTOCOL_VERSION, RELEASE};
use nails_gui::AppWindow;
use nails_gui::emergency::{Emergency, Fallback};
use nails_gui::launch::{self, Start};
use nails_gui::mailbox::Mailbox;
use nails_gui::model::Model;
use nails_gui::process;
use nails_gui::text;
use nails_gui::ui::{Controller, Hooks};
use nails_gui::worker::{self, Connect};
use slint::ComponentHandle;

thread_local! {
    /// The window's controller, on the window's thread, where the worker's
    /// updates are delivered.
    static CONTROLLER: RefCell<Option<Rc<RefCell<Controller>>>> = const { RefCell::new(None) };
}

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Args {
    /// Print the versions.
    Version,
    /// Open the window, starting this engine's helper when one is named.
    Open(Option<PathBuf>),
    /// Open the window that a menu entry's start started again: its engine
    /// comes on standard input.
    Restarted,
}

/// Read the arguments after the program's name.
fn parse(args: &[OsString]) -> Option<Args> {
    match args {
        [] => Some(Args::Open(None)),
        [flag] if flag == "--version" => Some(Args::Version),
        [flag, engine] if flag == "--engine" && engine == process::ENGINE_ON_STDIN => {
            Some(Args::Restarted)
        }
        [flag, engine] if flag == "--engine" && !engine.is_empty() => {
            Some(Args::Open(Some(PathBuf::from(engine))))
        }
        _ => None,
    }
}

fn main() -> ExitCode {
    // Before anything else, so every thread the window starts inherits it.
    if let Err(error) = process::name_neutrally() {
        eprintln!("The window could not name its process: {error}");
        return ExitCode::FAILURE;
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let engine = match parse(&args) {
        Some(Args::Version) => {
            println!(
                "nails-gui {} for NAILS {RELEASE} (protocol {PROTOCOL_VERSION})",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        Some(Args::Open(engine)) => engine,
        Some(Args::Restarted) => match process::engine_on_stdin() {
            Ok(engine) => Some(engine),
            Err(why) => {
                eprintln!("The window could not open: {why}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            eprintln!("usage: {} [--version | --engine <path>]", text::APP_ID);
            return ExitCode::from(2);
        }
    };

    let program = std::env::current_exe().unwrap_or_default();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok();
    // The menu entry names its engine and never hands over a socket; only
    // without one is standard input the launcher's.
    let launcher = if engine.is_none() {
        launch::take_launcher_socket()
    } else {
        None
    };
    let start = launch::decide(engine, launcher, &program, mountinfo.as_deref());
    let (connect, engine) = match start {
        Start::Launcher { stream, engine } => (Connect::Stream(stream), engine),
        Start::Pkexec { engine } => {
            // A menu entry's start comes with the desktop's environment and
            // streams: the window starts itself again on the launcher's
            // allowlist first, and only returns here once it runs on it.
            if let Err(why) = process::harden_menu_entry_start(&engine) {
                eprintln!("The window could not open: {why}");
                return ExitCode::FAILURE;
            }
            // pkexec starts before the window limits itself: under
            // no_new_privs execve ignores its set-user-ID bit, and it would
            // never become root.
            let connect = Connect::pkexec(launch::find_pkexec(), &engine);
            (connect, Some(engine))
        }
        Start::Refuse(line) => {
            eprintln!("{line}");
            return ExitCode::from(2);
        }
    };
    // Whichever way it started, before the toolkit starts a thread, and
    // after pkexec started.
    if let Err(error) = process::limit() {
        eprintln!("The window could not open: it could not limit itself: {error}");
        return ExitCode::FAILURE;
    }
    // The window's own reading, which needs no helper: in a hidden session
    // its Emergency control shows from the start.
    let in_hidden_session = match (&engine, mountinfo.as_deref()) {
        (Some(engine), Some(mountinfo)) => engine
            .parent()
            .is_some_and(|root| launch::root_is_hidden_overlay(mountinfo, root)),
        _ => false,
    };
    match open(connect, engine, in_hidden_session) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("The window could not open: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Open the window, start the worker on `connect`, and run until the window
/// closes. `engine` is the engine the pages name; `in_hidden_session` whether
/// the window runs in one.
fn open(
    connect: Connect,
    engine: Option<PathBuf>,
    in_hidden_session: bool,
) -> Result<(), slint::PlatformError> {
    let window = AppWindow::new()?;
    // The menu entry of a hidden session has this name, so the desktop puts
    // the window with it; it names nothing about NAILS.
    slint::set_xdg_app_id(text::APP_ID)?;
    let waits_for_password = matches!(connect, Connect::Pkexec { .. });
    // Its thread starts before the worker's and waits for nothing but the
    // control's gesture.
    let emergency = Emergency::start(Fallback::system(), |_| {});
    // The worker's updates reach the window's thread through one task on
    // its event loop at a time, however many come.
    let mailbox = Mailbox::new(|mailbox: Mailbox| {
        let _ = slint::invoke_from_event_loop(move || {
            CONTROLLER.with(|controller| match controller.borrow().as_ref() {
                Some(controller) => controller.borrow_mut().take_turn(&mailbox),
                None => drop(mailbox.take()),
            });
        });
    });
    let worker = worker::spawn(connect, Some(emergency.clone()), move |update| {
        mailbox.put(update);
    });
    let line = worker.hang_up();
    let weak = window.as_weak();
    let hooks = Hooks {
        // The worker is gone only when the session is over, which the page
        // already says.
        ask: Box::new(move |ask| {
            let _ = worker.ask(ask);
        }),
        hang_up: Box::new(move || {
            let _ = line.hang_up();
        }),
        close: Box::new(move || {
            if let Some(window) = weak.upgrade() {
                let _ = window.hide();
            }
            let _ = slint::quit_event_loop();
        }),
        emergency: Box::new(move || {
            emergency.fire();
        }),
    };
    let model = Model::new(engine, waits_for_password).in_hidden_session(in_hidden_session);
    let controller = Controller::new(&window, model, hooks);
    CONTROLLER.with(|slot| *slot.borrow_mut() = Some(controller));
    window.show()?;
    // The loop ends with the window, whether its own Close or the window
    // manager's closed it.
    slint::run_event_loop()?;
    CONTROLLER.with(|slot| slot.borrow_mut().take());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_command_line_is_the_version_the_launchers_window_or_a_menu_entrys() {
        assert_eq!(parse(&args(&[])), Some(Args::Open(None)));
        assert_eq!(parse(&args(&["--version"])), Some(Args::Version));
        assert_eq!(parse(&args(&["--engine", "-"])), Some(Args::Restarted));
        assert_eq!(
            parse(&args(&["--engine", "/mnt/data/nails"])),
            Some(Args::Open(Some(PathBuf::from("/mnt/data/nails"))))
        );
        for wrong in [
            &["--engine"][..],
            &["--engine", ""],
            &["--version", "x"],
            &["--help"],
            &["/mnt/data/nails"],
            &["--engine", "/a", "--engine", "/b"],
        ] {
            assert_eq!(parse(&args(wrong)), None, "{wrong:?}");
        }
    }
}
