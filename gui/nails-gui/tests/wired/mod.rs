// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window wired as `main` wires it, without a display: the window on
//! Slint's headless platform, the real worker and the real emergency line
//! against a fake helper, and a stand-in for `systemctl`. A test hands the
//! window's asks to the worker and the worker's updates to the window
//! itself, since the headless platform runs no event loop.

#![allow(dead_code)]

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use i_slint_backend_testing::{AccessibleRole, ElementHandle};
use nails_api::protocol::{Frame, Op, Request};
use nails_gui::client::ours;
use nails_gui::emergency::{Emergency, Outcome};
use nails_gui::model::Model;
use nails_gui::text;
use nails_gui::worker::{Connect, Update, Worker, spawn};

use crate::screen::Screen;
use crate::support::{FakeHelper, FakePowerOff, hello_answer};

/// How long a test waits for the worker, the helper or the emergency.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// How long the emergency waits for the helper here.
pub const GRACE: Duration = Duration::from_millis(500);

/// A fake helper that answers the hello and passes every other request to
/// `respond`, telling `seen` of each one.
pub fn helper<F>(seen: Sender<Request>, mut respond: F) -> (UnixStream, FakeHelper)
where
    F: FnMut(&Request) -> Vec<Frame> + Send + 'static,
{
    FakeHelper::start(ours(), move |request| {
        let _ = seen.send(request.clone());
        Some(match &request.op {
            Op::Hello(hello) => vec![hello_answer(request.id, hello)],
            _ => respond(request),
        })
    })
}

/// The next request the helper read that is not a hello.
pub fn next_request(seen: &Receiver<Request>) -> Request {
    loop {
        let request = seen.recv_timeout(PATIENCE).expect("the helper reads");
        if !matches!(request.op, Op::Hello(_)) {
            return request;
        }
    }
}

/// The window, its worker and its emergency.
pub struct Wired {
    pub screen: Screen,
    pub worker: Worker,
    heard: Receiver<Update>,
    outcomes: Receiver<Outcome>,
}

impl Wired {
    /// A window on `connect` that powers off through `power_off`, in a
    /// hidden session by its own reading when `in_hidden_session`.
    pub fn new(connect: Connect, power_off: &FakePowerOff, in_hidden_session: bool) -> Self {
        let (tell, outcomes) = channel();
        let emergency = Emergency::start(power_off.fallback(GRACE), move |outcome| {
            let _ = tell.send(outcome);
        });
        let (tell, heard) = channel();
        let worker = spawn(connect, Some(emergency.clone()), move |update| {
            let _ = tell.send(update);
        });
        let model = Model::new(Some(PathBuf::from("/mnt/data/nails")), false)
            .in_hidden_session(in_hidden_session);
        let screen = Screen::with_emergency(
            model,
            Box::new(move || {
                emergency.fire();
            }),
        );
        Self {
            screen,
            worker,
            heard,
            outcomes,
        }
    }

    /// Hand the worker the window's asks and the window the worker's
    /// updates, until one for which `last` holds was handed over, and the
    /// asks it brought to the worker too.
    pub fn pump_until(&self, last: impl Fn(&Update) -> bool) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            self.hand_over_asks();
            let left = deadline.saturating_duration_since(Instant::now());
            let update = self.heard.recv_timeout(left).expect("the worker reports");
            let done = last(&update);
            self.screen.update(update);
            if done {
                self.hand_over_asks();
                return;
            }
        }
    }

    fn hand_over_asks(&self) {
        for ask in self.screen.asks() {
            assert!(self.worker.ask(ask), "the worker listens");
        }
    }

    /// What the emergency's thread reported next.
    pub fn outcome(&self) -> Outcome {
        self.outcomes
            .recv_timeout(PATIENCE)
            .expect("the emergency reports")
    }

    /// The Emergency control at rest.
    pub fn control(&self) -> ElementHandle {
        self.screen
            .find_with(text::EMERGENCY, AccessibleRole::Button)
    }

    /// The person's gesture: hold the control until its bar is full, let go.
    pub fn hold(&self) {
        hold(&self.screen);
    }
}

/// Hold `screen`'s Emergency control until its bar is full, and let go.
pub fn hold(screen: &Screen) {
    let control = screen.find_with(text::EMERGENCY, AccessibleRole::Button);
    let at = screen.middle(&control);
    screen.press_at(at);
    screen.wait_ms(1100);
    screen.release_at(at);
    assert_eq!(screen.emergencies(), 1, "the emergency fired");
}
