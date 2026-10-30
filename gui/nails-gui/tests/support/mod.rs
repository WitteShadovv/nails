// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! A fake helper for the tests: the helper's end of a socket pair, served by
//! a thread that opens with a hello and answers each request the way a test
//! scripts it, and the recorded envelopes the real helper gave.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;
use std::time::Duration;

use nails_api::Event;
use nails_api::protocol::{Frame, Hello, Request, decode_request};
use serde_json::{Value, json};

/// How long either end of a test's pipe waits for the other before the read
/// fails: a test that would wait for ever fails instead.
pub const PIPE_TIMEOUT: Duration = Duration::from_secs(20);

/// A socket pair whose two ends give up a read after [`PIPE_TIMEOUT`].
pub fn pair() -> (UnixStream, UnixStream) {
    let (one, other) = UnixStream::pair().expect("a socket pair");
    for end in [&one, &other] {
        end.set_read_timeout(Some(PIPE_TIMEOUT))
            .expect("a read timeout");
        end.set_write_timeout(Some(PIPE_TIMEOUT))
            .expect("a write timeout");
    }
    (one, other)
}

/// A running fake helper.
pub struct FakeHelper {
    thread: JoinHandle<Vec<Request>>,
}

impl FakeHelper {
    /// Start a helper that opens with `hello` and answers each request with
    /// the frames `respond` gives for it, or closes the pipe when it gives
    /// `None`. Returns the window's end of the pipe.
    pub fn start<F>(hello: Hello, respond: F) -> (UnixStream, Self)
    where
        F: FnMut(&Request) -> Option<Vec<Frame>> + Send + 'static,
    {
        Self::start_raw(vec![Frame::Hello(hello).to_line()], respond)
    }

    /// As [`FakeHelper::start`], but the helper opens with `opening`, raw
    /// lines that need not be frames.
    pub fn start_raw<F>(opening: Vec<String>, mut respond: F) -> (UnixStream, Self)
    where
        F: FnMut(&Request) -> Option<Vec<Frame>> + Send + 'static,
    {
        let (window, helper) = pair();
        let thread = std::thread::spawn(move || {
            let mut requests = Vec::new();
            let mut output = helper.try_clone().expect("the helper's end");
            for line in opening {
                if writeln!(output, "{line}").is_err() {
                    return requests;
                }
            }
            let mut input = BufReader::new(helper);
            loop {
                let mut line = String::new();
                match input.read_line(&mut line) {
                    Ok(0) | Err(_) => return requests,
                    Ok(_) => {}
                }
                let request = decode_request(line.trim_end().as_bytes())
                    .unwrap_or_else(|error| panic!("the window sent {line:?}: {error:?}"));
                let reply = respond(&request);
                requests.push(request);
                let Some(frames) = reply else {
                    return requests;
                };
                for frame in frames {
                    if writeln!(output, "{}", frame.to_line()).is_err() {
                        return requests;
                    }
                }
            }
        });
        (window, Self { thread })
    }

    /// Every request the helper read, once it ended (at the latest when a
    /// read of it timed out).
    pub fn requests(self) -> Vec<Request> {
        self.thread.join().expect("the fake helper ran")
    }
}

/// The helper's answer to the window's hello, request `id`.
pub fn hello_answer(id: u64, hello: &Hello) -> Frame {
    result(
        id,
        0,
        json!({
            "schema_version": 2,
            "command": "hello",
            "ok": true,
            "data": hello,
        }),
    )
}

/// A result frame.
pub fn result(id: u64, exit: u8, envelope: Value) -> Frame {
    Frame::Result { id, exit, envelope }
}

/// An event frame.
pub fn event(id: u64, event: Event) -> Frame {
    Frame::Event { id, event }
}

/// A recorded envelope from `tests/fixtures/`, as the real helper gave it.
pub fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The events recorded with a fixture: its `.events.jsonl`
/// lines (one event a line).
pub fn fixture_events(name: &str) -> Vec<Event> {
    let path = format!(
        "{}/tests/fixtures/{name}.events.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{path}: {e}: {line}")))
        .collect()
}
