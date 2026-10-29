// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_api::protocol::{CheckArgs, Request, Token};

/// A pipe end that keeps what was written, shared with the test.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn frames(&self) -> Vec<Frame> {
        let bytes = self.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}: {line}")))
            .collect()
    }
}

/// A dispatcher that records the operations it ran, sends one event for each
/// and answers with exit 0, or refuses an apply.
#[derive(Default)]
struct Recorder {
    ran: Vec<Op>,
}

impl Dispatch for Recorder {
    fn run(&mut self, op: Op, mut events: EventOut) -> Answer {
        self.ran.push(op.clone());
        events.emit(Event::Finished { success: true });
        if let Op::DiscardApply(_) = op {
            return Answer::Refused(ProtocolError {
                code: ErrorCode::BadToken,
                message: "no plan".to_string(),
            });
        }
        Answer::result(ExitStatus::Ok, &Envelope::success("test", op.name()))
    }
}

fn line(id: u64, op: Op) -> String {
    let mut line = Request {
        v: PROTOCOL_VERSION,
        id,
        op,
    }
    .to_line();
    line.push('\n');
    line
}

fn hello_line() -> String {
    line(1, Op::Hello(our_hello()))
}

/// Serve `input` with a [`Recorder`]: how it ended, the frames it wrote and
/// the operations it ran.
fn session(input: &str) -> (End, Vec<Frame>, Vec<Op>) {
    session_stopping(input, || false)
}

fn session_stopping(input: &str, stopped: impl Fn() -> bool) -> (End, Vec<Frame>, Vec<Op>) {
    let out = Captured::default();
    let writer = FrameWriter::new(Box::new(out.clone()));
    let mut reader = LineReader::new(input.as_bytes(), || Readiness::Ready);
    let mut recorder = Recorder::default();
    let end = serve(&mut reader, &writer, &mut recorder, stopped);
    (end, out.frames(), recorder.ran)
}

fn error_code(frame: &Frame) -> ErrorCode {
    match frame {
        Frame::Error { error, .. } => error.code,
        other => panic!("not an error: {other:?}"),
    }
}

#[test]
fn the_helper_speaks_first_and_answers_a_matching_hello() {
    let (end, frames, ran) = session(&hello_line());
    assert_eq!(end, End::Closed);
    assert_eq!(frames[0], Frame::Hello(our_hello()));
    let Frame::Result { id, exit, envelope } = &frames[1] else {
        panic!("{frames:?}");
    };
    assert_eq!((*id, *exit), (1, 0));
    assert_eq!(envelope["command"], "hello");
    assert_eq!(envelope["data"]["engine"], env!("CARGO_PKG_VERSION"));
    assert!(ran.is_empty());
}

#[test]
fn requests_run_one_at_a_time_in_order_with_their_events_before_the_answer() {
    let input = format!(
        "{}{}{}",
        hello_line(),
        line(2, Op::Status),
        line(3, Op::Check(CheckArgs::default()))
    );
    let (end, frames, ran) = session(&input);
    assert_eq!(end, End::Closed);
    assert_eq!(ran, vec![Op::Status, Op::Check(CheckArgs::default())]);
    let ids: Vec<(u64, &str)> = frames[2..]
        .iter()
        .map(|frame| match frame {
            Frame::Event { id, .. } => (*id, "event"),
            Frame::Result { id, .. } => (*id, "result"),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        ids,
        vec![(2, "event"), (2, "result"), (3, "event"), (3, "result")]
    );
}

#[test]
fn a_hello_from_another_release_or_protocol_ends_the_session() {
    for theirs in [
        Hello {
            protocol: PROTOCOL_VERSION,
            engine: "0.0.1".to_string(),
        },
        Hello {
            protocol: PROTOCOL_VERSION + 1,
            engine: env!("CARGO_PKG_VERSION").to_string(),
        },
    ] {
        let input = format!("{}{}", line(1, Op::Hello(theirs)), line(2, Op::Status));
        let (end, frames, ran) = session(&input);
        assert_eq!(end, End::Refused);
        assert_eq!(frames.len(), 2, "{frames:?}");
        assert_eq!(error_code(&frames[1]), ErrorCode::Handshake);
        assert!(ran.is_empty(), "nothing runs after a failed handshake");
    }
}

#[test]
fn an_operation_before_the_hello_or_a_second_hello_ends_the_session() {
    let (end, frames, ran) = session(&line(1, Op::Status));
    assert_eq!(end, End::Refused);
    assert_eq!(error_code(&frames[1]), ErrorCode::Handshake);
    assert!(ran.is_empty());

    let input = format!("{}{}{}", hello_line(), hello_line(), line(3, Op::Status));
    let (end, frames, ran) = session(&input);
    assert_eq!(end, End::Refused);
    assert_eq!(error_code(frames.last().unwrap()), ErrorCode::Handshake);
    assert!(ran.is_empty());
}

#[test]
fn a_malformed_or_overlong_request_ends_the_session() {
    let input = format!("{}not json\n{}", hello_line(), line(3, Op::Status));
    let (end, frames, ran) = session(&input);
    assert_eq!(end, End::Refused);
    let Frame::Error { id, error } = frames.last().unwrap() else {
        panic!("{frames:?}");
    };
    assert_eq!((*id, error.code), (None, ErrorCode::Malformed));
    assert!(ran.is_empty());

    let long = "x".repeat(nails_api::protocol::MAX_LINE_BYTES + 1);
    let (end, frames, _) = session(&format!("{}{long}\n", hello_line()));
    assert_eq!(end, End::Refused);
    assert_eq!(error_code(frames.last().unwrap()), ErrorCode::TooLong);
}

#[test]
fn a_request_with_a_bad_argument_is_refused_with_its_id() {
    let bad = "{\"v\":1,\"id\":9,\"op\":{\"discard_plan\":{\"target\":\"home\"}}}\n";
    let (end, frames, ran) = session(&format!("{}{bad}", hello_line()));
    assert_eq!(end, End::Refused);
    let Frame::Error { id, error } = frames.last().unwrap() else {
        panic!("{frames:?}");
    };
    assert_eq!((*id, error.code), (Some(9), ErrorCode::InvalidArgument));
    assert!(ran.is_empty());
}

#[test]
fn a_refused_token_answers_the_request_and_the_session_goes_on() {
    let apply = Op::DiscardApply(Token {
        token: "0".repeat(nails_api::protocol::TOKEN_HEX_DIGITS),
    });
    let input = format!("{}{}{}", hello_line(), line(2, apply), line(3, Op::Status));
    let (end, frames, ran) = session(&input);
    assert_eq!(end, End::Closed);
    assert_eq!(ran.len(), 2);
    assert!(frames.iter().any(|frame| matches!(
        frame,
        Frame::Error { id: Some(2), error } if error.code == ErrorCode::BadToken
    )));
    assert!(matches!(frames.last(), Some(Frame::Result { id: 3, .. })));
}

#[test]
fn a_stop_request_ends_the_session_after_the_running_answer() {
    let input = format!(
        "{}{}{}",
        hello_line(),
        line(2, Op::Status),
        line(3, Op::Status)
    );
    let asked = std::cell::Cell::new(0);
    let (end, _, ran) = session_stopping(&input, || {
        asked.set(asked.get() + 1);
        asked.get() >= 2
    });
    assert_eq!(end, End::Stopped);
    assert_eq!(ran, vec![Op::Status], "the second status never ran");
}

#[test]
fn a_stop_while_idle_and_a_broken_pipe_end_the_session() {
    let out = Captured::default();
    let writer = FrameWriter::new(Box::new(out));
    let mut reader = LineReader::new(&b""[..], || Readiness::Stop);
    let end = serve(&mut reader, &writer, &mut Recorder::default(), || false);
    assert_eq!(end, End::Stopped);

    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let writer = FrameWriter::new(Box::new(Closed));
    let input = hello_line();
    let mut reader = LineReader::new(input.as_bytes(), || Readiness::Ready);
    let end = serve(&mut reader, &writer, &mut Recorder::default(), || false);
    assert_eq!(end, End::Broken);
}

#[test]
fn each_end_has_its_exit_status() {
    assert_eq!(End::Closed.exit_status(), ExitStatus::Ok);
    assert_eq!(End::Stopped.exit_status(), ExitStatus::Cancelled);
    assert_eq!(End::Refused.exit_status(), ExitStatus::Failed);
    assert_eq!(End::Broken.exit_status(), ExitStatus::Failed);
}
