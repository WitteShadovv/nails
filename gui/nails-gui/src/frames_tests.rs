// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use nails_api::protocol::{Hello, PROTOCOL_VERSION};

fn reader(bytes: &[u8]) -> FrameReader<&[u8]> {
    FrameReader::new(bytes)
}

fn hello_line() -> String {
    Frame::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        engine: "0.3.0".to_string(),
    })
    .to_line()
}

#[test]
fn frames_are_read_a_line_each_until_the_pipe_closes() {
    let input = format!("{}\n{}\n", hello_line(), hello_line());
    let mut frames = reader(input.as_bytes());
    for _ in 0..2 {
        assert!(matches!(frames.next_frame(), Ok(Some(Frame::Hello(_)))));
    }
    assert!(matches!(frames.next_frame(), Ok(None)));
    assert!(
        matches!(frames.next_frame(), Ok(None)),
        "the end stays the end"
    );
}

#[test]
fn a_frame_split_across_reads_is_joined() {
    // A reader that hands out one byte at a time, as a slow pipe may.
    struct Trickle<'a>(&'a [u8]);
    impl Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            match self.0.split_first() {
                Some((first, rest)) if !out.is_empty() => {
                    out[0] = *first;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }
    let input = format!("{}\n", hello_line());
    let mut frames = FrameReader::new(Trickle(input.as_bytes()));
    assert!(matches!(frames.next_frame(), Ok(Some(Frame::Hello(_)))));
    assert!(matches!(frames.next_frame(), Ok(None)));
}

#[test]
fn a_pipe_that_closes_inside_a_line_is_an_error() {
    let input = hello_line();
    let mut frames = reader(input.as_bytes());
    assert!(matches!(frames.next_frame(), Err(FrameError::Truncated)));
}

#[test]
fn a_line_over_the_limit_is_refused_before_it_is_parsed() {
    let input = vec![b' '; MAX_FRAME_BYTES + 1];
    let mut frames = reader(&input);
    assert!(matches!(frames.next_frame(), Err(FrameError::TooLong)));
    assert!(matches!(decode_frame(&input), Err(FrameError::TooLong)));
}

#[test]
fn a_line_at_the_limit_is_read() {
    // A hello padded with spaces to exactly the limit: JSON allows the
    // whitespace, so only the length is under test.
    let hello = hello_line();
    let mut line = hello.into_bytes();
    line.resize(MAX_FRAME_BYTES, b' ');
    line.push(b'\n');
    let mut frames = reader(&line);
    assert!(matches!(frames.next_frame(), Ok(Some(Frame::Hello(_)))));
}

#[test]
fn a_line_of_another_shape_is_malformed() {
    for line in [
        "not json",
        "{}",
        r#"{"hello":{"protocol":1,"engine":"0.3.0","extra":1}}"#,
        r#"{"event":{"id":1,"event":{"type":"reboot"}}}"#,
        r#"{"result":{"id":1,"exit":0}}"#,
        r#"{"result":{"id":-1,"exit":0,"envelope":{}}}"#,
        r#"{"result":{"id":1,"exit":300,"envelope":{}}}"#,
        r#"{"hello":{"protocol":1,"engine":"0.3.0"},"event":{}}"#,
    ] {
        let input = format!("{line}\n");
        let mut frames = reader(input.as_bytes());
        assert!(
            matches!(frames.next_frame(), Err(FrameError::Malformed(_))),
            "{line}"
        );
    }
}

#[test]
fn every_error_says_what_went_wrong() {
    let io = FrameError::Io(std::io::Error::other("gone"));
    for (error, words) in [
        (io, "the pipe failed: gone"),
        (FrameError::TooLong, "longer than"),
        (FrameError::Truncated, "middle of a frame"),
        (FrameError::Malformed("x".to_string()), "not a frame: x"),
    ] {
        assert!(error.to_string().contains(words), "{error}");
    }
}
