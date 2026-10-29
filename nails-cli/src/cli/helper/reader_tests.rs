// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::io::Write;
use std::os::fd::AsFd;

fn ready() -> Readiness {
    Readiness::Ready
}

fn lines_of(input: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = LineReader::new(input, ready);
    let mut lines = Vec::new();
    while let Some(line) = reader.next_line().unwrap() {
        lines.push(line);
    }
    lines
}

#[test]
fn lines_come_out_one_at_a_time_without_their_newline() {
    assert_eq!(
        lines_of(b"one\ntwo\n\nthree\n"),
        vec![
            b"one".to_vec(),
            b"two".to_vec(),
            Vec::new(),
            b"three".to_vec()
        ]
    );
}

#[test]
fn bytes_after_the_last_newline_are_no_request() {
    assert_eq!(lines_of(b"one\npartial"), vec![b"one".to_vec()]);
    assert!(lines_of(b"").is_empty());
}

/// A reader that hands out at most `step` bytes per read, as a pipe may.
struct Trickle<'a> {
    data: &'a [u8],
    step: usize,
    reads: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.reads.is_multiple_of(2) {
            return Err(ErrorKind::Interrupted.into());
        }
        let n = self.step.min(self.data.len()).min(buf.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

#[test]
fn a_line_split_over_reads_and_interrupted_reads_is_one_line() {
    let input = Trickle {
        data: b"{\"a\":1}\n{\"b\":2}\n",
        step: 3,
        reads: 0,
    };
    let mut reader = LineReader::new(input, ready);
    assert_eq!(reader.next_line().unwrap(), Some(b"{\"a\":1}".to_vec()));
    assert_eq!(reader.next_line().unwrap(), Some(b"{\"b\":2}".to_vec()));
    assert_eq!(reader.next_line().unwrap(), None);
}

#[test]
fn a_line_at_the_limit_is_read_and_one_past_it_is_refused() {
    let mut at_limit = vec![b'x'; MAX_LINE_BYTES];
    at_limit.push(b'\n');
    assert_eq!(lines_of(&at_limit), vec![vec![b'x'; MAX_LINE_BYTES]]);

    let mut past = vec![b'x'; MAX_LINE_BYTES + 1];
    past.push(b'\n');
    let mut reader = LineReader::new(past.as_slice(), ready);
    assert!(matches!(reader.next_line(), Err(LineError::TooLong)));
}

/// An endless line is refused once it passes the limit, without reading on:
/// the buffer never holds more than the limit and one read.
#[test]
fn an_endless_line_is_refused_without_buffering_it() {
    let mut reader = LineReader::new(std::io::repeat(b'x'), ready);
    assert!(matches!(reader.next_line(), Err(LineError::TooLong)));
    assert!(reader.buffer.len() <= MAX_LINE_BYTES + CHUNK);
}

#[test]
fn a_stop_while_waiting_ends_the_read() {
    let mut reader = LineReader::new(&b"never read\n"[..], || Readiness::Stop);
    assert!(matches!(reader.next_line(), Err(LineError::Stopped)));
}

#[test]
fn a_failed_read_is_reported() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(ErrorKind::BrokenPipe.into())
        }
    }
    let mut reader = LineReader::new(Broken, ready);
    assert!(matches!(reader.next_line(), Err(LineError::Io(_))));
}

#[test]
fn waiting_on_a_pipe_returns_once_it_holds_input_or_stop_is_asked() {
    let interval = nix::poll::PollTimeout::from(10u8);
    let (read_end, mut write_end) = std::io::pipe().unwrap();
    // Nothing written yet: only the stop request ends the wait.
    let asked = std::cell::Cell::new(0);
    let stop_on_third = || {
        asked.set(asked.get() + 1);
        asked.get() >= 3
    };
    assert_eq!(
        wait_readable(read_end.as_fd(), interval, stop_on_third),
        Readiness::Stop
    );
    assert_eq!(asked.get(), 3);

    write_end.write_all(b"x\n").unwrap();
    assert_eq!(
        wait_readable(read_end.as_fd(), interval, || false),
        Readiness::Ready
    );
}
