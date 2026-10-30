// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The helper's bounded line reader.
//!
//! The window may write anything onto the pipe, so the reader never holds
//! more than one line of [`MAX_LINE_BYTES`] plus one read's worth of bytes:
//! a longer line is refused before it is parsed, never buffered in full. It
//! waits for input through a `wait` step, which on the real pipe polls so a
//! SIGINT or SIGTERM ends an idle helper instead of leaving it blocked in a
//! read.

use std::io::{ErrorKind, Read};

use nails_api::protocol::MAX_LINE_BYTES;

/// How many bytes one read takes from the pipe.
const CHUNK: usize = 4096;

/// What the `wait` step found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// Input (or the end of it) is there to read.
    Ready,
    /// The helper was asked to stop while it waited.
    Stop,
}

/// Why no line was read.
#[derive(Debug)]
pub(crate) enum LineError {
    /// A line ran past [`MAX_LINE_BYTES`].
    TooLong,
    /// The helper was asked to stop while it waited for input.
    Stopped,
    /// Reading the pipe failed.
    Io(std::io::Error),
}

/// Lines from `input`, one request each, at most [`MAX_LINE_BYTES`] long.
pub(crate) struct LineReader<R, W> {
    input: R,
    wait: W,
    buffer: Vec<u8>,
    ended: bool,
}

impl<R: Read, W: FnMut() -> Readiness> LineReader<R, W> {
    /// A reader over `input` that calls `wait` before each read.
    pub(crate) fn new(input: R, wait: W) -> Self {
        Self {
            input,
            wait,
            buffer: Vec::new(),
            ended: false,
        }
    }

    /// The next line without its newline, or `None` at the end of the input.
    /// Bytes after the last newline at the end of the input are no request and
    /// are dropped.
    pub(crate) fn next_line(&mut self) -> Result<Option<Vec<u8>>, LineError> {
        loop {
            if let Some(end) = self.buffer.iter().position(|&b| b == b'\n') {
                if end > MAX_LINE_BYTES {
                    return Err(LineError::TooLong);
                }
                let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
                line.pop();
                return Ok(Some(line));
            }
            if self.buffer.len() > MAX_LINE_BYTES {
                return Err(LineError::TooLong);
            }
            if self.ended {
                return Ok(None);
            }
            if (self.wait)() == Readiness::Stop {
                return Err(LineError::Stopped);
            }
            self.fill()?;
        }
    }

    /// Append one read's worth of bytes to the buffer, noting the end of the
    /// input.
    fn fill(&mut self) -> Result<(), LineError> {
        let mut chunk = [0u8; CHUNK];
        loop {
            match self.input.read(&mut chunk) {
                Ok(0) => {
                    self.ended = true;
                    return Ok(());
                }
                Ok(n) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(LineError::Io(error)),
            }
        }
    }
}

/// Wait until `input` can be read, polling so that `stop` is asked about every
/// `interval`: [`Readiness::Stop`] as soon as it says so.
pub(crate) fn wait_readable(
    input: std::os::fd::BorrowedFd<'_>,
    interval: nix::poll::PollTimeout,
    stop: impl Fn() -> bool,
) -> Readiness {
    use nix::poll::{PollFd, PollFlags, poll};
    loop {
        if stop() {
            return Readiness::Stop;
        }
        let mut fds = [PollFd::new(input, PollFlags::POLLIN)];
        match poll(&mut fds, interval) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {}
            // Readable, hung up or failed: the read that follows tells which.
            _ => return Readiness::Ready,
        }
    }
}

#[cfg(test)]
#[path = "reader_tests.rs"]
mod tests;
