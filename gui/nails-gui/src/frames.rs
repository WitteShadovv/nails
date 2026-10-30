// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Reading the helper's frames: one JSON document a line, bounded and
//! strict.
//!
//! The helper runs as root and the window as the operator, so the helper is
//! the more trusted end; the window still reads its bytes with a limit, so a
//! line that never ends cannot take the window's memory, and as exactly a
//! [`Frame`] of the protocol, so a line of any other shape ends the session
//! instead of being guessed at.

use std::io::{BufRead, BufReader, ErrorKind, Read};

use nails_api::protocol::Frame;

/// The longest frame line the window reads, in bytes, without its newline.
/// An envelope with every finding of a deep verify stays well below it.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    /// The pipe failed.
    Io(std::io::Error),
    /// A line was longer than [`MAX_FRAME_BYTES`].
    TooLong,
    /// The pipe closed in the middle of a line.
    Truncated,
    /// A line is not a frame of the protocol.
    Malformed(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(error) => write!(f, "the pipe failed: {error}"),
            FrameError::TooLong => write!(f, "a frame is longer than {MAX_FRAME_BYTES} bytes"),
            FrameError::Truncated => write!(f, "the pipe closed in the middle of a frame"),
            FrameError::Malformed(why) => write!(f, "not a frame: {why}"),
        }
    }
}

/// The frames of one pipe, a line each.
pub struct FrameReader<R> {
    input: BufReader<R>,
    line: Vec<u8>,
}

impl<R: Read> FrameReader<R> {
    /// The frames read from `input`.
    pub fn new(input: R) -> Self {
        Self {
            input: BufReader::new(input),
            line: Vec::new(),
        }
    }

    /// The next frame, or `None` once the pipe closed between two frames.
    ///
    /// # Errors
    ///
    /// A [`FrameError`] for a failed pipe, a line over the limit, a pipe that
    /// closed inside a line, or a line that is not exactly a [`Frame`].
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if !self.next_line()? {
            return Ok(None);
        }
        decode_frame(&self.line).map(Some)
    }

    /// Read the next line into `self.line`, without its newline; false at the
    /// end of the pipe before any byte of a line.
    fn next_line(&mut self) -> Result<bool, FrameError> {
        self.line.clear();
        loop {
            let available = match self.input.fill_buf() {
                Ok(available) => available,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(FrameError::Io(error)),
            };
            if available.is_empty() {
                return if self.line.is_empty() {
                    Ok(false)
                } else {
                    Err(FrameError::Truncated)
                };
            }
            let (taken, ends) = match available.iter().position(|&b| b == b'\n') {
                Some(at) => (at, true),
                None => (available.len(), false),
            };
            if self.line.len() + taken > MAX_FRAME_BYTES {
                return Err(FrameError::TooLong);
            }
            self.line.extend_from_slice(&available[..taken]);
            self.input.consume(taken + usize::from(ends));
            if ends {
                return Ok(true);
            }
        }
    }
}

/// Read one frame line (without its newline) as exactly a [`Frame`].
///
/// # Errors
///
/// [`FrameError::TooLong`] over the limit and [`FrameError::Malformed`] for
/// a line that is not a frame: not JSON, an unknown kind or field, or a value
/// of the wrong type.
pub fn decode_frame(line: &[u8]) -> Result<Frame, FrameError> {
    if line.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLong);
    }
    serde_json::from_slice(line).map_err(|error| FrameError::Malformed(error.to_string()))
}

#[cfg(test)]
#[path = "frames_tests.rs"]
mod tests;
