// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The answer to a confirmation prompt, read from the terminal.
//!
//! `activate`, `deactivate` and `discard` confirm before they act. Each runs
//! with the cancellation handlers installed ([`nails_core::cancel`]), which
//! restart an interrupted read: a plain read of the answer would go on until
//! Enter, and Ctrl+C would only echo `^C`. [`read_answer`] polls instead and
//! looks at the cancel flag in between, so Ctrl+C at any of these prompts ends
//! it at once, and the command reports the cancel.

use std::io::BufRead;
use std::os::fd::BorrowedFd;

/// What the operator answered at a confirmation prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// `y` or `yes`.
    Yes,
    /// Anything else, or the end of the input.
    No,
    /// Ctrl+C (or a SIGTERM) while the prompt waited.
    Cancelled,
}

/// How often the prompt looks at the cancel flag while it waits.
const PROMPT_POLL: u16 = 100;

/// The answer typed on stdin, or [`Answer::Cancelled`] as soon as a signal
/// sets the cancel flag.
pub(crate) fn read_answer_from_stdin() -> Answer {
    use std::os::fd::AsFd;
    let stdin = std::io::stdin();
    read_answer(
        stdin.as_fd(),
        &mut stdin.lock(),
        nails_core::cancel::is_cancelled,
    )
}

/// Wait for a line on `input` (read through `reader`) and judge it, giving up
/// as soon as `cancelled` says so. Only `y` or `yes` (any case) confirms;
/// anything else, the end of the input or a read error declines.
pub(crate) fn read_answer(
    input: BorrowedFd<'_>,
    reader: &mut impl BufRead,
    cancelled: impl Fn() -> bool,
) -> Answer {
    use nix::poll::{PollFd, PollFlags, poll};
    loop {
        if cancelled() {
            return Answer::Cancelled;
        }
        let mut fds = [PollFd::new(input, PollFlags::POLLIN)];
        match poll(&mut fds, PROMPT_POLL) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {}
            Ok(_) => break,
            Err(_) => return Answer::No,
        }
    }
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return if cancelled() {
            Answer::Cancelled
        } else {
            Answer::No
        };
    }
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Answer::Yes
    } else {
        Answer::No
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The answer to `input` typed on a pipe standing in for the terminal,
    /// with the cancel flag as `cancelled` says.
    fn answer_to(input: &[u8], cancelled: bool) -> Answer {
        use std::io::Write;
        use std::os::fd::AsFd;
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(input).unwrap();
        drop(writer);
        let poll_end = reader.try_clone().unwrap();
        read_answer(
            poll_end.as_fd(),
            &mut std::io::BufReader::new(reader),
            || cancelled,
        )
    }

    #[test]
    fn the_prompt_takes_yes_and_nothing_else() {
        for input in [&b"y\n"[..], b" YES \n", b"Yes\n"] {
            assert_eq!(answer_to(input, false), Answer::Yes, "{input:?}");
        }
        for input in [&b"n\n"[..], b"\n", b"yep\n", b"sure\n"] {
            assert_eq!(answer_to(input, false), Answer::No, "{input:?}");
        }
        assert_eq!(answer_to(b"", false), Answer::No, "end of input");
        // Input that is not UTF-8 is a read error, and declines.
        assert_eq!(answer_to(b"\xff\n", false), Answer::No);
    }

    /// Ctrl+C at the prompt ends it at once, with nothing typed: the read is
    /// never left waiting for Enter.
    #[test]
    fn a_cancel_at_the_prompt_ends_it_without_waiting_for_enter() {
        use std::os::fd::AsFd;
        let (reader, _writer) = std::io::pipe().unwrap();
        let poll_end = reader.try_clone().unwrap();
        let asked = std::cell::Cell::new(0);
        let answer = read_answer(
            poll_end.as_fd(),
            &mut std::io::BufReader::new(reader),
            || {
                asked.set(asked.get() + 1);
                asked.get() > 2
            },
        );
        assert_eq!(answer, Answer::Cancelled);
        assert!(asked.get() > 2, "the flag was read while the prompt waited");
        assert_eq!(answer_to(b"y\n", true), Answer::Cancelled);
    }
}
