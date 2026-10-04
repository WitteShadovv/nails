// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test support for [`ProcessRunner`]: a recording runner and helpers for
//! tests that drive the real executors into the runtime guard.

use super::{ProcessCommand, ProcessRunner};
use crate::{NailsError, Result};
use std::collections::VecDeque;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
use std::sync::Mutex;

/// Records every command and answers from a queue of scripted results.
///
/// Once the queue is empty, commands exit 0 with no output.
pub(crate) struct MockProcessRunner {
    calls: Mutex<Vec<ProcessCommand>>,
    responses: Mutex<VecDeque<Result<Output>>>,
}

impl MockProcessRunner {
    pub(crate) fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::new()),
        }
    }

    /// Queues the result of the next command that has no answer yet.
    pub(crate) fn with_response(self, response: Result<Output>) -> Self {
        self.responses
            .lock()
            .expect("mock runner mutex poisoned")
            .push_back(response);
        self
    }

    /// Commands run so far, oldest first.
    pub(crate) fn calls(&self) -> Vec<ProcessCommand> {
        self.calls
            .lock()
            .expect("mock runner mutex poisoned")
            .clone()
    }
}

impl ProcessRunner for MockProcessRunner {
    fn run(&self, command: &ProcessCommand) -> Result<Output> {
        self.calls
            .lock()
            .expect("mock runner mutex poisoned")
            .push(command.clone());
        self.responses
            .lock()
            .expect("mock runner mutex poisoned")
            .pop_front()
            .unwrap_or_else(|| Ok(exited(0, "", "")))
    }
}

/// The output of a command that exited with `code`.
pub(crate) fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        status: ExitStatus::from_raw(code << 8),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

/// A PID above the kernel's `PID_MAX_LIMIT` (2^22), so no process can hold it.
///
/// Tests that drive a real executor into the runtime guard use it so that a
/// regressed guard still cannot signal a host process.
pub(crate) const UNUSED_PID: u32 = 4_194_305;

/// A systemd unit no host defines, for the same reason as [`UNUSED_PID`].
pub(crate) const UNKNOWN_UNIT: &str = "nails-test-no-such-unit.service";

/// Asserts that `result` is the real runner's test-runtime refusal of `program`.
pub(crate) fn assert_refused_in_test_runtime<T: std::fmt::Debug>(result: Result<T>, program: &str) {
    match result {
        Err(NailsError::InvalidState(message)) => {
            assert!(
                message.contains(&format!("Refusing to run {program} ")),
                "{message}"
            );
            assert!(message.contains("test/test-like runtime"), "{message}");
        }
        other => panic!("expected the runtime guard to refuse {program}, got {other:?}"),
    }
}
