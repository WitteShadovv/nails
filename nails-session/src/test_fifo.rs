// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! For the tests of code that must never open a FIFO. Code that opens one
//! anyway reads it to its end at once here, so the test fails on what that
//! code read instead of waiting for a writer that never comes.

use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use rustix::fs::{Mode, OFlags};

/// Run `f` while another thread opens the FIFO at `fifo` for writing every
/// few milliseconds, without blocking, and closes it again at once. A reader
/// `f` leaves waiting in its open then goes on and finds the FIFO empty with
/// no writer: the end of the file. While no reader has it open, each of these
/// opens fails and changes nothing.
pub(crate) fn releasing_readers<T>(fifo: &Path, f: impl FnOnce() -> T) -> T {
    let (stop, stopped) = mpsc::channel::<()>();
    let fifo = fifo.to_path_buf();
    let writer = std::thread::spawn(move || {
        while stopped.recv_timeout(Duration::from_millis(20)) == Err(RecvTimeoutError::Timeout) {
            let _ = rustix::fs::open(
                &fifo,
                OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            );
        }
    });
    let result = f();
    drop(stop);
    writer.join().expect("the thread that opens the FIFO");
    result
}

#[test]
fn a_read_of_the_fifo_ends_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let read = releasing_readers(&fifo, || std::fs::read(&fifo).unwrap());
    assert!(read.is_empty());
}
