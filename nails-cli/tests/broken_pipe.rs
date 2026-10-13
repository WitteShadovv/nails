// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pipe-tolerant print helpers against a real pipe whose reader is gone.
//!
//! An emergency teardown restarts journald, which closes the stream the unit's
//! stderr is wired to; the next `eprintln!` then hits `EPIPE` and panics. The unit
//! tests cover the helpers with a writer that returns `BrokenPipe`, but cannot
//! redirect the process's real stderr. Here a child process gets a pipe as its
//! stderr with the read end already closed, so every write is a real `EPIPE`
//! from the kernel (Rust ignores `SIGPIPE`, so the process is not killed).

use nails::cli::output::{eprint_tolerating_broken_pipe, eprintln_tolerating_broken_pipe};
use nails_core::test_path;
use nails_core::test_support::{Outcome, Rerun};
use std::process::Stdio;

#[test]
fn stderr_helpers_survive_a_reader_that_has_gone() {
    let (reader, writer) = std::io::pipe().expect("create a pipe");
    drop(reader);
    let outcome = Rerun::new(test_path!(stderr_helpers_survive_a_reader_that_has_gone))
        .stderr(Stdio::from(writer))
        .run(|| {
            // Control: the plain macro really does panic here, so the pipe is
            // broken and the helpers below are tested against a real EPIPE.
            let plain = std::panic::catch_unwind(|| eprintln!("plain eprintln"));
            assert!(plain.is_err(), "eprintln! must panic on a closed pipe");

            eprintln_tolerating_broken_pipe("teardown diagnostic after journald restart");
            eprint_tolerating_broken_pipe("\r  countdown ");
        });
    assert_eq!(outcome, Outcome::Ran);
}
