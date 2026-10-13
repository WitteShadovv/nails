// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting modules for CLI commands
//!
//! [`OutputSettings`] holds the rendering decisions resolved once per run; the
//! per-command modules render results with it. Machine-readable output goes
//! through one [`envelope::Envelope`] on stdout, and every handler returns an
//! [`exit::ExitStatus`] so `main` owns the process exit code.

use std::io::{self, Write};

/// Write `line` and a trailing newline to `writer`, treating a broken pipe as
/// success.
///
/// A command's final result may be piped to a reader that has already exited —
/// `nails emergency | head`, or an emergency teardown that severs the session
/// reading its own stdout. The last write then fails with `BrokenPipe`. Because
/// the operation it reports has already completed, that is not a failure worth
/// aborting over (the default `println!` panics, which the panic hook turns into
/// a fatal-error line and a non-zero exit), so it is swallowed. Every other I/O
/// error is returned unchanged.
pub fn write_line_tolerating_broken_pipe<W: Write>(writer: &mut W, line: &str) -> io::Result<()> {
    match writeln!(writer, "{line}") {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Print `line` on stdout, tolerating a broken pipe (see
/// [`write_line_tolerating_broken_pipe`]). The pipe-safe replacement for
/// `println!` on the result-writing paths.
pub fn println_tolerating_broken_pipe(line: &str) {
    let mut stdout = io::stdout().lock();
    let _ = write_line_tolerating_broken_pipe(&mut stdout, line);
}

/// Print `line` and a trailing newline on stderr, tolerating a broken pipe. The
/// pipe-safe replacement for `eprintln!`.
///
/// An emergency teardown restarts journald as it scrubs the runtime journal,
/// which severs the `journal+console` stream the unit's stderr is wired to; a
/// later `eprintln!` then fails with `BrokenPipe` and panics. A teardown must
/// never abort on its own diagnostic output, so the broken pipe is swallowed
/// here and every other I/O error is ignored too (there is nowhere left to
/// report it).
pub fn eprintln_tolerating_broken_pipe(line: &str) {
    let mut stderr = io::stderr().lock();
    let _ = write_line_tolerating_broken_pipe(&mut stderr, line);
}

/// Write `text` to stderr with no trailing newline, flushing and tolerating a
/// broken pipe. The pipe-safe replacement for `eprint!` followed by a flush.
pub fn eprint_tolerating_broken_pipe(text: &str) {
    let mut stderr = io::stderr().lock();
    let _ = write!(stderr, "{text}");
    let _ = stderr.flush();
}

/// Flush stdout and stderr, ignoring every error (a broken pipe included):
/// whatever could be delivered has been.
pub fn flush_stdio() {
    let _ = io::stdout().lock().flush();
    let _ = io::stderr().lock().flush();
}

pub mod activate;
pub mod check;
pub mod deactivate;
pub mod dto;
pub mod envelope;
pub mod exit;
pub mod rehearse;
pub mod settings;
pub mod status;
pub mod verify;

// Re-export commonly used formatters
pub use activate::{
    ActivateResult, print_activate_human, print_activate_json_result, print_activate_progress,
};
pub use check::{print_check_human, print_check_json};
pub use deactivate::{deactivate_error_body, print_deactivate_json};
pub use envelope::{Envelope, ErrorBody, report_error};
pub use exit::ExitStatus;
pub use settings::{Environment, OutputMode, OutputSettings};
pub use status::{print_status_header, print_status_human, print_status_json};
pub use verify::print_verify_result;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// A writer whose every write fails with a chosen `ErrorKind`.
    struct FailingWriter(io::ErrorKind);

    impl io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "simulated"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.0, "simulated"))
        }
    }

    #[test]
    fn write_line_swallows_broken_pipe() {
        let mut writer = FailingWriter(io::ErrorKind::BrokenPipe);
        assert!(write_line_tolerating_broken_pipe(&mut writer, "done").is_ok());
    }

    #[test]
    fn write_line_surfaces_other_errors() {
        let mut writer = FailingWriter(io::ErrorKind::Other);
        let err = write_line_tolerating_broken_pipe(&mut writer, "done").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn write_line_writes_the_line_and_a_newline() {
        let mut buffer: Vec<u8> = Vec::new();
        write_line_tolerating_broken_pipe(&mut buffer, "hello").unwrap();
        assert_eq!(buffer, b"hello\n");
    }

    #[test]
    fn stderr_helpers_do_not_panic_on_a_broken_pipe() {
        // The stderr helpers lock the real stderr, so they cannot be redirected
        // to a FailingWriter here; the broken-pipe tolerance they rely on lives in
        // write_line_tolerating_broken_pipe, which the cases above exercise. This
        // smoke test guards against a regression that would make the wrappers
        // themselves panic on an ordinary write.
        eprintln_tolerating_broken_pipe("teardown diagnostic line");
        eprint_tolerating_broken_pipe("\r  countdown ");
    }
}
