// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The process-exit chokepoint and the panic hook.

/// The process-exit chokepoint.
///
/// `main` turns a handler's [`crate::cli::output::ExitStatus`] into a
/// [`std::process::ExitCode`] and returns it, so this is the only place in the
/// binary that exits the process directly: the early dispatch of `emergency`
/// and `transition` (which run before clap) and the test-harness subprocess
/// entrypoints use it to end the process with a code.
pub(crate) fn exit_process(code: u8) -> ! {
    std::process::exit(i32::from(code));
}

/// Install a panic hook that keeps source paths off stderr.
///
/// The default hook prints `thread '…' panicked at <crate>/<file>:<line>` to
/// stderr, and a panic payload can carry a hidden-root path. This hook sends
/// the full payload and location only through `tracing` (whose active sink is
/// the hidden-root file log for the commands that write one) and prints a
/// single neutral line, with no path, crate name or payload, to stderr. It
/// deliberately does not chain to the previous hook.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        tracing::error!(target: "panic", detail = %info, "aborted by an internal error");
        // Pipe-safe: the terminal may already be gone (an emergency kills it).
        crate::cli::output::eprintln_tolerating_broken_pipe(
            "A fatal internal error occurred; the operation was aborted.",
        );
    }));
}
