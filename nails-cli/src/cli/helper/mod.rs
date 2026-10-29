// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails helper --stdio`: the root end of a window's private pipe.
//!
//! A window never runs as root. It starts this helper as root (through the
//! launcher on the decoy, or pkexec in the hidden session) with the helper's
//! stdin and stdout as its pipe, and drives the engine through it with the
//! protocol of [`nails_api::protocol`]: a hello handshake that refuses a
//! window of another release, then one request at a time, each answered with
//! the envelope the CLI prints for the same command. The helper reads only
//! requests from the pipe and only frames go out on it; it takes no file path
//! from the window but a discard target, which the engine checks as it checks
//! the CLI's.
//!
//! The helper is built only with the `gui` cargo feature, so a release built
//! without it has no such command and no root interface for a window.

mod ops;
mod reader;
mod session;

use std::os::fd::AsFd;
use std::path::Path;

use crate::cli::output::ExitStatus;

/// How often an idle helper looks whether a signal asked it to stop.
const STOP_POLL_MS: u8 = 200;

/// Serve one window on stdin and stdout until it closes the pipe, a request is
/// refused, or SIGINT or SIGTERM asks the helper to stop (a running operation
/// finishes first, cancelled at its next checkpoint). A hangup does not stop
/// it: the dispatcher installed the handlers that catch SIGHUP.
pub fn execute(env: &nails_core::RuntimeEnv, config: Option<&Path>) -> ExitStatus {
    let stdin = std::io::stdin();
    // An unbuffered handle of its own, so no request sits in a buffer the poll
    // cannot see.
    let input = match stdin.as_fd().try_clone_to_owned() {
        Ok(fd) => std::fs::File::from(fd),
        Err(error) => {
            tracing::error!(%error, "the helper could not read its pipe");
            return ExitStatus::Failed;
        }
    };
    let poll_on = match input.try_clone() {
        Ok(fd) => fd,
        Err(error) => {
            tracing::error!(%error, "the helper could not read its pipe");
            return ExitStatus::Failed;
        }
    };
    let stopped = nails_core::cancel::is_cancelled;
    let wait = || {
        reader::wait_readable(
            poll_on.as_fd(),
            nix::poll::PollTimeout::from(STOP_POLL_MS),
            stopped,
        )
    };
    let mut lines = reader::LineReader::new(input, wait);
    let writer = session::FrameWriter::new(Box::new(std::io::stdout()));
    let mut engine = ops::Engine::new(env, config.map(Path::to_path_buf));
    let end = session::serve(&mut lines, &writer, &mut engine, stopped);
    tracing::debug!(?end, "helper session ended");
    end.exit_status()
}

#[cfg(test)]
mod tests {
    use crate::cli::{Cli, Commands};

    #[test]
    fn the_helper_takes_only_its_stdio_transport_and_needs_root() {
        assert!(Cli::try_parse_checked_from(["nails", "helper"]).is_err());
        assert!(Cli::try_parse_checked_from(["nails", "helper", "--stdio", "x"]).is_err());
        let cli = Cli::try_parse_checked_from(["nails", "helper", "--stdio"]).unwrap();
        assert!(matches!(cli.command, Commands::Helper(ref args) if args.stdio));
        assert!(crate::cli::main_guard::requires_root(&cli.command));
        assert!(super::super::command_is_mutating(&cli.command));
    }
}
