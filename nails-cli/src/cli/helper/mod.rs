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
//! requests from the pipe and only frames go out on it: before it serves, it
//! moves the pipe off its standard input and output, which then lead to
//! `/dev/null`, so no line a command or a child process prints can reach the
//! window. It reads no configuration a window names: started by `nails gui`
//! it reads the launcher's own (`--config` included), and started by pkexec
//! it takes no argument but `--stdio` (the dialog of its polkit action shows
//! none, see `main_guard::refuse_helper_options_under_pkexec`) and reads the
//! configuration beside the engine. The paths an operation takes (a discard
//! target, an offline image, the volume init lays out) reach the engine as
//! the CLI's arguments do, after the decoder has checked their shape.
//!
//! The helper is built only with the `gui` cargo feature, so a release built
//! without it has no such command and no root interface for a window.

mod hangup;
mod maintain;
mod ops;
mod reader;
mod session;
mod switch;

use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use crate::cli::output::ExitStatus;

/// How often an idle helper looks whether a signal asked it to stop.
const STOP_POLL_MS: u8 = 200;

/// Serve one window on stdin and stdout until it closes the pipe, a request is
/// refused, or SIGINT or SIGTERM asks the helper to stop (a running operation
/// finishes first, cancelled at its next checkpoint). A hangup does not stop
/// it: the dispatcher installed the handlers that catch SIGHUP.
pub fn execute(env: &nails_core::RuntimeEnv, config: Option<&Path>) -> ExitStatus {
    let (input, output) = match take_pipe() {
        Ok(pipe) => pipe,
        Err(error) => {
            tracing::error!(%error, "the helper could not take its pipe");
            return ExitStatus::Failed;
        }
    };
    let (poll_on, watched) = match (input.try_clone(), input.try_clone()) {
        (Ok(poll_on), Ok(watched)) => (poll_on, OwnedFd::from(watched)),
        (Err(error), _) | (_, Err(error)) => {
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
    let writer = session::FrameWriter::new(Box::new(output));
    let mut engine = ops::Engine::new(env, config.map(Path::to_path_buf)).watching(watched);
    let end = session::serve(&mut lines, &writer, &mut engine, stopped);
    tracing::debug!(?end, "helper session ended");
    end.exit_status()
}

/// Take the pipe off the standard input and output: duplicates of both that
/// no child inherits, with `/dev/null` put in their place. Everything the
/// helper's commands print on stdout, and every child they start, then goes
/// nowhere instead of between two frames.
fn take_pipe() -> std::io::Result<(std::fs::File, std::fs::File)> {
    // Unbuffered handles of their own (close-on-exec duplicates), so no
    // request sits in a buffer the poll cannot see.
    let input = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let output = std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    nix::unistd::dup2_stdin(&null)?;
    nix::unistd::dup2_stdout(&null)?;
    Ok((input, output))
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
