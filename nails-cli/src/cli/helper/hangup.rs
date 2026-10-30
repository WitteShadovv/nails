// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Watching the window's end of the pipe while an activation runs.
//!
//! A window that dies, or closes its pipe, while its activation is still
//! before the point of no return leaves nobody watching the switch, so the
//! activation is cancelled: a thread polls the helper's end of the pipe for a
//! hangup and trips the activation's cancel token, which its checkpoints read
//! as a Ctrl+C. The thread never reads from the pipe, so a request the window
//! writes meanwhile waits for the session, which reads it once the activation
//! has answered. After the point of no return a trip is never read: no
//! checkpoint is left.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nails_core::cancel::CancelToken;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

/// How often the watcher looks whether it should stop.
const STOP_POLL_MS: u8 = 100;

/// A running watcher. Dropping it stops the thread at its next look, without
/// waiting for it: the answer that follows the activation is not held up.
pub(crate) struct HangupWatch {
    stop: Arc<AtomicBool>,
}

impl HangupWatch {
    /// Watch `pipe` on a thread of its own, tripping `token` once the window
    /// has hung up. A window already gone trips it before this returns, so
    /// the activation never starts. `None` (and a log line) when the pipe
    /// cannot be watched: the activation then runs as the CLI's does,
    /// cancelled only by a signal.
    pub(crate) fn start(pipe: &OwnedFd, token: CancelToken) -> Option<Self> {
        let mut looked = false;
        if watch(pipe.as_fd(), PollTimeout::ZERO, || {
            std::mem::replace(&mut looked, true)
        }) {
            tracing::info!("the window has closed its pipe: cancelling the activation");
            token.cancel();
        }
        let fd = match pipe.try_clone() {
            Ok(fd) => fd,
            Err(error) => {
                tracing::warn!(%error, "the helper cannot watch the window's pipe");
                return None;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let spawned = std::thread::Builder::new()
            .name("hangup-watch".to_string())
            .spawn(move || {
                let interval = PollTimeout::from(STOP_POLL_MS);
                if watch(fd.as_fd(), interval, || stopped.load(Ordering::SeqCst)) {
                    tracing::info!("the window closed its pipe: cancelling the activation");
                    token.cancel();
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "the helper cannot watch the window's pipe");
            return None;
        }
        Some(Self { stop })
    }
}

impl Drop for HangupWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Wait until the other end of `pipe` hangs up (`true`) or `stop` says so
/// (`false`), asking `stop` about every `interval`. Data waiting on the pipe
/// is no hangup and is left where it is. A failed poll counts as a hangup:
/// the pipe can no longer be trusted to say whether anyone is watching.
pub(crate) fn watch(
    pipe: BorrowedFd<'_>,
    interval: PollTimeout,
    mut stop: impl FnMut() -> bool,
) -> bool {
    loop {
        if stop() {
            return false;
        }
        // POLLRDHUP alone: a pipe that only holds data does not wake the poll,
        // and POLLHUP, POLLERR and POLLNVAL are always reported. So whatever
        // woke it is a hangup (nix reads no POLLRDHUP back, so the flags are
        // not looked at).
        let mut fds = [PollFd::new(pipe, rdhup())];
        match poll(&mut fds, interval) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {}
            // Woken, or failed: either way nobody can be counted on to watch.
            Ok(_) | Err(_) => return true,
        }
    }
}

/// `POLLRDHUP`: the other end shut its writing half or closed. nix names no
/// such flag, so it is taken from the C library.
fn rdhup() -> PollFlags {
    PollFlags::from_bits_retain(nix::libc::POLLRDHUP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    const QUICK: PollTimeout = PollTimeout::ZERO;

    fn stop_after(limit: Duration) -> impl Fn() -> bool {
        let start = Instant::now();
        move || start.elapsed() > limit
    }

    /// A window that exits closes its end of the socket pair the launcher
    /// hands out: that is a hangup.
    #[test]
    fn a_closed_socket_is_a_hangup() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        assert!(watch(
            ours.as_fd(),
            QUICK,
            stop_after(Duration::from_secs(5))
        ));
    }

    /// A window that only shuts its writing half is gone as a sender too.
    #[test]
    fn a_shut_down_writing_half_is_a_hangup() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        theirs.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(watch(
            ours.as_fd(),
            QUICK,
            stop_after(Duration::from_secs(5))
        ));
    }

    /// A pipe whose writer closed, as a test's or a terminal's stdin.
    #[test]
    fn a_closed_pipe_is_a_hangup_even_with_data_left_in_it() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"{\"v\":1}\n").unwrap();
        drop(writer);
        let fd = OwnedFd::from(reader);
        assert!(watch(fd.as_fd(), QUICK, stop_after(Duration::from_secs(5))));
    }

    /// A request written while the activation runs is no hangup, and stays on
    /// the pipe for the session to read.
    #[test]
    fn data_on_an_open_pipe_is_no_hangup_and_is_left_unread() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        theirs.write_all(b"{\"v\":1}\n").unwrap();
        let start = Instant::now();
        assert!(!watch(
            ours.as_fd(),
            PollTimeout::from(10u8),
            stop_after(Duration::from_millis(100))
        ));
        assert!(start.elapsed() >= Duration::from_millis(100));
        let mut waiting = [0u8; 8];
        ours.set_nonblocking(true).unwrap();
        assert_eq!(std::io::Read::read(&mut &ours, &mut waiting).unwrap(), 8);
        drop(theirs);
    }

    /// The watcher trips the token once the window hangs up, and a stopped
    /// watcher trips nothing.
    #[test]
    fn the_watcher_trips_the_token_on_a_hangup_and_not_once_stopped() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(ours);
        let token = CancelToken::new();
        let watch = HangupWatch::start(&fd, token.clone()).expect("a watcher");
        assert!(!token.is_cancelled());
        drop(theirs);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !token.is_cancelled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(token.is_cancelled(), "the hangup tripped the token");
        drop(watch);

        let (ours, theirs) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(ours);
        let token = CancelToken::new();
        drop(HangupWatch::start(&fd, token.clone()).expect("a watcher"));
        std::thread::sleep(Duration::from_millis(u64::from(STOP_POLL_MS) * 3));
        drop(theirs);
        std::thread::sleep(Duration::from_millis(u64::from(STOP_POLL_MS) * 2));
        assert!(!token.is_cancelled(), "a stopped watcher trips nothing");
    }
}
