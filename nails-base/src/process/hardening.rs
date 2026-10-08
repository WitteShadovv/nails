// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process hardening applied before NAILS touches anything.
//!
//! A crash before `/var` is overlaid would write a core dump to the decoy: a
//! `core` file in the working directory, or a systemd-coredump entry under
//! `/var/lib/systemd/coredump` together with a journal record. Either holds the
//! process memory (configuration, paths, the hidden volume's mount point) on the
//! disk the session is meant to leave untouched.

/// Disable core dumps for this process and everything it spawns.
///
/// `PR_SET_DUMPABLE=0` makes the kernel skip the dump for this process even when
/// `core_pattern` pipes to a helper, and it also blocks `ptrace` attaches by
/// unprivileged processes. It is reset by `execve`, so `RLIMIT_CORE` is lowered
/// to zero as well (soft and hard): children inherit the limit and a file-based
/// `core_pattern` writes nothing for them. Both steps are attempted; the first
/// error is returned so the caller can log it, but a failure never stops NAILS.
pub fn disable_core_dumps() -> std::io::Result<()> {
    use nix::sys::resource::{Resource, setrlimit};

    let dumpable = nix::sys::prctl::set_dumpable(false);
    let rlimit = setrlimit(Resource::RLIMIT_CORE, 0, 0);
    dumpable.and(rlimit).map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `body` in a forked child and return whether it reported success, so
    /// the process-wide settings never leak into the test harness.
    fn in_child(body: fn() -> bool) -> bool {
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};

        // SAFETY: the child only issues raw syscalls (prctl, setrlimit,
        // getrlimit) and leaves with `_exit`, never touching locks the parent's
        // other threads may hold.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let code = if body() { 0 } else { 1 };
                // SAFETY: `_exit` skips atexit handlers and is async-signal-safe.
                unsafe { nix::libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
            }
        }
    }

    #[test]
    fn disables_dumps_and_zeroes_the_core_limit() {
        assert!(in_child(|| {
            use nix::sys::resource::{Resource, getrlimit};
            disable_core_dumps().is_ok()
                && nix::sys::prctl::get_dumpable() == Ok(false)
                && getrlimit(Resource::RLIMIT_CORE) == Ok((0, 0))
        }));
    }
}
