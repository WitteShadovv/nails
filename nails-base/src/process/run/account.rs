// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Starting a child as another account.
//!
//! nails runs as root, and its children run as root with it. A command that
//! acts in the operator's desktop session must not: a session bus admits only
//! the account that owns it, so an alert started as root never reaches the
//! desktop. Such a command names the account with
//! [`ProcessCommand::run_as`](super::ProcessCommand::run_as), and the runner
//! drops the child to it after the fork and before `exec`. The drop happens in
//! the child itself rather than through `runuser` or `su`, which would open a
//! PAM session that the system logs.
//!
//! After the drop the child also leaves the caller's session (`setsid`), so it
//! has no controlling terminal: a root shell's terminal is out of reach of a
//! process the operator's account can trace. And it sets `no_new_privs`, so
//! nothing it executes can gain privileges again (a setuid program included).
//! The new session is also the process group a deadline kills.

use std::io;

/// An account a child runs as: a uid and a primary gid, with no supplementary
/// groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    /// The user id.
    pub uid: u32,
    /// The primary group id.
    pub gid: u32,
}

/// Arrange for `child` to drop to `account` after the fork and before `exec`.
#[allow(unsafe_code)]
pub(super) fn drop_before_exec(child: &mut std::process::Command, account: Account) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the hook runs in the forked child before exec. It makes only the
    // getuid(2), geteuid(2), getgid(2), getegid(2), setgroups(2), setgid(2),
    // setuid(2), setsid(2) and prctl(2) system calls on integers copied into
    // the closure: no allocation, no lock, nothing that is not
    // async-signal-safe.
    unsafe {
        child.pre_exec(move || drop_to(account));
    }
}

/// Drop the calling process to `account`.
///
/// As root the supplementary groups go first, then the gid, then the uid: the
/// order in which each step still holds the privilege it needs. setuid(2) as
/// root sets the real, effective and saved uid at once, so nothing can take
/// root back afterwards. An unprivileged process cannot change its account, so
/// it can only already be `account`. Either way the result is checked, and a
/// process that is not `account` afterwards fails with `EPERM`. Then the
/// process starts a session of its own and sets `no_new_privs`; a failure of
/// either fails the start too.
#[allow(unsafe_code)]
fn drop_to(account: Account) -> io::Result<()> {
    use nix::libc;
    // SAFETY: plain system calls on integers (see `drop_before_exec`).
    unsafe {
        if libc::geteuid() == 0
            && (libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(account.gid) != 0
                || libc::setuid(account.uid) != 0)
        {
            return Err(io::Error::last_os_error());
        }
        let dropped = libc::getuid() == account.uid
            && libc::geteuid() == account.uid
            && libc::getgid() == account.gid
            && libc::getegid() == account.gid;
        if !dropped {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if libc::setsid() < 0 || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Account;
    use crate::process::run::{ProcessCommand, ProcessRunner, RealProcessRunner};

    /// The account the tests run as.
    fn this_account() -> Account {
        Account {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        }
    }

    /// `sh -c <script>` as `account`, allowed in the test runtime.
    fn shell_as(script: &str, account: Account) -> ProcessCommand {
        ProcessCommand::exact("/bin/sh")
            .arg("-c")
            .arg(script)
            .run_as(account.uid, account.gid)
            .allow_in_test_runtime()
    }

    /// Every alert drops to an account and has a deadline. The drop starts a
    /// session of its own (setsid), which a process group leader cannot, so
    /// the deadline must not make the child one first.
    #[test]
    fn a_command_with_an_account_and_a_deadline_starts() {
        let (ok, stdout, stderr) = RealProcessRunner
            .run_text(
                &shell_as("echo started", this_account())
                    .deadline(std::time::Duration::from_secs(5)),
            )
            .unwrap();
        assert!(ok, "{stderr}");
        assert_eq!(stdout.trim(), "started");
    }

    #[test]
    fn a_command_names_the_account_it_runs_as() {
        let command = ProcessCommand::tool("busctl").run_as(1000, 100);
        assert_eq!(
            command.account(),
            Some(Account {
                uid: 1000,
                gid: 100
            })
        );
        assert_eq!(ProcessCommand::tool("busctl").account(), None);
    }

    #[test]
    fn the_child_runs_as_the_account_it_names() {
        let account = this_account();
        let (ok, stdout, stderr) = RealProcessRunner
            .run_text(&shell_as("id -u; id -g; id -G", account))
            .unwrap();
        assert!(ok, "{stderr}");
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines[0], account.uid.to_string(), "{stdout}");
        assert_eq!(lines[1], account.gid.to_string(), "{stdout}");
    }

    /// The child leads a session of its own (so it has no controlling
    /// terminal) and cannot gain privileges through what it executes.
    #[test]
    fn the_child_leaves_the_session_and_gains_no_privileges() {
        let (ok, stdout, stderr) = RealProcessRunner
            .run_text(&shell_as(
                "set -- $(cut -d' ' -f6,7 /proc/self/stat); echo \"$$ $1 $2\"; \
                 grep '^NoNewPrivs:' /proc/self/status",
                this_account(),
            ))
            .unwrap();
        assert!(ok, "{stderr}");
        let mut lines = stdout.lines();
        let ids: Vec<&str> = lines.next().unwrap().split(' ').collect();
        assert_eq!(ids[0], ids[1], "the shell leads its own session: {stdout}");
        assert_eq!(ids[2], "0", "no controlling terminal: {stdout}");
        assert_eq!(
            lines
                .next()
                .map(|line| line.split_whitespace().collect::<Vec<_>>()),
            Some(vec!["NoNewPrivs:", "1"]),
            "{stdout}"
        );
    }

    #[test]
    fn a_drop_the_process_cannot_make_never_starts_the_program() {
        // Root can take any account; only an unprivileged run shows the refusal.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let other = Account {
            uid: this_account().uid + 1,
            ..this_account()
        };

        let err = RealProcessRunner
            .run(&shell_as(&format!("touch '{}'", marker.display()), other))
            .unwrap_err();

        assert_eq!(
            err.io_kind(),
            Some(std::io::ErrorKind::PermissionDenied),
            "{err}"
        );
        assert!(!marker.exists(), "the program ran without the drop");
    }

    /// The drop as the root of an unprivileged user namespace, where the kernel
    /// refuses setgroups(2).
    mod kernel_tests {
        use super::*;
        use crate::test_support::Rerun;

        #[test]
        fn a_drop_the_kernel_refuses_never_starts_the_program() {
            let _ = Rerun::new(crate::test_path!(
                a_drop_the_kernel_refuses_never_starts_the_program
            ))
            .in_user_mount_ns()
            .run(|| {
                let dir = tempfile::tempdir().unwrap();
                let marker = dir.path().join("ran");
                let root = Account { uid: 0, gid: 0 };

                let err = RealProcessRunner
                    .run(&shell_as(&format!("touch '{}'", marker.display()), root))
                    .unwrap_err();

                assert_eq!(
                    err.io_kind(),
                    Some(std::io::ErrorKind::PermissionDenied),
                    "{err}"
                );
                assert!(!marker.exists(), "the program ran although the drop failed");
            });
        }
    }
}
