// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Starting the helper and the window on the two ends of one socket pair.
//!
//! The helper is the engine itself (`<root>/nails helper --stdio`), still
//! root, with its end of the pair as its standard input and output; the
//! window gets the other end as its standard input, which it reads and
//! writes. The helper learns the operator from the launcher
//! (`NAILS_TARGET_UID`), never from the privilege tool's variables: those are
//! left out of its environment, so a helper of this launcher, which carries
//! the launcher's `--config`, is never taken for one that pkexec started
//! itself, which takes no argument but `--stdio`. Neither inherits anything else from the launcher: their other
//! standard streams lead to `/dev/null`, so nothing either prints can reach a
//! terminal or a log a desktop keeps, and both start in `/`.
//!
//! Each leads a session of its own from before its `exec`: no controlling
//! terminal, and no process group the launching terminal or shell can
//! signal. The window is besides dropped to the operator's account, with no
//! supplementary groups, `no_new_privs`, no inherited descriptor above the
//! standard three, and the zero core-dump limit the launcher set for itself
//! at start (`main`).

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nails_core::process::run::{Account, drop_before_exec, leave_session_before_exec};

/// The window to start.
#[derive(Debug, Clone)]
pub(super) struct Window {
    /// Its program.
    pub(super) program: PathBuf,
    /// The account it runs as.
    pub(super) account: Account,
    /// Its whole environment.
    pub(super) vars: Vec<(OsString, OsString)>,
}

/// The helper's command: `engine` with `helper_args`, in `/`, naming the
/// operator `operator_uid` with `NAILS_TARGET_UID` and none of the privilege
/// tools' variables.
fn helper_command(engine: &Path, helper_args: &[OsString], operator_uid: u32) -> Command {
    let mut command = Command::new(engine);
    for var in nails_core::target_user::PRIVILEGE_ENV_VARS {
        command.env_remove(var);
    }
    command
        .env(
            nails_core::constants::ENV_TARGET_UID,
            operator_uid.to_string(),
        )
        .args(helper_args)
        .current_dir("/");
    command
}

/// Start the helper (`engine` with `helper_args`) and then `window`, and
/// return their process ids. The launcher keeps neither end of the pair, so
/// when one of them ends the other reads the end of its pipe: a window that
/// fails to start leaves a helper that ends at once.
pub(super) fn start(
    engine: &Path,
    helper_args: &[OsString],
    window: Window,
) -> std::io::Result<(u32, u32)> {
    let (helper_end, window_end) = UnixStream::pair()?;

    let mut command = helper_command(engine, helper_args, window.account.uid);
    command
        .stdin(Stdio::from(OwnedFd::from(helper_end.try_clone()?)))
        .stdout(Stdio::from(OwnedFd::from(helper_end)))
        .stderr(Stdio::null());
    leave_session_before_exec(&mut command);
    let helper = command.spawn();
    // The launcher's copies of the helper's end go with the command.
    drop(command);
    let helper = helper?;

    let mut child = Command::new(&window.program);
    child
        .env_clear()
        .envs(window.vars)
        .current_dir("/")
        .stdin(Stdio::from(OwnedFd::from(window_end)))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    drop_before_exec(&mut child, window.account);
    // The command holds the window's end until it is dropped here, whether
    // the start succeeded or not.
    let started = child.spawn();
    drop(child);
    let window = started?;
    Ok((helper.id(), window.id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// The helper names the operator the launcher resolved, and gets none of
    /// the privilege tools' variables: a helper with the launcher's options
    /// must not look like one that pkexec started itself.
    #[test]
    fn the_helper_learns_the_operator_from_the_launcher_alone() {
        let args = ["--config", "/mnt/config/nails.toml", "helper", "--stdio"].map(OsString::from);
        let command = helper_command(Path::new("/mnt/nails"), &args, 1000);
        let envs: Vec<(&OsStr, Option<&OsStr>)> = command.get_envs().collect();
        assert!(
            envs.contains(&(OsStr::new("NAILS_TARGET_UID"), Some(OsStr::new("1000")))),
            "{envs:?}"
        );
        for var in [
            "PKEXEC_UID",
            "SUDO_UID",
            "SUDO_USER",
            "DOAS_UID",
            "DOAS_USER",
        ] {
            assert!(
                envs.contains(&(OsStr::new(var), None)),
                "{var} not removed: {envs:?}"
            );
        }
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            args.iter().map(OsString::as_os_str).collect::<Vec<_>>()
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
    }
}
