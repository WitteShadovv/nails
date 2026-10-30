// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's runtime directory, and the window's own directory in it.
//!
//! sudo and pkexec drop `XDG_RUNTIME_DIR`, so the launcher finds the
//! directory logind made for the operator, `/run/user/<uid>`, itself. The
//! window's Wayland and session-bus sockets are there, and so is everything
//! the window may write: its home and every XDG base directory point at a
//! fresh directory of its own in it. The launcher accepts the runtime
//! directory only if it is the operator's, private, and in RAM (a tmpfs, as
//! logind makes it), so nothing the window's libraries write (a font cache, say) can
//! reach a disk.

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use nails_api::window_env::{DirFacts, OWN_DIR_BYTES, USER_RUNTIME_BASE, judge, own_dir_name};
use nails_core::RuntimeEnv;
use nails_core::target_user::TargetUser;

use super::Refusal;
use crate::cli::output::ExitStatus;

/// The operator's runtime directory, checked.
pub(super) fn find(env: &RuntimeEnv, operator: &TargetUser) -> Result<PathBuf, Refusal> {
    let dir = base(env).join(operator.uid.to_string());
    let facts = facts_of(&dir).map_err(|error| no_session(operator, &dir, &error.to_string()))?;
    judge(&facts, operator.uid).map_err(|why| no_session(operator, &dir, &why))?;
    Ok(dir)
}

#[cfg(feature = "test-hooks")]
fn base(env: &RuntimeEnv) -> PathBuf {
    env.test_hooks
        .user_runtime_base
        .as_ref()
        .map_or_else(|| PathBuf::from(USER_RUNTIME_BASE), PathBuf::from)
}

#[cfg(not(feature = "test-hooks"))]
fn base(_env: &RuntimeEnv) -> PathBuf {
    PathBuf::from(USER_RUNTIME_BASE)
}

fn facts_of(dir: &Path) -> std::io::Result<DirFacts> {
    use nix::sys::statfs::{TMPFS_MAGIC, statfs};
    let meta = std::fs::symlink_metadata(dir)?;
    let in_ram = meta.is_dir() && statfs(dir).is_ok_and(|fs| fs.filesystem_type() == TMPFS_MAGIC);
    Ok(DirFacts {
        is_dir: meta.is_dir(),
        owner: meta.uid(),
        mode: meta.mode() & 0o7777,
        in_ram,
    })
}

fn no_session(operator: &TargetUser, dir: &Path, why: &str) -> Refusal {
    Refusal::new(
        ExitStatus::Config,
        "no_desktop_session",
        format!(
            "No desktop session of {} to open the window in: {} cannot be used ({why}).\n\
             Log in to the desktop as {} and run the line from a terminal there.",
            operator.name,
            dir.display(),
            operator.name
        ),
    )
}

/// Make the window's own directory in `runtime`: a fresh name, mode 0700,
/// owned by the operator.
pub(super) fn make_own_dir(runtime: &Path, operator: &TargetUser) -> Result<PathBuf, Refusal> {
    let made = random_name().and_then(|name| {
        let dir = runtime.join(name);
        // A fresh name: an entry already there (one the operator made) fails
        // the creation instead of being reused.
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        if let Err(error) = hand_over(&dir, operator) {
            // Not left behind for the launcher's account.
            let _ = std::fs::remove_dir(&dir);
            return Err(error);
        }
        Ok(dir)
    });
    made.map_err(|error| {
        Refusal::new(
            ExitStatus::Failed,
            "launch_failed",
            format!(
                "the window's directory in {} could not be made: {error}",
                runtime.display()
            ),
        )
    })
}

/// Give the directory just made to the operator, through a handle that did
/// not follow a symlink, so a swapped entry is never followed by root.
pub(super) fn hand_over(dir: &Path, operator: &TargetUser) -> std::io::Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use nix::unistd::{Gid, Uid, fchown};
    let fd = open(
        dir,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    fchown(
        &fd,
        Some(Uid::from_raw(operator.uid)),
        Some(Gid::from_raw(operator.gid)),
    )?;
    Ok(())
}

/// A neutral, fresh directory name from the kernel's random source.
fn random_name() -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; OWN_DIR_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(own_dir_name(&bytes))
}
