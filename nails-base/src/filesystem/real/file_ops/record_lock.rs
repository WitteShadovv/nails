// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Who holds a record lock on a file, as the kernel answers `F_GETLK`.
//!
//! The kernel's list of locks, `/proc/locks`, is no snapshot: it prints a
//! page at a time, walking its list from the start at each `read(2)`, so a
//! lock released between two pages moves every later one up and the next
//! page skips one. `F_GETLK` asks about one file, under the lock of its
//! inode's locks, and so cannot miss a lock that is held throughout.

use crate::{IoResultExt, Result};
use std::path::Path;

/// See [`Filesystem::record_lock_holder`](crate::Filesystem::record_lock_holder).
pub(in crate::filesystem::real) fn record_lock_holder(path: &Path) -> Result<Option<i32>> {
    use nix::fcntl::{FcntlArg, fcntl};
    use nix::libc;
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};

    // No link is followed at `path`, a FIFO swapped in does not block the
    // open, and no terminal becomes the controlling one. Only the open takes
    // place: no read, so no access time changes, and O_NOATIME is asked for
    // all the same, as for every open of the decoy's files.
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let fd =
        nails_teardown::noatime::with_noatime(|noatime| open(path, flags | noatime, Mode::empty()))
            .map_err(std::io::Error::from)
            .at_path(path)?;
    let stat = fstat(&fd).map_err(std::io::Error::from).at_path(path)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
        .at_path(path);
    }
    // A write lock over the whole file, which every lock on it conflicts
    // with. F_GETLK does not need the descriptor open for writing.
    let mut lock = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    fcntl(&fd, FcntlArg::F_GETLK(&mut lock))
        .map_err(std::io::Error::from)
        .at_path(path)?;
    Ok((lock.l_type != libc::F_UNLCK as libc::c_short).then_some(lock.l_pid))
}

#[cfg(test)]
#[path = "record_lock_tests.rs"]
mod tests;
