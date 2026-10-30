// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A directory reached without a link or another mount on the way, used by its
//! descriptor.
//!
//! Replacing a file by its path can be sent elsewhere: a link at the file or on
//! the way to it, or another filesystem mounted on the way, takes the write to
//! wherever it points, the decoy disk included. [`PinnedDir::open`] opens the
//! root, checks that it is the mount the caller judged (by its mount ID), and
//! resolves the directory beneath it with `openat2` under `RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, so the kernel
//! refuses a link and a mount crossing anywhere on the way. The lock, the read
//! and the replacement then act on that descriptor under the same rules, so a
//! path swapped afterwards cannot move them. A kernel without `openat2` fails
//! closed, as [`SafeRoot`](super::SafeRoot) does.
//!
//! A cancel ([`crate::cancel`]: SIGINT or SIGTERM under the installed
//! handlers, or a caller's token) is honoured while the lock is awaited and up
//! to the rename of a replacement, and never after it: a replacement either
//! leaves the old file and no new one, or is complete.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{
    AtFlags, CWD, FileType, FlockOperation, Gid, Mode, OFlags, ResolveFlags, StatxFlags, Uid,
};
use rustix::io::Errno;

use crate::NailsError;

/// Why a pinned directory refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// A link at the path or on the way to it, or another filesystem mounted
    /// on the way.
    #[error("{} is a link, or another filesystem is mounted on the way to it", .0.display())]
    Linked(PathBuf),
    /// The root is not the mount the caller judged.
    #[error("{} is no longer the volume that was checked", .0.display())]
    OtherMount(PathBuf),
    /// The path is not a regular file.
    #[error("{} is not a regular file", .0.display())]
    NotAFile(PathBuf),
    /// The file has another name too, which a replacement would leave behind.
    #[error("{} has another name too (a hard link)", .0.display())]
    HardLinked(PathBuf),
    /// The file is larger than the reader takes.
    #[error("{} is larger than {} bytes", .0.display(), .1)]
    TooLarge(PathBuf, usize),
    /// A cancel arrived before anything was replaced.
    #[error("cancelled before {} was replaced", .0.display())]
    Cancelled(PathBuf),
    /// Any other failure.
    #[error(transparent)]
    Io(NailsError),
}

/// The owner and mode of a file, which its replacement keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// The owning user.
    pub uid: u32,
    /// The owning group.
    pub gid: u32,
    /// The permission bits, set-id and sticky bits included.
    pub mode: u32,
}

/// A regular file read from a pinned directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRead {
    /// Its content.
    pub bytes: Vec<u8>,
    /// Its owner and mode.
    pub owner: Owner,
}

/// The mode a new file gets: root's alone, as `nails init` writes the
/// configuration.
pub const NEW_FILE_MODE: u32 = 0o600;

/// A directory reached beneath a root without a link or another mount on the
/// way.
#[derive(Debug)]
pub struct PinnedDir {
    fd: OwnedFd,
    path: PathBuf,
}

/// An exclusive lock on a pinned directory, released when it is dropped.
#[derive(Debug)]
pub struct DirLock {
    _fd: OwnedFd,
}

/// The rules of every resolution beneath the root.
fn beneath() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

fn io(path: &Path, errno: Errno) -> PinError {
    let error = if errno == Errno::NOSYS {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "openat2 is unavailable on this kernel; refusing to write without it",
        )
    } else {
        std::io::Error::from(errno)
    };
    PinError::Io(NailsError::io(path, error))
}

/// A refusal for a link or a mount crossing, any other error as it is.
fn refusal_or_io(path: &Path, errno: Errno) -> PinError {
    if errno == Errno::LOOP || errno == Errno::XDEV {
        PinError::Linked(path.to_path_buf())
    } else {
        io(path, errno)
    }
}

impl PinnedDir {
    /// Open the directory `relative` (empty for the root itself) beneath
    /// `root`, which is opened with no link on its way. With `mount_id`, the
    /// root must be on the mount of that ID, the one the caller judged.
    ///
    /// # Errors
    ///
    /// [`PinError::Linked`] for a link or a mount crossing on the way,
    /// [`PinError::OtherMount`] for a root on another mount, and
    /// [`PinError::Io`] for any other failure, a missing directory included.
    pub fn open(root: &Path, relative: &Path, mount_id: Option<u64>) -> Result<Self, PinError> {
        let root_fd = rustix::fs::openat2(
            CWD,
            root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|errno| refusal_or_io(root, errno))?;
        if let Some(id) = mount_id {
            let stat = rustix::fs::statx(&root_fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
                .map_err(|errno| io(root, errno))?;
            if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 || stat.stx_mnt_id != id {
                return Err(PinError::OtherMount(root.to_path_buf()));
            }
        }
        let path = root.join(relative);
        let target = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        let fd = rustix::fs::openat2(
            &root_fd,
            target,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            beneath(),
        )
        .map_err(|errno| refusal_or_io(&path, errno))?;
        Ok(Self { fd, path })
    }

    /// The directory's path, for messages.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Take an exclusive lock on the directory, waiting at most `wait` for
    /// another holder. `None` when the holder keeps it longer.
    ///
    /// # Errors
    ///
    /// [`PinError::Cancelled`] when a cancel arrives while the lock is
    /// awaited, and [`PinError::Io`] when the lock cannot be taken at all.
    pub fn lock(&self, wait: Duration) -> Result<Option<DirLock>, PinError> {
        // A descriptor of its own: the lock belongs to its open file and ends
        // when the guard closes it.
        let fd = rustix::fs::openat2(
            &self.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            beneath(),
        )
        .map_err(|errno| refusal_or_io(&self.path, errno))?;
        let deadline = Instant::now() + wait;
        loop {
            if crate::cancel::is_cancelled() {
                return Err(PinError::Cancelled(self.path.clone()));
            }
            match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Some(DirLock { _fd: fd })),
                Err(errno) if errno == Errno::INTR => {}
                Err(errno) if errno == Errno::AGAIN => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(errno) => return Err(io(&self.path, errno)),
            }
        }
    }

    /// Read the file `name` in the directory, at most `limit` bytes of it:
    /// `None` when there is none.
    ///
    /// # Errors
    ///
    /// [`PinError::Linked`] for a link or a mount at the name,
    /// [`PinError::NotAFile`] for anything but a regular file,
    /// [`PinError::HardLinked`] for a file with another name,
    /// [`PinError::TooLarge`] past `limit`, [`PinError::Io`] otherwise.
    pub fn read(&self, name: &OsStr, limit: usize) -> Result<Option<FileRead>, PinError> {
        let path = self.path.join(name);
        // Non-blocking, so a FIFO planted at the name cannot hold the read.
        let opened = rustix::fs::openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
            beneath(),
        );
        let fd = match opened {
            Ok(fd) => fd,
            Err(errno) if errno == Errno::NOENT => return Ok(None),
            Err(errno) => return Err(refusal_or_io(&path, errno)),
        };
        let stat = rustix::fs::fstat(&fd).map_err(|errno| io(&path, errno))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(PinError::NotAFile(path));
        }
        if stat.st_nlink != 1 {
            return Err(PinError::HardLinked(path));
        }
        let mut bytes = Vec::new();
        let most = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        std::fs::File::from(fd)
            .take(most)
            .read_to_end(&mut bytes)
            .map_err(|error| PinError::Io(NailsError::io(&path, error)))?;
        if bytes.len() > limit {
            return Err(PinError::TooLarge(path, limit));
        }
        let owner = Owner {
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode & 0o7777,
        };
        Ok(Some(FileRead { bytes, owner }))
    }

    /// Put `bytes` in place of the file `name` at once.
    ///
    /// The bytes go to a new file in the directory first, created so that
    /// nothing already there is followed or reused, given `like`'s owner and
    /// mode (the creator and [`NEW_FILE_MODE`] for a file that is new) and
    /// flushed; then it is renamed over `name`, and the directory is flushed.
    /// A failure or a cancel before the rename removes the new file and leaves
    /// `name` as it was; a cancel after the rename is not seen.
    ///
    /// # Errors
    ///
    /// [`PinError::Linked`] for a link or a mount in the way,
    /// [`PinError::Cancelled`] for a cancel before the rename, and
    /// [`PinError::Io`] for a write, an owner or a mode that failed, such as
    /// an owner only root can give.
    pub fn replace(&self, name: &OsStr, bytes: &[u8], like: Option<Owner>) -> Result<(), PinError> {
        let path = self.path.join(name);
        let (temp, fd) = self.create_temp(&path)?;
        let written = (|| {
            let mut file = std::fs::File::from(fd);
            file.write_all(bytes)
                .map_err(|error| PinError::Io(NailsError::io(&path, error)))?;
            if let Some(like) = like {
                let (uid, gid) = (Uid::from_raw(like.uid), Gid::from_raw(like.gid));
                rustix::fs::fchown(&file, Some(uid), Some(gid))
                    .map_err(|errno| io(&path, errno))?;
            }
            let mode = like.map_or(NEW_FILE_MODE, |like| like.mode);
            rustix::fs::fchmod(&file, Mode::from_raw_mode(mode))
                .map_err(|errno| io(&path, errno))?;
            file.sync_all()
                .map_err(|error| PinError::Io(NailsError::io(&path, error)))?;
            // The last moment a cancel is honoured: the rename is the change.
            if crate::cancel::is_cancelled() {
                return Err(PinError::Cancelled(path.clone()));
            }
            rustix::fs::renameat(&self.fd, temp.as_str(), &self.fd, name)
                .map_err(|errno| refusal_or_io(&path, errno))
        })();
        if let Err(error) = written {
            let _ = rustix::fs::unlinkat(&self.fd, temp.as_str(), AtFlags::empty());
            return Err(error);
        }
        // The rename lasts through a crash once the directory is flushed. The
        // new file is in place by now, so a failure here is only logged.
        if let Err(errno) = rustix::fs::fsync(&self.fd) {
            tracing::warn!(path = %self.path.display(), %errno, "could not flush the directory");
        }
        Ok(())
    }

    /// A new file in the directory with a name no one chose before: created
    /// `O_EXCL | O_NOFOLLOW`, so an entry planted at a name is never reused.
    fn create_temp(&self, path: &Path) -> Result<(String, OwnedFd), PinError> {
        for _ in 0..8 {
            let temp = crate::filesystem::real::unique_temp_name();
            let created = rustix::fs::openat2(
                &self.fd,
                temp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(NEW_FILE_MODE),
                beneath(),
            );
            match created {
                Ok(fd) => return Ok((temp, fd)),
                Err(errno) if errno == Errno::EXIST => {}
                Err(errno) => return Err(refusal_or_io(path, errno)),
            }
        }
        Err(io(path, Errno::EXIST))
    }
}

#[cfg(test)]
#[path = "pinned_dir_tests.rs"]
mod tests;
