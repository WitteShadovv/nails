// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Symlink- and traversal-safe path resolution beneath the hidden volume root.
//!
//! Paths under the hidden root used to be built with plain [`Path::join`] and
//! opened with `std::fs`, so nothing stopped a symlink or a `..` planted *inside*
//! the hidden volume from redirecting a create, open or remove to somewhere on
//! the decoy root. That is exactly the kind of leak NAILS exists to prevent: a
//! single attacker-planted symlink under the upper dir could send hidden-session
//! writes back onto the decoy filesystem.
//!
//! [`SafeRoot`] closes that at the syscall. It holds an `O_PATH` directory fd
//! for the hidden root and resolves every relative path with `openat2` under
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`:
//!
//! - `RESOLVE_BENEATH` refuses any resolution that would leave the root fd (so an
//!   absolute path or a `..` that climbs out is rejected by the kernel, not just
//!   by our own component check).
//! - `RESOLVE_NO_SYMLINKS` refuses to traverse *any* symlink, including the final
//!   component, so a planted link cannot redirect the operation.
//! - `RESOLVE_NO_MAGICLINKS` (implied by the former, kept explicit) refuses the
//!   `/proc/<pid>/...` magic links that would otherwise jump out of the tree.
//!
//! On a kernel without `openat2` the call returns `ENOSYS`. The helper then
//! **fails closed** — it returns an error and never silently drops back to
//! `std::fs`, because doing so would reintroduce the very symlink-following the
//! helper exists to remove.

use crate::{IoResultExt, NailsError, Result};
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

/// Resolution flags applied to every `openat2` under the hidden root.
///
/// Kept in one place so no call site can forget one of them.
fn containment_flags() -> ResolveFlag {
    ResolveFlag::RESOLVE_BENEATH
        | ResolveFlag::RESOLVE_NO_SYMLINKS
        | ResolveFlag::RESOLVE_NO_MAGICLINKS
}

/// A handle to the hidden volume root that resolves paths safely beneath it.
///
/// Obtain one with [`SafeRoot::open`]; every method takes a path *relative* to
/// the root and resolves it with [`containment_flags`], so a component that
/// escapes the root or traverses a symlink is refused by the kernel.
#[derive(Debug)]
pub struct SafeRoot {
    /// The configured root, kept for diagnostics only. Resolution anchors on the
    /// fd, never on this path, so a rename of the root after opening cannot
    /// redirect operations.
    root: PathBuf,
    /// `O_PATH` directory fd on the root. Every resolution is anchored here.
    dir_fd: OwnedFd,
}

impl SafeRoot {
    /// Open the hidden root at `root` and pin it as an `O_PATH` directory fd.
    ///
    /// The root path itself is operator-configured (not attacker-controlled), so
    /// it is opened directly; all *subsequent* resolution is anchored on the
    /// returned fd and contained beneath it. `root` must already exist and be a
    /// directory (the hidden volume is mounted before any overlay is built).
    pub fn open(root: &Path) -> Result<Self> {
        let dir_fd = nix::fcntl::open(
            root,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            NailsError::io(
                root,
                std::io::Error::new(
                    errno_kind(e),
                    format!(
                        "Failed to open hidden root {} as a directory: {e}",
                        root.display()
                    ),
                ),
            )
        })?;
        Ok(Self {
            root: root.to_path_buf(),
            dir_fd,
        })
    }

    /// The configured root path (for diagnostics).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create `relative` and every missing ancestor beneath the root, mode 0700.
    ///
    /// Each component is created and re-opened one level at a time beneath the
    /// running directory fd, so a symlink planted at any level is refused rather
    /// than followed.
    pub fn create_dir_all(&self, relative: &Path) -> Result<()> {
        let components = safe_components(relative, &self.root)?;
        let mut cur = self.try_clone_root()?;
        for comp in components {
            cur = self.ensure_child_dir(&cur, comp, relative)?;
        }
        Ok(())
    }

    /// Resolve the parent directory of `relative` as a *readable* directory fd,
    /// returning it together with the final component name.
    ///
    /// The parent is opened `O_RDONLY | O_DIRECTORY` (not `O_PATH`) so it can
    /// serve as the `dirfd` for `openat2`/`renameat`/`unlinkat` and still be
    /// `fsync`-ed for durability.
    fn open_parent_rw<'a>(&self, relative: &'a Path) -> Result<(OwnedFd, &'a OsStr)> {
        let components = safe_components(relative, &self.root)?;
        let (leaf, parents) = components.split_last().ok_or_else(|| {
            NailsError::io(
                relative,
                std::io::Error::other(format!(
                    "Refusing to operate on the hidden root itself: {}",
                    relative.display()
                )),
            )
        })?;

        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(containment_flags());

        // Start from a *readable* fd on the root rather than the `O_PATH` anchor,
        // so that a file written directly under the root (parents empty) can still
        // have its parent directory `fsync`-ed for durability — `fsync` rejects an
        // `O_PATH` fd with `EBADF`.
        let mut cur = self.open_root_dir_rw()?;
        for comp in parents {
            cur = openat2(cur.as_fd(), *comp, how).map_err(|e| self.resolve_error(relative, e))?;
        }
        Ok((cur, leaf))
    }

    /// Reopen the root itself as a readable directory fd beneath the pinned
    /// `O_PATH` anchor. Used where the root is the parent of the operation and a
    /// `fsync`-able (non-`O_PATH`) fd is needed.
    fn open_root_dir_rw(&self) -> Result<OwnedFd> {
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        openat2(self.dir_fd.as_fd(), ".", how).map_err(|e| self.resolve_error(Path::new("."), e))
    }

    /// Open the directory at `relative` beneath the root as a readable directory
    /// fd (`O_RDONLY | O_DIRECTORY`, no symlink traversal).
    ///
    /// The returned fd anchors ownership and mode changes (`fchown`/`fchmod`) on
    /// the directory itself, so a symlink swapped in at the path after creation
    /// cannot redirect them off the hidden root.
    pub fn open_dir(&self, relative: &Path) -> Result<OwnedFd> {
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        self.resolve(relative, how)
    }

    /// Open the file at `relative` beneath the root for read and write, creating
    /// it (mode `mode`) if it does not exist, returning the handle.
    ///
    /// Missing ancestors are created first (mode 0700). The open is `O_NOFOLLOW`,
    /// so a symlink planted at the final component is refused rather than
    /// followed; the file is neither truncated nor required to be new, which suits
    /// a reused lock file. Unlike [`SafeRoot::create_new`] it is not exclusive.
    pub fn open_rw_create(&self, relative: &Path, mode: u32) -> Result<std::fs::File> {
        if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
            self.create_dir_all(parent)?;
        }
        let how = OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .mode(Mode::from_bits_truncate(mode))
            .resolve(containment_flags());
        let fd = self.resolve(relative, how)?;
        Ok(std::fs::File::from(fd))
    }

    /// Open the existing file at `relative` beneath the root for read and write,
    /// returning the handle. The file is NOT created: a missing file surfaces as
    /// an error (ENOENT) rather than being created, and no ancestors are made.
    ///
    /// The open is `O_RDWR | O_NOFOLLOW`, so a symlink planted at the final
    /// component is refused rather than followed, and the existing inode, owner
    /// and mode are preserved. The file is neither truncated nor positioned;
    /// callers that want to rewrite it truncate the returned handle themselves.
    pub fn open_rw_existing(&self, relative: &Path) -> Result<std::fs::File> {
        let how = OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        let fd = self.resolve(relative, how)?;
        Ok(std::fs::File::from(fd))
    }

    /// Exclusively create the file at `relative` beneath the root with mode
    /// `mode`, returning the open write handle.
    ///
    /// Missing ancestors are created first (mode 0700). The file itself is created
    /// `O_CREAT | O_EXCL | O_NOFOLLOW`: an entry already present at the name —
    /// including a planted symlink — is reported as [`std::io::ErrorKind::AlreadyExists`]
    /// rather than followed, so a caller can retry under a different name without
    /// ever writing through a link. Operating on the returned descriptor (not the
    /// path) lets callers `fchmod`/`fchown` it without reopening.
    pub fn create_new(&self, relative: &Path, mode: u32) -> Result<std::fs::File> {
        if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
            self.create_dir_all(parent)?;
        }
        let _ = safe_components(relative, &self.root)?;
        let how = OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(Mode::from_bits_truncate(mode))
            .resolve(containment_flags());
        match openat2(self.dir_fd.as_fd(), relative, how) {
            Ok(fd) => Ok(std::fs::File::from(fd)),
            Err(Errno::EEXIST) => Err(NailsError::io(
                relative,
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "an entry already exists at {} under hidden root {}",
                        relative.display(),
                        self.root.display()
                    ),
                ),
            )),
            Err(e) => Err(self.resolve_error(relative, e)),
        }
    }

    /// Atomically write `content` to `relative` with mode `mode`.
    ///
    /// Parents are created first, then the payload is written to a uniquely named
    /// temp created `O_CREAT | O_EXCL | O_NOFOLLOW` beneath the parent dir fd,
    /// synced, and renamed over the destination. There is no predictable sibling
    /// name to pre-plant and the rename replaces a symlink at the destination
    /// rather than following it.
    pub fn write_atomic(&self, relative: &Path, content: &[u8], mode: u32) -> Result<()> {
        if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
            self.create_dir_all(parent)?;
        }
        let (parent_fd, leaf) = self.open_parent_rw(relative)?;

        let create_how = OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(Mode::from_bits_truncate(mode))
            .resolve(containment_flags());

        let mut temp_name = String::new();
        let mut temp_fd = None;
        let mut last_err = None;
        for _ in 0..8 {
            let candidate = crate::filesystem::real::unique_temp_name();
            match openat2(parent_fd.as_fd(), candidate.as_str(), create_how) {
                Ok(fd) => {
                    temp_name = candidate;
                    temp_fd = Some(fd);
                    break;
                }
                Err(Errno::EEXIST) => {
                    last_err = Some(Errno::EEXIST);
                    continue;
                }
                Err(e) => return Err(self.resolve_error(relative, e)),
            }
        }
        let temp_fd = temp_fd.ok_or_else(|| {
            NailsError::io(
                relative,
                std::io::Error::other(format!(
                    "Failed to create a unique temp file under hidden root for {} ({last_err:?})",
                    relative.display()
                )),
            )
        })?;

        let target = self.root.join(relative);
        let outcome = (|| -> Result<()> {
            let mut file = std::fs::File::from(temp_fd);
            file.write_all(content).at_path(&target)?;
            nix::sys::stat::fchmod(file.as_fd(), Mode::from_bits_truncate(mode)).map_err(|e| {
                NailsError::io(&target, std::io::Error::new(errno_kind(e), e.to_string()))
            })?;
            file.sync_all().at_path(&target)?;
            nix::fcntl::renameat(
                parent_fd.as_fd(),
                temp_name.as_str(),
                parent_fd.as_fd(),
                leaf,
            )
            .map_err(|e| {
                NailsError::io(
                    relative,
                    std::io::Error::new(
                        errno_kind(e),
                        format!(
                            "Failed to move temp file into place at {}: {e}",
                            relative.display()
                        ),
                    ),
                )
            })?;
            // Durability: the rename is only guaranteed to survive a crash once
            // the parent directory entry is flushed.
            let _ = nix::unistd::fsync(parent_fd.as_fd());
            Ok(())
        })();

        if outcome.is_err() {
            let _ = unlinkat(
                parent_fd.as_fd(),
                temp_name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
        outcome
    }

    /// Read the file at `relative` beneath the root to a `String`.
    pub fn read_to_string(&self, relative: &Path) -> Result<String> {
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        let fd = self.resolve(relative, how)?;
        let mut file = std::fs::File::from(fd);
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .at_path(self.root.join(relative))?;
        Ok(buf)
    }

    /// Remove the file at `relative` beneath the root. Idempotent: a missing file
    /// is success, so this is safe to call on a cleanup path.
    pub fn remove_file(&self, relative: &Path) -> Result<()> {
        let (parent_fd, leaf) = self.open_parent_rw(relative)?;
        match unlinkat(parent_fd.as_fd(), leaf, UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(self.resolve_error(relative, e)),
        }
    }

    /// Remove the (empty) directory at `relative` beneath the root. Idempotent.
    pub fn remove_dir(&self, relative: &Path) -> Result<()> {
        let (parent_fd, leaf) = self.open_parent_rw(relative)?;
        match unlinkat(parent_fd.as_fd(), leaf, UnlinkatFlags::RemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(self.resolve_error(relative, e)),
        }
    }

    /// Whether a real (non-symlink) entry exists at `relative` beneath the root.
    ///
    /// A missing entry is `Ok(false)`; a symlink or an escape attempt at the path
    /// surfaces as an error, never as `Ok(true)`, so callers cannot be fooled by
    /// a planted link into believing a safe file is present.
    pub fn exists(&self, relative: &Path) -> Result<bool> {
        let _ = safe_components(relative, &self.root)?;
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        match openat2(self.dir_fd.as_fd(), relative, how) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) => Ok(false),
            Err(e) => Err(self.resolve_error(relative, e)),
        }
    }

    /// Whether `relative` beneath the root resolves to a directory.
    ///
    /// `O_DIRECTORY` makes the open itself the test: a non-directory yields
    /// `ENOTDIR` and a missing entry `ENOENT`, both reported as `Ok(false)`.
    pub fn is_dir(&self, relative: &Path) -> Result<bool> {
        let _ = safe_components(relative, &self.root)?;
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        match openat2(self.dir_fd.as_fd(), relative, how) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) | Err(Errno::ENOTDIR) => Ok(false),
            Err(e) => Err(self.resolve_error(relative, e)),
        }
    }

    /// Resolve `relative` beneath the root with `how` and hand back the fd.
    fn resolve(&self, relative: &Path, how: OpenHow) -> Result<OwnedFd> {
        let _ = safe_components(relative, &self.root)?;
        openat2(self.dir_fd.as_fd(), relative, how).map_err(|e| self.resolve_error(relative, e))
    }

    /// Open `name` (a single component) beneath `parent`, creating it as a 0700
    /// directory if it does not yet exist.
    fn ensure_child_dir(&self, parent: &OwnedFd, name: &OsStr, whole: &Path) -> Result<OwnedFd> {
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(containment_flags());
        match openat2(parent.as_fd(), name, how) {
            Ok(fd) => Ok(fd),
            Err(Errno::ENOENT) => {
                match mkdirat(parent.as_fd(), name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(e) => return Err(self.resolve_error(whole, e)),
                }
                openat2(parent.as_fd(), name, how).map_err(|e| self.resolve_error(whole, e))
            }
            Err(e) => Err(self.resolve_error(whole, e)),
        }
    }

    fn try_clone_root(&self) -> Result<OwnedFd> {
        self.dir_fd.try_clone().at_path(&self.root)
    }

    /// Turn an `openat2`/`mkdirat`/`unlinkat` errno into a `NailsError`,
    /// distinguishing the fail-closed "no `openat2`" case from a refused path.
    fn resolve_error(&self, relative: &Path, e: Errno) -> NailsError {
        NailsError::io(relative, resolve_io_error(&self.root, relative, e))
    }
}

/// Build the fail-closed `io::Error` for a refused resolution.
///
/// Split out from [`SafeRoot`] so it can be unit-tested without a live fd: in
/// particular, that `ENOSYS` (kernel without `openat2`) maps to an error rather
/// than to any kind of fallback.
fn resolve_io_error(root: &Path, relative: &Path, e: Errno) -> std::io::Error {
    if e == Errno::ENOSYS {
        return std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "openat2 is unavailable on this kernel; refusing to resolve {} under hidden root {} \
                 without symlink containment (failing closed rather than falling back to std::fs)",
                relative.display(),
                root.display()
            ),
        );
    }
    std::io::Error::new(
        errno_kind(e),
        format!(
            "Refusing {}: it escapes hidden root {} or traverses a symlink ({e})",
            relative.display(),
            root.display()
        ),
    )
}

/// Map an errno to the closest [`std::io::ErrorKind`] while preserving the raw
/// code via [`std::io::Error::from_raw_os_error`] semantics for callers that
/// re-inspect it.
fn errno_kind(e: Errno) -> std::io::ErrorKind {
    std::io::Error::from_raw_os_error(e as i32).kind()
}

/// Validate and return the `Normal` components of `relative`.
///
/// This is defence in depth on top of the kernel's `RESOLVE_BENEATH`: an
/// absolute path, a root/prefix component, or a `..` is rejected up front with a
/// clear error instead of being handed to the kernel. `.` is skipped.
fn safe_components<'a>(relative: &'a Path, root: &Path) -> Result<Vec<&'a OsStr>> {
    if relative.is_absolute() {
        return Err(NailsError::io(
            relative,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Refusing absolute path {} under hidden root {}: only relative paths are allowed",
                    relative.display(),
                    root.display()
                ),
            ),
        ));
    }
    let mut out = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(NailsError::io(
                    relative,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Refusing path {} under hidden root {}: a `..` component would climb out",
                            relative.display(),
                            root.display()
                        ),
                    ),
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(NailsError::io(
                    relative,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Refusing path {} under hidden root {}: it is not a plain relative path",
                            relative.display(),
                            root.display()
                        ),
                    ),
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::Path;

    fn tmp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn create_write_read_and_remove_round_trip() {
        let dir = tmp_root();
        let root = SafeRoot::open(dir.path()).unwrap();

        root.create_dir_all(Path::new(".work/home")).unwrap();
        assert!(root.is_dir(Path::new(".work/home")).unwrap());

        root.write_atomic(Path::new("home/state.json"), b"{}", 0o600)
            .unwrap();
        assert!(root.exists(Path::new("home/state.json")).unwrap());
        assert_eq!(
            root.read_to_string(Path::new("home/state.json")).unwrap(),
            "{}"
        );

        // Mode is honoured exactly, independent of umask.
        let meta = std::fs::metadata(dir.path().join("home/state.json")).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);

        root.remove_file(Path::new("home/state.json")).unwrap();
        assert!(!root.exists(Path::new("home/state.json")).unwrap());
        // Idempotent on the cleanup path.
        root.remove_file(Path::new("home/state.json")).unwrap();
    }

    #[test]
    fn written_file_stays_inside_root() {
        let dir = tmp_root();
        let root = SafeRoot::open(dir.path()).unwrap();
        root.write_atomic(Path::new("a/b/c.txt"), b"x", 0o600)
            .unwrap();
        let real = dir.path().join("a/b/c.txt").canonicalize().unwrap();
        assert!(real.starts_with(dir.path().canonicalize().unwrap()));
    }

    #[test]
    fn parent_dir_component_is_rejected() {
        let dir = tmp_root();
        let root = SafeRoot::open(dir.path()).unwrap();
        for p in ["../escape", "a/../../escape", ".."] {
            let err = root.create_dir_all(Path::new(p)).unwrap_err();
            assert!(err.to_string().contains("climb out"), "{p}: {err}");
        }
    }

    #[test]
    fn absolute_component_is_rejected() {
        let dir = tmp_root();
        let root = SafeRoot::open(dir.path()).unwrap();
        let err = root
            .write_atomic(Path::new("/etc/passwd"), b"x", 0o600)
            .unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
    }

    #[test]
    fn relative_symlink_inside_root_is_refused() {
        let dir = tmp_root();
        // Plant `link -> sub`, a legitimate in-root relative symlink; resolution
        // must still refuse to traverse it.
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        symlink("sub", dir.path().join("link")).unwrap();
        let root = SafeRoot::open(dir.path()).unwrap();

        let err = root.create_dir_all(Path::new("link/child")).unwrap_err();
        assert!(
            err.to_string().contains("symlink") || err.to_string().contains("escapes"),
            "{err}"
        );
    }

    #[test]
    fn absolute_symlink_escaping_root_is_refused() {
        let dir = tmp_root();
        let outside = tmp_root();
        // `escape -> /outside`, pointing clean out of the hidden root.
        symlink(outside.path(), dir.path().join("escape")).unwrap();
        let root = SafeRoot::open(dir.path()).unwrap();

        let err = root
            .write_atomic(Path::new("escape/pwned"), b"x", 0o600)
            .unwrap_err();
        assert!(
            err.to_string().contains("symlink") || err.to_string().contains("escapes"),
            "{err}"
        );
        // And nothing was written outside the root.
        assert!(!outside.path().join("pwned").exists());
    }

    #[test]
    fn symlink_loop_is_refused() {
        let dir = tmp_root();
        symlink("loop_b", dir.path().join("loop_a")).unwrap();
        symlink("loop_a", dir.path().join("loop_b")).unwrap();
        let root = SafeRoot::open(dir.path()).unwrap();
        // RESOLVE_NO_SYMLINKS refuses at the first link, so this is a clean error
        // rather than an ELOOP spin.
        assert!(root.exists(Path::new("loop_a/x")).is_err());
    }

    #[test]
    fn magic_link_into_proc_is_refused() {
        let dir = tmp_root();
        // A symlink to a /proc magic link: RESOLVE_NO_SYMLINKS refuses the link
        // itself, and RESOLVE_NO_MAGICLINKS would refuse the magic link beyond it.
        symlink("/proc/self/root", dir.path().join("magic")).unwrap();
        let root = SafeRoot::open(dir.path()).unwrap();
        assert!(
            root.read_to_string(Path::new("magic/etc/hostname"))
                .is_err()
        );
    }

    #[test]
    fn enosys_fails_closed_with_explicit_message() {
        // On a kernel without openat2 the resolution must error, never fall back.
        let err = resolve_io_error(Path::new("/mnt/hidden"), Path::new("home"), Errno::ENOSYS);
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("openat2 is unavailable"), "{err}");
        assert!(err.to_string().contains("failing closed"), "{err}");
    }

    #[test]
    fn refused_path_error_names_the_root() {
        let err = resolve_io_error(Path::new("/mnt/hidden"), Path::new("link/x"), Errno::ELOOP);
        assert!(err.to_string().contains("/mnt/hidden"), "{err}");
        assert!(
            err.to_string().contains("symlink") || err.to_string().contains("escapes"),
            "{err}"
        );
    }

    #[test]
    fn create_new_is_exclusive_and_sets_mode() {
        let dir = tmp_root();
        let root = SafeRoot::open(dir.path()).unwrap();

        let file = root
            .create_new(Path::new("notifications/a.json"), 0o600)
            .unwrap();
        drop(file);
        let meta = std::fs::metadata(dir.path().join("notifications/a.json")).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);

        // A second create at the same name is refused as AlreadyExists, never a
        // silent overwrite.
        let err = root
            .create_new(Path::new("notifications/a.json"), 0o600)
            .unwrap_err();
        let NailsError::IoError { source: io, .. } = &err else {
            panic!("expected IoError, got {err}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
    }

    #[test]
    fn create_new_refuses_a_planted_symlink_at_the_name() {
        let dir = tmp_root();
        let outside = tmp_root();
        std::fs::create_dir(dir.path().join("notifications")).unwrap();
        // Plant `notifications/evil.json -> /outside/evil.json`. An O_EXCL|O_NOFOLLOW
        // create must refuse the link rather than write through it.
        symlink(
            outside.path().join("evil.json"),
            dir.path().join("notifications/evil.json"),
        )
        .unwrap();
        let root = SafeRoot::open(dir.path()).unwrap();

        let err = root
            .create_new(Path::new("notifications/evil.json"), 0o600)
            .unwrap_err();
        let NailsError::IoError { source: io, .. } = &err else {
            panic!("expected IoError, got {err}");
        };
        // The planted link reads as "already exists" (O_EXCL), never followed.
        assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
        assert!(!outside.path().join("evil.json").exists());
    }

    #[test]
    fn open_dir_refuses_a_symlinked_directory() {
        let dir = tmp_root();
        let outside = tmp_root();
        symlink(outside.path(), dir.path().join("link")).unwrap();
        let root = SafeRoot::open(dir.path()).unwrap();
        assert!(root.open_dir(Path::new("link")).is_err());
        // A real directory opens fine.
        root.create_dir_all(Path::new("real")).unwrap();
        assert!(root.open_dir(Path::new("real")).is_ok());
    }

    #[test]
    fn opening_a_missing_root_errors() {
        let dir = tmp_root();
        let missing = dir.path().join("does-not-exist");
        assert!(SafeRoot::open(&missing).is_err());
    }

    use proptest::prelude::*;

    /// A single path segment with no separators, NULs, or dot-only names.
    fn segment() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,12}".prop_filter("no dot-only", |s| s != "." && s != "..")
    }

    proptest! {
        /// Any relative path of ordinary segments creates and resolves strictly
        /// beneath the root — the canonical created path is always a descendant.
        #[test]
        fn ordinary_relative_paths_stay_beneath_root(segs in prop::collection::vec(segment(), 1..6)) {
            let dir = tmp_root();
            let root = SafeRoot::open(dir.path()).unwrap();
            let rel: PathBuf = segs.iter().collect();

            root.create_dir_all(&rel).unwrap();
            let created = dir.path().join(&rel).canonicalize().unwrap();
            let canon_root = dir.path().canonicalize().unwrap();
            prop_assert!(created.starts_with(&canon_root), "{} escaped {}", created.display(), canon_root.display());
            prop_assert!(root.is_dir(&rel).unwrap());
        }

        /// Any path containing a `..` component is rejected regardless of where
        /// the `..` sits or what surrounds it.
        #[test]
        fn any_parent_component_is_rejected(
            prefix in prop::collection::vec(segment(), 0..3),
            suffix in prop::collection::vec(segment(), 0..3),
        ) {
            let dir = tmp_root();
            let root = SafeRoot::open(dir.path()).unwrap();
            let mut parts: Vec<String> = prefix;
            parts.push("..".to_string());
            parts.extend(suffix);
            let rel: PathBuf = parts.iter().collect();
            prop_assert!(root.create_dir_all(&rel).is_err());
        }
    }
}
