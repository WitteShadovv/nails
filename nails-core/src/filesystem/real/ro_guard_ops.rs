// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount operations behind the read-only guard.
//!
//! Every guarded tree except the root is kept read-only by a self-bind remounted
//! read-only (see [`super::mount_ops::remount_read_only`]). The root cannot be
//! guarded that way:
//!
//! - A mount stacked on `/` does not change the root of any running process: a
//!   process's root is the mount it had when it started, and a lookup that starts
//!   there never crosses into a mount stacked on top of it. The stacked bind was
//!   therefore never seen by the shells and services it was meant to stop, and the
//!   root stayed writable for them.
//! - `umount("/")` reaches the namespace root, not the stacked bind, so the guard
//!   could never be removed (`EBUSY` on every distribution in the smoke test).
//!   Each activation then stacked one more bind on `/`.
//! - Two `/proc/self/mountinfo` entries for `/` is a layout systemd's PID 1 is
//!   known to abort on (`Caught <ABRT>` then `Freezing execution`, upstream
//!   issues #29559 and #37086). A frozen PID 1 closes every socket it holds, so
//!   `systemctl` and `systemd-run` then time out or fail.
//!
//! The root is therefore guarded **in place**: its own mount gets the per-mount
//! read-only flag (`MS_REMOUNT|MS_BIND|MS_RDONLY`), which every process sees and
//! which adds no mount table entry. Removing the guard clears the flag again. The
//! flag lives on the mount, not the filesystem, so the superblock stays
//! read-write; that is what tells a guarded root from a root that was mounted
//! read-only to begin with, which the guard never makes writable.

use std::path::Path;

use nix::mount::MsFlags;

use super::RealFilesystem;
use crate::filesystem::mountinfo::{MountEntry, is_read_only_self_bind, read_mountinfo};
use crate::{NailsError, Result};

/// The tree guarded in place rather than by a stacked self-bind.
const ROOT: &str = "/";

/// Whether `target` is the root, the one tree guarded in place.
fn is_root(target: &Path) -> bool {
    target == Path::new(ROOT)
}

/// The namespace root's own mount: the entry at `/` whose parent is not another
/// entry at `/`. A bind stacked on `/` (left by an older release) sits above it
/// and is skipped.
fn namespace_root(entries: &[MountEntry]) -> Option<&MountEntry> {
    let root = Path::new(ROOT);
    entries.iter().find(|entry| {
        entry.mount_point == root
            && !entries
                .iter()
                .any(|below| below.mount_id == entry.parent_id && below.mount_point == root)
    })
}

/// The per-mount flags a bind remount must repeat so it changes only the
/// read-only bit. Access-time flags are kept by the kernel when none is passed.
fn preserved_flags(mount_opts: &str) -> MsFlags {
    mount_opts
        .split(',')
        .fold(MsFlags::empty(), |flags, opt| match opt {
            "nosuid" => flags | MsFlags::MS_NOSUID,
            "nodev" => flags | MsFlags::MS_NODEV,
            "noexec" => flags | MsFlags::MS_NOEXEC,
            _ => flags,
        })
}

/// Whether the root carries the in-place guard: read-only as a mount on a
/// filesystem that is itself read-write.
fn root_guarded_in_place(root: &MountEntry) -> bool {
    root.read_only() && !root.super_opts.split(',').any(|opt| opt == "ro")
}

/// Map a failed root remount to the guard's error vocabulary.
fn remount_error(errno: nix::errno::Errno, stage: &str) -> NailsError {
    match errno {
        nix::errno::Errno::EACCES | nix::errno::Errno::EPERM => {
            NailsError::PermissionDenied("Read-only remount requires root privileges".to_string())
        }
        nix::errno::Errno::EBUSY => NailsError::MountBusy {
            path: Path::new(ROOT).to_path_buf(),
            suggestion: "The root mount refused the per-mount flag change".to_string(),
        },
        other => NailsError::OverlayError(format!("Failed to {stage} the root: {other}")),
    }
}

/// Flip the root mount's per-mount read-only flag.
fn bind_remount_root(root: &MountEntry, read_only: bool) -> Result<()> {
    let mut flags = MsFlags::MS_REMOUNT | MsFlags::MS_BIND | preserved_flags(&root.mount_opts);
    if read_only {
        flags |= MsFlags::MS_RDONLY;
    }
    let stage = if read_only {
        "keep read-only"
    } else {
        "make writable again"
    };
    nix::mount::mount(None::<&str>, ROOT, None::<&str>, flags, None::<&str>)
        .map_err(|errno| remount_error(errno, stage))
}

/// Keep `target` read-only for the session.
///
/// The root is guarded in place; any other tree gets a read-only self-bind. A
/// root that is already read-only needs no guard and is left as it is.
pub(super) fn guard_read_only(target: &Path) -> Result<()> {
    if !is_root(target) {
        return super::mount_ops::remount_read_only(target);
    }
    let entries = read_mountinfo()?;
    let root = namespace_root(&entries)
        .ok_or_else(|| NailsError::OverlayError("no mount for / in mountinfo".to_string()))?;
    if root.read_only() {
        return Ok(());
    }
    bind_remount_root(root, true)
}

/// Remove the guard from `target`, restoring write access.
///
/// Idempotent. The root gets its per-mount read-only flag cleared, and only when
/// that flag is the guard's (a read-only mount on a read-write filesystem). Any
/// other tree has its self-bind unmounted; a busy bind is detached lazily, since
/// leaving it would keep the tree read-only after teardown and let the next
/// activation stack another bind on the same path.
pub(super) fn remove_guard(fs: &RealFilesystem, target: &Path) -> Result<()> {
    if is_root(target) {
        let entries = read_mountinfo()?;
        return match namespace_root(&entries) {
            Some(root) if root_guarded_in_place(root) => bind_remount_root(root, false),
            _ => Ok(()),
        };
    }
    match super::mount_ops::unmount_bind(fs, target) {
        Err(NailsError::UnmountError { reason, .. }) if reason.contains("EBUSY") => {
            tracing::warn!(
                tree = %target.display(),
                "Read-only guard is busy; detaching it lazily"
            );
            nix::mount::umount2(target, nix::mount::MntFlags::MNT_DETACH).map_err(|errno| {
                NailsError::UnmountError {
                    path: target.to_path_buf(),
                    reason: format!("{errno}"),
                }
            })
        }
        other => other,
    }
}

/// Whether a guard is present on `target`: the in-place flag on the root (or a
/// bind an older release stacked there), a read-only self-bind elsewhere.
pub(super) fn is_guarded(target: &Path) -> Result<bool> {
    let entries = read_mountinfo()?;
    if is_root(target) && namespace_root(&entries).is_some_and(root_guarded_in_place) {
        return Ok(true);
    }
    Ok(is_read_only_self_bind(&entries, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::mountinfo::parse_mountinfo;

    const PLAIN_ROOT: &str = "\
22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs udev rw
";

    #[test]
    fn namespace_root_is_the_mount_at_slash() {
        let entries = parse_mountinfo(PLAIN_ROOT);
        assert_eq!(namespace_root(&entries).map(|e| e.mount_id), Some(22));
    }

    #[test]
    fn namespace_root_skips_a_bind_stacked_on_slash() {
        // An older release stacked a read-only self-bind on `/`; the namespace
        // root is still the mount below it.
        let table = format!(
            "{PLAIN_ROOT}90 22 252:1 / / ro,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro\n"
        );
        let entries = parse_mountinfo(&table);
        assert_eq!(namespace_root(&entries).map(|e| e.mount_id), Some(22));
    }

    #[test]
    fn preserved_flags_keep_the_security_flags_only() {
        assert_eq!(
            preserved_flags("rw,nosuid,nodev,noexec,relatime"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC
        );
        assert_eq!(preserved_flags("rw,relatime"), MsFlags::empty());
        // A substring is not a flag.
        assert_eq!(preserved_flags("rw,nosuidx"), MsFlags::empty());
    }

    #[test]
    fn in_place_guard_is_a_read_only_mount_on_a_writable_filesystem() {
        let guarded = parse_mountinfo(
            "22 1 252:1 / / ro,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro\n",
        );
        assert!(root_guarded_in_place(&guarded[0]));

        // A root mounted read-only to begin with (read-only superblock) is not
        // the guard's, so teardown never makes it writable.
        let booted_ro = parse_mountinfo("22 1 252:1 / / ro,relatime - ext4 /dev/sda1 ro\n");
        assert!(!root_guarded_in_place(&booted_ro[0]));

        let writable = parse_mountinfo(PLAIN_ROOT);
        assert!(!root_guarded_in_place(&writable[0]));
    }

    #[test]
    fn only_the_root_is_guarded_in_place() {
        assert!(is_root(Path::new("/")));
        assert!(!is_root(Path::new("/usr")));
    }
}
