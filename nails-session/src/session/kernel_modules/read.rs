// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading the decoy's side and the upper's for the judge of the running
//! kernel's modules. Every read is an `lstat`, a `statx` or an `lgetxattr`,
//! and each lookup passes only through entries already seen to be
//! directories.

use super::{Decoy, Doubt, Held, Opacity, Step};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::SystemTime;

/// The overlay attribute that marks an opaque directory.
const OPAQUE_XATTR: &str = "trusted.overlay.opaque";

/// The inode number of the initial user namespace, as `/proc/self/ns/user`
/// shows it (the kernel's `PROC_USER_INIT_INO`).
const INITIAL_USER_NS: u64 = 0xEFFF_FFFD;

/// Whether this process sees `trusted.*` extended attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedXattrs {
    /// It does: a missing attribute is missing.
    Visible,
    /// It does not: the kernel reports every one of them missing.
    Invisible,
}

impl TrustedXattrs {
    /// What this process sees: `trusted.*` attributes need `CAP_SYS_ADMIN` in
    /// the initial user namespace, which a namespaced root lacks.
    pub fn of_this_process() -> Self {
        let initial_namespace = std::fs::metadata("/proc/self/ns/user")
            .is_ok_and(|namespace| namespace.ino() == INITIAL_USER_NS);
        let admin = rustix::thread::capabilities(None).is_ok_and(|sets| {
            sets.effective
                .contains(rustix::thread::CapabilitySet::SYS_ADMIN)
        });
        if initial_namespace && admin {
            TrustedXattrs::Visible
        } else {
            TrustedXattrs::Invisible
        }
    }
}

/// Read what `upper` holds on the way to `release`'s index, one entry per
/// [`Step`], stopping after the first that is not a directory.
pub fn read_upper(upper: &Path, release: &OsStr, xattrs: TrustedXattrs) -> Vec<Held> {
    let mut held = Vec::new();
    for step in Step::ALL {
        let entry = read_held(upper, &step.path(release), step, xattrs);
        let go_on = matches!(entry, Held::Dir(_));
        held.push(entry);
        if !go_on {
            break;
        }
    }
    held
}

/// What `upper` holds at `rel`, the path of `step`. A failed read names the
/// path as hidden sessions see it, never the upper's own.
fn read_held(upper: &Path, rel: &Path, step: Step, xattrs: TrustedXattrs) -> Held {
    let path = upper.join(rel);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Held::Nothing,
        Err(e) => Held::Unreadable(format!(
            "what hidden sessions keep at /{} cannot be read ({e})",
            rel.display()
        )),
        Ok(meta) => {
            let kind = meta.file_type();
            if kind.is_char_device() && meta.rdev() == 0 {
                Held::Whiteout
            } else if kind.is_dir() && step != Step::Index {
                Held::Dir(opacity(&path, rel, xattrs))
            } else if kind.is_file() {
                // Linux always reports the time; without one the index would
                // count as the oldest, and an older one warns.
                Held::File(meta.modified().unwrap_or(SystemTime::UNIX_EPOCH))
            } else {
                Held::Other
            }
        }
    }
}

/// Whether the directory `dir` in the upper, the copy of `rel`, is opaque,
/// read as overlayfs reads it: exactly one byte, `y`.
fn opacity(dir: &Path, rel: &Path, xattrs: TrustedXattrs) -> Opacity {
    use rustix::io::Errno;
    let mut value = [0u8; 1];
    match rustix::fs::lgetxattr(dir, OPAQUE_XATTR, &mut value[..]) {
        Ok(1) if value[0] == b'y' => Opacity::Opaque,
        // Another value, or a longer one, which overlayfs does not take.
        Ok(_) | Err(Errno::RANGE) => Opacity::Merged,
        // A filesystem without extended attributes cannot mark one opaque.
        Err(Errno::NOTSUP) => Opacity::Merged,
        Err(Errno::NODATA) if xattrs == TrustedXattrs::Visible => Opacity::Merged,
        Err(Errno::NODATA) => Opacity::Unknown(Doubt::NeedsRoot),
        Err(e) => Opacity::Unknown(Doubt::Other(format!(
            "whether a hidden session replaced /{} with a new directory cannot be read ({e})",
            rel.display()
        ))),
    }
}

/// Read the decoy's side of `release`'s tree below `root`.
pub fn read_decoy(root: &Path, release: &OsStr) -> Decoy {
    for step in Step::DIRS {
        let rel = step.path(release);
        match std::fs::symlink_metadata(root.join(&rel)) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) if meta.file_type().is_symlink() => {
                return Decoy::Unknown(format!(
                    "/{} on the decoy is a symbolic link",
                    rel.display()
                ));
            }
            Ok(_) => return missing(step),
            Err(e) if is_missing(&e) => return missing(step),
            Err(e) => {
                return Decoy::Unknown(format!(
                    "/{} on the decoy cannot be read ({e})",
                    rel.display()
                ));
            }
        }
    }
    let tree = Step::Release.path(release);
    match same_mount(root, &root.join(&tree)) {
        Some(true) => {}
        Some(false) => {
            return Decoy::Unknown(format!(
                "/{} is on a filesystem of its own, and only what hidden sessions changed on \
                 the root filesystem is read",
                tree.display()
            ));
        }
        None => {
            return Decoy::Unknown(format!(
                "the kernel does not tell which filesystem holds /{}",
                tree.display()
            ));
        }
    }
    let index = Step::Index.path(release);
    match std::fs::symlink_metadata(root.join(&index)) {
        Ok(meta) if meta.is_file() => Decoy::Release {
            index: meta.modified().ok(),
        },
        Ok(_) => Decoy::Release { index: None },
        Err(e) if is_missing(&e) => Decoy::Release { index: None },
        Err(e) => Decoy::Unknown(format!(
            "/{} on the decoy cannot be read ({e})",
            index.display()
        )),
    }
}

/// The decoy's side when it lacks `step`.
fn missing(step: Step) -> Decoy {
    if step == Step::Release {
        Decoy::NoRelease
    } else {
        Decoy::NoModuleDir
    }
}

/// Whether a lookup failed because the path, or a directory on the way, does
/// not exist.
fn is_missing(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Whether `a` and `b` are on the same mount, or `None` when the kernel does
/// not say. Neither lookup follows a final symbolic link or triggers an
/// automount.
pub(super) fn same_mount(a: &Path, b: &Path) -> Option<bool> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    let mount = |path: &Path| {
        statx(
            CWD,
            path,
            AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
            StatxFlags::MNT_ID,
        )
        .ok()
        .filter(|stat| stat.stx_mask & StatxFlags::MNT_ID.bits() != 0)
        .map(|stat| stat.stx_mnt_id)
    };
    Some(mount(a)? == mount(b)?)
}

/// The running kernel's release, as `uname -r` prints it.
pub fn running_release() -> OsString {
    OsStr::from_bytes(rustix::system::uname().release().to_bytes()).to_os_string()
}
