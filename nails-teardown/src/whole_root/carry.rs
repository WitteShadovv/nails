// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Carrying the decoy's own filesystems through the hidden session.
//!
//! The way back mounts the decoy root device at `/run/nextroot`, but the decoy
//! often cannot boot from that device alone: on NixOS its init lives in a
//! `/nix/store` that is a filesystem of its own (a separate `/nix` partition, the
//! host store a VM gets over 9p with a tmpfs upper). Mounting those again from
//! their sources is not always possible (a virtio 9p channel takes one mount
//! at a time) and would lose what a tmpfs held. So the entry carries them:
//!
//! - at entry, each decoy filesystem the fstab policy placed in the hidden root
//!   is bound, read-only and non-recursively, onto a directory on the hidden
//!   volume inside `/run/nextroot`. Mounts below `/run/nextroot` become the new
//!   tree, so the hidden session holds them;
//! - on the way back, [`restore`] binds each one at its own mount point in the
//!   decoy root at `/run/nextroot`, parents first, and makes it writable again
//!   when the decoy had it so.
//!
//! The binds are the decoy's own mounts, so the decoy comes back with exactly
//! the filesystems it had, tmpfs contents included.

use crate::whole_root::nextroot;
use crate::whole_root::plan::CarriedMount;
use std::io;
use std::path::Path;

/// Bind the decoy mount at `source` read-only onto `at_in_nextroot` (the same
/// directory as `at_real` on the hidden volume, seen through the next root).
pub fn carry(source: &Path, at_real: &Path, at_in_nextroot: &Path) -> io::Result<()> {
    std::fs::create_dir_all(at_real)?;
    nextroot::bind_read_only(source, at_in_nextroot)
}

/// Bind every carried mount at its mount point under `root`, parents first.
/// Writes nothing to the decoy: a mount point that is missing is an error.
pub fn restore(carried: &[CarriedMount], root: &Path) -> io::Result<()> {
    let mut ordered: Vec<&CarriedMount> = carried.iter().collect();
    ordered.sort_by_key(|m| m.target.components().count());
    for mount in ordered {
        let target = root.join(mount.target.strip_prefix("/").unwrap_or(&mount.target));
        if !target.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("mount point {} is missing", mount.target.display()),
            ));
        }
        nextroot::bind(&mount.at, &target, false)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", mount.target.display())))?;
        if !mount.read_only {
            nextroot::remount_writable(&target).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: {e}", mount.target.display()))
            })?;
        }
    }
    Ok(())
}
