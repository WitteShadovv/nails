// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux labels of the directories NAILS creates in the uppers.
//!
//! An overlay inode takes its SELinux label from the `security.selinux`
//! attribute of the upper inode, and a file copied up keeps the label of the
//! decoy file it copies. The directories NAILS itself creates on the hidden
//! volume are neither: the root of each upper, and the empty home of the
//! fresh-home persona with the parents it needs. On a hidden volume nobody
//! relabelled they carry no label, or one the kernel derived from their parent
//! there, so the policy sees the hidden `/` as `unlabeled_t`, and confined
//! services may not even look it up: the hidden session does not boot on an
//! enforcing host. [`copy_label`] gives each such directory the label of the
//! decoy directory it stands for, read with `lgetxattr` and written with
//! `lsetxattr`, so the hidden `/`, a separate `/home` and the empty home carry
//! the types they have on the decoy (`root_t`, `home_root_t` and
//! `user_home_dir_t` under Fedora's policy). Whatever the hidden session
//! creates below them then takes its label from the policy, as on the decoy.
//!
//! Whether a copy must succeed depends on the host ([`Labels::for_host`]). With
//! SELinux enabled the hidden root needs the labels, so a copy that fails
//! refuses the entry: a hidden volume whose filesystem cannot store labels, a
//! policy that does not let NAILS relabel, a decoy directory with no label to
//! read. Without SELinux nothing reads them and the copy is best effort: a
//! decoy directory without a label (the usual case there), or a filesystem
//! without extended attributes, leaves the upper directory as it was, so such a
//! host gets the same hidden root as before. Any other failure is an error in
//! both cases.
//!
//! SELinux counts as enabled whenever the host facts report it, that is when
//! [`HostProfile::selinux`](nails_platform::HostProfile::selinux) is `Some`:
//! selinuxfs is mounted, or `/etc/selinux/config` exists. A host that keeps
//! only the configuration file (SELinux disabled at boot) counts too. Its facts
//! cannot be told apart from a mounted selinuxfs whose enforce flag could not be
//! read, and refusing an entry is the safe side of that doubt.
//!
//! # Where the copies go
//!
//! Nothing calls [`copy_label`] yet. The entry is to make one [`Labels`] from
//! the host profile the activation detected, carry it in
//! [`EntryInputs`](super::entry::EntryInputs), and copy at four places, each
//! right after the line that gives the new directory the mode and owner of the
//! same decoy directory:
//!
//! - **the root upper**: `make_layer` in [`super::entry`], after
//!   `match_attributes(upper, like)`, as `copy_label(like, upper, labels)`.
//!   `build` calls it for [`Layout::upper`](super::Layout::upper) with the
//!   decoy root ([`Paths::root`](super::Paths::root)), before
//!   `nextroot::overlay_over` mounts the root overlay;
//! - **the per-mount uppers**: the same line, which `apply_mounts` reaches for
//!   every overlay decision of the fstab policy, with the root of that decoy
//!   filesystem ([`Paths::decoy`](super::Paths::decoy) of its mount point) for
//!   the upper of [`Layout::mount_layers`](super::Layout::mount_layers), before
//!   that filesystem's overlay is mounted;
//! - **the empty home**: [`prepare_fresh_home`](super::persona::prepare_fresh_home),
//!   after the `chown` of `upper_home` and before the opaque attribute, as
//!   `copy_label(decoy_home, upper_home, labels)`. A failure removes
//!   `upper_home` again, as a failed opaque attribute does, so that no home
//!   without its label is kept by a later entry;
//! - **its parents**: `create_parents_like` in [`super::persona`], after the
//!   `chown` of each directory it creates, from the `like` directory whose mode
//!   and owner it took. Where `like` is `None` there is no decoy directory to
//!   copy from, and the directory keeps the label the kernel gave it.
//!
//! `make_layer` runs at every entry, so the roots of the uppers take the
//! decoy's labels again each time, as they take its mode and owner; a label
//! already in place is not written again. The empty home and its parents get
//! theirs once, when they are created, and are the hidden session's own after
//! that. `nextroot` needs no call: it only mounts the uppers prepared here.
//! Every other directory the entry creates is made through the next root once
//! the overlays are mounted (the mount points of the fstab policy and of the
//! carried decoy filesystems, the persona's masks), and the kernel labels it
//! by the policy, like a file the hidden session creates. The hidden NixOS
//! configuration, which `init` writes into the upper's `/etc/nixos`, needs no
//! copy: only a NixOS hidden system has one, and NixOS does not run SELinux.

use crate::error::{NailsError, Result};
use nails_platform::SelinuxStatus;
use rustix::fs::XattrFlags;
use rustix::io::Errno;
use std::path::Path;

/// The extended attribute that holds a file's SELinux label.
pub const LABEL_XATTR: &str = "security.selinux";

/// The largest value the kernel returns for an extended attribute
/// (`XATTR_SIZE_MAX`): a buffer this size reads any label in one call.
const LABEL_MAX: usize = 64 * 1024;

/// Whether a label copy must succeed, from the host's SELinux facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Labels {
    /// SELinux is enabled: the hidden root needs every label, so a copy that
    /// fails refuses the entry.
    Required,
    /// SELinux is not enabled and nothing reads the labels: a decoy directory
    /// without one, or a filesystem that stores none, leaves the upper
    /// directory as it was.
    BestEffort,
}

impl Labels {
    /// What a host with these SELinux facts
    /// ([`HostProfile::selinux`](nails_platform::HostProfile::selinux)) needs:
    /// [`Labels::Required`] for any SELinux the facts report (see the module
    /// docs), [`Labels::BestEffort`] for none.
    pub fn for_host(selinux: Option<&SelinuxStatus>) -> Self {
        if selinux.is_some() {
            Self::Required
        } else {
            Self::BestEffort
        }
    }
}

/// What [`copy_label`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Copied {
    /// The upper directory carries the decoy directory's label: written now,
    /// or already there from an earlier entry.
    Label,
    /// The decoy has no label for the directory, or no such directory
    /// ([`Labels::BestEffort`] only).
    NoLabel,
    /// The decoy directory or the upper one is on a filesystem without extended
    /// attributes ([`Labels::BestEffort`] only).
    Unsupported,
}

/// Give `upper`, a directory NAILS created in an upper, the SELinux label of
/// `decoy`, the decoy directory it stands for in the hidden root.
///
/// Neither call follows a symlink in the last component of its path, so a link
/// planted where `upper` should be is labelled itself and never leads the write
/// elsewhere. `decoy` is only read, and reading an extended attribute updates
/// no access time. Only `upper` is written, and only when its label differs, so
/// a later entry relabels nothing. With [`Labels::Required`] anything short of
/// the label on `upper` is an error, which refuses the entry; with
/// [`Labels::BestEffort`] a missing label or a filesystem without extended
/// attributes is not.
pub fn copy_label(decoy: &Path, upper: &Path, labels: Labels) -> Result<Copied> {
    let copied = read_label(decoy).map_err(Failure::Read).and_then(|label| {
        if read_label(upper).is_ok_and(|current| current == label) {
            return Ok(());
        }
        rustix::fs::lsetxattr(upper, LABEL_XATTR, &label, XattrFlags::empty())
            .map_err(Failure::Write)
    });
    judge(decoy, upper, labels, copied)
}

/// The SELinux label of `path`, not following a symlink in its last component.
fn read_label(path: &Path) -> rustix::io::Result<Vec<u8>> {
    let mut label = vec![0; LABEL_MAX];
    let len = rustix::fs::lgetxattr(path, LABEL_XATTR, &mut label[..])?;
    label.truncate(len);
    Ok(label)
}

/// The step of a copy that failed, with the kernel's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// Reading the decoy directory's label.
    Read(Errno),
    /// Writing it onto the upper directory.
    Write(Errno),
}

/// The result of a copy from `decoy` to `upper` under `labels`.
fn judge(
    decoy: &Path,
    upper: &Path,
    labels: Labels,
    copied: std::result::Result<(), Failure>,
) -> Result<Copied> {
    let failure = match copied {
        Ok(()) => return Ok(Copied::Label),
        Err(failure) => failure,
    };
    if labels == Labels::BestEffort {
        match failure {
            // No label to copy, or no decoy directory at all: the fresh home
            // of an operator who has no home on the decoy.
            Failure::Read(Errno::NODATA | Errno::NOENT) => return Ok(Copied::NoLabel),
            Failure::Read(Errno::NOTSUP) | Failure::Write(Errno::NOTSUP) => {
                return Ok(Copied::Unsupported);
            }
            _ => {}
        }
    }
    Err(refusal(decoy, upper, labels, failure))
}

/// The error for a copy that failed: what failed and, with SELinux enabled,
/// why the entry cannot go on without the label.
fn refusal(decoy: &Path, upper: &Path, labels: Labels, failure: Failure) -> NailsError {
    let (decoy, upper) = (decoy.display(), upper.display());
    let why = match failure {
        Failure::Read(Errno::NODATA) => format!("{decoy} has no label"),
        Failure::Read(Errno::NOENT) => format!("{decoy} does not exist"),
        Failure::Read(Errno::NOTSUP) => format!("the filesystem of {decoy} stores no labels"),
        Failure::Write(Errno::NOTSUP) => {
            format!("the filesystem of {upper} cannot store labels")
        }
        Failure::Read(errno) => format!(
            "reading the label of {decoy} failed: {}",
            std::io::Error::from(errno)
        ),
        Failure::Write(errno) => format!(
            "writing the label onto {upper} failed: {}",
            std::io::Error::from(errno)
        ),
    };
    NailsError::InvalidState(match labels {
        Labels::Required => format!(
            "SELinux is enabled on this host, so {upper} needs the SELinux label of {decoy} \
             for the hidden root to boot, but {why}"
        ),
        Labels::BestEffort => {
            format!("the SELinux label of {decoy} could not be copied onto {upper}: {why}")
        }
    })
}

#[cfg(test)]
#[path = "labels_tests.rs"]
mod tests;
