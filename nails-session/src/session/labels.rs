// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux labels of the directories NAILS creates in the uppers.
//!
//! An overlay inode takes its SELinux label from the `security.selinux`
//! attribute of the upper inode, and a file copied up keeps the label of the
//! decoy file it copies. The directories NAILS itself creates in the uppers
//! are neither: the root of each upper, and the empty home of the
//! fresh-home persona with the parents it needs. On a hidden volume nobody
//! relabelled they carry no label, or one the kernel derived from their parent
//! there, so the policy sees the hidden `/` as `unlabeled_t`, and confined
//! services may not even look it up: the hidden session does not boot on an
//! enforcing host. [`copy_label`] gives such a directory the label of the
//! decoy directory it stands for, [`copy_labels_along`] gives one to each
//! directory on the way from the root of an upper down to the home, and
//! [`copy_labels_along_existing`] to as much of that way as the upper holds.
//! They read the label with `lgetxattr` and write it with `fsetxattr` on the
//! upper directory itself, so the hidden `/`, a separate `/home` and the empty
//! home carry the types they have on the decoy (`root_t`, `home_root_t` and
//! `user_home_dir_t` under Fedora's policy). Whatever the hidden session
//! creates below them then takes its label from the policy, as on the decoy.
//!
//! Whether a copy must succeed depends on the host ([`Labels::for_host`]).
//! Where the host facts report SELinux, a copy that fails refuses the entry: a
//! hidden volume whose filesystem cannot store labels, a policy that does not
//! let NAILS relabel, a decoy directory with no label to read. The facts report
//! SELinux when `/sys/fs/selinux` exists or `/etc/selinux/config` names a mode
//! or a policy ([`HostProfile::selinux`] is `Some`). That includes a host that
//! keeps only the configuration file, `SELINUX=disabled` in it: its facts
//! cannot be told apart from a mounted selinuxfs whose enforce flag could not
//! be read, and refusing an entry is the safe side of that doubt. A host that
//! was not detected at all counts the same way, since nothing rules SELinux
//! out there. Where the facts report no SELinux, nothing reads the labels and
//! the copy is best effort: a decoy directory without a label (the usual case
//! there) or none at all, a filesystem without extended attributes, or a link
//! or a file in place of an upper directory leaves the upper as it was, so such
//! a host gets the same hidden root as before. Any other failure is an error
//! either way.
//!
//! # Where the copies go
//!
//! The activation makes one [`Labels`] with
//! `Labels::for_host(manager.host_profile())`, so a detection that failed
//! counts as SELinux, and carries it in
//! [`EntryInputs::labels`](super::entry::EntryInputs::labels). The entry
//! copies at three places, each before the overlay over that upper is mounted
//! (an upper must not change under a mounted overlay):
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
//! - **the home and its parents**: `persona_home` in [`super::entry`], at every
//!   entry that knows the operator, whatever the persona mode. The home is
//!   found as `fresh_home` finds it: the upper root is [`Layout::upper`](super::Layout::upper) for a
//!   home on the decoy root, else the upper of [`Layout::mount_layers`](super::Layout::mount_layers)
//!   of the decoy filesystem `mount` it lives on, and `rest` is the home below
//!   `mount`. In the fresh-home persona the call is in `fresh_home`, right
//!   after [`prepare_fresh_home`](super::persona::prepare_fresh_home) returns,
//!   whether it created the home or found it in place, as
//!   `copy_labels_along(&paths.decoy(mount), &upper_root, rest, labels)`,
//!   which labels every directory below the upper root down to the home, the
//!   home included. In the shared-home persona it is
//!   `copy_labels_along_existing` with the same arguments, which labels as
//!   much of that way as the upper holds. `make_layer` labels the upper root
//!   itself, and the directories `create_parents_like` makes above it
//!   (`root/mounts/<unit>`) belong to no overlay. Both calls come before
//!   `make_layer` and `apply_mounts`, so no overlay is mounted on either upper
//!   yet.
//!
//! All three run at every entry: a label already in place is not written again,
//! and one that is missing or wrong is written at the next entry. The roots of
//! the uppers take the decoy's labels again each time, as they take its mode
//! and owner. The home and its parents take the labels again each time too,
//! though their mode and owner are set only when they are created, so a label
//! the hidden session gives one of them gives way to the decoy's at the next
//! entry. Nothing copies a label where a directory is created
//! (`create_parents_like`, `prepare_fresh_home`): `create_parents_like` keeps a
//! directory that exists, and nothing removes a parent whose copy failed, so
//! with a copy made only there a later entry would go on with that parent
//! unlabelled, after a relabel the policy denied once, an `ENOSPC` or `EIO` on
//! the hidden volume, or a decoy directory or label that appeared since.
//! Whether a directory gets a copy follows the rules of [`copy_label`] alone,
//! never whether `create_parents_like` could give it the decoy directory's mode
//! and owner (it gives neither where `like` is `None` or the decoy directory's
//! metadata cannot be read). With [`Labels::BestEffort`] a directory is left as
//! it is when its decoy counterpart does not exist or has no label, or a
//! filesystem stores no labels, and the walk stops at a link or a file in place
//! of a directory; with [`Labels::Required`] every directory gets the label or
//! the entry is refused. The entry tests of the kernel tier hold the entry to
//! this: an entry refused at the copy for a parent of the home, then a later
//! entry, with the home in place, labels that parent or is refused again and
//! never goes on without the label, in the fresh-home persona and with the
//! persona set to shared-home after the refusal.
//!
//! The shared-home walk is for what a refused fresh-home entry leaves in the
//! upper. An entry refused at its walk (the decoy has no home for the operator,
//! or the policy denied the relabel of a parent) keeps the directories
//! `prepare_fresh_home` created, without the decoy's labels: `rollback` removes
//! nothing from the upper. Once the persona is set to shared-home, `fresh_home`
//! no longer runs, but the overlay still merges those directories into the
//! hidden root, so without the walk the hidden `/home`, or the opaque home left
//! there, would show unlabelled. The other way to cover it, a refused entry
//! removing what its `prepare_fresh_home` created, is not taken: it has to
//! tell what the entry created from what it found in place, and an entry killed
//! before the removal, or a removal that fails, leaves the same directories
//! behind. The walk does not depend on how an earlier entry ended, so it also
//! covers what one from a release without this module left. It follows the
//! rules of [`copy_label`] in either persona: with [`Labels::Required`] a
//! directory on the way that cannot take its label refuses the shared-home
//! entry as well, so a home left for an operator the decoy has no home for
//! refuses that operator's shared-home entries too, until it is removed from
//! the upper. A directory the overlay copied up from the decoy keeps the
//! decoy's label, so the walk of a usual shared-home entry writes nothing. It
//! covers the way to the home of the entry's operator only: a home left for
//! another operator takes its label at that operator's next entry, and an
//! entry without an operator walks nothing.
//!
//! `nextroot` needs no call: it only mounts the uppers prepared here. Every
//! other directory the entry creates in the hidden root is made through the
//! next root once the overlays are mounted (the mount points of the fstab
//! policy and of the carried decoy filesystems, the persona's masks), and the
//! kernel labels it by the policy, like a file the hidden session creates.
//! The directories the entry makes directly on the hidden volume beside the
//! uppers take no label from the decoy: `root` itself, `root/mounts` and
//! `root/mounts/<unit>`, the work directory of every overlay, and `root/cache`
//! for a hidden NixOS build. They are no part of a merged view, so no overlay
//! inode takes its label from them, but the hidden session sees them through
//! the hidden volume's bind at its path, as `unlabeled_t` on a volume nobody
//! relabelled.
//!
//! The hidden NixOS configuration is not covered yet. `init` writes it into
//! the upper's `/etc/nixos` directly on the hidden volume, on NixOS and on any
//! host where `--hardware-config` is given, so it creates the upper's `/etc`
//! itself, and on an SELinux host the hidden `/etc` would take its label from
//! that directory. The follow-up either has `init` refuse `--hardware-config`
//! where the host facts report SELinux, or has the entry copy the decoy's
//! label onto an upper `/etc` that was not created through the overlay.

use crate::error::{NailsError, Result};
use nails_platform::HostProfile;
use rustix::fs::{Mode, OFlags, XattrFlags};
use rustix::io::Errno;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

/// The extended attribute that holds a file's SELinux label.
pub const LABEL_XATTR: &str = "security.selinux";

/// The largest value the kernel returns for an extended attribute
/// (`XATTR_SIZE_MAX`): a buffer this size reads any label in one call.
const LABEL_MAX: usize = 64 * 1024;

/// How an upper directory is opened: the directory itself, for its attributes
/// only. A symlink in the last component is not followed, and it or a file
/// there fails the open with `ENOTDIR`.
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Whether a label copy must succeed, from what the host facts say about
/// SELinux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Labels {
    /// The hidden root may need every label, for the reason given: a copy that
    /// fails refuses the entry.
    Required(Reason),
    /// The host facts report no SELinux, so nothing reads the labels: a decoy
    /// directory that has none or does not exist, a filesystem that stores
    /// none, or a link or a file in place of an upper directory leaves that
    /// directory as it was.
    BestEffort,
}

/// Why [`Labels::Required`] applies, for a refusal to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The host facts report SELinux: `/sys/fs/selinux` exists, or
    /// `/etc/selinux/config` names a mode or a policy.
    SelinuxReported,
    /// The host was not detected, so no facts rule SELinux out.
    HostUndetected,
}

impl Labels {
    /// What a host with this profile needs (the one `NailsManager::host_profile`
    /// returns, `None` where the detection failed): [`Labels::Required`] where
    /// its facts report SELinux ([`HostProfile::selinux`] is `Some`, see the
    /// module docs) and where there is no profile at all,
    /// [`Labels::BestEffort`] where they report none.
    pub fn for_host(profile: Option<&HostProfile>) -> Self {
        match profile {
            None => Self::Required(Reason::HostUndetected),
            Some(profile) if profile.selinux.is_some() => Self::Required(Reason::SelinuxReported),
            Some(_) => Self::BestEffort,
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
    /// A link or a file stands where the upper directory should be, and nothing
    /// was written onto it or through it ([`Labels::BestEffort`] only).
    NotADirectory,
}

/// Give `upper`, a directory NAILS created in an upper, the SELinux label of
/// `decoy`, the decoy directory it stands for in the hidden root.
///
/// `decoy` is only read, without following a symlink in its last component,
/// and reading an extended attribute updates no access time. `upper` is opened
/// as a directory without following a symlink in its last component (the rest
/// of its path resolves as it does for `make_layer` and the overlay), and the
/// label is written through that descriptor, only where it differs, so a later
/// entry relabels nothing. A link in place of `upper` is never labelled, nor is
/// its target, though an overlay given that path would take its root from the
/// target. With [`Labels::Required`] anything short of the label on `upper`
/// itself is an error, which refuses the entry; with [`Labels::BestEffort`] a
/// missing label, a filesystem without extended attributes, or a link or a file
/// in place of `upper` is not.
pub fn copy_label(decoy: &Path, upper: &Path, labels: Labels) -> Result<Copied> {
    let copied = read_label(decoy).map_err(Failure::Read).and_then(|label| {
        let dir = rustix::fs::open(upper, DIRECTORY, Mode::empty()).map_err(Failure::Upper)?;
        write_label(&dir, &label)
    });
    judge(decoy, upper, labels, copied)
}

/// Give every directory on the way from the upper root `upper` down to
/// `upper/rest`, `upper/rest` included and `upper` itself not, the label of
/// the directory at the same place below `decoy`, nearest to the root first,
/// by the rules of [`copy_label`].
///
/// The way down follows no link: `upper` is opened as [`copy_label`] opens it,
/// and each directory below it in the one above, without following a symlink.
/// A link or a file at `upper` or anywhere below it ends the walk there, with
/// nothing labelled at or past it: [`Labels::BestEffort`] stops, and
/// [`Labels::Required`] refuses. `rest` is relative and made of plain names,
/// and every directory on it must exist in the upper.
pub fn copy_labels_along(decoy: &Path, upper: &Path, rest: &Path, labels: Labels) -> Result<()> {
    walk(decoy, upper, rest, labels, Missing::Error)
}

/// [`copy_labels_along`] for an entry that has not just created the way (the
/// shared-home persona): it goes down only as far as the upper holds the way,
/// and an upper root or a directory on the way that does not exist ends it
/// there, without an error, on every host. Everything else is as for
/// [`copy_labels_along`]: a link or a file ends the walk too, with nothing
/// labelled at or past it, and each directory it reaches gets the label by the
/// rules of [`copy_label`].
pub fn copy_labels_along_existing(
    decoy: &Path,
    upper: &Path,
    rest: &Path,
    labels: Labels,
) -> Result<()> {
    walk(decoy, upper, rest, labels, Missing::End)
}

/// What a walk makes of a directory on the way that the upper does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    /// An error on every host: the entry has just created the way.
    Error,
    /// The end of the walk: nothing below it is in the upper either.
    End,
}

/// The walk of [`copy_labels_along`] and [`copy_labels_along_existing`].
fn walk(decoy: &Path, upper: &Path, rest: &Path, labels: Labels, missing: Missing) -> Result<()> {
    let mut names = Vec::new();
    for component in rest.components() {
        match component {
            Component::Normal(name) => names.push(name),
            Component::CurDir => {}
            _ => {
                return Err(NailsError::InvalidState(format!(
                    "{} is not a path of plain names below {}",
                    rest.display(),
                    upper.display()
                )));
            }
        }
    }
    let mut dir = match rustix::fs::open(upper, DIRECTORY, Mode::empty()) {
        Ok(dir) => dir,
        Err(Errno::NOENT) if missing == Missing::End => return Ok(()),
        Err(errno) => return judge(decoy, upper, labels, Err(Failure::Upper(errno))).map(drop),
    };
    let (mut decoy, mut upper) = (decoy.to_path_buf(), upper.to_path_buf());
    for name in names {
        decoy.push(name);
        upper.push(name);
        let next = match rustix::fs::openat(&dir, name, DIRECTORY, Mode::empty()) {
            Ok(next) => next,
            Err(Errno::NOENT) if missing == Missing::End => return Ok(()),
            // A link or a file: nothing at or below it is labelled.
            Err(errno) => {
                return judge(&decoy, &upper, labels, Err(Failure::Upper(errno))).map(drop);
            }
        };
        let copied = read_label(&decoy)
            .map_err(Failure::Read)
            .and_then(|label| write_label(&next, &label));
        judge(&decoy, &upper, labels, copied)?;
        dir = next;
    }
    Ok(())
}

/// The SELinux label of `path`, not following a symlink in its last component.
fn read_label(path: &Path) -> rustix::io::Result<Vec<u8>> {
    label_with(|buf| rustix::fs::lgetxattr(path, LABEL_XATTR, buf))
}

/// Write `label` onto the open directory `dir`, unless it carries it already.
fn write_label(dir: &OwnedFd, label: &[u8]) -> std::result::Result<(), Failure> {
    if label_with(|buf| rustix::fs::fgetxattr(dir, LABEL_XATTR, buf))
        .is_ok_and(|current| current == label)
    {
        return Ok(());
    }
    rustix::fs::fsetxattr(dir, LABEL_XATTR, label, XattrFlags::empty()).map_err(Failure::Write)
}

/// A label `read` puts into a buffer that holds any.
fn label_with(
    read: impl FnOnce(&mut [u8]) -> rustix::io::Result<usize>,
) -> rustix::io::Result<Vec<u8>> {
    let mut label = vec![0; LABEL_MAX];
    let len = read(&mut label[..])?;
    label.truncate(len);
    Ok(label)
}

/// The step of a copy that failed, with the kernel's error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// Reading the decoy directory's label.
    Read(Errno),
    /// Opening the upper directory itself: `ENOTDIR` where a link or a file
    /// stands in its place.
    Upper(Errno),
    /// Writing the label onto it.
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
            Failure::Upper(Errno::NOTDIR | Errno::LOOP) => return Ok(Copied::NotADirectory),
            _ => {}
        }
    }
    Err(refusal(decoy, upper, labels, failure))
}

/// The error for a copy that failed: what failed and, where every label is
/// required, why.
fn refusal(decoy: &Path, upper: &Path, labels: Labels, failure: Failure) -> NailsError {
    let (decoy, upper) = (decoy.display(), upper.display());
    let why = match failure {
        Failure::Read(Errno::NODATA) => format!("{decoy} has no label"),
        Failure::Read(Errno::NOENT) => format!("{decoy} does not exist"),
        Failure::Read(Errno::NOTSUP) => format!("the filesystem of {decoy} stores no labels"),
        Failure::Upper(Errno::NOTDIR | Errno::LOOP) => {
            format!("{upper} is a link or a file, not a directory")
        }
        Failure::Upper(Errno::NOENT) => format!("{upper} does not exist"),
        Failure::Write(Errno::NOTSUP) => {
            format!("the filesystem of {upper} cannot store labels")
        }
        Failure::Read(errno) => format!(
            "reading the label of {decoy} failed: {}",
            std::io::Error::from(errno)
        ),
        Failure::Upper(errno) => {
            format!("opening {upper} failed: {}", std::io::Error::from(errno))
        }
        Failure::Write(errno) => format!(
            "writing the label onto {upper} failed: {}",
            std::io::Error::from(errno)
        ),
    };
    NailsError::InvalidState(match labels {
        Labels::Required(reason) => {
            let reason = match reason {
                Reason::SelinuxReported => {
                    "the host facts report SELinux (/sys/fs/selinux exists, or \
                     /etc/selinux/config names a mode or a policy)"
                }
                Reason::HostUndetected => "the host could not be detected and may run SELinux",
            };
            format!("{reason}, so {upper} must carry the SELinux label of {decoy}, but {why}")
        }
        Labels::BestEffort => {
            format!("the SELinux label of {decoy} could not be copied onto {upper}: {why}")
        }
    })
}

#[cfg(test)]
#[path = "labels_tests.rs"]
mod tests;
