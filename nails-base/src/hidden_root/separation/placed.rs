// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines the claims place by a path they name, judged where that path
//! reads, with no link in it followed (see the `paths` module): a bind line's
//! source, the file of a swap or image line, the source a FUSE line gives its
//! program and the program itself where the line names it by its path, the file
//! a crypttab line opens, its key file and its header and a file its boot
//! mounts for one of these, and a path an option of a line names (see the
//! `reads` module).
//!
//! A path that lies in the volume, at the root's folder or inside it as the
//! mount that holds it shows it, makes a finding: a bind line mounts the
//! volume or a folder of it, and any other line reads a file there, or runs
//! one. So does a path whose place cannot be told ([`UntoldPath`]), which may
//! lead anywhere, the volume included. Either way the line claims the
//! filesystem that holds its path, where it reads or, where that cannot be
//! told, where its text places it.
//!
//! A path that names the file a loop device of the root's stack reads, the
//! container file the volume is opened from or the image it is in, makes a
//! finding too, as a line that opens the volume does: the boot opens that file
//! again, through a loop device of its own as `systemd-cryptsetup` does for a
//! crypttab line's file and `mount` for an image file, or swaps on it, and so
//! makes a second mapping or a second mount of the volume, or writes over it.
//! It names that file when it is the path the loop driver shows for it, as it
//! reads, or when the file it names there is that file, by its device and inode
//! as the loop driver recorded them ([`FileId`]): a hard link or a path through
//! another mount of the same folder names it too. Where the record of such a
//! loop device could not be read, whether a file that is there is that one
//! cannot be told.

use super::{EntryFinding, EntryKind, FileId, LoopFile, Scene, UntoldPath};
use crate::filesystem::mountinfo::MountEntry;
use crate::hidden_root::mount_holding;
use std::path::Path;

/// What a line names by a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Named {
    /// The source of a bind line, which it mounts.
    Source,
    /// The file a swap or image line names, or the one a FUSE line gives its
    /// program.
    File,
    /// The program a FUSE line has `mount.fuse` run.
    Program,
    /// The file a crypttab line opens.
    Opened,
    /// The key file of a crypttab line, in its key field or a
    /// `tcrypt-keyfile=`.
    KeyFile,
    /// What the boot mounts for the key file of a crypttab line, the device
    /// of its `keyfile:keydev` key field.
    KeyDevice,
    /// The header of a crypttab line, its `header=`.
    Header,
    /// What the boot mounts for the header of a crypttab line, the device of
    /// its `header=<path>:<device>`.
    HeaderDevice,
    /// The path or the device an option of a line names, by the option's
    /// name (see the `known` module): an overlay's `upperdir=`, say, or a
    /// crypttab line's `tpm2-device=`.
    Option(&'static str),
}

impl Named {
    /// What it is, as the subject of "lies".
    fn what(self) -> String {
        match self {
            Named::Source => "its source".into(),
            Named::File => "the file it names".into(),
            Named::Program => "the program it runs".into(),
            Named::Opened => "the file it opens".into(),
            Named::KeyFile => "its key file".into(),
            Named::KeyDevice => "what it mounts for its key file".into(),
            Named::Header => "its header".into(),
            Named::HeaderDevice => "what it mounts for its header".into(),
            Named::Option(option) => format!("the path its option {option}= names"),
        }
    }
}

/// A line the claims place by a path it names.
#[derive(Clone)]
pub(super) struct Line {
    /// The file it is in, the fstab or the crypttab.
    pub file: &'static str,
    /// The line, as its first fields read.
    pub shown: String,
    /// What it names by the path.
    pub named: Named,
    /// Whether the decoy's own boot needs the line, when its path lies in
    /// the volume.
    pub boot_needs: bool,
}

/// `written`, the path `line` names, judged where it reads below `hidden`,
/// the visible mount at the hidden root, whose stack reads the files `files`
/// through its loop devices: the finding it makes, if any, and the mount that
/// holds it, which the line claims. Where it lies cannot be told when
/// [`Scene::paths`] says so, or holds no reading of it: the finding says why,
/// and the mount is the one its text leads to.
pub(super) fn place<'a>(
    scene: &Scene<'a>,
    hidden: &MountEntry,
    files: &[&LoopFile],
    line: &Line,
    written: &str,
) -> (Option<EntryFinding>, Option<&'a MountEntry>) {
    match scene.named_path(written) {
        Ok(path) => {
            let holder = mount_holding(scene.mounts, path);
            let finding = stored_in(hidden, files, line, path, scene.files.get(written))
                .or_else(|| holder.and_then(|holder| in_volume(hidden, line, path, holder)));
            (finding, holder)
        }
        Err(why) => (
            Some(untold(line, &why)),
            mount_holding(scene.mounts, Path::new(written)),
        ),
    }
}

/// The finding for `line`, whose path reads as `path` on the mount `holder`,
/// when that path lies in the volume of `hidden`: at the volume's folder of
/// that filesystem or inside it, as `holder` shows it now. A bind line then
/// mounts the volume or a folder of it, and any other line names a file in
/// the volume, which the boot swaps on, mounts, opens or runs. It goes as
/// any line does that names the volume itself, unless the decoy's own boot
/// needs it ([`Line::boot_needs`]), and it is never the decoy's own line.
fn in_volume(
    hidden: &MountEntry,
    line: &Line,
    path: &Path,
    holder: &MountEntry,
) -> Option<EntryFinding> {
    let below = path.strip_prefix(&holder.mount_point).ok()?;
    let folder = holder.root.join(below);
    if holder.dev != hidden.dev || !folder.starts_with(&hidden.root) {
        return None;
    }
    let root = hidden.mount_point.display();
    let why = match line.named {
        Named::Source if folder == hidden.root => format!("it mounts the volume at {root}"),
        Named::Source => format!("it mounts a folder of the volume at {root}"),
        named => format!("{} lies in the volume at {root}", named.what()),
    };
    Some(EntryFinding {
        kind: EntryKind::Blocking,
        file: line.file,
        line: line.shown.clone(),
        why,
        boot_needs: line.boot_needs,
        system_folder: None,
        not_plain: false,
        options: Vec::new(),
    })
}

/// The finding for `line`, whose path reads as `path` and names the file
/// `named` there, if anything is there, when it is one of `files`, which the
/// stack of the volume of `hidden` reads through its loop devices: the path
/// the loop driver shows for one of them, or the file one is by its device
/// and inode. The boot then opens the file the volume is stored in a second
/// time. Where the record of one of `files` could not be read, whether a file
/// that is there is that one cannot be told.
fn stored_in(
    hidden: &MountEntry,
    files: &[&LoopFile],
    line: &Line,
    path: &Path,
    named: Option<&FileId>,
) -> Option<EntryFinding> {
    let root = hidden.mount_point.display();
    let what = line.named.what();
    let same = files
        .iter()
        .any(|file| file.path == path || (named.is_some() && file.id.as_ref() == named));
    if same {
        return Some(EntryFinding {
            kind: EntryKind::Blocking,
            file: line.file,
            line: line.shown.clone(),
            why: format!("{what} is the file the volume at {root} is stored in"),
            boot_needs: line.boot_needs,
            system_folder: None,
            not_plain: false,
            options: Vec::new(),
        });
    }
    // A path at which nothing is there names no file: none of these.
    named?;
    let unread = files.iter().find(|file| file.id.is_none())?;
    Some(EntryFinding {
        kind: EntryKind::Untold,
        file: line.file,
        line: line.shown.clone(),
        why: format!(
            "whether {what} is the file the volume at {root} is stored in cannot be told: the \
             loop driver's record of {} could not be read",
            unread.path.display()
        ),
        boot_needs: false,
        system_folder: None,
        not_plain: false,
        options: Vec::new(),
    })
}

/// The finding for `line`, whose path cannot be told (`why`): it may lead
/// anywhere, the volume included, which cannot be told.
fn untold(line: &Line, why: &UntoldPath) -> EntryFinding {
    EntryFinding {
        kind: EntryKind::Untold,
        file: line.file,
        line: line.shown.clone(),
        why: format!(
            "where {} lies cannot be told: {}",
            line.named.what(),
            why.reason()
        ),
        boot_needs: false,
        system_folder: None,
        not_plain: false,
        options: Vec::new(),
    }
}
