// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines the claims place by a path they name, judged where that path
//! reads, with no link in it followed (see the `paths` module): a bind
//! line's source, the file of a swap or image line, and the source a FUSE
//! line gives its program and the program itself where the line names it by
//! its path.
//!
//! A path that lies in the volume, at the root's folder or inside it as the
//! mount that holds it shows it, makes a finding: a bind line mounts the
//! volume or a folder of it, and any other line reads a file there, or runs
//! one. So does a path whose place cannot be told ([`UntoldPath`]), which may
//! lead anywhere, the volume included. Either way the line claims the
//! filesystem that holds its path, where it reads or, where that cannot be
//! told, where its text places it.

use super::{EntryFinding, EntryKind, Scene, UntoldPath};
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
}

impl Named {
    /// What it is, as the subject of "lies".
    fn what(self) -> &'static str {
        match self {
            Named::Source => "its source",
            Named::File => "the file it names",
            Named::Program => "the program it runs",
        }
    }
}

/// A line the claims place by a path it names.
pub(super) struct Line {
    /// The file it is in.
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
/// the visible mount at the hidden root: the finding it makes, if any, and
/// the mount that holds it, which the line claims. Where it lies cannot be
/// told when [`Scene::paths`] says so, or holds no reading of it: the
/// finding says why, and the mount is the one its text leads to.
pub(super) fn place<'a>(
    scene: &Scene<'a>,
    hidden: &MountEntry,
    line: &Line,
    written: &str,
) -> (Option<EntryFinding>, Option<&'a MountEntry>) {
    match scene.named_path(written) {
        Ok(path) => {
            let holder = mount_holding(scene.mounts, path);
            let finding = holder.and_then(|holder| in_volume(hidden, line, path, holder));
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
/// the volume, which the boot swaps on, mounts or runs. It goes as
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
    }
}
