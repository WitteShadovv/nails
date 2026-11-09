// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step 5 of an entry without a build (see [`super`]): the next root's own
//! `/etc/fstab`, which the hidden systemd reads at the switch. On NixOS
//! (`--overlay-only`) it is the one of the hidden `/etc` the last activation
//! of a hidden system wrote into the root upper, which leads into that
//! system's store; on another host it is one a hidden session wrote there
//! over the decoy's, or else the decoy's own.
//!
//! Its lines are decided by the fstab policy as the decoy's are, naming
//! whose fstab it is ([`Whose`]): the hidden NixOS system's where the file
//! leads into the store, else the hidden session's, a file written in a
//! session on NixOS too. A line at or below the hidden root is kept off
//! rather than refused, with a warning ([`policy::decide_hidden_fstab`]): the
//! session entered to remove such a line must still start. A line the
//! decoy's fstab holds too, as the next root resolves it, is decided once, as
//! the decoy's.
//!
//! The file is read as the next root resolves it, its links followed inside
//! the next root and never out of it ([`fstab::read_in_root`]), after the
//! decoy's filesystems are in place there, a separate `/nix` among them. A
//! missing one, or a link that leads to nothing, holds no line. One that is
//! not a regular file is not read: a FIFO would hold the entry until a writer
//! came, and a device might never end the read. That one, one that cannot be
//! read, and one with a line that the hidden systemd may read otherwise than
//! NAILS ([`fstab::entry_lines`]) refuse the entry: NAILS could not tell what
//! the hidden systemd mounts from it. The refusal names where the root upper
//! keeps the hidden root's own `/etc/fstab` on the hidden volume, as the
//! session cannot be entered to change it.

use super::refuse_undecided;
use crate::error::{NailsError, Result};
use crate::session::fstab::{self, FstabEntry};
use crate::session::layout::Layout;
use crate::session::policy::{self, Decision, Present, Whose};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::nextroot::{regular_file_in_root, resolve_in_root};
use std::path::Path;

/// What an entry without a build decides of the next root's own fstab.
#[derive(Debug, Default)]
pub(super) struct HiddenFstab {
    /// Its entries that the decoy's fstab does not hold, resolved in the next
    /// root, each once.
    pub(super) entries: Vec<FstabEntry>,
    /// Their decisions ([`policy::decide_all_hidden_fstab`]).
    pub(super) decisions: Vec<Decision>,
    /// A warning for each of them kept off at or below the hidden root
    /// ([`policy::kept_below_warning`]).
    pub(super) warnings: Vec<String>,
}

/// Read and decide the `/etc/fstab` of `nextroot`, on a NixOS host or
/// another (`nixos`), against `mounts`, the decoy's mounts as its fstab names
/// them: `decoy_text` is the decoy's fstab, and `decided` the entries decided
/// already, the decoy's as the decoy root and the next root resolve them. A
/// file that is the decoy's own, byte for byte, holds nothing to decide
/// again.
pub(super) fn decide(
    nextroot: &Path,
    decoy_text: &[u8],
    decided: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
    present: Present<'_>,
    nixos: bool,
) -> Result<HiddenFstab> {
    let mut hidden = HiddenFstab::default();
    let Some(text) = read(nextroot, hidden_root)? else {
        return Ok(hidden);
    };
    if text == decoy_text {
        return Ok(hidden);
    }
    let raw_lines = fstab::entry_lines(&text).map_err(|(line, why)| {
        refusal(
            &format!("line {line} of the hidden /etc/fstab {why}"),
            hidden_root,
        )
    })?;
    let mut lines: Vec<String> = Vec::new();
    for raw in raw_lines {
        for entry in fstab::parse_in_root(raw, nextroot) {
            if decided.contains(&entry) || hidden.entries.contains(&entry) {
                continue;
            }
            lines.push(String::from_utf8_lossy(raw).trim().to_string());
            hidden.entries.push(entry);
        }
    }
    let whose = whose(nextroot, nixos);
    let decisions = policy::decide_all_hidden_fstab(&hidden.entries, mounts, hidden_root, present);
    hidden.decisions = refuse_undecided(decisions, whose)?;
    hidden.warnings = hidden
        .entries
        .iter()
        .zip(&lines)
        .filter_map(|(entry, line)| policy::kept_below_warning(entry, line, hidden_root, whose))
        .collect();
    Ok(hidden)
}

/// The `/etc/fstab` of `nextroot`, `None` where there is none: nothing is
/// there, or a link that leads to nothing. One that is not a regular file is
/// refused unread (see the module docs), as is one that cannot be read.
fn read(nextroot: &Path, hidden_root: &Path) -> Result<Option<Vec<u8>>> {
    let unreadable = |why: &str| {
        refusal(
            &format!("the hidden /etc/fstab cannot be read ({why})"),
            hidden_root,
        )
    };
    match regular_file_in_root(nextroot, Path::new("/etc/fstab")) {
        Ok(true) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Ok(false) => return Err(unreadable("it is not a regular file")),
        Err(e) => return Err(unreadable(&e.to_string())),
    }
    fstab::read_in_root(nextroot)
        .map(Some)
        .map_err(|e| unreadable(&e.to_string()))
}

/// The refusal of the entry for `why`, a fault of the hidden `/etc/fstab`,
/// with where the root upper on the hidden volume keeps the hidden root's own
/// `/etc/fstab`, if it has one.
fn refusal(why: &str, hidden_root: &Path) -> NailsError {
    NailsError::InvalidState(format!(
        "{why}: the hidden session would run with it, and NAILS cannot tell what it mounts. \
         The hidden root's own /etc/fstab, if it has one, is {} on the hidden volume.",
        Layout::new(hidden_root).upper().join("etc/fstab").display()
    ))
}

/// Whose the `/etc/fstab` of `nextroot` is: on NixOS (`nixos`) the hidden
/// system's where it leads into the store, as the hidden `/etc` an activation
/// wrote links it, and else the hidden session's, a file written in a
/// session.
fn whose(nextroot: &Path, nixos: bool) -> Whose {
    let into_store = || {
        resolve_in_root(nextroot, Path::new("/etc/fstab"))
            .is_some_and(|file| file.starts_with("/nix/store"))
    };
    if nixos && into_store() {
        Whose::HiddenSystem
    } else {
        Whose::HiddenSession
    }
}
