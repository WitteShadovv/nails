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
//! missing one, or a link that leads to nothing, holds no line. One that
//! cannot be read, or an entry of it that is not UTF-8 text, refuses the
//! entry: NAILS could not tell what the hidden systemd mounts from it.

use super::refuse_undecided;
use crate::error::{NailsError, Result};
use crate::session::fstab::{self, FstabEntry};
use crate::session::policy::{self, Decision, Present, Whose};
use nails_teardown::mountinfo::MountEntry;
use nails_teardown::whole_root::nextroot::resolve_in_root;
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
    let text = fstab::read_in_root(nextroot).map_err(|e| {
        NailsError::InvalidState(format!(
            "the hidden /etc/fstab cannot be read ({e}): the hidden session would run with it, \
             and NAILS cannot tell what it mounts"
        ))
    })?;
    let mut hidden = HiddenFstab::default();
    if text == decoy_text {
        return Ok(hidden);
    }
    let mut lines: Vec<String> = Vec::new();
    for (index, raw) in text.split(|byte| *byte == b'\n').enumerate() {
        let Some(entry) = fstab::parse_in_root(raw, nextroot).pop() else {
            continue;
        };
        let Ok(line) = std::str::from_utf8(raw) else {
            return Err(NailsError::InvalidState(format!(
                "line {} of the hidden /etc/fstab is not UTF-8 text: the hidden session would \
                 run with it, and NAILS cannot tell what it mounts",
                index + 1
            )));
        };
        if decided.contains(&entry) || hidden.entries.contains(&entry) {
            continue;
        }
        lines.push(line.trim().to_string());
        hidden.entries.push(entry);
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
