// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/fstab` as the hidden systemd will read it, and systemd's unit names.
//!
//! The hidden root runs the decoy's own fstab (or, on NixOS, the hidden
//! toplevel's). `systemd-fstab-generator` turns every entry into a `.mount` or
//! `.swap` unit, so the session policy ([`super::policy`]) needs the same view
//! of it, plus the unit names it would generate, to overlay, bind or mask each
//! entry before the switch. The parser is [`nails_base::fstab`], re-exported
//! here; the unit names are the session's own.

use std::path::{Path, PathBuf};

pub use nails_base::fstab::{FstabEntry, escape_path, parse_fstab, spec_device};

/// The `/etc/fstab` of the root at `root`, read as that root resolves it
/// ([`read_in_root`](nails_teardown::whole_root::nextroot::read_in_root)).
/// A root without one has no entries; any other error is returned, never
/// taken for an empty fstab, which would leave every entry undecided.
pub fn read_in_root(root: &Path) -> std::io::Result<Vec<u8>> {
    match nails_teardown::whole_root::nextroot::read_in_root(root, Path::new("/etc/fstab")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        result => result,
    }
}

/// The `.mount` unit for a mount point.
pub fn mount_unit(path: &Path) -> String {
    format!("{}.mount", escape_path(path))
}

/// The `.automount` unit for a mount point.
pub fn automount_unit(path: &Path) -> String {
    format!("{}.automount", escape_path(path))
}

/// The `.swap` unit for a swap spec, when it names a device or file.
pub fn swap_unit(spec: &str) -> Option<String> {
    let path = spec_device(spec).or_else(|| spec.starts_with('/').then(|| PathBuf::from(spec)))?;
    Some(format!("{}.swap", escape_path(&path)))
}

#[cfg(test)]
#[path = "fstab_tests.rs"]
mod tests;
