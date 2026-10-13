// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The one `/proc/self/mountinfo` parser, shared with the teardown crate.
//!
//! The parser and the classifier of NAILS-created mounts live in
//! [`nails_teardown::mountinfo`], so the emergency hot path and the rest of the
//! crate read the mount table the same way. This module re-exports them and adds
//! the two wrappers that speak this crate's error type.

pub use nails_teardown::mountinfo::{
    MountEntry, OverlayOpts, parse_mountinfo, parse_overlay_opts, root_is_hidden_overlay,
    top_mount_at, unescape_octal,
};

use crate::{IoResultExt, NailsError, Result};
use std::path::Path;

/// Read and parse `/proc/self/mountinfo` once.
pub fn read_mountinfo() -> Result<Vec<MountEntry>> {
    nails_teardown::mountinfo::read_mountinfo().at_path(nails_teardown::mountinfo::SELF_MOUNTINFO)
}

/// Escape a path for use inside an overlay mount option value (see
/// [`nails_teardown::mountinfo::escape_overlay_path`]). A path holding a newline
/// cannot be represented in a mount option and is refused.
pub fn escape_overlay_path(path: &Path) -> Result<String> {
    nails_teardown::mountinfo::escape_overlay_path(path).ok_or_else(|| {
        NailsError::OverlayError(format!(
            "overlay path contains a newline and cannot be mounted: {}",
            path.display()
        ))
    })
}
