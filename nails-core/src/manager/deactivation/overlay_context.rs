// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which services a teardown must restart: whether `/nix` and `/var` were
//! overlaid, read from the state file or, for an untrusted state, re-derived
//! from the live mount table. What to unmount comes from the teardown plan.

use crate::manager::NailsManager;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub(super) struct OverlayContext {
    pub(super) nix_was_overlaid: bool,
    pub(super) var_was_overlaid: bool,
}

pub(super) fn inspect_overlay_context<F: Filesystem>(
    manager: &NailsManager<F>,
) -> Result<OverlayContext> {
    let _ = manager.current_state()?;
    let cached = manager.cached_state.borrow();
    let overlay_paths: Vec<PathBuf> = cached
        .as_ref()
        .map(|state_file| state_file.overlay_status.keys().cloned().collect())
        .unwrap_or_default();
    Ok(OverlayContext {
        nix_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/nix")),
        var_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/var")),
    })
}

/// Derive the service-restart context from the live mount table rather than the
/// state file, for a teardown on an untrusted state: the cached state is the
/// safe default (empty overlay list) when the state file is corrupt.
pub(super) fn overlay_context_from_mounts<F: Filesystem>(
    manager: &NailsManager<F>,
) -> Result<OverlayContext> {
    let hidden_root = manager.config().hidden_volume_root.clone();
    let mounts = manager
        .filesystem()
        .discover_nails_mounts(Some(&hidden_root))?;
    let var_was_overlaid = mounts
        .persistent_overlays
        .iter()
        .chain(mounts.ephemeral_overlays.iter())
        .any(|p| p == Path::new("/var"));
    Ok(OverlayContext {
        nix_was_overlaid: mounts.nix_overlay_present,
        var_was_overlaid,
    })
}
