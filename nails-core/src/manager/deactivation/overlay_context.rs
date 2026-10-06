// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The overlay layout a teardown must undo, read from the state file or,
//! for an untrusted state, re-derived from the live mount table.

use crate::manager::NailsManager;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub(super) struct OverlayContext {
    pub(super) nix_was_overlaid: bool,
    pub(super) var_was_overlaid: bool,
    /// Activation recorded a read-only `/nix/store` self-bind in PID 1's mount
    /// namespace (set only when the manager and init namespaces differed). The
    /// manager-namespace unmount cannot reach it, so teardown undoes it directly.
    pub(super) nix_store_init_namespace_bound: bool,
    /// Decoy OS trees activation bind-remounted read-only for the session, to undo
    /// so the host regains write access (the decoy root and `/usr` on an FHS host;
    /// empty on NixOS).
    pub(super) read_only_guards: Vec<PathBuf>,
    /// Mounts activation created to keep host submounts visible under overlaid
    /// targets, to undo (in reverse) before the parent overlays come down. Empty
    /// when no target had a hidden submount.
    pub(super) submount_attachments: Vec<crate::state::SubmountAttachment>,
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

    let nix_store_init_namespace_bound = cached
        .as_ref()
        .map(|state_file| state_file.nix_store_init_namespace_bound)
        .unwrap_or(false);

    let read_only_guards = cached
        .as_ref()
        .map(|state_file| state_file.read_only_guards.clone())
        .unwrap_or_default();

    let submount_attachments = cached
        .as_ref()
        .map(|state_file| state_file.submount_attachments.clone())
        .unwrap_or_default();

    Ok(OverlayContext {
        nix_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/nix")),
        var_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/var")),
        nix_store_init_namespace_bound,
        read_only_guards,
        submount_attachments,
    })
}

/// Derive the service-restart context from the live mount table rather than the
/// state file, for an emergency teardown on an untrusted state.
///
/// The cached state is the safe default (empty overlay list) when the state file
/// is corrupt, so the nix-daemon / journald restart must be driven by what is
/// actually mounted: whether `/nix` is overlaid, and whether `/var` is among the
/// discovered overlays.
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

    // The recorded guard list cannot be trusted on a corrupt state, so re-derive
    // the trees the active platform's policy would have kept read-only and undo
    // those. `unmount_bind` is idempotent, so undoing a tree that was never
    // guarded is a harmless no-op, and this makes sure an emergency teardown
    // always returns write access to the decoy.
    let read_only_guards = crate::platform::detect_platform(manager.filesystem())
        .ok()
        .map(|platform| platform.overlay_policy())
        .and_then(|policy| policy.resolve_read_only(manager.filesystem()).ok())
        .unwrap_or_default();

    Ok(OverlayContext {
        nix_was_overlaid: mounts.nix_overlay_present,
        var_was_overlaid,
        // An untrusted-state teardown cannot trust the recorded flag, and the
        // init-namespace bind is invisible in the manager's mount table, so it is
        // left for manual recovery rather than guessed at.
        nix_store_init_namespace_bound: false,
        read_only_guards,
        // The recorded attachment list cannot be trusted on a corrupt state. Nested
        // overlays are still discovered and torn down as persistent overlays below;
        // the staging/re-attach binds are left for the forced parent-overlay detach
        // rather than guessed at.
        submount_attachments: Vec::new(),
    })
}
