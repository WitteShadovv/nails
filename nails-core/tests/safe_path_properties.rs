// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests for `SafeRoot` containment, sharing the adversarial path
//! generators with the configured-path containment suite (`path_properties.rs`)
//! via `tests/common`.
//!
//! `SafeRoot` resolves every relative path beneath a pinned `O_PATH` root fd with
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`. The
//! same component alphabet T-015 uses to probe configured-path containment — `.`,
//! `..` and in-tree symlinks pointing at themselves, their parent, outside the
//! volume, or in a loop — is driven here against the helper itself, so the two
//! suites exercise the same planted-symlink and traversal inputs.

use nails_core::filesystem::SafeRoot;
use proptest::prelude::*;
use std::path::{Path, PathBuf};

mod common;
use common::{SYMLINKS, components, fixture, is_plain, join, resolve};

/// Cases per property: enough to mix every component kind while staying fast.
const CASES: u32 = 64;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// Whatever the generated path, `SafeRoot` never creates anything outside the
    /// real root, and a path built only from plain, in-tree components is always
    /// accepted. A path that traverses a planted symlink or a `..` is refused.
    #[test]
    fn safe_root_contains_or_refuses_generated_paths(parts in components(4)) {
        let fx = fixture();
        let vol = fx.vol();
        let real_root = resolve(&vol);
        let root = SafeRoot::open(&vol).unwrap();

        // Build the relative path (never prefixed with the root) ending in a new
        // leaf so each case tries to create something.
        let relative = join("", &parts, "new");
        let relative = relative.trim_start_matches('/').to_string();
        let rel = Path::new(&relative);

        match root.create_dir_all(rel) {
            Ok(()) => {
                // Anything created stays strictly beneath the real root.
                let created = vol.join(rel);
                let resolved = resolve(&created);
                prop_assert!(
                    resolved.starts_with(&real_root),
                    "{} resolved to {} outside {}",
                    created.display(), resolved.display(), real_root.display()
                );
                // A `..` component is always refused up front, so it can never
                // appear on the accepted path.
                prop_assert!(!parts.contains(&".."), "a `..` path was accepted: {relative}");
            }
            Err(_) => {
                // A refusal is only allowed when something could escape or
                // traverse a link: a purely plain path must always be accepted.
                prop_assert!(
                    !is_plain(&parts),
                    "a plain in-tree path was refused: {relative}"
                );
            }
        }
    }

    /// A path whose first component is a planted symlink in the volume root is
    /// always refused — the helper will not traverse the link even though it
    /// resolves (for `in`/`up`/`loop`) back inside the volume.
    #[test]
    fn safe_root_refuses_a_leading_symlink(
        tail in components(3),
        link in prop::sample::select(SYMLINKS),
    ) {
        let fx = fixture();
        let root = SafeRoot::open(&fx.vol()).unwrap();
        let mut parts = vec![link];
        parts.extend(tail);
        let relative = join("", &parts, "new");
        let relative = relative.trim_start_matches('/').to_string();

        prop_assert!(
            root.create_dir_all(Path::new(&relative)).is_err(),
            "a leading symlink was traversed: {relative}"
        );
        // And nothing leaked onto the out-of-tree target.
        let leaked: Vec<PathBuf> = std::fs::read_dir(&fx.outside)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        prop_assert!(leaked.is_empty(), "a write leaked outside the root: {leaked:?}");
    }
}
