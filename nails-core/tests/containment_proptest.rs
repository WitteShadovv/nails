// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests for the containment-critical helper that decides what counts
//! as "on the hidden volume".
//!
//! `is_on_hidden_volume` guards every path nails writes for the hidden
//! environment. These suites drive it over generated inputs, reusing the adversarial component alphabet in `tests/common` (plain
//! names, `.`, `..` and in-tree symlinks that point at themselves, their parent,
//! outside the volume, or in a loop) so they exercise the same traversal and
//! planted-symlink inputs as the configured-path and `SafeRoot` suites.
//!
//! Two kinds of root are covered:
//!
//! - a root that does not exist on disk: no generated path, absolute or
//!   relative, however it mixes `.`, `..` and repeated separators, is accepted
//!   below it;
//! - a root that exists: a tempdir with planted symlinks, asserting that plain
//!   in-tree paths are accepted and that the check fails closed on anything
//!   below the symlink that leads out of the volume.
//!
//! Case counts are bounded so the suites run inside the normal `cargo test` gate.

use nails_core::state::is_on_hidden_volume;
use proptest::prelude::*;
use std::path::Path;

mod common;
use common::{components, fixture, join, resolve};

/// Cases per property: enough to mix every component kind while staying fast.
const CASES: u32 = 64;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// A root that does not exist holds no path: what would be made below it
    /// lands on the filesystem that holds its parent. Every generated path is
    /// refused, also one that reads as below the root once `..`, `.` and
    /// repeated separators are cleaned away, and a relative one.
    #[test]
    fn a_root_that_does_not_exist_holds_no_path(
        root_parts in prop::collection::vec(prop::sample::select(&["a", "b", "c"][..]), 1..4),
        tail in components(5),
        leaf in prop::sample::select(&["x", "y", "new"][..]),
    ) {
        // A root under a directory that cannot exist.
        let root = format!("/nails-nonexistent-{}", root_parts.join("/"));
        // Sprinkle repeated separators so the parser must collapse them too.
        let path = join(&root, &tail, leaf).replace("/a/", "/a//");
        let relative = join("sub", &tail, leaf);

        prop_assert!(
            !is_on_hidden_volume(Path::new(&path), &root),
            "{} accepted below the missing root {}", path, root
        );
        prop_assert!(
            !is_on_hidden_volume(Path::new(&relative), &root),
            "relative {} accepted below the missing root {}", relative, root
        );
    }

    /// Filesystem branch, accept side: with a real root on disk, a path built
    /// only from plain, in-tree components stays inside the volume and must be
    /// accepted.
    #[test]
    fn filesystem_branch_accepts_plain_in_tree_paths(
        parts in prop::collection::vec(prop::sample::select(&["a", "b", "new"][..]), 0..4),
    ) {
        let fx = fixture();
        let root = fx.vol().to_string_lossy().into_owned();
        let path = join(&root, &parts, "new");
        prop_assert!(
            is_on_hidden_volume(Path::new(&path), &root),
            "plain in-tree path rejected: {}", path
        );
    }

    /// Filesystem branch, fail-closed side: below the `out` symlink, planted to
    /// point outside the volume, the check must reject the path whatever
    /// components follow. The kernel takes a `..` after `out` from where `out`
    /// leads, a `..` after a directory that does not exist yet is refused, and
    /// none of the alphabet's names leads back into the volume from outside it.
    #[test]
    fn filesystem_branch_rejects_paths_under_an_escaping_symlink(
        tail in components(4),
    ) {
        let fx = fixture();
        let root = fx.vol().to_string_lossy().into_owned();
        // `out` is a symlink to a directory outside the volume, and nothing
        // exists beneath it.
        let parts: Vec<&str> = std::iter::once("out").chain(tail.iter().copied()).collect();
        let path = join(&root, &parts, "new");
        // Sanity: the planted symlink really does leave the real root.
        prop_assert!(!resolve(Path::new(&path)).starts_with(resolve(&fx.vol())));
        prop_assert!(
            !is_on_hidden_volume(Path::new(&path), &root),
            "path under an escaping symlink accepted: {}", path
        );
    }
}
