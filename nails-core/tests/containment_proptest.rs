//! Property tests for the containment-critical helpers that decide what counts
//! as "on the hidden volume" and which directories survive the exclusion filter.
//!
//! `is_on_hidden_volume` guards every path nails writes for the hidden
//! environment, and `apply_exclusion_filter` decides which base-OS trees are
//! overlaid. Both had only example tests. These suites drive them over generated
//! inputs, reusing the adversarial component alphabet in `tests/common` (plain
//! names, `.`, `..` and in-tree symlinks that point at themselves, their parent,
//! outside the volume, or in a loop) so they exercise the same traversal and
//! planted-symlink inputs as the configured-path and `SafeRoot` suites.
//!
//! Two branches of `is_on_hidden_volume` are covered:
//!
//! - the string fallback taken when the root does not exist on disk (config-time
//!   validation before the volume is mounted): a non-existent root and generated
//!   absolute paths mixing `.`, `..` and repeated separators, asserting escapes
//!   are rejected and in-tree cleaned paths accepted;
//! - the filesystem branch taken when the root exists: a tempdir with planted
//!   symlinks, asserting the check fails closed on anything that resolves outside
//!   the real root.
//!
//! Case counts are bounded so the suites run inside the normal `cargo test` gate.

use nails_core::apply_exclusion_filter;
use nails_core::state::is_on_hidden_volume;
use proptest::prelude::*;
use std::path::{Path, PathBuf};

mod common;
use common::{components, fixture, join, resolve};

/// Cases per property: enough to mix every component kind while staying fast.
const CASES: u32 = 64;

/// Resolve `..`/`.`/repeated separators the way `is_on_hidden_volume`'s string
/// fallback does, so the oracle below predicts its answer exactly.
fn clean(path: &str) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(c) => out.push(c.to_owned()),
            std::path::Component::RootDir => out.clear(),
            _ => {}
        }
    }
    let mut cleaned = PathBuf::from("/");
    for c in out {
        cleaned.push(c);
    }
    cleaned
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// String-fallback branch: with a root that does not exist on disk, the
    /// decision is a cleaned string-prefix test. The predicate must accept a path
    /// exactly when its cleaned form stays under the cleaned root and reject it
    /// otherwise — in particular every `..` escape is rejected, however it is
    /// spelled.
    #[test]
    fn string_fallback_accepts_exactly_the_contained_paths(
        root_parts in prop::collection::vec(prop::sample::select(&["a", "b", "c"][..]), 1..4),
        tail in components(5),
        leaf in prop::sample::select(&["x", "y", "new"][..]),
    ) {
        // A root under a directory that cannot exist, so canonicalize() fails and
        // the string fallback is taken deterministically.
        let root = format!("/nails-nonexistent-{}", root_parts.join("/"));
        // Sprinkle repeated separators so the parser must collapse them too.
        let path = join(&root, &tail, leaf).replace("/a/", "/a//");

        let expected = clean(&path).starts_with(clean(&root));
        let got = is_on_hidden_volume(Path::new(&path), &root);
        prop_assert_eq!(
            got, expected,
            "is_on_hidden_volume({:?}, {:?}) = {}, expected {}", path, root, got, expected
        );
    }

    /// A relative path can never sit on an absolute, non-existent hidden root.
    #[test]
    fn string_fallback_rejects_relative_paths(tail in components(4)) {
        let root = "/nails-nonexistent-root";
        let relative = join("sub", &tail, "leaf");
        prop_assert!(!is_on_hidden_volume(Path::new(&relative), root));
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

    /// Filesystem branch, fail-closed side: when the nearest existing ancestor of
    /// the path is the `out` symlink (planted to point outside the volume), the
    /// check must reject it. The tail beneath `out` is plain names only: a `..`
    /// in it would textually cancel the symlink before the on-disk check sees it,
    /// which is the soft spot `SafeRoot`/openat2 closes at mount time, not this
    /// config-time helper.
    #[test]
    fn filesystem_branch_rejects_paths_under_an_escaping_symlink(
        tail in prop::collection::vec(prop::sample::select(&["a", "b", "new"][..]), 0..4),
    ) {
        let fx = fixture();
        let root = fx.vol().to_string_lossy().into_owned();
        // `out` is a symlink to a directory outside the volume; nothing exists
        // beneath it, so `out` is the nearest existing ancestor of any such path.
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// `apply_exclusion_filter` removes exactly the directories equal to an
    /// exclusion, keeps every other input, never invents a path, and returns a
    /// sorted list. (It matches whole paths, not prefixes, by design.)
    #[test]
    fn exclusion_filter_removes_exactly_the_excluded(
        dirs in prop::collection::vec(
            prop::sample::select(&["/etc", "/home", "/var", "/proc", "/sys", "/nix"][..]),
            0..8,
        ),
        exclude in prop::collection::vec(
            prop::sample::select(&["/proc", "/sys", "/var", "/missing"][..]),
            0..4,
        ),
    ) {
        let directories: Vec<PathBuf> = dirs.iter().map(PathBuf::from).collect();
        let exclusions: Vec<PathBuf> = exclude.iter().map(PathBuf::from).collect();

        let filtered = apply_exclusion_filter(directories.clone(), &exclusions);

        // No excluded directory survives.
        for ex in &exclusions {
            prop_assert!(!filtered.contains(ex), "excluded {} survived", ex.display());
        }
        // Every surviving entry was an input and was not excluded.
        for kept in &filtered {
            prop_assert!(directories.contains(kept), "{} was invented", kept.display());
            prop_assert!(!exclusions.contains(kept), "{} should be excluded", kept.display());
        }
        // Every non-excluded input survives.
        for dir in &directories {
            if !exclusions.contains(dir) {
                prop_assert!(filtered.contains(dir), "{} was dropped", dir.display());
            }
        }
        // The result is sorted.
        let mut sorted = filtered.clone();
        sorted.sort();
        prop_assert_eq!(filtered, sorted);
    }
}
