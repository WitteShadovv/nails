// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared adversarial path generators for the containment property tests.
//!
//! Both the configured-path containment suite (`path_properties.rs`) and the
//! `SafeRoot` containment suite (`safe_path_properties.rs`) build paths out of
//! the same component alphabet — plain names, `.`, `..` and in-tree symlinks that
//! point at themselves, their parent, outside the volume, or in a loop — created
//! in a tempdir. Keeping one generator module means the two suites exercise the
//! same planted-symlink and traversal inputs rather than drifting apart.

// Each integration test crate compiles this module independently and uses a
// different subset of it, so unused items here are expected.
#![allow(dead_code)]

use proptest::prelude::*;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Components a generated path is made of. `a`, `b` are real directories and
/// `new` does not exist; the others are traversal segments or symlinks that the
/// fixture creates in every real directory: `in` points at its own directory,
/// `up` at its parent, `out` at a directory outside the volume and `loop` at
/// itself.
pub const COMPONENTS: &[&str] = &["a", "b", "new", ".", "..", "in", "up", "out", "loop"];

/// Components that can never leave the directory they start from.
pub const PLAIN: &[&str] = &["a", "b", "new"];

/// Symlink components the fixture plants in every real directory of the volume.
pub const SYMLINKS: &[&str] = &["in", "up", "out", "loop"];

pub struct Fixture {
    _dir: TempDir,
    pub base: PathBuf,
    pub outside: PathBuf,
}

impl Fixture {
    /// The hidden-volume root inside the fixture.
    pub fn vol(&self) -> PathBuf {
        self.base.join("vol")
    }
}

/// `base/vol/a/b` with the symlinks of [`COMPONENTS`] in each directory and
/// `base/outside` next to the volume.
pub fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    // Resolve the tempdir itself so only links created here are symlinks.
    let base = dir.path().canonicalize().unwrap();
    let outside = base.join("outside");
    let vol = base.join("vol");
    std::fs::create_dir_all(vol.join("a/b")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    for parent in [vol.clone(), vol.join("a"), vol.join("a/b")] {
        symlink(".", parent.join("in")).unwrap();
        symlink("..", parent.join("up")).unwrap();
        symlink(&outside, parent.join("out")).unwrap();
        symlink("loop", parent.join("loop")).unwrap();
    }
    Fixture {
        _dir: dir,
        base,
        outside,
    }
}

/// `start` followed by `components` and `leaf`, joined as text so `.` and `..`
/// survive exactly as written.
pub fn join(start: &str, components: &[&str], leaf: &str) -> String {
    let mut path = start.to_string();
    for component in components.iter().chain(std::iter::once(&leaf)) {
        if !component.is_empty() {
            path.push('/');
            path.push_str(component);
        }
    }
    path
}

/// Where `path` really points: the longest existing ancestor with every symlink
/// resolved, followed by the part that does not exist yet.
pub fn resolve(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(real) = ancestor.canonicalize() {
            let rest = path.strip_prefix(ancestor).unwrap();
            return real.join(rest);
        }
    }
    path.to_path_buf()
}

/// A strategy over up to `max` components drawn from [`COMPONENTS`].
pub fn components(max: usize) -> impl Strategy<Value = Vec<&'static str>> {
    prop::collection::vec(prop::sample::select(COMPONENTS), 0..=max)
}

/// Whether every component can never leave its starting directory.
pub fn is_plain(components: &[&str]) -> bool {
    components.iter().all(|c| PLAIN.contains(c))
}
