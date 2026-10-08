// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A bounded, read-only walk of a mounted decoy tree.
//!
//! Directories are listed with `O_NOATIME` and entries are typed with `lstat`,
//! so the walk leaves every access time as it found it. It never follows a
//! symlink, stays on the filesystem it started on, and stops at an entry
//! budget so a huge tree cannot make an audit unbounded.

use crate::filesystem::real::{EntryType, read_dir_noatime};
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Limits for a walk.
#[derive(Debug, Clone, Copy)]
pub struct WalkLimits {
    /// Stop after visiting this many entries.
    pub max_entries: usize,
    /// Do not descend deeper than this below the start.
    pub max_depth: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_entries: 500_000,
            max_depth: 32,
        }
    }
}

/// What a walk covered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkSummary {
    /// Entries visited.
    pub entries: usize,
    /// Whether the entry budget stopped the walk early.
    pub truncated: bool,
    /// Directories that could not be listed.
    pub unreadable: Vec<PathBuf>,
}

/// Walk `root`, calling `visit` for every regular file with its `lstat`
/// metadata. Directories named in `skip` (relative to `root`) are not entered.
pub fn walk_files(
    root: &Path,
    skip: &[&str],
    limits: WalkLimits,
    mut visit: impl FnMut(&Path, &Metadata),
) -> WalkSummary {
    let mut summary = WalkSummary::default();
    let Ok(root_meta) = std::fs::symlink_metadata(root) else {
        summary.unreadable.push(root.to_path_buf());
        return summary;
    };
    let device = root_meta.dev();
    let skipped: Vec<PathBuf> = skip.iter().map(|rel| root.join(rel)).collect();
    let mut stack = vec![(root.to_path_buf(), 0usize)];

    while let Some((dir, depth)) = stack.pop() {
        let entries = match read_dir_noatime(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                summary.unreadable.push(dir);
                continue;
            }
        };
        for entry in entries {
            if summary.entries >= limits.max_entries {
                summary.truncated = true;
                return summary;
            }
            summary.entries += 1;
            let path = dir.join(&entry.name);
            let Ok(kind) = entry.resolved_type(&dir) else {
                continue;
            };
            match kind {
                EntryType::Directory => {
                    if depth < limits.max_depth
                        && !skipped.contains(&path)
                        && std::fs::symlink_metadata(&path).is_ok_and(|m| m.dev() == device)
                    {
                        stack.push((path, depth + 1));
                    }
                }
                EntryType::File => {
                    if let Ok(meta) = std::fs::symlink_metadata(&path) {
                        visit(&path, &meta);
                    }
                }
                EntryType::Symlink | EntryType::Other => {}
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visits_regular_files_and_skips_listed_directories() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a/b")).unwrap();
        std::fs::create_dir_all(root.path().join("proc/1")).unwrap();
        std::fs::write(root.path().join("a/b/file"), b"x").unwrap();
        std::fs::write(root.path().join("proc/1/status"), b"x").unwrap();
        std::os::unix::fs::symlink("a/b/file", root.path().join("link")).unwrap();

        let mut seen = Vec::new();
        let summary = walk_files(root.path(), &["proc"], WalkLimits::default(), |path, _| {
            seen.push(path.strip_prefix(root.path()).unwrap().to_path_buf());
        });

        assert_eq!(seen, vec![PathBuf::from("a/b/file")]);
        assert!(!summary.truncated);
    }

    #[test]
    fn the_entry_budget_truncates() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..20 {
            std::fs::write(root.path().join(format!("f{i}")), b"x").unwrap();
        }
        let mut count = 0;
        let summary = walk_files(
            root.path(),
            &[],
            WalkLimits {
                max_entries: 5,
                max_depth: 4,
            },
            |_, _| count += 1,
        );
        assert!(summary.truncated);
        assert_eq!(count, 5);
    }
}
