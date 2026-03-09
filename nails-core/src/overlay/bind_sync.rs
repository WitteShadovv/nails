//! Bind mount visibility for overlayfs via multiple lower layers
//!
//! overlayfs does **not** follow bind mounts in the lower layer. The kernel's
//! `clone_private_mount()` isolates the overlay from the VFS mount tree, so
//! any bind-mounted content within the lower directory is invisible.
//!
//! On NixOS impermanence systems this is a critical problem: `/etc` is on tmpfs
//! and `/etc/nixos` is bind-mounted from `/persist/etc/nixos/`. When overlayfs
//! mounts with `lowerdir=/etc`, it sees the empty tmpfs directory — files like
//! `flake.nix` and `configuration.nix` are invisible.
//!
//! This module computes extra lower layer directories from bind mount sources,
//! enabling overlayfs's native multiple lower layer support
//! (`lowerdir=/etc:/persist/etc`) to make bind-mounted content visible without
//! copying.

use std::path::{Path, PathBuf};

/// Compute extra lower layer directories from submount source paths.
///
/// For each `(mount_point, source_path)` pair under `target`, strips the
/// relative suffix to recover the "root" of the backing store. The result
/// is a deduplicated list of extra lower directories that should be appended
/// to the primary lower layer when constructing the overlayfs `lowerdir=`
/// option.
///
/// # Algorithm
///
/// Given `target = /etc` and `(mount_point = /etc/nixos, source = /persist/etc/nixos)`:
/// 1. Compute relative path: `nixos`
/// 2. Strip relative suffix from source: `/persist/etc/nixos` → `/persist/etc`
/// 3. That gives us the extra lower root: `/persist/etc`
///
/// # Arguments
///
/// * `target` - The overlay target directory (e.g., `/etc`)
/// * `submount_sources` - Pairs of `(mount_point, source_path)` for bind mounts within `target`
///
/// # Returns
///
/// Deduplicated `Vec<PathBuf>` of extra lower directories (order preserved).
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::bind_sync::compute_extra_lower_dirs;
/// use std::path::{Path, PathBuf};
///
/// let target = Path::new("/etc");
/// let sources = vec![
///     (PathBuf::from("/etc/nixos"), PathBuf::from("/persist/etc/nixos")),
/// ];
///
/// let extra = compute_extra_lower_dirs(target, &sources);
/// assert_eq!(extra, vec![PathBuf::from("/persist/etc")]);
/// ```
pub fn compute_extra_lower_dirs(
    target: &Path,
    submount_sources: &[(PathBuf, PathBuf)],
) -> Vec<PathBuf> {
    let mut seen = Vec::new();

    for (mount_point, source_path) in submount_sources {
        // Compute relative path from target to mount_point
        let relative = match mount_point.strip_prefix(target) {
            Ok(rel) => rel,
            Err(_) => {
                tracing::warn!(
                    mount_point = %mount_point.display(),
                    target = %target.display(),
                    "Submount is not under target, skipping"
                );
                continue;
            }
        };

        // Strip the relative suffix from the source to get the extra lower root.
        // e.g., source=/persist/etc/nixos, relative=nixos → root=/persist/etc
        let extra_lower = match source_path.strip_suffix_path(relative) {
            Some(root) => root,
            None => {
                tracing::warn!(
                    source = %source_path.display(),
                    relative = %relative.display(),
                    "Source path does not end with relative suffix, skipping"
                );
                continue;
            }
        };

        // Deduplicate — keep first occurrence, preserve order
        if !seen.contains(&extra_lower) {
            seen.push(extra_lower);
        }
    }

    seen
}

/// Extension trait to strip a suffix path from a `Path`.
///
/// `Path` has `strip_prefix` but no `strip_suffix` — this fills the gap.
trait StripSuffixPath {
    fn strip_suffix_path(&self, suffix: &Path) -> Option<PathBuf>;
}

impl StripSuffixPath for Path {
    fn strip_suffix_path(&self, suffix: &Path) -> Option<PathBuf> {
        let self_components: Vec<_> = self.components().collect();
        let suffix_components: Vec<_> = suffix.components().collect();

        if suffix_components.is_empty() {
            return Some(self.to_path_buf());
        }

        if suffix_components.len() > self_components.len() {
            return None;
        }

        // Check that the last N components of self match suffix
        let start = self_components.len() - suffix_components.len();
        for (a, b) in self_components[start..]
            .iter()
            .zip(suffix_components.iter())
        {
            if a != b {
                return None;
            }
        }

        // Build the prefix from the remaining components
        let prefix: PathBuf = self_components[..start].iter().collect();
        if prefix.as_os_str().is_empty() {
            // Would produce empty path — use root
            Some(PathBuf::from("/"))
        } else {
            Some(prefix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_submounts_returns_empty() {
        let result = compute_extra_lower_dirs(Path::new("/etc"), &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_submount_computes_extra_lower() {
        let sources = vec![(
            PathBuf::from("/etc/nixos"),
            PathBuf::from("/persist/etc/nixos"),
        )];
        let result = compute_extra_lower_dirs(Path::new("/etc"), &sources);
        assert_eq!(result, vec![PathBuf::from("/persist/etc")]);
    }

    #[test]
    fn test_multiple_submounts_same_root_deduplicates() {
        let sources = vec![
            (
                PathBuf::from("/etc/nixos"),
                PathBuf::from("/persist/etc/nixos"),
            ),
            (PathBuf::from("/etc/ssh"), PathBuf::from("/persist/etc/ssh")),
        ];
        let result = compute_extra_lower_dirs(Path::new("/etc"), &sources);
        // Both map to /persist/etc — should be deduplicated
        assert_eq!(result, vec![PathBuf::from("/persist/etc")]);
    }

    #[test]
    fn test_multiple_submounts_different_roots() {
        let sources = vec![
            (
                PathBuf::from("/etc/nixos"),
                PathBuf::from("/persist/etc/nixos"),
            ),
            (
                PathBuf::from("/etc/machine-id"),
                PathBuf::from("/nix/state/etc/machine-id"),
            ),
        ];
        let result = compute_extra_lower_dirs(Path::new("/etc"), &sources);
        assert_eq!(
            result,
            vec![
                PathBuf::from("/persist/etc"),
                PathBuf::from("/nix/state/etc"),
            ]
        );
    }

    #[test]
    fn test_nested_submount_path() {
        let sources = vec![(
            PathBuf::from("/etc/nixos/secrets"),
            PathBuf::from("/persist/etc/nixos/secrets"),
        )];
        let result = compute_extra_lower_dirs(Path::new("/etc"), &sources);
        assert_eq!(result, vec![PathBuf::from("/persist/etc")]);
    }

    #[test]
    fn test_submount_not_under_target_skipped() {
        let sources = vec![(
            PathBuf::from("/var/lib/something"),
            PathBuf::from("/persist/var/lib/something"),
        )];
        let result = compute_extra_lower_dirs(Path::new("/etc"), &sources);
        assert!(result.is_empty());
    }

    #[test]
    fn test_source_suffix_mismatch_skipped() {
        // Source doesn't end with the relative path — can't compute root
        let sources = vec![(
            PathBuf::from("/etc/nixos"),
            PathBuf::from("/persist/completely/different"),
        )];
        let result = compute_extra_lower_dirs(Path::new("/etc"), &sources);
        assert!(result.is_empty());
    }

    #[test]
    fn test_strip_suffix_path_basic() {
        let p = Path::new("/persist/etc/nixos");
        assert_eq!(
            p.strip_suffix_path(Path::new("nixos")),
            Some(PathBuf::from("/persist/etc"))
        );
    }

    #[test]
    fn test_strip_suffix_path_multi_component() {
        let p = Path::new("/persist/etc/nixos/secrets");
        assert_eq!(
            p.strip_suffix_path(Path::new("nixos/secrets")),
            Some(PathBuf::from("/persist/etc"))
        );
    }

    #[test]
    fn test_strip_suffix_path_no_match() {
        let p = Path::new("/persist/etc/nixos");
        assert_eq!(p.strip_suffix_path(Path::new("ssh")), None);
    }

    #[test]
    fn test_strip_suffix_path_empty_suffix() {
        let p = Path::new("/persist/etc");
        assert_eq!(
            p.strip_suffix_path(Path::new("")),
            Some(PathBuf::from("/persist/etc"))
        );
    }

    #[test]
    fn test_strip_suffix_path_suffix_longer_than_path() {
        let p = Path::new("/etc");
        assert_eq!(p.strip_suffix_path(Path::new("persist/etc/nixos")), None);
    }
}
