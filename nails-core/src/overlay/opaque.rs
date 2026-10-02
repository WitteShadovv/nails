//! Overlayfs opaque-marker handling for NAILS-managed paths.
//!
//! When a directory is deleted and recreated through an active overlayfs mount,
//! the kernel sets `trusted.overlay.opaque=y` on the upper-layer directory.
//! This makes the upper directory completely **replace** (instead of merge
//! with) the lower-layer directory, hiding every lower-layer entry.
//!
//! That marker is only a problem on the one directory NAILS populates itself:
//! `/etc/nixos`. NAILS writes `hardware-configuration.nix` into the upper there,
//! and an opaque marker on it would hide the decoy's `flake.nix` from the lower
//! layer, breaking `nixos-rebuild`. Clearing the marker restores the merged
//! view.
//!
//! Everything else is deliberately left alone. If the hidden user runs
//! `rm -rf ~/dir && mkdir ~/dir`, the kernel sets the opaque marker on that
//! user upper on purpose, and clearing it would resurface the decoy's data.
//! `/nix` is likewise never touched. So the handling here is scoped to an
//! explicit allow-list of managed directories rather than walking whole uppers.
//!
//! The marker is read and cleared with `rustix`'s `l*xattr` calls, which issue
//! the syscalls directly (no dependency on the external `attr` package) and do
//! not follow symlinks in the final path component.

use std::io;
use std::path::{Path, PathBuf};

/// The overlayfs opaque marker set by the kernel on a replaced upper directory.
pub const OPAQUE_XATTR: &str = "trusted.overlay.opaque";

/// NAILS-managed directories inside `upper` whose opaque marker may be cleared.
///
/// Only `/etc/nixos` qualifies: it is the single path NAILS writes into, so a
/// stale marker there hides the lower `flake.nix`. User-data uppers and `/nix`
/// return nothing, so their intended whiteouts are preserved.
fn managed_opaque_dirs(upper: &Path, target: &Path) -> Vec<PathBuf> {
    if target == Path::new("/etc") {
        vec![upper.join("nixos")]
    } else {
        Vec::new()
    }
}

/// Whether `dir` carries extended attribute `name` (no symlink following).
///
/// A missing attribute (`ENODATA`), an unsupported filesystem (`ENOTSUP`) and a
/// missing directory (`ENOENT`) all count as "not present". Any other error is
/// also reported as "not present" so that this read-only probe never panics; the
/// write path logs real failures separately.
fn has_opaque(dir: &Path, name: &str) -> bool {
    // A zero-length buffer turns lgetxattr into a presence/length query.
    let mut probe: [u8; 0] = [];
    rustix::fs::lgetxattr(dir, name, &mut probe[..]).is_ok()
}

/// Remove extended attribute `name` from `dir` (no symlink following).
///
/// Returns `Ok(true)` when a marker was removed, `Ok(false)` when there was
/// nothing to remove (`ENODATA`), the filesystem does not support xattrs
/// (`ENOTSUP`) or the directory is absent (`ENOENT`), and `Err` for any real
/// failure (for example `EPERM` when not privileged for `trusted.*`).
fn strip_opaque(dir: &Path, name: &str) -> io::Result<bool> {
    use rustix::io::Errno;
    match rustix::fs::lremovexattr(dir, name) {
        Ok(()) => Ok(true),
        Err(Errno::NODATA | Errno::NOTSUP | Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Clear the opaque marker from every NAILS-managed directory under `upper`.
///
/// This is the single place NAILS strips opaque markers and is run once, in the
/// mount step. Returns the number of markers removed. Real failures are logged
/// as warnings that name the path and otherwise ignored, so a single bad
/// directory cannot abort activation.
pub fn strip_managed_opaque(upper: &Path, target: &Path) -> usize {
    strip_managed_opaque_named(upper, target, OPAQUE_XATTR)
}

pub(crate) fn strip_managed_opaque_named(upper: &Path, target: &Path, name: &str) -> usize {
    let mut removed = 0;
    for dir in managed_opaque_dirs(upper, target) {
        match strip_opaque(&dir, name) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    path = %dir.display(),
                    error = %e,
                    "Could not clear overlay opaque marker on {}: {}",
                    dir.display(),
                    e
                );
            }
        }
    }
    removed
}

/// Report NAILS-managed directories under `upper` that currently carry the
/// opaque marker.
///
/// Read-only: it performs no writes, so it is safe to call from preflight and
/// `--dry-run` without changing the hidden volume.
pub fn report_managed_opaque(upper: &Path, target: &Path) -> Vec<PathBuf> {
    report_managed_opaque_named(upper, target, OPAQUE_XATTR)
}

pub(crate) fn report_managed_opaque_named(upper: &Path, target: &Path, name: &str) -> Vec<PathBuf> {
    managed_opaque_dirs(upper, target)
        .into_iter()
        .filter(|dir| has_opaque(dir, name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::XattrFlags;
    use std::fs;

    /// A `user.*` xattr name so unit tests can exercise the real syscalls
    /// without the root privilege that `trusted.*` requires. The production
    /// marker (`trusted.overlay.opaque`) is covered by the root VM E2E tests.
    const TEST_XATTR: &str = "user.nails.test.opaque";

    /// Set a marker on `dir`, returning false if the temp filesystem rejects
    /// `user.*` xattrs (some tmpfs configurations do), so callers can self-skip.
    fn try_set_marker(dir: &Path) -> bool {
        rustix::fs::lsetxattr(dir, TEST_XATTR, b"y", XattrFlags::empty()).is_ok()
    }

    #[test]
    fn managed_dirs_only_cover_etc_nixos() {
        let upper = PathBuf::from("/mnt/hidden/etc");
        assert_eq!(
            managed_opaque_dirs(&upper, Path::new("/etc")),
            vec![upper.join("nixos")]
        );
    }

    #[test]
    fn managed_dirs_never_touch_user_or_nix_uppers() {
        for target in ["/home", "/nix", "/var", "/root"] {
            let upper = PathBuf::from("/mnt/hidden").join(target.trim_start_matches('/'));
            assert!(
                managed_opaque_dirs(&upper, Path::new(target)).is_empty(),
                "{target} must not be a managed opaque path"
            );
        }
    }

    #[test]
    fn managed_dirs_never_touch_persona_home_upper() {
        // The fresh persona home is a plain bind, never an overlay upper, and its
        // target is the operator's home, never /etc; opaque stripping must never
        // reach into it.
        let upper = PathBuf::from("/mnt/data/persona/home");
        assert!(
            managed_opaque_dirs(&upper, Path::new("/home/op")).is_empty(),
            "persona home must never be a managed opaque path"
        );
    }

    #[test]
    fn report_is_empty_for_missing_path() {
        let report = report_managed_opaque(
            Path::new("/nonexistent/path/that/does/not/exist/etc"),
            Path::new("/etc"),
        );
        assert!(report.is_empty());
    }

    #[test]
    fn strip_is_zero_for_missing_path() {
        let count = strip_managed_opaque(
            Path::new("/nonexistent/path/that/does/not/exist/etc"),
            Path::new("/etc"),
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn report_is_empty_for_marker_free_tree() {
        let temp = tempfile::tempdir().unwrap();
        let upper = temp.path().join("etc");
        fs::create_dir_all(upper.join("nixos")).unwrap();

        assert!(report_managed_opaque(&upper, Path::new("/etc")).is_empty());
    }

    #[test]
    fn strip_is_zero_for_marker_free_tree() {
        let temp = tempfile::tempdir().unwrap();
        let upper = temp.path().join("etc");
        fs::create_dir_all(upper.join("nixos")).unwrap();

        assert_eq!(strip_managed_opaque(&upper, Path::new("/etc")), 0);
    }

    #[test]
    fn report_and_strip_round_trip_on_managed_dir() {
        let temp = tempfile::tempdir().unwrap();
        let upper = temp.path().join("etc");
        let managed = upper.join("nixos");
        fs::create_dir_all(&managed).unwrap();

        if !try_set_marker(&managed) {
            // tmpfs without user-xattr support: the real round-trip is proven
            // by the root VM E2E test instead.
            return;
        }

        // The marker is seen by the read-only report.
        assert_eq!(
            report_managed_opaque_named(&upper, Path::new("/etc"), TEST_XATTR),
            vec![managed.clone()]
        );

        // Stripping removes it and reports one removal.
        assert_eq!(
            strip_managed_opaque_named(&upper, Path::new("/etc"), TEST_XATTR),
            1
        );

        // A second strip is a no-op and the report is now empty.
        assert_eq!(
            strip_managed_opaque_named(&upper, Path::new("/etc"), TEST_XATTR),
            0
        );
        assert!(report_managed_opaque_named(&upper, Path::new("/etc"), TEST_XATTR).is_empty());
    }

    #[test]
    fn marker_on_unmanaged_dir_is_left_alone() {
        let temp = tempfile::tempdir().unwrap();
        // An opaque marker on a user upper (here /home) must never be reported
        // or stripped, so a hidden-session whiteout survives.
        let upper = temp.path().join("home");
        fs::create_dir_all(&upper).unwrap();

        if !try_set_marker(&upper) {
            return;
        }

        assert!(report_managed_opaque_named(&upper, Path::new("/home"), TEST_XATTR).is_empty());
        assert_eq!(
            strip_managed_opaque_named(&upper, Path::new("/home"), TEST_XATTR),
            0
        );
        // The marker is still there.
        assert!(has_opaque(&upper, TEST_XATTR));
    }
}
