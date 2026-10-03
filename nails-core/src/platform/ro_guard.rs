//! The overlay policy as platform data, and the read-only guard that enforces
//! the decoy-stays-read-only invariant while a hidden session is active.
//!
//! Each [`Platform`](super::Platform) backend answers
//! [`overlay_policy`](super::Platform::overlay_policy) with an [`OverlayPolicy`]:
//! the pseudo-filesystems it never overlays, the base-OS trees it does not
//! overlay because they are kept read-only instead, and the trees it bind-remounts
//! read-only for the session. Keeping this as data (rather than scattered `if
//! nixos` branches) is what lets the mount loop, the pre-flight checks and the
//! read-only guard all agree on one description of the host.
//!
//! The invariant the guard enforces: while hidden is active, every writable OS
//! tree on the decoy is either overlaid (hidden writes land in the upper) or
//! bind-remounted read-only (hidden writes are refused). On a usr-merged FHS host
//! all software lives in `/usr`, so `/usr` plus the real-dir core binary roots are
//! kept read-only; the usr-merge symlinks (`/bin`, `/sbin`, `/lib*` pointing into
//! `/usr`) resolve into the already-guarded `/usr` and are not guarded twice.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::filesystem::Filesystem;

/// Which distro-specific hooks the overlay mount loop runs around the generic
/// overlay mounts.
///
/// This is the decision the old `OverlayPolicy` enum carried; it now rides on
/// [`OverlayPolicy::mount_hooks`] alongside the policy's path sets so a single
/// value describes the whole host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountHooks {
    /// Overlay directories plus the NixOS-specific `/nix`, `/var` and `/etc`
    /// handling (pivot/bind mounts, service stop/start around `/nix`).
    NixOs,
    /// Overlay directories with no distro-specific mount hooks.
    Fhs,
    /// No overlays: the host is refused.
    None,
}

/// The pseudo-filesystems no platform ever overlays or writes to.
///
/// The hidden-root mount is also never overlaid, but its path is only known at
/// runtime, so callers append it to [`OverlayPolicy::never_overlay`] from the
/// config (see [`OverlayPolicy::is_never_overlay`]).
const UNIVERSAL_NEVER_OVERLAY: &[&str] = &["/proc", "/sys", "/dev", "/run"];

/// Core binary roots an FHS host keeps out of overlay enumeration because they
/// are kept read-only.
///
/// `/usr` always resolves to a real directory; the rest are usr-merge symlinks
/// into `/usr` on a merged host (Debian 12+, Ubuntu) and real directories on a
/// non-merged one (where each must be guarded on its own). The resolver in
/// [`OverlayPolicy::resolve_read_only`] keeps only the ones that are real
/// directories, so the merged symlinks are not guarded a second time.
const FHS_CORE_ROOTS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

/// Top-level trees an FHS host keeps out of overlay enumeration beyond the core
/// binary roots.
///
/// These are never overlaid wholesale: `/snap` holds the per-revision squashfs
/// mounts of installed snaps (Ubuntu), `/.snapshots` the snapper/btrfs snapshot
/// roots, and `/sysroot`, `/ostree` and `/efi` the ostree and boot/ESP
/// infrastructure. Overlaying any of them is either meaningless (an ESP is vfat,
/// a snapshot tree is immutable) or actively breaks the host (an overlay on
/// `/snap` hides the squashfs submounts so snaps stop launching). The live
/// submounts nested beneath `/snap` are kept visible by re-attaching them over
/// the parent overlay instead (see the submount re-attach step), not by
/// overlaying the root.
const FHS_EXTRA_EXCLUSIONS: &[&str] = &["/snap", "/.snapshots", "/sysroot", "/ostree", "/efi"];

/// The whole decoy root. Bind-remounted read-only on an FHS host so a write that
/// is not caught by an overlay (a new top-level directory, a package payload
/// under `/usr`) is refused with `EROFS` instead of reaching the decoy disk.
const DECOY_ROOT: &str = "/";

/// The overlay policy for a platform, expressed as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPolicy {
    /// Which mount hooks the overlay loop runs for this host.
    pub mount_hooks: MountHooks,
    /// Top-level entries never overlaid and never written while hidden: the
    /// pseudo-filesystems (and, appended by the caller, the hidden-root mount).
    pub never_overlay: Vec<PathBuf>,
    /// Base-OS trees this platform does not overlay because they are kept
    /// read-only (or are immutable), so they must be excluded from auto overlay
    /// enumeration.
    pub default_exclusions: Vec<PathBuf>,
    /// Trees kept read-only for the session by a bind-remount. These are
    /// candidates: [`resolve_read_only`](Self::resolve_read_only) drops the ones
    /// that are usr-merge symlinks so the real tree is guarded exactly once.
    pub read_only: Vec<PathBuf>,
}

impl OverlayPolicy {
    fn universal_never_overlay() -> Vec<PathBuf> {
        UNIVERSAL_NEVER_OVERLAY.iter().map(PathBuf::from).collect()
    }

    /// The NixOS policy.
    ///
    /// `/bin` and `/usr` are overlaid (not excluded) so the hidden
    /// `switch-to-configuration` rewrites of `/bin/sh` and `/usr/bin/env` land in
    /// the overlay upper on the hidden volume instead of the decoy root. `/nix`,
    /// `/var` and `/etc` keep their first-class handling via
    /// [`MountHooks::NixOs`]. There is no read-only guard: protection comes from
    /// the overlays.
    pub fn nixos() -> Self {
        Self {
            mount_hooks: MountHooks::NixOs,
            never_overlay: Self::universal_never_overlay(),
            // NixOS has no /lib, /lib64 or /sbin at the root; listing them is a
            // harmless guard against a host that does.
            default_exclusions: ["/lib", "/lib64", "/sbin"]
                .iter()
                .map(PathBuf::from)
                .collect(),
            read_only: Vec::new(),
        }
    }

    /// The FHS policy (Debian/Ubuntu first, other FHS families provisionally).
    ///
    /// The base OS lives under `/usr` on every FHS host, so `/usr` and the core
    /// binary roots are excluded from overlay and kept read-only instead. The
    /// usr-merge difference between Debian/Ubuntu (symlinks) and a non-merged host
    /// (real directories) is handled by [`resolve_read_only`](Self::resolve_read_only)
    /// rather than a distro flag, so this one constructor serves them all.
    pub fn fhs() -> Self {
        // The whole decoy root is kept read-only; the core binary roots are kept
        // read-only on their own too, in case any is a separate mount the root
        // remount would not cover.
        let mut read_only = vec![PathBuf::from(DECOY_ROOT)];
        read_only.extend(FHS_CORE_ROOTS.iter().map(PathBuf::from));
        Self {
            mount_hooks: MountHooks::Fhs,
            never_overlay: Self::universal_never_overlay(),
            default_exclusions: FHS_CORE_ROOTS
                .iter()
                .chain(FHS_EXTRA_EXCLUSIONS.iter())
                .map(PathBuf::from)
                .collect(),
            read_only,
        }
    }

    /// The policy for a refused host: nothing is overlaid or guarded.
    pub fn none() -> Self {
        Self {
            mount_hooks: MountHooks::None,
            never_overlay: Self::universal_never_overlay(),
            default_exclusions: Vec::new(),
            read_only: Vec::new(),
        }
    }

    /// Whether `path` is a top-level entry this policy never overlays.
    ///
    /// Covers the policy's own [`never_overlay`](Self::never_overlay) set plus
    /// `hidden_root` (and the top-level directory that contains it), which is
    /// never known statically.
    pub fn is_never_overlay(&self, path: &Path, hidden_root: &Path) -> bool {
        if self.never_overlay.iter().any(|p| p == path) {
            return true;
        }
        if path == hidden_root {
            return true;
        }
        // The top-level directory the hidden root lives under must not be
        // overlaid either, or the overlay would hide the hidden volume.
        hidden_root_top_level(hidden_root).as_deref() == Some(path)
    }

    /// Every top-level entry that must be kept out of auto overlay enumeration:
    /// the never-overlay set, the base-OS exclusions and the read-only trees
    /// (overlaying a tree that is kept read-only would be contradictory).
    pub fn overlay_exclusions(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = self
            .never_overlay
            .iter()
            .chain(self.default_exclusions.iter())
            .chain(self.read_only.iter())
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Resolve the read-only candidates against the live filesystem, keeping only
    /// the trees that are real directories.
    ///
    /// A candidate that is a symbolic link (a usr-merge `/bin` → `/usr/bin`) is
    /// dropped: its target lives under `/usr`, which is guarded on its own, so
    /// guarding the link would bind-remount the `/usr` tree a second time. A
    /// candidate that does not exist is dropped too. The result is sorted and
    /// de-duplicated.
    pub fn resolve_read_only<F: Filesystem>(&self, fs: &F) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for candidate in &self.read_only {
            // A usr-merge symlink resolves into an already-guarded tree.
            if fs.is_symlink(candidate)? {
                continue;
            }
            if fs.is_directory(candidate)? {
                out.push(candidate.clone());
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// Bind-remount every tree in `trees` read-only, failing closed.
///
/// Applies [`Filesystem::remount_read_only`] to each tree in order and returns
/// the paths actually guarded. If any remount fails — most importantly with
/// `EBUSY`, when a tree has active references — every guard made so far is undone
/// (best-effort, via [`Filesystem::unmount_bind`]) and the original error is
/// returned, so a partial guard never leaves the host inconsistent. The caller
/// aborts and rolls the activation back on an error.
pub fn guard_read_only_trees<F: Filesystem>(fs: &F, trees: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut guarded: Vec<PathBuf> = Vec::new();
    for tree in trees {
        match fs.remount_read_only(tree) {
            Ok(()) => {
                tracing::info!(tree = %tree.display(), "Kept decoy OS tree read-only for the session");
                guarded.push(tree.clone());
            }
            Err(error) => {
                tracing::error!(
                    tree = %tree.display(),
                    error = %error,
                    rollback = true,
                    "Failed to keep decoy OS tree read-only; rolling back the read-only guard"
                );
                for done in guarded.iter().rev() {
                    if let Err(undo_error) = fs.unmount_bind(done) {
                        tracing::warn!(
                            tree = %done.display(),
                            error = %undo_error,
                            "Best-effort rollback of a read-only guard failed"
                        );
                    }
                }
                return Err(error);
            }
        }
    }
    Ok(guarded)
}

/// The top-level directory that contains `hidden_root`, if it has one distinct
/// from the root itself (`/mnt/hidden` → `/mnt`). Returns `None` for an empty or
/// bare-root path.
fn hidden_root_top_level(hidden_root: &Path) -> Option<PathBuf> {
    let mut components = hidden_root
        .components()
        .filter(|component| !matches!(component, std::path::Component::RootDir));
    let first = components.next()?;
    Some(Path::new("/").join(first.as_os_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    #[test]
    fn nixos_policy_overlays_bin_and_usr_and_guards_nothing() {
        let policy = OverlayPolicy::nixos();
        assert_eq!(policy.mount_hooks, MountHooks::NixOs);
        assert!(policy.read_only.is_empty());
        // /bin and /usr must not be excluded: they are overlaid so the hidden
        // switch's /bin/sh and /usr/bin/env rewrites stay off the decoy root.
        assert!(!policy.default_exclusions.contains(&PathBuf::from("/bin")));
        assert!(!policy.default_exclusions.contains(&PathBuf::from("/usr")));
        for pseudo in ["/proc", "/sys", "/dev", "/run"] {
            assert!(policy.never_overlay.contains(&PathBuf::from(pseudo)));
        }
    }

    #[test]
    fn fhs_policy_keeps_usr_and_core_roots_read_only() {
        let policy = OverlayPolicy::fhs();
        assert_eq!(policy.mount_hooks, MountHooks::Fhs);
        for tree in ["/usr", "/bin", "/sbin", "/lib", "/lib64"] {
            assert!(policy.read_only.contains(&PathBuf::from(tree)), "{tree}");
            assert!(
                policy.default_exclusions.contains(&PathBuf::from(tree)),
                "a read-only tree must also be excluded from overlay: {tree}"
            );
        }
    }

    #[test]
    fn fhs_excludes_snap_snapshot_and_boot_roots() {
        // Snap squashfs roots, snapshot roots and the ostree/boot infrastructure
        // are excluded from overlay enumeration on an FHS host.
        let policy = OverlayPolicy::fhs();
        for tree in ["/snap", "/.snapshots", "/sysroot", "/ostree", "/efi"] {
            assert!(
                policy.default_exclusions.contains(&PathBuf::from(tree)),
                "FHS default exclusions must contain {tree}"
            );
            assert!(
                policy.overlay_exclusions().contains(&PathBuf::from(tree)),
                "FHS overlay exclusions must contain {tree}"
            );
        }
        // These are enumeration exclusions, not read-only guards: overlaying them
        // is wrong, but they are not bind-remounted read-only like /usr.
        for tree in ["/snap", "/.snapshots", "/sysroot", "/ostree", "/efi"] {
            assert!(
                !policy.read_only.contains(&PathBuf::from(tree)),
                "{tree} must not be a read-only guard target"
            );
        }
    }

    #[test]
    fn nixos_does_not_exclude_snap_or_snapshot_roots() {
        // The snap/snapshot/ostree exclusions are FHS data and must not leak into
        // the NixOS policy.
        let policy = OverlayPolicy::nixos();
        for tree in ["/snap", "/.snapshots", "/sysroot", "/ostree", "/efi"] {
            assert!(
                !policy.default_exclusions.contains(&PathBuf::from(tree)),
                "NixOS default exclusions must not contain {tree}"
            );
        }
    }

    #[test]
    fn universal_never_overlay_is_present_and_downloads_absent() {
        for policy in [
            OverlayPolicy::nixos(),
            OverlayPolicy::fhs(),
            OverlayPolicy::none(),
        ] {
            for pseudo in ["/proc", "/sys", "/dev", "/run"] {
                assert!(policy.never_overlay.contains(&PathBuf::from(pseudo)));
            }
            assert!(!policy.never_overlay.contains(&PathBuf::from("/Downloads")));
            assert!(
                !policy
                    .default_exclusions
                    .contains(&PathBuf::from("/Downloads"))
            );
        }
    }

    #[test]
    fn hidden_root_mount_is_never_overlaid() {
        let policy = OverlayPolicy::fhs();
        let hidden = Path::new("/mnt/hidden");
        assert!(policy.is_never_overlay(Path::new("/mnt/hidden"), hidden));
        // The top-level directory the hidden volume lives under is protected too.
        assert!(policy.is_never_overlay(Path::new("/mnt"), hidden));
        assert!(!policy.is_never_overlay(Path::new("/home"), hidden));
    }

    #[test]
    fn resolve_read_only_drops_usrmerge_symlinks_on_debian() {
        // Debian/Ubuntu: /bin, /sbin, /lib, /lib64 are symlinks into /usr. Only
        // the whole root and /usr are guarded.
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/", PathKind::Dir);
        fs.mock_set_path_type("/usr", PathKind::Dir);
        for link in ["/bin", "/sbin", "/lib", "/lib64"] {
            fs.mock_set_path_type(link, PathKind::Symlink);
        }

        let resolved = OverlayPolicy::fhs().resolve_read_only(&fs).unwrap();
        assert_eq!(resolved, vec![PathBuf::from("/"), PathBuf::from("/usr")]);
    }

    #[test]
    fn resolve_read_only_keeps_real_core_roots_on_non_merged_fhs() {
        // A non-usr-merged FHS host: /bin and /sbin are real directories.
        let fs = MockFilesystem::new();
        for dir in ["/", "/usr", "/bin", "/sbin"] {
            fs.mock_set_path_type(dir, PathKind::Dir);
        }
        // /lib, /lib64 absent on this host.

        let resolved = OverlayPolicy::fhs().resolve_read_only(&fs).unwrap();
        assert_eq!(
            resolved,
            vec![
                PathBuf::from("/"),
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
                PathBuf::from("/usr"),
            ]
        );
    }

    #[test]
    fn nixos_resolve_read_only_is_empty() {
        let fs = MockFilesystem::new();
        assert!(
            OverlayPolicy::nixos()
                .resolve_read_only(&fs)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn overlay_exclusions_cover_never_overlay_and_read_only() {
        let policy = OverlayPolicy::fhs();
        let exclusions = policy.overlay_exclusions();
        for expected in ["/proc", "/sys", "/dev", "/run", "/usr", "/bin"] {
            assert!(
                exclusions.contains(&PathBuf::from(expected)),
                "missing {expected} from {exclusions:?}"
            );
        }
    }

    #[test]
    fn guard_read_only_trees_guards_each_tree() {
        let fs = MockFilesystem::new();
        let trees = vec![PathBuf::from("/usr"), PathBuf::from("/bin")];

        let guarded = guard_read_only_trees(&fs, &trees).unwrap();
        assert_eq!(guarded, trees);
        assert!(fs.mock_is_read_only_guarded(Path::new("/usr")));
        assert!(fs.mock_is_read_only_guarded(Path::new("/bin")));
    }

    #[test]
    fn guard_read_only_trees_rolls_back_on_ebusy() {
        let fs = MockFilesystem::new();
        // The second tree is busy: its read-only remount returns EBUSY, so the
        // first tree's guard must be undone and the error surfaced.
        fs.mock_set_mount_fail_errno("/bin", nix::errno::Errno::EBUSY);
        let trees = vec![PathBuf::from("/usr"), PathBuf::from("/bin")];

        let error = guard_read_only_trees(&fs, &trees).expect_err("EBUSY must fail closed");
        assert!(matches!(error, crate::NailsError::MountBusy { .. }));
        assert!(
            !fs.mock_is_read_only_guarded(Path::new("/usr")),
            "the first guard must be rolled back when a later one fails"
        );
        assert!(!fs.mock_is_read_only_guarded(Path::new("/bin")));
    }
}
