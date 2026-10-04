// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Submount detection and classification for overlayfs targets.
//!
//! When NAILS overlays a target (`/var`, `/home`, `/snap`, …) any filesystem the
//! host had already mounted *under* that target is shadowed by the overlay and
//! vanishes from the merged view. That is the right behaviour for a plain bind of
//! a real path — its content is folded back in as an extra lower layer — but it
//! silently breaks three other cases: a snap's per-revision squashfs under
//! `/snap`, a separate `/var/log` or `/boot/efi` partition, and a RAM/virtual
//! mount (tmpfs) nested in the tree. Each would otherwise become an empty
//! directory.
//!
//! [`classify_submounts`] walks `/proc/self/mountinfo` and sorts every submount
//! strictly under the target into one of three plans (see [`Submount`]). The
//! parent-overlay mount loop enacts them after the overlay is in place:
//! extra-lower binds fold into the lower stack, read-only and virtual mounts are
//! re-attached over the overlay, and a writable decoy-backed partition gets its
//! own nested overlay so its writes stay off the decoy disk.

use crate::filesystem::mountinfo::parse_mountinfo;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// How a single submount nested under an overlay target must be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submount {
    /// A bind mount whose backing content resolves to a real path on a mounted
    /// filesystem. Its source is added as an extra lower layer so overlayfs keeps
    /// the content visible while the overlay's own upper captures writes (for
    /// example `/etc/nixos` bound from `/persist/etc/nixos`).
    ExtraLower {
        mount_point: PathBuf,
        source: PathBuf,
    },
    /// A mount re-attached in place over the parent overlay so its path keeps
    /// resolving. Used for a snap squashfs, any other read-only mount, and
    /// RAM/virtual mounts (tmpfs): the live mount is recursively bound back on top
    /// of the overlay. `read_only` records whether the re-attach must also be
    /// remounted read-only — always true for a squashfs or an already-read-only
    /// mount, false for a writable tmpfs whose writes are RAM-backed and never
    /// reach the decoy disk.
    Reattach {
        mount_point: PathBuf,
        fstype: String,
        read_only: bool,
    },
    /// A writable, decoy-disk-backed partition nested under the target (a separate
    /// `/var/log` or `/boot` partition). It is given its own overlay with the
    /// upper/work directories under the hidden root, so session writes land hidden
    /// and the decoy partition is never written.
    NestedOverlay {
        mount_point: PathBuf,
        fstype: String,
    },
}

impl Submount {
    /// The path the submount appears at (and is re-attached or nested onto).
    pub fn mount_point(&self) -> &Path {
        match self {
            Submount::ExtraLower { mount_point, .. }
            | Submount::Reattach { mount_point, .. }
            | Submount::NestedOverlay { mount_point, .. } => mount_point,
        }
    }

    /// The filesystem type, when known (not tracked for an extra-lower bind).
    pub fn fstype(&self) -> Option<&str> {
        match self {
            Submount::ExtraLower { .. } => None,
            Submount::Reattach { fstype, .. } | Submount::NestedOverlay { fstype, .. } => {
                Some(fstype.as_str())
            }
        }
    }
}

/// Classify every mount strictly under `target` into a [`Submount`] plan.
///
/// Uses a two-pass scan of mountinfo:
/// - **Pass 1** maps each `dev_id` to the shortest mount point of its `fs_root ==
///   "/"` entry, so a device-backed bind can be resolved to a real source path,
///   and records the target's own device so a submount whose backing root equals
///   the target's is dropped (it is already visible through the target, and
///   re-attaching it would loop).
/// - **Pass 2** classifies each submount:
///   - a real-path bind, or a device-backed bind whose `fs_root != "/"`, resolves
///     to a source path and becomes [`Submount::ExtraLower`];
///   - a whole-partition device mount (`fs_root == "/"`) becomes
///     [`Submount::Reattach`] when read-only or [`Submount::NestedOverlay`] when
///     writable;
///   - a pseudo/virtual mount (tmpfs and friends) becomes [`Submount::Reattach`],
///     read-only only if it already was.
pub(crate) fn classify_submounts(mountinfo: &str, target: &Path) -> Vec<Submount> {
    // Parse once through the shared, octal-decoding parser so paths with spaces,
    // tabs or backslashes resolve correctly and no line is split on whitespace.
    let entries = parse_mountinfo(mountinfo);

    // Pass 1: Build a map from dev_id -> mount_point for entries where
    // fs_root == "/". These represent the root mounts of each device/partition.
    let mut device_root_mounts: HashMap<String, PathBuf> = HashMap::new();
    // Track the target's own dev_id/fs_root so we can detect target-equivalent
    // same-device submounts in Pass 2.
    let mut target_dev_id: Option<String> = None;
    let mut target_fs_root: Option<String> = None;

    for entry in &entries {
        let dev_id = entry.dev.as_str();
        let fs_root = entry.root.to_string_lossy();
        let mount_point = entry.mount_point.clone();

        if fs_root == "/" {
            match device_root_mounts.get_mut(dev_id) {
                Some(existing) => {
                    if mount_point.components().count() < existing.components().count() {
                        *existing = mount_point;
                    }
                }
                None => {
                    device_root_mounts.insert(dev_id.to_string(), mount_point);
                }
            }
        }

        // Track the target's device ID (last-wins for overmounts)
        if entry.mount_point == target {
            target_dev_id = Some(dev_id.to_string());
            target_fs_root = Some(fs_root.into_owned());
        }
    }

    let target_backing_root = target_dev_id.as_ref().and_then(|target_dev| {
        device_root_mounts
            .get(target_dev)
            .map(|root_mount_point| match target_fs_root.as_deref() {
                Some("/") | None => root_mount_point.clone(),
                Some(fs_root) => {
                    root_mount_point.join(fs_root.strip_prefix('/').unwrap_or(fs_root))
                }
            })
    });

    // Pass 2: Find all mounts strictly under the target directory and classify
    // each one.
    let mut results = Vec::new();

    let is_target_equivalent_same_device =
        |mount_point: &Path, source_path: &Path, dev_id: &str, fs_root: &str| {
            if let Some(ref target_dev) = target_dev_id
                && dev_id == target_dev
            {
                let relative = mount_point
                    .strip_prefix(target)
                    .unwrap_or_else(|_| Path::new(""));
                let extra_lower = source_path
                    .strip_suffix_path(relative)
                    .unwrap_or_else(|| source_path.to_path_buf());

                if target_backing_root.as_ref() == Some(&extra_lower) {
                    tracing::debug!(
                        mount_point = %mount_point.display(),
                        source = %source_path.display(),
                        extra_lower = %extra_lower.display(),
                        dev_id = %dev_id,
                        fs_root = %fs_root,
                        "Skipping target-equivalent same-device submount to avoid ELOOP"
                    );
                    return true;
                }
            }

            false
        };

    for entry in &entries {
        let dev_id = entry.dev.as_str();
        let fs_root = entry.root.to_string_lossy();
        let fs_root = fs_root.as_ref();
        let mount_point = entry.mount_point.clone();

        // Include mount points strictly under target (not target itself)
        if !mount_point.starts_with(target) || mount_point == target {
            continue;
        }

        let mount_source = entry.source.to_string_lossy();
        let mount_source = mount_source.as_ref();

        if mount_source.starts_with("/") && !mount_source.starts_with("/dev/") {
            // Non-device path source — a bind of a real path; fold it in as an
            // extra lower layer so its content stays visible.
            let source_path = PathBuf::from(mount_source);

            if is_target_equivalent_same_device(&mount_point, &source_path, dev_id, fs_root) {
                continue;
            }

            results.push(Submount::ExtraLower {
                mount_point,
                source: source_path,
            });
        } else if mount_source.starts_with("/dev/") {
            // Device-backed mount.
            let Some(root_mount_point) = device_root_mounts.get(dev_id) else {
                tracing::warn!(
                    mount_point = %mount_point.display(),
                    dev_id = %dev_id,
                    fs_root = %fs_root,
                    mount_source = %mount_source,
                    "Cannot resolve device-backed submount: no root mount found for dev_id"
                );
                continue;
            };

            if fs_root == "/" {
                // A whole separate partition mounted under the target (a snap
                // squashfs, a dedicated /var/log, /boot/efi, …). Its content is
                // not reachable as a bind source, so re-attach it over the overlay
                // (read-only) or give it a nested overlay (writable).
                if entry.read_only() {
                    results.push(Submount::Reattach {
                        mount_point,
                        fstype: entry.fstype.clone(),
                        read_only: true,
                    });
                } else {
                    results.push(Submount::NestedOverlay {
                        mount_point,
                        fstype: entry.fstype.clone(),
                    });
                }
                continue;
            }

            // A device-backed bind (fs_root != "/"): resolve to a real source and
            // fold in as an extra lower layer, as before.
            let source_path = root_mount_point.join(fs_root.strip_prefix('/').unwrap_or(fs_root));

            if source_path == mount_point {
                tracing::trace!(
                    mount_point = %mount_point.display(),
                    source = %source_path.display(),
                    dev_id = %dev_id,
                    "Skipping self-backed submount (content already visible through target)"
                );
                continue;
            }

            if is_target_equivalent_same_device(&mount_point, &source_path, dev_id, fs_root) {
                continue;
            }

            tracing::debug!(
                mount_point = %mount_point.display(),
                dev_id = %dev_id,
                fs_root = %fs_root,
                root_mount = %root_mount_point.display(),
                resolved_source = %source_path.display(),
                "Resolved device-backed bind mount source"
            );
            results.push(Submount::ExtraLower {
                mount_point,
                source: source_path,
            });
        } else {
            // Pseudo/virtual filesystem (tmpfs, sysfs, proc, none, …). Re-attach it
            // over the overlay so the path keeps resolving; its writes (if any) go
            // to RAM, never the decoy disk, so a writable one is re-attached as-is.
            tracing::debug!(
                mount_point = %mount_point.display(),
                mount_source = %mount_source,
                fstype = %entry.fstype,
                "Re-attaching pseudo submount over the overlay"
            );
            results.push(Submount::Reattach {
                mount_point,
                fstype: entry.fstype.clone(),
                read_only: entry.read_only(),
            });
        }
    }

    // Sort for consistent ordering (shallowest first, so a parent re-attaches
    // before anything nested inside it).
    results.sort_by(|a, b| a.mount_point().cmp(b.mount_point()));
    results
}

/// Parse `/proc/self/mountinfo` content to find submount source paths under
/// `target`, for extra lower-layer computation.
///
/// This is the extra-lower subset of [`classify_submounts`]: only
/// [`Submount::ExtraLower`] plans (binds that resolve to a real source) yield a
/// `(mount_point, source)` pair. Re-attached and nested submounts are handled
/// separately by the mount loop and never appear here.
pub(crate) fn parse_submount_sources(mountinfo: &str, target: &Path) -> Vec<(PathBuf, PathBuf)> {
    classify_submounts(mountinfo, target)
        .into_iter()
        .filter_map(|submount| match submount {
            Submount::ExtraLower {
                mount_point,
                source,
            } => Some((mount_point, source)),
            _ => None,
        })
        .collect()
}

trait StripSuffixPath {
    fn strip_suffix_path(&self, suffix: &Path) -> Option<PathBuf>;
}

impl StripSuffixPath for PathBuf {
    fn strip_suffix_path(&self, suffix: &Path) -> Option<PathBuf> {
        self.as_path().strip_suffix_path(suffix)
    }
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

        let start = self_components.len() - suffix_components.len();
        for (a, b) in self_components[start..]
            .iter()
            .zip(suffix_components.iter())
        {
            if a != b {
                return None;
            }
        }

        let prefix: PathBuf = self_components[..start].iter().collect();
        if prefix.as_os_str().is_empty() {
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
    fn squashfs_snap_submount_is_reattached_read_only() {
        // Ubuntu: a snap's per-revision squashfs is mounted read-only from a loop
        // device under /snap. Overlaying /snap would hide it, so it must be
        // re-attached read-only over the overlay.
        let mountinfo = "\
30 1 7:3 / /snap/firefox/1234 ro,nodev,relatime - squashfs /dev/loop3 ro";
        let plan = classify_submounts(mountinfo, Path::new("/snap"));
        assert_eq!(
            plan,
            vec![Submount::Reattach {
                mount_point: PathBuf::from("/snap/firefox/1234"),
                fstype: "squashfs".to_string(),
                read_only: true,
            }]
        );
    }

    #[test]
    fn writable_partition_submount_becomes_nested_overlay() {
        // A separate ext4 /var/log partition is writable and backed by the decoy
        // disk, so it needs its own nested overlay rather than a bind.
        let mountinfo = "\
40 1 8:1 / /var rw,relatime - ext4 /dev/sda1 rw
41 40 8:5 / /var/log rw,relatime - ext4 /dev/sda5 rw";
        let plan = classify_submounts(mountinfo, Path::new("/var"));
        assert_eq!(
            plan,
            vec![Submount::NestedOverlay {
                mount_point: PathBuf::from("/var/log"),
                fstype: "ext4".to_string(),
            }]
        );
    }

    #[test]
    fn read_only_partition_submount_is_reattached_read_only() {
        // A read-only separate partition (e.g. a vfat /boot/efi mounted ro) is
        // re-attached read-only, never given a writable nested overlay.
        let mountinfo = "\
40 1 8:1 / /boot rw,relatime - ext4 /dev/sda1 rw
41 40 8:2 / /boot/efi ro,relatime - vfat /dev/sda2 ro";
        let plan = classify_submounts(mountinfo, Path::new("/boot"));
        assert_eq!(
            plan,
            vec![Submount::Reattach {
                mount_point: PathBuf::from("/boot/efi"),
                fstype: "vfat".to_string(),
                read_only: true,
            }]
        );
    }

    #[test]
    fn real_path_bind_submount_stays_extra_lower() {
        // A bind of a real path (the classic /etc/nixos from /persist case) stays
        // an extra lower layer so overlayfs keeps its content visible.
        let mountinfo = "\
42 1 254:1 / /persist rw,relatime - ext4 /dev/mapper/persist rw
73 42 254:1 /etc/nixos /etc/nixos rw,relatime - ext4 /dev/mapper/persist rw";
        let plan = classify_submounts(mountinfo, Path::new("/etc"));
        assert_eq!(
            plan,
            vec![Submount::ExtraLower {
                mount_point: PathBuf::from("/etc/nixos"),
                source: PathBuf::from("/persist/etc/nixos"),
            }]
        );
    }

    #[test]
    fn whole_partition_submount_is_no_longer_dropped() {
        // Regression: a device-backed fs_root=="/" submount used to be silently
        // dropped, leaving an empty directory in the merged view. It must now be
        // classified (here a writable data partition -> nested overlay).
        let mountinfo = "\
42 1 254:1 / /home rw - ext4 /dev/sda2 rw
73 1 254:2 / /home/data rw - ext4 /dev/sda3 rw";
        let plan = classify_submounts(mountinfo, Path::new("/home"));
        assert_eq!(
            plan,
            vec![Submount::NestedOverlay {
                mount_point: PathBuf::from("/home/data"),
                fstype: "ext4".to_string(),
            }]
        );
        // And it is not mistaken for an extra lower.
        assert!(parse_submount_sources(mountinfo, Path::new("/home")).is_empty());
    }

    #[test]
    fn pseudo_submount_is_reattached_preserving_writability() {
        // A tmpfs nested under an overlaid target is re-attached so the path keeps
        // resolving; it stays writable because its writes are RAM-backed.
        let mountinfo = "\
40 1 8:1 / /var rw,relatime - ext4 /dev/sda1 rw
41 40 0:55 / /var/run rw,nosuid - tmpfs tmpfs rw";
        let plan = classify_submounts(mountinfo, Path::new("/var"));
        assert_eq!(
            plan,
            vec![Submount::Reattach {
                mount_point: PathBuf::from("/var/run"),
                fstype: "tmpfs".to_string(),
                read_only: false,
            }]
        );
        // A pseudo mount is never an extra lower.
        assert!(parse_submount_sources(mountinfo, Path::new("/var")).is_empty());
    }

    #[test]
    fn mountinfo_octal_escaped_path_decodes_in_classification() {
        // A submount at a path with a space (\040) must decode via the shared
        // parser, not split on whitespace.
        let mountinfo = "\
40 1 8:1 / /mnt rw,relatime - ext4 /dev/sda1 rw
41 40 7:0 / /mnt/my\\040snap ro,relatime - squashfs /dev/loop0 ro";
        let plan = classify_submounts(mountinfo, Path::new("/mnt"));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].mount_point(), Path::new("/mnt/my snap"));
    }

    #[test]
    fn empty_and_target_itself_yield_no_submounts() {
        assert!(classify_submounts("", Path::new("/etc")).is_empty());
        let mountinfo = "42 1 254:1 / /etc rw,relatime - ext4 /dev/mapper/persist rw";
        assert!(classify_submounts(mountinfo, Path::new("/etc")).is_empty());
    }
}
