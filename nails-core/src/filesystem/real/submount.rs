//! Submount source detection for multi-lower-layer overlayfs.

use crate::filesystem::mountinfo::parse_mountinfo;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parse `/proc/self/mountinfo` content to find submount source paths under `target`.
///
/// Uses a two-pass algorithm:
/// - **Pass 1**: Build a map from `dev_id` -> `mount_point` for entries where `fs_root == "/"`.
///   These represent root mounts of each device/partition.
/// - **Pass 2**: Find mounts strictly under `target` and resolve their source paths:
///   - Non-device path sources (e.g., bind mounts with a real path) are used directly.
///   - Device-backed sources (`/dev/...`) are resolved via the Pass 1 map.
///   - Pseudo-filesystem sources (`tmpfs`, `sysfs`, `proc`, `none`, etc.) are skipped.
///   - Direct partition mounts (`fs_root == "/"`) under target are skipped to avoid
///     circular references where source would equal mount point.
///
/// Returns a sorted `Vec<(mount_point, source_path)>`.
pub(crate) fn parse_submount_sources(mountinfo: &str, target: &Path) -> Vec<(PathBuf, PathBuf)> {
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

    // Pass 2: Find all mounts strictly under the target directory and resolve
    // their source paths.
    let mut results = Vec::new();

    let should_skip_target_equivalent_same_device =
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
                        target_backing_root = %extra_lower.display(),
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
            // Non-device path source — use directly
            let source_path = PathBuf::from(mount_source);

            if should_skip_target_equivalent_same_device(
                &mount_point,
                &source_path,
                dev_id,
                fs_root,
            ) {
                continue;
            }

            results.push((mount_point, source_path));
        } else if mount_source.starts_with("/dev/") {
            // Device-backed mount — resolve via device_root_mounts
            if let Some(root_mount_point) = device_root_mounts.get(dev_id) {
                if fs_root == "/" {
                    // Direct mount of entire partition under target — skip
                    continue;
                }
                let source_path =
                    root_mount_point.join(fs_root.strip_prefix('/').unwrap_or(fs_root));

                if source_path == mount_point {
                    tracing::trace!(
                        mount_point = %mount_point.display(),
                        source = %source_path.display(),
                        dev_id = %dev_id,
                        "Skipping self-backed submount (content already visible through target)"
                    );
                    continue;
                }

                if should_skip_target_equivalent_same_device(
                    &mount_point,
                    &source_path,
                    dev_id,
                    fs_root,
                ) {
                    continue;
                }

                if let Some(ref target_dev) = target_dev_id
                    && dev_id == target_dev
                {
                    let relative = mount_point
                        .strip_prefix(target)
                        .unwrap_or_else(|_| Path::new(""));
                    let extra_lower = source_path
                        .strip_suffix_path(relative)
                        .unwrap_or_else(|| source_path.clone());

                    tracing::debug!(
                        mount_point = %mount_point.display(),
                        source = %source_path.display(),
                        extra_lower = %extra_lower.display(),
                        dev_id = %dev_id,
                        fs_root = %fs_root,
                        "Preserving non-equivalent same-device bind submount under target"
                    );
                }

                tracing::debug!(
                    mount_point = %mount_point.display(),
                    dev_id = %dev_id,
                    fs_root = %fs_root,
                    root_mount = %root_mount_point.display(),
                    resolved_source = %source_path.display(),
                    "Resolved device-backed bind mount source"
                );
                results.push((mount_point, source_path));
            } else {
                tracing::warn!(
                    mount_point = %mount_point.display(),
                    dev_id = %dev_id,
                    fs_root = %fs_root,
                    mount_source = %mount_source,
                    "Cannot resolve device-backed bind mount: no root mount found for dev_id"
                );
            }
        } else {
            // Pseudo-filesystem (tmpfs, sysfs, proc, none, etc.) — skip silently
            tracing::trace!(
                mount_point = %mount_point.display(),
                mount_source = %mount_source,
                "Skipping non-device submount under target"
            );
        }
    }

    // Sort for consistent ordering
    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
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
