//! Submount source detection for multi-lower-layer overlayfs.

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
    // Pass 1: Build a map from dev_id -> mount_point for entries where
    // fs_root == "/". These represent the root mounts of each device/partition.
    let mut device_root_mounts: HashMap<String, PathBuf> = HashMap::new();
    // Track the target's own dev_id so we can skip same-device submounts in Pass 2.
    let mut target_dev_id: Option<String> = None;

    for line in mountinfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let dev_id = parts[2];
        let fs_root = parts[3];
        let mount_point = PathBuf::from(parts[4]);

        if fs_root == "/" {
            device_root_mounts.insert(dev_id.to_string(), mount_point);
        }

        // Track the target's device ID (last-wins for overmounts)
        if Path::new(parts[4]) == target {
            target_dev_id = Some(dev_id.to_string());
        }
    }

    // Pass 2: Find all mounts strictly under the target directory and resolve
    // their source paths.
    let mut results = Vec::new();

    for line in mountinfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let dev_id = parts[2];
        let fs_root = parts[3];
        let mount_point = PathBuf::from(parts[4]);

        // Include mount points strictly under target (not target itself)
        if !mount_point.starts_with(target) || mount_point == target {
            continue;
        }

        // Find the source (mount source) after the "-" separator
        let separator_pos = parts.iter().position(|&p| p == "-");
        let mount_source = match separator_pos {
            Some(pos) if pos + 2 < parts.len() => parts[pos + 2],
            _ => continue,
        };

        if mount_source.starts_with("/") && !mount_source.starts_with("/dev/") {
            // Non-device path source — use directly
            results.push((mount_point, PathBuf::from(mount_source)));
        } else if mount_source.starts_with("/dev/") {
            // Device-backed mount — resolve via device_root_mounts
            if let Some(root_mount_point) = device_root_mounts.get(dev_id) {
                // Skip submounts on the same device as the target
                if let Some(ref target_dev) = target_dev_id
                    && dev_id == target_dev
                {
                    tracing::trace!(
                        mount_point = %mount_point.display(),
                        dev_id = %dev_id,
                        "Skipping same-device submount (content visible through target)"
                    );
                    continue;
                }
                if fs_root == "/" {
                    // Direct mount of entire partition under target — skip
                    continue;
                }
                let source_path =
                    root_mount_point.join(fs_root.strip_prefix('/').unwrap_or(fs_root));
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
