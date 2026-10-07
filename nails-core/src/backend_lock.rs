// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The device stack behind the hidden root.
//!
//! The entry records the device-mapper names behind the hidden volume in the
//! session plan, so the way back and the emergency path can mark them for
//! deferred removal without reading anything from the volume. Resolving them
//! (the mount's source in `/proc/self/mountinfo`, then the `/sys/block`
//! device-mapper and loop stack) is a pure function over the [`Filesystem`]
//! trait ([`resolve_backend_chain`]), exercised against `MockFilesystem`.

use std::path::{Path, PathBuf};

use crate::filesystem::{Filesystem, parse_mountinfo};

/// The kernel mount table.
const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";
/// The sysfs block-device tree, where a device-mapper device's name and its
/// backing devices (`slaves/`) are read.
const SYS_BLOCK: &str = "/sys/block";

/// The device-mapper / loop chain backing the hidden-root mount.
///
/// Resolved from the mount's source in `/proc/self/mountinfo` by walking the
/// `/sys/block/<dev>/slaves` tree. A plain block-device backend (no
/// device-mapper layer) resolves to an empty [`dm_names`](Self::dm_names).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendChain {
    /// The hidden-root mount point as it appears in the mount table.
    pub mount_point: PathBuf,
    /// The mount source (`/dev/mapper/<name>`, `/dev/dm-N`, `/dev/sdb1`, ...).
    pub source_device: PathBuf,
    /// Device-mapper names behind the mount, top of the stack first. Empty when
    /// the backend is a plain block device rather than a device-mapper target.
    pub dm_names: Vec<String>,
    /// Loop backing devices found under the stack (e.g. `/dev/loop0`), for the
    /// common file-backed volume layout.
    pub loop_devices: Vec<PathBuf>,
}

impl BackendChain {
    /// Whether this backend is device-mapper based (has at least one dm device to
    /// remove). A `false` means the mount is a plain block device and only the
    /// way back's lazy unmount applies.
    pub fn is_device_mapper(&self) -> bool {
        !self.dm_names.is_empty()
    }
}

/// Resolve the device-mapper / loop chain behind the hidden-root mount.
///
/// Returns `Ok(None)` when `hidden_root` is not a mount point (already
/// unmounted). Reads only `/proc/self/mountinfo` and `/sys/block` through `fs`,
/// so it is total and side-effect-free: an unreadable sysfs node simply ends the
/// walk rather than failing it.
pub fn resolve_backend_chain<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
) -> crate::Result<Option<BackendChain>> {
    let content = match fs.read_file_content(Path::new(SELF_MOUNTINFO)) {
        Ok(content) => content,
        // No mount table to read: treat as nothing mounted rather than an error,
        // so a locked-down or test environment degrades to a clean no-op.
        Err(_) => return Ok(None),
    };

    // Match the hidden root against both its literal and canonical form: the
    // mount table records the canonical path, but a caller may pass either.
    let canonical = fs.canonicalize(hidden_root).ok();
    let entry = parse_mountinfo(&content).into_iter().find(|entry| {
        entry.mount_point == hidden_root
            || canonical.as_deref().is_some_and(|c| entry.mount_point == c)
    });
    let Some(entry) = entry else {
        return Ok(None);
    };

    let source_device = entry.source.clone();
    let mut chain = BackendChain {
        mount_point: entry.mount_point,
        source_device: source_device.clone(),
        dm_names: Vec::new(),
        loop_devices: Vec::new(),
    };

    if let Some(top) = sysfs_block_name(fs, &source_device) {
        walk_dm_stack(fs, &top, &mut chain);
    } else if is_loop_device(&source_device) {
        chain.loop_devices.push(source_device);
    }

    Ok(Some(chain))
}

/// The `/sys/block` directory name for a mount source, when it is a
/// device-mapper device.
///
/// `/dev/dm-N` is already a sysfs block name; `/dev/mapper/<name>` is a symlink
/// resolved to its `/dev/dm-N` target. Anything else (a plain partition, a loop
/// device) is not a device-mapper device and yields `None`.
fn sysfs_block_name<F: Filesystem>(fs: &F, source: &Path) -> Option<String> {
    let name = source.file_name()?.to_str()?;
    if is_dm_name(name) {
        return Some(name.to_string());
    }
    if source.starts_with("/dev/mapper") {
        let resolved = fs.canonicalize(source).ok()?;
        let resolved_name = resolved.file_name()?.to_str()?.to_string();
        if is_dm_name(&resolved_name) {
            return Some(resolved_name);
        }
    }
    None
}

/// Whether a sysfs block name is a device-mapper node (`dm-<N>`).
fn is_dm_name(name: &str) -> bool {
    name.strip_prefix("dm-")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
}

/// Whether a device path is a loop device (`/dev/loop<N>`).
fn is_loop_device(source: &Path) -> bool {
    source
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("loop"))
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
}

/// Walk a device-mapper stack from `block_name` (`dm-N`), recording the dm names
/// top-first and any loop backing devices.
///
/// Reads `/sys/block/<dm>/dm/name` for each device-mapper node and recurses
/// through `/sys/block/<dm>/slaves/` so a stacked target (crypt over linear over
/// loop, say) is fully resolved. A node already seen is not revisited, so a
/// malformed sysfs cannot loop forever.
fn walk_dm_stack<F: Filesystem>(fs: &F, block_name: &str, chain: &mut BackendChain) {
    let sysfs = Path::new(SYS_BLOCK).join(block_name);

    if let Ok(name) = fs.read_file_content(&sysfs.join("dm/name")) {
        let name = name.trim().to_string();
        if !name.is_empty() && !chain.dm_names.contains(&name) {
            chain.dm_names.push(name);
        }
    }

    let slaves = match fs.list_directory(&sysfs.join("slaves")) {
        Ok(slaves) => slaves,
        Err(_) => return,
    };
    for slave in slaves {
        let Some(slave_name) = slave.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_dm_name(slave_name) {
            walk_dm_stack(fs, slave_name, chain);
        } else if slave_name.starts_with("loop") && is_loop_device(Path::new(slave_name)) {
            let loop_dev = PathBuf::from("/dev").join(slave_name);
            if !chain.loop_devices.contains(&loop_dev) {
                chain.loop_devices.push(loop_dev);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    /// One `/proc/self/mountinfo` line for a mount of `source` at `mount_point`.
    fn mountinfo_line(mount_point: &str, fstype: &str, source: &str) -> String {
        format!("36 35 254:0 / {mount_point} rw,relatime shared:1 - {fstype} {source} rw\n")
    }

    #[test]
    fn resolve_returns_none_when_already_unmounted() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/other", "ext4", "/dev/sda1"),
        );

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data")).unwrap();
        assert!(chain.is_none(), "an unmounted hidden root resolves to None");
    }

    #[test]
    fn resolve_returns_none_when_mount_table_is_unreadable() {
        let fs = MockFilesystem::new();
        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data")).unwrap();
        assert!(chain.is_none());
    }

    #[test]
    fn resolve_plain_block_device_has_no_dm_layer() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/sdb1"),
        );

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .expect("the hidden root is mounted");
        assert!(
            !chain.is_device_mapper(),
            "a plain partition has no dm stack"
        );
        assert_eq!(chain.source_device, PathBuf::from("/dev/sdb1"));
        assert!(chain.dm_names.is_empty());
        assert!(chain.loop_devices.is_empty());
    }

    #[test]
    fn resolve_loop_backed_plain_device_records_the_loop() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/loop3"),
        );

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .unwrap();
        assert!(!chain.is_device_mapper());
        assert_eq!(chain.loop_devices, vec![PathBuf::from("/dev/loop3")]);
    }

    #[test]
    fn resolve_dm_source_via_dm_node_reads_name_and_loop_slave() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/dm-2"),
        );
        fs.mock_add_file("/sys/block/dm-2/dm/name", "data0\n");
        fs.mock_set_directory_contents(
            Path::new("/sys/block/dm-2/slaves"),
            vec![PathBuf::from("/sys/block/dm-2/slaves/loop0")],
        );

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .unwrap();
        assert!(chain.is_device_mapper());
        assert_eq!(chain.dm_names, vec!["data0".to_string()]);
        assert_eq!(chain.loop_devices, vec![PathBuf::from("/dev/loop0")]);
    }

    #[test]
    fn resolve_mapper_source_canonicalizes_to_dm_node() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/mapper/data0"),
        );
        // /dev/mapper/<name> is a symlink to /dev/dm-N.
        fs.mock_set_file_content("/sys/block/dm-1/dm/name", "data0\n");
        fs.mock_set_directory_contents(Path::new("/sys/block/dm-1/slaves"), Vec::new());
        fs.create_symlink(Path::new("/dev/dm-1"), Path::new("/dev/mapper/data0"))
            .unwrap();

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .unwrap();
        assert_eq!(chain.dm_names, vec!["data0".to_string()]);
    }

    #[test]
    fn resolve_stacked_dm_walks_both_layers() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/dm-5"),
        );
        // dm-5 (crypt) over dm-4 (linear) over loop1.
        fs.mock_add_file("/sys/block/dm-5/dm/name", "crypt0\n");
        fs.mock_set_directory_contents(
            Path::new("/sys/block/dm-5/slaves"),
            vec![PathBuf::from("/sys/block/dm-5/slaves/dm-4")],
        );
        fs.mock_add_file("/sys/block/dm-4/dm/name", "linear0\n");
        fs.mock_set_directory_contents(
            Path::new("/sys/block/dm-4/slaves"),
            vec![PathBuf::from("/sys/block/dm-4/slaves/loop1")],
        );

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .unwrap();
        assert_eq!(
            chain.dm_names,
            vec!["crypt0".to_string(), "linear0".to_string()]
        );
        assert_eq!(chain.loop_devices, vec![PathBuf::from("/dev/loop1")]);
    }
}
