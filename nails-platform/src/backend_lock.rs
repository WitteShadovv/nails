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
//! A place on the way that is there but cannot be read, for another reason
//! than that it is not there, is kept in [`BackendChain::unread`]: the stack
//! may then hold a mapping the chain does not name.

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
    /// The places on the way down that are there but could not be read, for
    /// another reason than that they are not there: the `/dev/mapper` link
    /// of the source, a `dm/name` or a `slaves/` listing. Each may hide a
    /// device-mapper name that [`dm_names`](Self::dm_names) lacks.
    pub unread: Vec<PathBuf>,
}

impl BackendChain {
    /// Whether this backend is, or may be, device-mapper based: it has a dm
    /// device to remove, its source names one (`/dev/dm-N`, or a path under
    /// `/dev/mapper`) whatever could be read of it, or a place on the way
    /// could not be read. A `false` means the mount is a plain block device
    /// and only the way back's lazy unmount applies.
    pub fn is_device_mapper(&self) -> bool {
        !self.dm_names.is_empty() || names_dm_device(&self.source_device) || !self.unread.is_empty()
    }
}

/// Resolve the device-mapper / loop chain behind the hidden-root mount.
///
/// Returns `Ok(None)` when `hidden_root` is not a mount point (already
/// unmounted), or when there is no mount table, as in a test's tree. Reads
/// only `/proc/self/mountinfo` and `/sys/block` through `fs`, and changes
/// nothing: a sysfs place that is there but cannot be read ends the walk
/// there and lands in [`BackendChain::unread`].
///
/// # Errors
///
/// The mount table is there but cannot be read.
pub fn resolve_backend_chain<F: Filesystem>(
    fs: &F,
    hidden_root: &Path,
) -> crate::Result<Option<BackendChain>> {
    let content = match fs.read_file_content(Path::new(SELF_MOUNTINFO)) {
        Ok(content) => content,
        Err(error) if error.nothing_there() => return Ok(None),
        Err(error) => return Err(error),
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
        unread: Vec::new(),
    };

    if let Some(top) = sysfs_block_name(fs, &source_device, &mut chain.unread) {
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
/// device) is not a device-mapper device and yields `None`, and so does a
/// `/dev/mapper` link that cannot be resolved, which lands in `unread` where
/// it is there.
fn sysfs_block_name<F: Filesystem>(
    fs: &F,
    source: &Path,
    unread: &mut Vec<PathBuf>,
) -> Option<String> {
    let name = source.file_name()?.to_str()?;
    if is_dm_name(name) {
        return Some(name.to_string());
    }
    if source.starts_with("/dev/mapper") {
        let resolved = match fs.canonicalize(source) {
            Ok(resolved) => resolved,
            Err(error) => {
                if !error.nothing_there() {
                    unread.push(source.to_path_buf());
                }
                return None;
            }
        };
        let resolved_name = resolved.file_name()?.to_str()?.to_string();
        if is_dm_name(&resolved_name) {
            return Some(resolved_name);
        }
    }
    None
}

/// Whether a mount source names a device-mapper device by its path alone:
/// `/dev/dm-N`, or a name under `/dev/mapper`.
fn names_dm_device(source: &Path) -> bool {
    source.starts_with("/dev/mapper")
        || source
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_dm_name)
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
/// malformed sysfs cannot loop forever. A name or a listing that is there but
/// cannot be read lands in [`BackendChain::unread`].
fn walk_dm_stack<F: Filesystem>(fs: &F, block_name: &str, chain: &mut BackendChain) {
    let sysfs = Path::new(SYS_BLOCK).join(block_name);

    let name_path = sysfs.join("dm/name");
    match fs.read_file_content(&name_path) {
        Ok(name) => {
            let name = name.trim().to_string();
            if !name.is_empty() && !chain.dm_names.contains(&name) {
                chain.dm_names.push(name);
            }
        }
        Err(error) if error.nothing_there() => {}
        Err(_) => chain.unread.push(name_path),
    }

    let slaves_path = sysfs.join("slaves");
    let slaves = match fs.list_directory(&slaves_path) {
        Ok(slaves) => slaves,
        Err(error) => {
            if !error.nothing_there() {
                chain.unread.push(slaves_path);
            }
            return;
        }
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
    fn resolve_returns_none_without_a_mount_table() {
        let fs = MockFilesystem::new();
        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data")).unwrap();
        assert!(chain.is_none());
    }

    #[test]
    fn a_mount_table_that_cannot_be_read_is_an_error() {
        // It may show the hidden root on a mapping: taking it for nothing
        // mounted would record no mapping for the way back to close.
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/dm-0"),
        );
        fs.mock_set_lookup_error("/proc/self/mountinfo", std::io::ErrorKind::PermissionDenied);
        assert!(resolve_backend_chain(&fs, Path::new("/mnt/data")).is_err());
    }

    #[test]
    fn a_dm_source_is_device_mapper_whatever_its_name_reads() {
        // The source's kernel name or its /dev/mapper path already says it is
        // a mapping: dmsetup is needed for it even where no name could be
        // read, and a name or a link that could not be read is kept.
        for (source, fail, kind) in [
            (
                "/dev/dm-0",
                "/sys/block/dm-0/dm/name",
                std::io::ErrorKind::PermissionDenied,
            ),
            (
                "/dev/dm-0",
                "/sys/block/dm-0/dm/name",
                std::io::ErrorKind::Other,
            ),
            (
                "/dev/mapper/data",
                "/dev/mapper/data",
                std::io::ErrorKind::Other,
            ),
            (
                "/dev/mapper/data",
                "/dev/mapper/data",
                std::io::ErrorKind::PermissionDenied,
            ),
        ] {
            let fs = MockFilesystem::new();
            fs.mock_add_file(
                "/proc/self/mountinfo",
                &mountinfo_line("/mnt/data", "ext4", source),
            );
            fs.mock_add_file("/sys/block/dm-0/dm/name", "data\n");
            fs.mock_set_directory_contents(Path::new("/sys/block/dm-0/slaves"), Vec::new());
            fs.create_symlink(Path::new("/dev/dm-0"), Path::new("/dev/mapper/data"))
                .unwrap();
            fs.mock_set_lookup_error(fail, kind);

            let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
                .unwrap()
                .unwrap();
            assert!(chain.dm_names.is_empty(), "{source}: {chain:?}");
            assert_eq!(chain.unread, vec![PathBuf::from(fail)], "{source}");
            assert!(chain.is_device_mapper(), "{source}");
        }

        // With nothing to read under it, a dm node still names a mapping.
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/dm-0"),
        );
        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .unwrap();
        assert!(chain.unread.is_empty(), "{chain:?}");
        assert!(chain.is_device_mapper());
    }

    #[test]
    fn a_slaves_listing_that_cannot_be_read_is_kept() {
        let fs = MockFilesystem::new();
        fs.mock_add_file(
            "/proc/self/mountinfo",
            &mountinfo_line("/mnt/data", "ext4", "/dev/dm-2"),
        );
        fs.mock_add_file("/sys/block/dm-2/dm/name", "data0\n");
        fs.mock_set_directory_contents(
            Path::new("/sys/block/dm-2/slaves"),
            vec![PathBuf::from("/sys/block/dm-2/slaves/dm-1")],
        );
        fs.mock_set_lookup_error(
            "/sys/block/dm-2/slaves",
            std::io::ErrorKind::PermissionDenied,
        );

        let chain = resolve_backend_chain(&fs, Path::new("/mnt/data"))
            .unwrap()
            .unwrap();
        assert_eq!(chain.dm_names, vec!["data0".to_string()]);
        assert_eq!(chain.unread, vec![PathBuf::from("/sys/block/dm-2/slaves")]);
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
