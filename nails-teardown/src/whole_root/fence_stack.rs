// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The devices on a decoy disk that would write to it on their own past the
//! write fence ([`crate::whole_root::fence`]), which the entry refuses.
//!
//! The block layer's read-only flag only makes the kernel warn about a write
//! bio (`bio_check_ro`), so a stacked device that writes to the devices below
//! it by itself keeps writing to a fenced disk: md and device-mapper's `raid`
//! their superblocks and write-intent bitmaps, `mirror` its log, `cache`,
//! `writecache` and bcache their caches and metadata, `thin-pool` its
//! metadata, `integrity` its journal, drbd its metadata and its peer's
//! writes. The fence allows only the device-mapper targets that write
//! nothing but the writes they are given, of which a read-only filesystem
//! above gives none: `linear`, `striped` and `crypt` (and `zero` and `error`,
//! which write nothing). Every other stacked device on a decoy disk is
//! refused, at activation and at the switch.
//!
//! A loop device bound to a file of a decoy filesystem writes that file
//! through the filesystem; one that may write keeps the filesystem from going
//! read-only, so the switch would fail. The activation refuses it first; one
//! bound read-only (a snap's squashfs) writes nothing.

use crate::mountinfo::{MountEntry, top_mount_at};
use crate::whole_root::disk_guard::{DevNum, Sysfs};
use crate::whole_root::fence::{FenceKernel, Targets};
use std::collections::BTreeSet;

/// The device-mapper targets that write only the writes they are given.
pub const PASSIVE_DM_TARGETS: [&str; 5] = ["linear", "striped", "crypt", "zero", "error"];

impl Sysfs {
    /// Whether a device is a device-mapper device (`/sys/block/dm-0/dm`).
    pub(crate) fn is_dm(&self, dev: DevNum) -> bool {
        self.dir(dev).is_some_and(|d| d.join("dm").is_dir())
    }

    /// Whether a device is an md array (`/sys/block/md0/md`).
    pub(crate) fn is_md(&self, dev: DevNum) -> bool {
        self.dir(dev).is_some_and(|d| d.join("md").is_dir())
    }

    /// Every loop device sysfs lists.
    fn loop_devices(&self) -> Vec<DevNum> {
        let Ok(entries) = std::fs::read_dir(self.root.join("class/block")) else {
            return Vec::new();
        };
        let mut found: Vec<DevNum> = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("loop"))
            .filter_map(|e| Self::dev_in(&e.path()))
            .collect();
        found.sort();
        found
    }
}

/// What a stacked device is, for a refusal: its driver, or the active
/// device-mapper target it has.
fn kind(dev: DevNum, sys: &Sysfs, kernel: &dyn FenceKernel) -> Option<String> {
    if sys.is_dm(dev) {
        return match kernel.dm_targets(dev) {
            Ok(types) => types
                .into_iter()
                .find(|t| !PASSIVE_DM_TARGETS.contains(&t.as_str()))
                .map(|t| format!("device-mapper {t}")),
            Err(e) => Some(format!("device-mapper, whose table cannot be read: {e}")),
        };
    }
    if sys.is_md(dev) {
        return Some("md".to_string());
    }
    let dir = sys.dir(dev);
    let name = sys.name(dev).unwrap_or_default();
    Some(if dir.is_some_and(|d| d.join("bcache").is_dir()) {
        "bcache".to_string()
    } else if name.starts_with("drbd") {
        "drbd".to_string()
    } else {
        "a stacked driver".to_string()
    })
}

/// The stacked devices among those the fence sets read-only that would write
/// to the devices below them on their own, each as `name (kind)`: every
/// device with devices below it (`slaves`) but a device-mapper device whose
/// targets are all [`PASSIVE_DM_TARGETS`]. A device-mapper table that cannot
/// be read counts as active.
pub fn active_stacks(targets: &Targets, sys: &Sysfs, kernel: &dyn FenceKernel) -> Vec<String> {
    targets
        .rules
        .block
        .iter()
        .filter(|&&dev| !sys.slaves(dev).is_empty())
        .filter_map(|&dev| {
            let kind = kind(dev, sys, kernel)?;
            Some(format!(
                "{} ({kind})",
                sys.name(dev).unwrap_or_else(|| dev.text())
            ))
        })
        .collect()
}

/// The loop devices that may write and are bound to a file of a decoy
/// filesystem the fence makes read-only, by kernel name, with `mounts` the
/// decoy's mount table at activation, where the backing file's path leads,
/// and `kept` the hidden volume's own devices.
pub fn writable_loops(
    targets: &Targets,
    mounts: &[MountEntry],
    sys: &Sysfs,
    kept: &[DevNum],
) -> Vec<String> {
    let decoy: BTreeSet<&str> = targets
        .superblocks
        .iter()
        .filter(|sb| sb.device.is_some())
        .map(|sb| sb.sb_dev.as_str())
        .collect();
    sys.loop_devices()
        .into_iter()
        .filter(|&dev| !kept.contains(&dev) && !sys.is_read_only(dev))
        .filter(|&dev| {
            let Some(file) = sys.loop_backing(dev) else {
                return false;
            };
            let file = file
                .to_str()
                .and_then(|f| f.strip_suffix(" (deleted)"))
                .map_or(file.clone(), Into::into);
            let file = std::fs::canonicalize(&file).unwrap_or(file);
            file.ancestors()
                .find_map(|at| top_mount_at(mounts, at))
                .is_some_and(|mount| decoy.contains(mount.dev.as_str()))
        })
        .filter_map(|dev| sys.name(dev))
        .collect()
}

/// The target types of a `DM_TABLE_STATUS` reply: `buf` from the start of
/// the `struct dm_ioctl`, whose `data_start` the reply's targets follow, each
/// a `struct dm_target_spec` whose `next` is the offset of the next one from
/// the first.
pub fn parse_targets(buf: &[u8]) -> Result<Vec<String>, String> {
    let u32_at = |at: usize| -> Result<u32, String> {
        buf.get(at..at + 4)
            .map(|b| u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])))
            .ok_or_else(|| "a short reply".to_string())
    };
    let data_start = u32_at(16)? as usize;
    let count = u32_at(20)? as usize;
    let mut types = Vec::with_capacity(count);
    let mut at = data_start;
    for _ in 0..count {
        let name = buf
            .get(at + 24..at + 40)
            .ok_or_else(|| "a short reply".to_string())?;
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        types.push(String::from_utf8_lossy(&name[..end]).into_owned());
        let next = u32_at(at + 20)? as usize;
        at = data_start + next;
    }
    Ok(types)
}

#[cfg(test)]
#[path = "fence_stack_tests.rs"]
mod tests;
