// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The files the loop devices of the hidden root's stack read: the container
//! file the volume is opened from, or the image it is in.
//!
//! The loop driver names the file a loop device reads by the path it shows for
//! it (`loop/backing_file`) and by the device and inode it recorded
//! ([`FileId`](super::FileId)): two loop devices over one file, by either,
//! read the same storage. A line that names such a file opens the volume a
//! second time (see the `placed` module), and another loop device over it
//! counts as a device of the root's stack; a mount through such a loop device
//! shows the root's filesystem a second time ([`mounts_through_another_loop`]).

use super::judge::{hidden_stack, is_ram, is_stacked};
use super::{DeviceMap, LoopFile, NodeKind};
use crate::filesystem::mountinfo::MountEntry;

/// `stack`, then each other loop device over a file a loop device of
/// `stack` reads, as the loop driver names it by its path or recorded it by
/// its device and inode: what such a loop device reads is the same storage.
pub(super) fn with_loops_over_its_files(
    devices: &DeviceMap,
    mut stack: Vec<String>,
) -> Vec<String> {
    let files: Vec<&LoopFile> = loop_files(devices, &stack);
    let same = |file: &LoopFile| {
        files
            .iter()
            .any(|own| own.path == file.path || (own.id.is_some() && own.id == file.id))
    };
    let others: Vec<String> = devices
        .nodes
        .iter()
        .filter(|(name, node)| {
            !stack.contains(name)
                && matches!(&node.kind, NodeKind::Loop { file: Some(file) } if same(file))
        })
        .map(|(name, _)| name.clone())
        .collect();
    stack.extend(others);
    stack
}

/// The files the loop devices among `stack` read, in its order.
pub(super) fn loop_files<'a>(devices: &'a DeviceMap, stack: &[String]) -> Vec<&'a LoopFile> {
    stack
        .iter()
        .filter_map(|name| match &devices.nodes.get(name)?.kind {
            NodeKind::Loop { file: Some(file) } => Some(file),
            _ => None,
        })
        .collect()
}

/// The mounts of `mounts` that show the filesystem of `hidden` (the visible
/// mount at the hidden root) through another loop device than those of its
/// stack: one over a file a loop device of its stack reads, the container
/// file the volume is opened from or the image it is in, by the path the
/// loop driver shows for it or by its device and inode, and what lies on such
/// a loop device. The mount table gives such a mount another device number,
/// though it is a second mount of the same filesystem. None for a RAM
/// filesystem.
pub fn mounts_through_another_loop<'a>(
    devices: &DeviceMap,
    mounts: &'a [MountEntry],
    hidden: &MountEntry,
) -> Vec<&'a MountEntry> {
    if is_ram(&hidden.fstype) {
        return Vec::new();
    }
    let (_, stack) = hidden_stack(devices, hidden);
    let others: Vec<String> = with_loops_over_its_files(devices, stack.clone())
        .into_iter()
        .filter(|name| !stack.contains(name))
        .collect();
    if others.is_empty() {
        return Vec::new();
    }
    mounts
        .iter()
        .filter(|mount| mount.dev != hidden.dev && !is_stacked(&mount.fstype))
        .filter(|mount| {
            devices.node_of_mount(mount).is_some_and(|node| {
                devices
                    .full_stack(node)
                    .iter()
                    .any(|below| others.contains(below))
            })
        })
        .collect()
}
