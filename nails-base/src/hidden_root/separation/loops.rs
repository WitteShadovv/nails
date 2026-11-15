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
//! counts as a device of the root's stack.

use super::{DeviceMap, LoopFile, NodeKind};

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
