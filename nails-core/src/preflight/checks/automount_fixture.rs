// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Automount points that nothing is mounted on yet, on a mock decoy, for the
//! tests of the checks that read it through the automount guard.

use crate::filesystem::MockFilesystem;

/// The decoy's root filesystem, as the mount table lists it.
pub(crate) const ROOT_MOUNT: &str = "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";

/// The mount table line of a direct automount point at `point`, as systemd
/// makes one for `x-systemd.automount`, that nothing is mounted on yet.
pub(crate) fn direct(point: &str, id: usize) -> String {
    format!(
        "{} 1 0:{} / {point} rw,relatime - autofs systemd-1 \
         rw,fd={id},pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino={id}\n",
        30 + id,
        50 + id
    )
}

/// Give `fs` a mount table of the root and a direct automount point at each
/// of `points`, nothing mounted on any.
pub(crate) fn with_automounts(fs: &MockFilesystem, points: &[&str]) {
    let mut table = ROOT_MOUNT.to_string();
    for (id, point) in points.iter().enumerate() {
        table.push_str(&direct(point, id));
    }
    fs.mock_set_mount_table(&table);
}

/// Whether `fs` was asked to look up `point` or a path below it.
pub(crate) fn reached(fs: &MockFilesystem, point: &str) -> bool {
    fs.mock_lookups().iter().any(|path| path.starts_with(point))
}
