// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The block devices the mock's mount table implies, in `/sys/class/block`.
//!
//! Code that follows a mount to its block device (the attach gate's storage
//! judge) lists `/sys/class/block` and reads each device's `dev`. Unless a
//! test configures that directory itself, the mock renders one device for
//! each mount whose source is a `/dev` path, named after the source and
//! carrying the mount's `major:minor`: a mounted path is a device of its own,
//! as the rendered mount table already says. A test hides the list with
//! [`mock_hide_block_devices`](MockFilesystem::mock_hide_block_devices).

use super::MockFilesystem;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where the kernel lists every block device.
const SYS_CLASS_BLOCK: &str = "/sys/class/block";

impl MockFilesystem {
    /// Render no block device: `/sys/class/block` cannot be listed, as on a
    /// system without sysfs.
    pub fn mock_hide_block_devices(&self) {
        *self
            .block_devices_hidden
            .lock()
            .expect("MockFilesystem mutex poisoned") = true;
    }

    /// The rendered devices, kernel name to `major:minor`; `None` when the
    /// test hid them or configured `/sys/class/block` itself.
    fn rendered_block_devices(&self) -> Option<BTreeMap<String, String>> {
        if *self
            .block_devices_hidden
            .lock()
            .expect("MockFilesystem mutex poisoned")
        {
            return None;
        }
        let configured = self
            .directory_contents
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains_key(Path::new(SYS_CLASS_BLOCK));
        if configured {
            return None;
        }
        let mut devices = BTreeMap::new();
        for mount in self.mount_table_impl() {
            if !mount.source.starts_with("/dev") {
                continue;
            }
            if let Some(name) = mount.source.file_name() {
                devices
                    .entry(name.to_string_lossy().into_owned())
                    .or_insert(mount.dev);
            }
        }
        Some(devices)
    }

    /// The rendered listing of `dir`, when it is `/sys/class/block`.
    pub(super) fn rendered_listing(&self, dir: &Path) -> Option<Vec<PathBuf>> {
        if dir != Path::new(SYS_CLASS_BLOCK) {
            return None;
        }
        let devices = self.rendered_block_devices()?;
        Some(
            devices
                .keys()
                .map(|name| Path::new(SYS_CLASS_BLOCK).join(name))
                .collect(),
        )
    }

    /// The rendered contents of `path`, when it is a device's `dev`.
    pub(super) fn rendered_file(&self, path: &Path) -> Option<String> {
        let mut parts = path.strip_prefix(SYS_CLASS_BLOCK).ok()?.iter();
        let name = parts.next()?.to_string_lossy().into_owned();
        if parts.next()? != "dev" || parts.next().is_some() {
            return None;
        }
        let devices = self.rendered_block_devices()?;
        devices.get(&name).map(|dev| format!("{dev}\n"))
    }
}
