// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::MountSource;
use super::MockFilesystem;
use crate::{NailsError, Result};
use std::path::Path;

impl MockFilesystem {
    pub(super) fn is_mounted_impl(&self, target: &Path) -> Result<bool> {
        if let Some(message) = self
            .is_mounted_errors
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
        {
            return Err(NailsError::io(
                target,
                std::io::Error::other(message.clone()),
            ));
        }

        Ok(self
            .mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target))
    }

    pub(super) fn get_filesystem_type_impl(&self, target: &Path) -> Result<Option<String>> {
        Ok(self
            .filesystem_types
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
            .cloned())
    }

    pub(super) fn mount_source_impl(&self, mount_point: &Path) -> Result<Option<MountSource>> {
        Ok(self
            .mount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(mount_point)
            .cloned())
    }

    pub(super) fn is_mount_read_only_impl(&self, target: &Path) -> bool {
        self.read_only_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
    }
}
