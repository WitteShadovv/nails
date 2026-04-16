use super::super::{MountInfo, verify_mount_preconditions};
use super::{MockFilesystem, MockOp};
use crate::{NailsError, Result};
use std::path::Path;

impl MockFilesystem {
    pub(super) fn mount_overlay_impl(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> Result<()> {
        let fail_set = self
            .mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if fail_set.contains(target) {
            return Err(NailsError::OverlayError(format!(
                "Mock mount failure for testing: {}",
                target.display()
            )));
        }
        drop(fail_set);

        if lower.is_empty() {
            return Err(NailsError::OverlayError(
                "mount_overlay requires at least one lower layer".to_string(),
            ));
        }

        verify_mount_preconditions(self, lower[0], upper, work, target)?;

        let mount_info = MountInfo {
            lower: lower[0].to_path_buf(),
            upper: upper.to_path_buf(),
            work: work.to_path_buf(),
            target: target.to_path_buf(),
            mounted_at: chrono::Utc::now(),
        };

        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());
        self.mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf(), mount_info);

        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::MountOverlay {
                target: target.to_path_buf(),
            });

        Ok(())
    }

    pub(super) fn unmount_impl(&self, target: &Path, force: bool) -> Result<()> {
        let fail_set = self
            .unmount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if fail_set.contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock unmount failure for testing".to_string(),
            });
        }
        drop(fail_set);

        let graceful_fail_set = self
            .unmount_graceful_fails
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if graceful_fail_set.contains(target) && !force {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock graceful unmount failure (force would succeed)".to_string(),
            });
        }
        drop(graceful_fail_set);

        let mut mounts = self.mounted.lock().expect("MockFilesystem mutex poisoned");
        if !mounts.contains(target) {
            return Ok(());
        }

        let busy = self.busy.lock().expect("MockFilesystem mutex poisoned");
        if busy.contains(target) && !force {
            return Err(NailsError::MountBusy {
                path: target.to_path_buf(),
                suggestion: "Use force=true to override or close open files".to_string(),
            });
        }
        drop(busy);

        mounts.remove(target);
        drop(mounts);
        self.mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);

        Ok(())
    }

    pub(super) fn is_mounted_impl(&self, target: &Path) -> Result<bool> {
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

    pub(super) fn is_overlay_mounted_impl(&self, target: &Path) -> Result<bool> {
        Ok(self
            .mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains_key(target))
    }

    pub(super) fn get_mount_info_impl(&self, target: &Path) -> Option<MountInfo> {
        self.mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
            .cloned()
    }

    pub(super) fn swap_is_enabled_impl(&self) -> Result<bool> {
        Ok(*self
            .swap_enabled
            .lock()
            .expect("MockFilesystem mutex poisoned"))
    }

    pub(super) fn swap_disable_impl(&self) -> Result<()> {
        *self
            .swap_enabled
            .lock()
            .expect("MockFilesystem mutex poisoned") = false;
        Ok(())
    }

    pub(super) fn mount_tmpfs_impl(&self, target: &Path, size: &str) -> Result<()> {
        let test_dir = crate::config::EphemeralOverlayDir {
            path: target.to_path_buf(),
            tmpfs_upper_size: size.to_string(),
            tmpfs_work_size: size.to_string(),
        };

        if test_dir.parse_upper_size().is_err() {
            return Err(NailsError::OverlayError(format!(
                "Invalid tmpfs size format: {}",
                size
            )));
        }

        if self
            .tmpfs_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
        {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        if !self.path_exists_impl(target)? {
            self.create_directory_impl(target)?;
        }

        self.tmpfs_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());

        Ok(())
    }

    pub(super) fn unmount_tmpfs_impl(&self, target: &Path) -> Result<()> {
        if !self
            .tmpfs_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
        {
            return Ok(());
        }

        if self
            .unmount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
        {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock: unmount_tmpfs configured to fail".to_string(),
            });
        }

        self.tmpfs_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);

        Ok(())
    }

    pub(super) fn bind_mount_impl(&self, source: &Path, target: &Path) -> Result<()> {
        let fail_set = self
            .mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if fail_set.contains(target) {
            return Err(NailsError::OverlayError(format!(
                "Mock bind mount failure for testing: {}",
                target.display()
            )));
        }
        drop(fail_set);

        if !self.path_exists_impl(source)? {
            return Err(NailsError::OverlayError(format!(
                "Bind mount source not found: {}",
                source.display()
            )));
        }

        if self
            .bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains_key(target)
        {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        self.bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf(), source.to_path_buf());
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());

        Ok(())
    }

    pub(super) fn unmount_bind_impl(&self, target: &Path) -> Result<()> {
        if !self
            .bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains_key(target)
        {
            return Ok(());
        }

        if self
            .unmount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
        {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock: unmount_bind configured to fail".to_string(),
            });
        }

        self.bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);

        Ok(())
    }
}
