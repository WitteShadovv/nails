use super::super::mountinfo::{MountEntry, NailsMounts, escape_overlay_path};
use super::super::{MountInfo, MountSource, verify_mount_preconditions};
use super::{MockFilesystem, MockOp};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    pub(super) fn mount_overlay_impl(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> Result<()> {
        let injected_errno = self
            .mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
            .copied();
        if let Some(errno) = injected_errno {
            return Err(NailsError::Mount {
                target: target.to_path_buf(),
                errno,
            });
        }

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
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());

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

        // Ownership gate: refuse to unmount a mount NAILS does not own, mirroring
        // the real filesystem's protection against force-detaching a host mount.
        if !self
            .nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
        {
            return Err(NailsError::RefusedUnmanagedUnmount {
                path: target.to_path_buf(),
            });
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
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);

        Ok(())
    }

    pub(super) fn is_mounted_impl(&self, target: &Path) -> Result<bool> {
        if let Some(message) = self
            .is_mounted_errors
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
        {
            return Err(NailsError::IoError(std::io::Error::other(message.clone())));
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

    /// Classify the mock's tracked mounts the way the real parser classifies
    /// `/proc/self/mountinfo`.
    ///
    /// Each tracked overlay is turned into a synthetic `overlay` mount entry
    /// carrying its recorded lower/upper/work, and each bind mount into a
    /// synthetic bind entry, so the shared [`NailsMounts::from_entries`]
    /// classifier decides persistent/ephemeral/pivot/nix-store ownership exactly
    /// as it would against a real kernel mount table. A mounted-but-unowned path
    /// (set with `mock_set_mount_unmanaged`) is tracked only as a plain mount, so
    /// it never appears here and is correctly reported as not owned.
    pub(super) fn discover_nails_mounts_impl(
        &self,
        hidden_root: Option<&Path>,
    ) -> Result<NailsMounts> {
        let mut entries = Vec::new();

        for (target, info) in self
            .mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .iter()
        {
            let super_opts = format!(
                "rw,lowerdir={},upperdir={},workdir={}",
                escape_overlay_path(&info.lower)?,
                escape_overlay_path(&info.upper)?,
                escape_overlay_path(&info.work)?,
            );
            entries.push(MountEntry {
                mount_id: 0,
                parent_id: 0,
                dev: String::new(),
                root: PathBuf::from("/"),
                mount_point: target.clone(),
                fstype: "overlay".to_string(),
                source: PathBuf::from("overlay"),
                super_opts,
            });
        }

        for (target, source) in self
            .bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .iter()
        {
            entries.push(MountEntry {
                mount_id: 0,
                parent_id: 0,
                dev: String::new(),
                root: PathBuf::from("/"),
                mount_point: target.clone(),
                fstype: "none".to_string(),
                source: source.clone(),
                super_opts: "rw".to_string(),
            });
        }

        Ok(NailsMounts::from_entries(&entries, hidden_root))
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
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());

        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::MountTmpfs {
                target: target.to_path_buf(),
                size: size.to_string(),
            });

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
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);

        Ok(())
    }

    pub(super) fn bind_mount_impl(&self, source: &Path, target: &Path) -> Result<()> {
        let bind_fails = self
            .mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains_key(target);
        if bind_fails {
            return Err(NailsError::OverlayError(format!(
                "Mock bind mount failure for testing: {}",
                target.display()
            )));
        }

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
        self.nails_owned_mounts
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
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(target);

        Ok(())
    }
}
