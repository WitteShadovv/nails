use super::MockFilesystem;
use super::state::DEFAULT_MOCK_FREE_SPACE_BYTES;
use crate::{NailsError, Result};
use std::path::Path;

impl MockFilesystem {
    pub(super) fn path_exists_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).map(|info| info.exists).unwrap_or(false))
    }

    pub(super) fn is_directory_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_directory)
            .unwrap_or(false))
    }

    pub(super) fn is_symlink_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths.get(path).map(|info| info.is_symlink).unwrap_or(false))
    }

    pub(super) fn supports_symlinks_impl(&self, dir: &Path) -> Result<bool> {
        let support = self
            .symlink_support
            .lock()
            .expect("MockFilesystem mutex poisoned");
        Ok(support.get(dir).copied().unwrap_or(true))
    }

    pub(super) fn create_symlink_impl(&self, target: &Path, link: &Path) -> Result<()> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get(link) {
            if info.exists && info.is_symlink {
                drop(paths);
                let symlinks = self
                    .symlink_targets
                    .lock()
                    .expect("MockFilesystem mutex poisoned");
                if symlinks.get(link).map(|t| t == target).unwrap_or(false) {
                    return Ok(());
                }
                return Err(NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "Symlink at {} already exists pointing to a different target",
                        link.display()
                    ),
                )));
            } else if info.exists {
                drop(paths);
                return Err(NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("Path already exists (not a symlink) at {}", link.display()),
                )));
            }
        }
        drop(paths);

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(link.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_symlink = true;
        drop(paths);

        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(link.to_path_buf(), target.to_path_buf());

        Ok(())
    }

    pub(super) fn get_free_space_impl(&self, path: &Path) -> Result<u64> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.free_space)
            .unwrap_or(DEFAULT_MOCK_FREE_SPACE_BYTES))
    }

    pub(super) fn create_directory_impl(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            let parent_exists = {
                let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                paths.get(parent).map(|info| info.exists).unwrap_or(false)
            };

            if !parent_exists {
                if let Some(grandparent) = parent.parent() {
                    let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                    let grandparent_writable = paths
                        .get(grandparent)
                        .map(|info| info.is_writable)
                        .unwrap_or(false);
                    drop(paths);
                    if !grandparent_writable {
                        return Err(NailsError::PermissionDenied(format!(
                            "Parent directory not writable: {}",
                            grandparent.display()
                        )));
                    }
                }

                self.create_directory_impl(parent)?;
                let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                if let Some(entry) = paths.get_mut(parent) {
                    entry.is_writable = true;
                }
            } else {
                let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                let parent_writable = paths
                    .get(parent)
                    .map(|info| info.is_writable)
                    .unwrap_or(false);
                drop(paths);
                if !parent_writable {
                    return Err(NailsError::PermissionDenied(format!(
                        "Parent directory not writable: {}",
                        parent.display()
                    )));
                }
            }
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_directory = true;
        Ok(())
    }

    pub(super) fn set_permissions_impl(&self, path: &Path, mode: u32) -> Result<()> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if !paths.get(path).map(|info| info.exists).unwrap_or(false) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Path does not exist: {}", path.display()),
            )));
        }
        drop(paths);

        self.permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), mode);
        Ok(())
    }

    pub(super) fn get_permissions_impl(&self, path: &Path) -> Result<u32> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get(path)
            && !info.exists
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Path does not exist: {}", path.display()),
            )));
        }
        drop(paths);

        Ok(self
            .permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
            .unwrap_or(0o755))
    }

    pub(super) fn is_readable_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_readable)
            .unwrap_or(false))
    }

    pub(super) fn is_writable_impl(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        Ok(paths
            .get(path)
            .map(|info| info.is_writable)
            .unwrap_or(false))
    }
}
