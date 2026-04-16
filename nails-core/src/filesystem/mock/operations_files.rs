use super::{MockFilesystem, MockOp};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    pub(super) fn file_size_impl(&self, path: &Path) -> Result<u64> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get(path) {
            if !info.exists {
                return Err(NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File not found: {}", path.display()),
                )));
            }

            let size_value = info.free_space;
            drop(paths);

            let explicit_sizes = self
                .explicit_file_sizes
                .lock()
                .expect("MockFilesystem mutex poisoned");
            if explicit_sizes.contains(path) {
                return Ok(size_value);
            }
            drop(explicit_sizes);

            let contents = self
                .file_contents
                .lock()
                .expect("MockFilesystem mutex poisoned");
            if let Some(content) = contents.get(path) {
                return Ok(content.len() as u64);
            }

            Ok(0)
        } else {
            Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File not found: {}", path.display()),
            )))
        }
    }

    pub(super) fn rename_file_impl(&self, from: &Path, to: &Path) -> Result<()> {
        if self
            .rename_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(from)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: rename_file configured to fail for {}",
                    from.display()
                ),
            )));
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if !paths.get(from).is_some_and(|info| info.exists) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Source file not found: {}", from.display()),
            )));
        }

        if let Some(mut info) = paths.remove(from) {
            info.exists = true;
            paths.insert(to.to_path_buf(), info);
        }
        drop(paths);

        let mut contents = self
            .file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if let Some(content) = contents.remove(from) {
            contents.insert(to.to_path_buf(), content);
        }

        Ok(())
    }

    pub(super) fn remove_file_impl(&self, path: &Path) -> Result<()> {
        if self
            .remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_file configured to fail for {}",
                    path.display()
                ),
            )));
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }

        let mut contents = self
            .file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned");
        contents.remove(path);

        Ok(())
    }

    pub(super) fn remove_directory_impl(&self, path: &Path) -> Result<()> {
        if self
            .remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_directory configured to fail for {}",
                    path.display()
                ),
            )));
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }

        Ok(())
    }

    pub(super) fn remove_dir_all_impl(&self, path: &Path) -> Result<()> {
        if self
            .remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_dir_all configured to fail for {}",
                    path.display()
                ),
            )));
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }

        Ok(())
    }

    pub(super) fn secure_delete_impl(&self, path: &Path) -> Result<()> {
        if self
            .remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: secure_delete configured to fail for {}",
                    path.display()
                ),
            )));
        }

        self.remove_file_impl(path)
    }

    pub(super) fn secure_delete_dir_all_impl(&self, path: &Path) -> Result<()> {
        if self
            .remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: secure_delete_dir_all configured to fail for {}",
                    path.display()
                ),
            )));
        }

        self.remove_dir_all_impl(path)
    }

    pub(super) fn read_directory_impl(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>> {
        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");

        let entries = Vec::new();
        for (p, info) in paths.iter() {
            if let Some(parent) = p.parent()
                && parent == path
                && info.exists
            {
                return Err(NailsError::IoError(std::io::Error::other(
                    "Mock: read_directory not fully implemented for MockFilesystem",
                )));
            }
        }

        Ok(entries)
    }

    pub(super) fn modified_time_impl(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
        let times = self
            .modified_times
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if let Some(modified) = times.get(&path.to_path_buf()) {
            return Ok(*modified);
        }

        Ok(chrono::Utc::now())
    }

    pub(super) fn copy_tree_impl(&self, src: &Path, dst: &Path) -> Result<()> {
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::CopyTree {
                src: src.to_path_buf(),
                dst: dst.to_path_buf(),
            });

        if self
            .copy_tree_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(src)
        {
            return Err(NailsError::IoError(std::io::Error::other(format!(
                "Mock copy_tree failure for {}",
                src.display()
            ))));
        }

        Ok(())
    }

    pub(super) fn get_directory_size_impl(&self, path: &Path) -> Result<u64> {
        let sizes = self
            .directory_sizes
            .lock()
            .expect("MockFilesystem mutex poisoned");
        Ok(sizes.get(path).copied().unwrap_or(0))
    }

    pub(super) fn find_submount_sources_impl(
        &self,
        target: &Path,
    ) -> Result<Vec<(PathBuf, PathBuf)>> {
        let sources = self
            .submount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned");
        Ok(sources.get(target).cloned().unwrap_or_default())
    }
}
