use super::{MockFilesystem, MockOp};
use crate::target_user::TargetUser;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    pub(super) fn nails_process_running_impl(&self) -> Result<bool> {
        Ok(*self
            .nails_process_running
            .lock()
            .expect("MockFilesystem mutex poisoned"))
    }

    pub(super) fn read_file_content_impl(&self, path: &Path) -> Result<String> {
        self.file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .cloned()
            .ok_or_else(|| {
                NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File not found in mock: {}", path.display()),
                ))
            })
    }

    pub(super) fn find_files_with_pattern_impl(
        &self,
        dir: &Path,
        pattern: &str,
    ) -> Result<Vec<PathBuf>> {
        let pattern_results = self
            .files_with_pattern
            .lock()
            .expect("MockFilesystem mutex poisoned");
        let key = (dir.to_path_buf(), pattern.to_string());
        let files = pattern_results.get(&key).cloned().unwrap_or_default();

        let paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let existing_files: Vec<PathBuf> = files
            .into_iter()
            .filter(|path| paths.get(path).map(|info| info.exists).unwrap_or(true))
            .collect();

        Ok(existing_files)
    }

    pub(super) fn write_file_content_impl(&self, path: &Path, content: &str) -> Result<()> {
        if self
            .write_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Mock write failure for {}", path.display()),
            )));
        }

        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.exists = true;
        drop(paths);

        let mut written = self
            .written_files
            .lock()
            .expect("MockFilesystem mutex poisoned");
        written.insert(path.to_path_buf(), content.to_string());

        let mut contents = self
            .file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned");
        contents.insert(path.to_path_buf(), content.to_string());

        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::WriteFile {
                path: path.to_path_buf(),
            });

        Ok(())
    }

    pub(super) fn write_user_file_impl(
        &self,
        path: &Path,
        content: &str,
        user: &TargetUser,
        default_mode: u32,
    ) -> Result<()> {
        if self
            .write_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(path)
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Mock write failure for {}", path.display()),
            )));
        }

        let existed = self
            .paths
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .map(|info| info.exists)
            .unwrap_or(false);

        // Missing parent directories are created owned by the target user, so
        // tests can assert `created parent dirs are user-owned`.
        if let Some(parent) = path.parent() {
            self.mock_create_user_dirs(parent, user);
        }

        // A new file takes the target user's numeric ids and the default mode;
        // an existing file keeps whatever owner and mode were already recorded.
        if !existed {
            self.owners
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .insert(path.to_path_buf(), (user.uid, user.gid));
            self.permissions
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .insert(path.to_path_buf(), default_mode & 0o7777);
        }

        {
            let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
            let entry = paths.entry(path.to_path_buf()).or_default();
            entry.exists = true;
        }

        self.written_files
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), content.to_string());
        self.file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), content.to_string());
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .push(MockOp::WriteFile {
                path: path.to_path_buf(),
            });

        Ok(())
    }

    /// Mark `dir` and any missing ancestors as directories owned by `user` with
    /// private (0700) permissions. Existing paths are left untouched.
    fn mock_create_user_dirs(&self, dir: &Path, user: &TargetUser) {
        let mut missing = Vec::new();
        let mut cursor = Some(dir);
        while let Some(current) = cursor {
            let exists = self
                .paths
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .get(current)
                .map(|info| info.exists)
                .unwrap_or(false);
            if exists {
                break;
            }
            missing.push(current.to_path_buf());
            cursor = current.parent();
        }

        for created in missing.iter().rev() {
            {
                let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
                let entry = paths.entry(created.clone()).or_default();
                entry.exists = true;
                entry.is_directory = true;
                entry.is_writable = true;
            }
            self.owners
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .insert(created.clone(), (user.uid, user.gid));
            self.permissions
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .entry(created.clone())
                .or_insert(0o700);
        }
    }

    pub(super) fn list_directory_impl(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let contents = self
            .directory_contents
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if let Some(entries) = contents.get(&dir.to_path_buf()) {
            return Ok(entries.clone());
        }

        Err(NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Mock: directory contents not configured for {}",
                dir.display()
            ),
        )))
    }

    pub(super) fn enumerate_root_directories_impl(&self) -> Result<Vec<PathBuf>> {
        let dirs = self
            .root_directories
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clone();
        let symlinks = self
            .root_symlinks
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clone();

        let mut result: Vec<PathBuf> = dirs
            .into_iter()
            .filter(|d| !symlinks.contains(d))
            .filter(|d| {
                if d.starts_with("/run/nails") {
                    tracing::debug!("Skipping NAILS runtime directory: {}", d.display());
                    false
                } else {
                    true
                }
            })
            .collect();

        result.sort();
        Ok(result)
    }
}
