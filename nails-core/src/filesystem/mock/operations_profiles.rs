use super::{MockFilesystem, MockOp};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    pub(super) fn nixos_profile_exists_impl(&self, profile: &str) -> Result<bool> {
        Ok(self
            .nixos_profiles
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(&profile.to_string()))
    }

    pub(super) fn nixos_build_profile_impl(&self, profile: &str) -> Result<()> {
        self.nixos_profiles
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(profile.to_string());
        Ok(())
    }

    pub(super) fn nixos_switch_profile_impl(&self, profile: &str) -> Result<()> {
        let exists = self
            .nixos_profiles
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(&profile.to_string());
        if !exists {
            return Err(NailsError::NixOSProfileNotFound {
                profile: profile.to_string(),
            });
        }

        *self
            .current_profile
            .lock()
            .expect("MockFilesystem mutex poisoned") = Some(profile.to_string());
        Ok(())
    }

    pub(super) fn nixos_get_current_profile_impl(&self) -> Result<String> {
        self.current_profile
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .as_ref()
            .cloned()
            .ok_or_else(|| NailsError::InvalidState("No NixOS profile is currently active".into()))
    }

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
