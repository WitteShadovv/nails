//! Temporary files cleanup for nails-related artifacts

#[cfg(test)]
mod tests;

use crate::{output, Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

const FORBIDDEN_PATHS: &[&str] = &[
    "/", "/etc", "/home", "/var", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/root", "/boot",
    "/dev", "/proc", "/sys", "/run",
];

pub struct TempFilesCleaner<F: Filesystem> {
    filesystem: F,
    temp_dirs: Vec<PathBuf>,
    patterns: Vec<String>,
    preserved_paths: Vec<PathBuf>,
    pub(crate) secure_delete: bool,
}

impl<F: Filesystem> TempFilesCleaner<F> {
    pub fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            temp_dirs: vec![PathBuf::from("/tmp")],
            patterns: vec!["nails".to_string()],
            preserved_paths: Vec::new(),
            secure_delete: false,
        }
    }

    pub fn with_temp_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.temp_dirs = dirs;
        self
    }

    pub fn with_patterns(mut self, patterns: Vec<String>) -> Self {
        self.patterns = patterns;
        self
    }

    pub fn with_preserved_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.preserved_paths = paths;
        self
    }

    pub fn with_secure_delete(mut self, enabled: bool) -> Self {
        self.secure_delete = enabled;
        self
    }

    fn validate_temp_dir(&self, dir: &Path) -> Result<()> {
        let dir_str = dir.to_string_lossy();

        for forbidden in FORBIDDEN_PATHS {
            if dir_str == *forbidden {
                return Err(NailsError::InvalidArgument(format!(
                    "Refusing to clean system-critical directory: {}",
                    dir.display()
                )));
            }

            if *forbidden == "/run"
                && (dir_str == "/run/nails" || dir_str.starts_with("/run/nails/"))
            {
                continue;
            }

            if *forbidden == "/" {
                continue;
            }

            let forbidden_with_slash = format!("{}/", forbidden);
            if dir_str.starts_with(&forbidden_with_slash) {
                return Err(NailsError::InvalidArgument(format!(
                    "Refusing to clean under system-critical path {}: {}",
                    forbidden,
                    dir.display()
                )));
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn matches_pattern(&self, filename: &str) -> bool {
        if Self::is_preserved_config_file(Path::new(filename)) {
            return false;
        }

        let filename_lower = filename.to_lowercase();
        self.patterns
            .iter()
            .any(|pattern| filename_lower.contains(&pattern.to_lowercase()))
    }

    pub(crate) fn is_preserved_config_file(path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "yaml" | "yml" | "toml"))
    }

    fn remove_path(&self, path: &Path) -> Result<()> {
        if self.filesystem.is_directory(path)? {
            if self.secure_delete {
                self.filesystem.secure_delete_dir_all(path)
            } else {
                self.filesystem.remove_dir_all(path)
            }
        } else if self.secure_delete {
            self.filesystem.secure_delete(path)
        } else {
            self.filesystem.remove_file(path)
        }
    }

    fn should_preserve(&self, path: &Path) -> bool {
        self.preserved_paths
            .iter()
            .any(|preserved| preserved == path)
    }

    pub fn clean(&self) -> Result<Vec<String>> {
        let mut cleaned = Vec::new();
        let mut errors = Vec::new();

        for temp_dir in &self.temp_dirs {
            self.validate_temp_dir(temp_dir)?;

            for pattern in &self.patterns {
                match self.filesystem.find_files_with_pattern(temp_dir, pattern) {
                    Ok(files) => {
                        for file in files {
                            if self.should_preserve(&file) || Self::is_preserved_config_file(&file)
                            {
                                continue;
                            }

                            match self.remove_path(&file) {
                                Ok(()) => {
                                    cleaned.push(format!("Removed {}", file.display()));
                                }
                                Err(e) => {
                                    errors.push(format!(
                                        "Failed to remove {}: {}",
                                        file.display(),
                                        e
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Failed to scan {}: {}", temp_dir.display(), e));
                    }
                }
            }
        }

        for error in &errors {
            output::warn(error);
        }

        Ok(cleaned)
    }
}
