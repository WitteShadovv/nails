//! Forensic validation verifier implementation

use super::types::{Finding, ScanDepth, Severity, VerifyResult, VerifyStatus};
use crate::{Filesystem, Result};

/// Forensic validation verifier
///
/// Performs systematic checks to validate that no NAILS artifacts remain
/// on the system after deactivation.
pub struct Verifier<F: Filesystem> {
    filesystem: F,
}

impl<F: Filesystem> Verifier<F> {
    /// Create a new verifier with the given filesystem
    pub fn new(filesystem: F) -> Self {
        Self { filesystem }
    }

    /// Run the verification process
    ///
    /// # Arguments
    ///
    /// * `deep` - If true, perform comprehensive deep scan
    ///
    /// # Returns
    ///
    /// `VerifyResult` containing all findings and overall status
    pub fn run(&self, deep: bool) -> Result<VerifyResult> {
        let mut findings = Vec::new();

        // 1. Check for overlay mounts
        findings.extend(self.check_overlay_mounts()?);

        // 2. Check for artifact files
        findings.extend(self.check_artifact_files()?);

        // 3. Check for nails processes
        findings.extend(self.check_nails_processes()?);

        // 4. Check memory status
        findings.extend(self.check_memory_status()?);

        // 5. Deep scan if requested
        if deep {
            findings.extend(self.deep_scan()?);
        }

        // Determine overall status
        let status = if findings.iter().any(|f| f.severity == Severity::Critical) {
            VerifyStatus::Critical
        } else if findings.iter().any(|f| f.severity == Severity::Warn) {
            VerifyStatus::Warning
        } else {
            VerifyStatus::Secure
        };

        let scan_depth = if deep {
            ScanDepth::Deep
        } else {
            ScanDepth::Standard
        };

        Ok(VerifyResult::new(status, findings, scan_depth))
    }

    /// Check for active overlay mounts
    fn check_overlay_mounts(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check common mount points for overlay filesystems
        let mount_points = vec![
            std::path::Path::new("/home"),
            std::path::Path::new("/etc"),
            std::path::Path::new("/root"),
        ];

        for mount_point in mount_points {
            if self.filesystem.is_mounted(mount_point)? {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "mount",
                        format!("Overlay mount found at {}", mount_point.display()),
                    )
                    .with_fix_guidance("Run 'nails deactivate' to unmount overlays"),
                );
            }
        }

        Ok(findings)
    }

    /// Check for artifact files in common locations
    fn check_artifact_files(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Define artifact paths to check
        let artifact_paths = vec![
            "/tmp/nails.log",
            "/tmp/nails.toml",
            "/var/log/nails.log",
            "/etc/nails",
            "/home/.nails",
            "/root/.nails",
        ];

        for path in artifact_paths {
            let path_buf = std::path::PathBuf::from(path);
            if self.filesystem.path_exists(&path_buf)? {
                findings.push(
                    Finding::new(
                        Severity::Warn,
                        "file",
                        format!("Artifact file found: {}", path),
                    )
                    .with_fix_guidance(format!("Delete file: rm {}", path)),
                );
            }
        }

        Ok(findings)
    }

    /// Check for nails-related processes
    fn check_nails_processes(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if nails processes are running
        if self.filesystem.nails_process_running()? {
            findings.push(
                Finding::new(
                    Severity::Critical,
                    "process",
                    "NAILS-related process is currently running",
                )
                .with_fix_guidance("Stop all nails processes before deactivation"),
            );
        }

        Ok(findings)
    }

    /// Check memory status (swap warnings)
    fn check_memory_status(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if swap is enabled
        if self.filesystem.swap_is_enabled()? {
            findings.push(
                Finding::new(
                    Severity::Info,
                    "memory",
                    "Swap is enabled - sensitive data may persist in swap space",
                )
                .with_fix_guidance("Consider disabling swap: swapoff -a"),
            );
        }

        // Always add RAM persistence warning as Info
        findings.push(Finding::new(
            Severity::Info,
            "memory",
            "RAM may retain data briefly after shutdown - consider cold boot for maximum security",
        ));

        Ok(findings)
    }

    /// Perform deep scan of temporary directories and logs
    fn deep_scan(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Deep scan paths - recursively scan for any nails-related files
        let deep_scan_paths = vec!["/tmp", "/var/tmp", "/var/log"];

        for base_path in deep_scan_paths {
            let path_buf = std::path::PathBuf::from(base_path);
            if self.filesystem.path_exists(&path_buf)? && self.filesystem.is_directory(&path_buf)? {
                // Recursively scan for files matching "nails" pattern
                let matching_files = self
                    .filesystem
                    .find_files_with_pattern(&path_buf, "nails")?;

                for file in matching_files {
                    findings.push(
                        Finding::new(
                            Severity::Warn,
                            "file",
                            format!("NAILS-related file found: {}", file.display()),
                        )
                        .with_fix_guidance(format!("Delete file: rm {}", file.display())),
                    );
                }
            }
        }

        // Check history files for nails commands
        let history_files = vec![
            "/root/.bash_history",
            "/root/.zsh_history",
            "/home/.bash_history",
            "/home/.zsh_history",
        ];

        for history_file in history_files {
            let path_buf = std::path::PathBuf::from(history_file);
            if self.filesystem.path_exists(&path_buf)? {
                // Read file contents and check for nails commands
                match self.filesystem.read_file_content(&path_buf) {
                    Ok(content) => {
                        if content.to_lowercase().contains("nails") {
                            findings.push(
                                Finding::new(
                                    Severity::Warn,
                                    "file",
                                    format!(
                                        "Shell history contains nails commands: {}",
                                        history_file
                                    ),
                                )
                                .with_fix_guidance(format!(
                                    "Edit history to remove nails commands: nano {}",
                                    history_file
                                )),
                            );
                        }
                    }
                    Err(_) => {
                        // File exists but cannot be read (permissions or binary file)
                        findings.push(
                            Finding::new(
                                Severity::Info,
                                "file",
                                format!(
                                    "History file exists (cannot read contents): {}",
                                    history_file
                                ),
                            )
                            .with_fix_guidance("Review history manually if needed"),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
