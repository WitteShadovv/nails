//! Forensic validation verifier implementation

use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::config::Config;
use crate::obfuscate;
use crate::state::StateFile;
use crate::{Filesystem, Result};

/// Forensic validation verifier
///
/// Performs systematic checks to validate that no NAILS artifacts remain
/// on the system after deactivation.
pub struct Verifier<F: Filesystem> {
    filesystem: F,
    config: Option<Config>,
    state: Option<StateFile>,
    state_file_status: StateFileStatus,
}

impl<F: Filesystem> Verifier<F> {
    /// Create a new verifier with the given filesystem
    pub fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            config: None,
            state: None,
            state_file_status: StateFileStatus::NotChecked,
        }
    }

    /// Create a new verifier with config and optional state
    pub fn with_config(
        filesystem: F,
        config: Config,
        state: Option<StateFile>,
        state_file_status: StateFileStatus,
    ) -> Self {
        Self {
            filesystem,
            config: Some(config),
            state,
            state_file_status,
        }
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
        let mut config_paths_checked: usize = 0;

        // 1. Check for overlay mounts
        findings.extend(self.check_overlay_mounts()?);

        // 2. Check for artifact files
        findings.extend(self.check_artifact_files()?);

        // 3. Check for nails processes
        findings.extend(self.check_nails_processes()?);

        // 4. Check memory status
        findings.extend(self.check_memory_status()?);

        // 5. Config-aware checks (if config is available)
        if let Some(ref config) = self.config {
            let (config_findings, paths_checked) = self.check_config_paths(config)?;
            findings.extend(config_findings);
            config_paths_checked = paths_checked;
        }

        // 6. State-aware checks (if state is available)
        if let Some(ref state) = self.state {
            findings.extend(self.check_state(state)?);
        }

        // 7. Deep scan if requested
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

        if self.config.is_some() {
            Ok(VerifyResult::new_config_aware(
                status,
                findings,
                scan_depth,
                config_paths_checked,
                self.state_file_status.clone(),
            ))
        } else {
            Ok(VerifyResult::new(status, findings, scan_depth))
        }
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
            if self.filesystem.is_overlay_mounted(mount_point)? {
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

        // Use obfuscated artifact paths for forensic resistance
        let artifact_paths = obfuscate::artifact_paths();

        for path in artifact_paths {
            let path_buf = std::path::PathBuf::from(&path);
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

    /// Check config-specific paths for residual artifacts
    ///
    /// Checks overlay mount points from config, log directory, hidden volume path,
    /// and state file location for any residual NAILS artifacts.
    fn check_config_paths(&self, config: &Config) -> Result<(Vec<Finding>, usize)> {
        let mut findings = Vec::new();
        let mut paths_checked: usize = 0;

        // 1. Check config overlay mount points for residual mounts
        for overlay in &config.overlays {
            let mount_path = &overlay.target;
            paths_checked += 1;
            if self.filesystem.is_overlay_mounted(mount_path)? {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "config",
                        format!(
                            "Config overlay mount point still mounted: {}",
                            mount_path.display()
                        ),
                    )
                    .with_fix_guidance("Run 'nails deactivate' to unmount overlays"),
                );
            }
        }

        // 2. Check hidden volume path for accessibility
        let hidden_vol = &config.hidden_volume_root;
        paths_checked += 1;
        if self.filesystem.path_exists(hidden_vol)? {
            findings.push(
                Finding::new(
                    Severity::Warn,
                    "config",
                    format!("Hidden volume path is accessible: {}", hidden_vol.display()),
                )
                .with_fix_guidance("Ensure hidden volume is unmounted when not in use"),
            );
        }

        // 3. Check log directory for remaining logs
        let log_path = &config.log_path;
        paths_checked += 1;
        if self.filesystem.path_exists(log_path)? && self.filesystem.is_directory(log_path)? {
            let log_files = self.filesystem.find_files_with_pattern(log_path, "nails")?;
            for log_file in log_files {
                findings.push(
                    Finding::new(
                        Severity::Warn,
                        "config",
                        format!(
                            "Log file found in config log directory: {}",
                            log_file.display()
                        ),
                    )
                    .with_fix_guidance(format!("Delete log file: rm {}", log_file.display())),
                );
            }
        }

        // 4. Check state file location
        let state_path = &config.state_file_path;
        paths_checked += 1;
        if self.filesystem.path_exists(state_path)? {
            findings.push(
                Finding::new(
                    Severity::Warn,
                    "config",
                    format!(
                        "State file exists at configured path: {}",
                        state_path.display()
                    ),
                )
                .with_fix_guidance("State file should only exist on hidden volume when active"),
            );
        }

        Ok((findings, paths_checked))
    }

    /// Check state file for indicators of incomplete deactivation
    fn check_state(&self, state: &StateFile) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if state indicates system is still active or in transition
        match &state.state {
            crate::SystemState::Active { overlays, .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        format!(
                            "State file indicates system is ACTIVE with {} overlays",
                            overlays.len()
                        ),
                    )
                    .with_fix_guidance("Run 'nails deactivate' to properly shut down"),
                );
            }
            crate::SystemState::Activating { .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        "State file indicates system is stuck in ACTIVATING state",
                    )
                    .with_fix_guidance(
                        "Run 'nails deactivate --force' to clean up partial activation",
                    ),
                );
            }
            crate::SystemState::Deactivating { .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        "State file indicates system is stuck in DEACTIVATING state",
                    )
                    .with_fix_guidance("Run 'nails deactivate --force' to complete deactivation"),
                );
            }
            crate::SystemState::Emergency { .. } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        "State file indicates EMERGENCY state — system may have residual artifacts",
                    )
                    .with_fix_guidance("Run 'nails verify --deep' after manual cleanup"),
                );
            }
            crate::SystemState::Inactive => {
                // Good — system is inactive, no state-level concerns
            }
        }

        // Check for failed overlays from previous activation
        if !state.failed_overlays.is_empty() {
            findings.push(Finding::new(
                Severity::Info,
                "state",
                format!(
                    "State records {} failed overlay(s) from previous activation",
                    state.failed_overlays.len()
                ),
            ));
        }

        Ok(findings)
    }
}
