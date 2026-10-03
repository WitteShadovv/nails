//! Forensic validation verifier implementation

use super::types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
use crate::artifacts::{self, ArtifactKind, ArtifactScope, ArtifactSeverity};
use crate::config::Config;
use crate::state::StateFile;
use crate::{Filesystem, Result};
use std::path::Path;

/// `/sys/block`, enumerated for open dm-crypt mappers and loop devices.
const SYS_BLOCK_DIR: &str = "/sys/block";

/// Kernel mount table, read to find the device backing the hidden volume.
const SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// Base-OS trees whose writable, non-overlay presence on the decoy block device
/// leaks a hidden session's package and `/usr` writes. `/` is checked separately.
const OS_TREE_MOUNTS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

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

        // 1b. While active, flag a writable non-overlay decoy OS tree.
        findings.extend(self.check_writable_decoy_mounts()?);

        // 2. Check for artifact files
        findings.extend(self.check_artifact_files()?);

        // 3. Check for nails processes
        findings.extend(self.check_nails_processes()?);

        // 4. Check memory status
        findings.extend(self.check_memory_status()?);

        // 4b. Name-independent open crypt mapper / loop device detection
        findings.extend(self.check_block_devices()?);

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

    /// While a hidden session is active, flag any base-OS tree on the decoy that
    /// is mounted writable and is not an overlay.
    ///
    /// The read-only invariant ([`crate::platform::ro_guard`]) says the decoy's
    /// base-OS trees are either overlaid or kept read-only for the session. A
    /// writable, non-overlay mount of `/` or `/usr` (and the other core binary
    /// roots) backed by a real block device means hidden-session writes are
    /// reaching the decoy disk — the exact leak the invariant exists to prevent —
    /// so it is reported Critical. The walk reads `/proc/self/mountinfo` directly
    /// rather than trusting recorded state; it runs only in the active state,
    /// since a writable decoy root is expected when nothing is hidden.
    fn check_writable_decoy_mounts(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let active = self
            .state
            .as_ref()
            .is_some_and(|state| matches!(state.state, crate::state::SystemState::Active { .. }));
        if !active {
            return Ok(findings);
        }

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Ok(findings);
        };

        let hidden_root = self
            .config
            .as_ref()
            .map(|config| config.hidden_volume_root.clone())
            .filter(|root| !root.as_os_str().is_empty());

        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            let pre_fields: Vec<&str> = pre.split(' ').collect();
            // mountinfo pre fields: id parent maj:min root mountpoint options ...
            let (Some(mount_point), Some(options)) = (pre_fields.get(4), pre_fields.get(5)) else {
                continue;
            };
            let post_fields: Vec<&str> = post.split(' ').collect();
            // mountinfo post fields: fstype source superopts.
            let (Some(fstype), Some(source)) = (post_fields.first(), post_fields.get(1)) else {
                continue;
            };

            let mount_point = Path::new(mount_point);
            let is_os_tree = mount_point == Path::new("/")
                || OS_TREE_MOUNTS
                    .iter()
                    .any(|tree| mount_point == Path::new(tree));
            if !is_os_tree {
                continue;
            }
            // A tree that lives under the hidden volume is supposed to be writable.
            if let Some(ref root) = hidden_root
                && mount_point.starts_with(root)
            {
                continue;
            }
            let writable = options.split(',').any(|opt| opt == "rw");
            let is_overlay = *fstype == "overlay";
            let block_backed = source.starts_with("/dev/");
            if writable && !is_overlay && block_backed {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "mount",
                        format!(
                            "Writable non-overlay decoy mount at {} ({fstype} on {source}); \
                             hidden-session writes are reaching the decoy disk",
                            mount_point.display()
                        ),
                    )
                    .with_fix_guidance(
                        "The decoy OS tree must be overlaid or kept read-only while hidden is \
                         active; run 'nails deactivate' and re-activate",
                    ),
                );
            }
        }

        Ok(findings)
    }

    /// Check for leftover NAILS artifacts drawn from the shared registry.
    ///
    /// Iterates [`artifacts::ARTIFACTS`] and flags every entry that resolves to a
    /// single filesystem path and still exists. Absolute paths (runtime and
    /// decoy traces) are always checked; hidden-root paths are checked against
    /// the configured hidden volume root when a config is available. Content
    /// markers and bare basenames do not map to one path — they are covered by
    /// the base-config pre-flight check and the disk-image harness instead.
    fn check_artifact_files(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let hidden_root = self
            .config
            .as_ref()
            .map(|config| config.hidden_volume_root.as_path());

        for artifact in artifacts::ARTIFACTS {
            let resolved = match artifact.kind {
                ArtifactKind::HiddenRootPath => {
                    hidden_root.and_then(|root| artifact.resolve_path(root))
                }
                _ => artifact.resolve_path(Path::new("")),
            };
            let Some(path) = resolved else {
                continue;
            };

            if self.filesystem.path_exists(&path)? {
                findings.push(
                    Finding::new(
                        map_artifact_severity(artifact.severity),
                        "file",
                        format!("Artifact file found: {}", path.display()),
                    )
                    .with_fix_guidance(artifact_fix_guidance(artifact.scope, &path)),
                );
            }
        }

        Ok(findings)
    }

    /// Name-independent detection of open dm-crypt mappers and loop devices.
    ///
    /// Reads `/sys/block`: a `dm-*` device whose `dm/uuid` begins with `CRYPT-`
    /// is a dm-crypt mapper, and a `loop*` device with a non-empty
    /// `loop/backing_file` is an attached loop device. The device that backs the
    /// hidden volume (and therefore the running binary) is reported at Info level
    /// — "close it before handing over the machine" — while any *other* open
    /// crypt mapper or loop device is a warning, because it can expose a second
    /// hidden volume regardless of the neutral name it was given.
    ///
    /// When `/sys/block` cannot be read (an offline scan, a container, or a mock
    /// without the fixture) this reports nothing rather than erroring.
    fn check_block_devices(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let entries = match self.filesystem.list_directory(Path::new(SYS_BLOCK_DIR)) {
            Ok(entries) => entries,
            Err(_) => return Ok(findings),
        };

        let own_sources = self.hidden_volume_backing_sources();

        for entry in entries {
            let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if name.starts_with("dm-") {
                let uuid = match self.filesystem.read_file_content(&entry.join("dm/uuid")) {
                    Ok(uuid) => uuid,
                    Err(_) => continue,
                };
                if !uuid.trim().starts_with("CRYPT-") {
                    continue;
                }
                let mapper_name = self
                    .filesystem
                    .read_file_content(&entry.join("dm/name"))
                    .map(|name| name.trim().to_string())
                    .unwrap_or_else(|_| name.to_string());
                let node = format!("/dev/mapper/{mapper_name}");
                let is_own = own_sources
                    .iter()
                    .any(|source| source == &node || source.ends_with(&format!("/{mapper_name}")));
                findings.push(block_device_finding(
                    is_own,
                    "dm-crypt mapper",
                    &mapper_name,
                    &node,
                ));
            } else if name.starts_with("loop") {
                let backing = match self
                    .filesystem
                    .read_file_content(&entry.join("loop/backing_file"))
                {
                    Ok(backing) => backing.trim().to_string(),
                    Err(_) => continue,
                };
                if backing.is_empty() {
                    continue;
                }
                let node = format!("/dev/{name}");
                let is_own = own_sources
                    .iter()
                    .any(|source| source == &node || source == &backing);
                findings.push(block_device_finding(is_own, "loop device", &backing, &node));
            }
        }

        Ok(findings)
    }

    /// The source device(s) that `/proc/self/mountinfo` reports for the
    /// configured hidden volume root, used to tell the hidden volume's own
    /// backing device apart from any other open crypt mapper or loop device.
    fn hidden_volume_backing_sources(&self) -> Vec<String> {
        let Some(config) = self.config.as_ref() else {
            return Vec::new();
        };
        let root = config.hidden_volume_root.as_path();
        if root.as_os_str().is_empty() {
            return Vec::new();
        }

        let Ok(mountinfo) = self.filesystem.read_file_content(Path::new(SELF_MOUNTINFO)) else {
            return Vec::new();
        };

        let mut sources = Vec::new();
        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            // mountinfo pre-separator field 5 (index 4) is the mount point.
            let Some(mount_point) = pre.split(' ').nth(4) else {
                continue;
            };
            if Path::new(mount_point) != root {
                continue;
            }
            // Post-separator fields: fstype, source, super_opts.
            if let Some(source) = post.split(' ').nth(1) {
                sources.push(source.to_string());
            }
        }

        sources
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

        // 3. Check log directory for remaining logs.
        //
        // A log directory that sits on the hidden volume is the intended,
        // on-volume log location, not decoy-disk residue: those logs live where
        // they belong and are only reachable while the volume is mounted, which
        // the hidden-volume-path finding above already reports. Flagging them
        // here would turn the active log dir into a permanent false positive
        // every time `verify` runs from the hidden environment. Logs whose
        // directory sits outside the hidden root are a real leak onto the decoy
        // disk and are still flagged.
        let log_path = &config.log_path;
        paths_checked += 1;
        let log_is_on_hidden_volume =
            !hidden_vol.as_os_str().is_empty() && log_path.starts_with(hidden_vol);
        if !log_is_on_hidden_volume
            && self.filesystem.path_exists(log_path)?
            && self.filesystem.is_directory(log_path)?
        {
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
            crate::SystemState::Degraded {
                remaining_mounts, ..
            } => {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "state",
                        format!(
                            "State file indicates DEGRADED state — {} mount(s) may still be live",
                            remaining_mounts.len()
                        ),
                    )
                    .with_fix_guidance(
                        "Run 'nails recover' to finish teardown, then 'nails verify --deep'",
                    ),
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

/// Map a registry severity hint onto a verification severity.
fn map_artifact_severity(severity: ArtifactSeverity) -> Severity {
    match severity {
        ArtifactSeverity::Info => Severity::Info,
        ArtifactSeverity::Warn => Severity::Warn,
        ArtifactSeverity::Critical => Severity::Critical,
    }
}

/// Fix guidance for a leftover artifact, tailored to where it lives.
fn artifact_fix_guidance(scope: ArtifactScope, path: &Path) -> String {
    match scope {
        ArtifactScope::Runtime => format!(
            "Runtime leftover from an incomplete teardown; run 'nails deactivate' (then confirm {} is gone)",
            path.display()
        ),
        ArtifactScope::Decoy => {
            format!(
                "Trace on the decoy filesystem; remove it: rm -rf {}",
                path.display()
            )
        }
        ArtifactScope::HiddenRoot => format!(
            "Expected on the hidden volume while mounted; unmount it before handing over the machine ({})",
            path.display()
        ),
    }
}

/// Build a finding for an open crypt mapper or loop device.
fn block_device_finding(is_own: bool, kind: &str, label: &str, node: &str) -> Finding {
    if is_own {
        Finding::new(
            Severity::Info,
            "block-device",
            format!("Open {kind} backing the hidden volume: {label} ({node})"),
        )
        .with_fix_guidance(
            "Close it before handing over the machine (cryptsetup close / losetup -d)",
        )
    } else {
        Finding::new(
            Severity::Warn,
            "block-device",
            format!("Open {kind} not backing the hidden volume: {label} ({node})"),
        )
        .with_fix_guidance(format!(
            "An unexpected {kind} is open; close it if it is not in use ({node})"
        ))
    }
}
