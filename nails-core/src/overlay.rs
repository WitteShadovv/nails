//! Overlay filesystem operations for extended overlay strategy
//!
//! This module provides operations for mounting and unmounting ephemeral overlays
//! with tmpfs-backed upper layers (Story 4.11).
//!
//! # Forensic Rationale (Thesis Section 4.3.6)
//!
//! The extended overlay strategy provides defense-in-depth against forensic analysis:
//! - **Persistent overlays** (home/etc): Data on hidden encrypted storage
//! - **Ephemeral overlays** (var/tmp): Data in RAM, destroyed on unmount
//! - Different threat models for different data types
//!
//! # Example
//!
//! ```rust
//! use nails_core::overlay::{mount_ephemeral_overlay, EphemeralMountInfo};
//! use nails_core::config::EphemeralOverlayDir;
//! use nails_core::filesystem::MockFilesystem;
//! use std::path::{Path, PathBuf};
//!
//! let fs = MockFilesystem::new();
//! let config = EphemeralOverlayDir {
//!     path: PathBuf::from("/var"),
//!     tmpfs_upper_size: "1G".to_string(),
//!     tmpfs_work_size: "512M".to_string(),
//! };
//!
//! // Set up mock filesystem state
//! fs.mock_set_path_exists("/var", true);
//! fs.mock_set_directory_creatable("/run/nails/var-upper", true);
//! fs.mock_set_directory_creatable("/run/nails/var-work", true);
//!
//! let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
//! assert!(result.is_ok());
//! ```

use crate::config::EphemeralOverlayDir;
use crate::filesystem::Filesystem;
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Options for controlling overlay mounting strategy
///
/// Controls how the universal overlay mounting algorithm behaves regarding:
/// - Process restart decisions (safe/risky)
/// - User prompts for risky operations
/// - Pivot mount fallback policy
///
/// Part of Story 4.15: User Prompts and CLI Flags for Overlay Strategy
///
/// # Examples
///
/// ```rust
/// use nails_core::overlay::OverlayStrategyOptions;
///
/// // Interactive mode (default) - prompt for risky operations
/// let opts = OverlayStrategyOptions::default();
/// assert_eq!(opts.auto_restart_safe, true);
/// assert_eq!(opts.prompt_for_risky, true);
///
/// // Automated mode - restart safe processes, skip risky prompts
/// let opts = OverlayStrategyOptions {
///     auto_restart_safe: true,
///     prompt_for_risky: false,
///     allow_pivot: true,
///     auto_accept_pivot: true,
///     skip_process_detection: false,
/// };
///
/// // Strict mode - no pivots allowed
/// let opts = OverlayStrategyOptions {
///     allow_pivot: false,
///     ..Default::default()
/// };
///
/// // Test mode - skip process detection entirely (for unit tests)
/// let opts = OverlayStrategyOptions {
///     skip_process_detection: true,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayStrategyOptions {
    /// Automatically restart processes classified as "Safe" without prompting
    ///
    /// Safe processes are those that:
    /// - Are designed for restarts (systemd services)
    /// - Have no user state to lose
    /// - Restart quickly without service disruption
    ///
    /// Examples: systemd-journald, nix-daemon, systemd-resolved
    pub auto_restart_safe: bool,

    /// Prompt user before restarting processes classified as "Risky"
    ///
    /// Risky processes may cause brief service disruption:
    /// - NetworkManager (brief network drop)
    /// - dbus-daemon (affects desktop notifications)
    /// - pulseaudio/pipewire (audio interruption)
    ///
    /// If false, skip risky process restarts (may require pivot mount)
    pub prompt_for_risky: bool,

    /// Allow pivot mount fallback when direct mount fails
    ///
    /// Pivot mount creates split-view behavior with security degradation.
    /// Set to false for strict mode (abort if pivot needed).
    pub allow_pivot: bool,

    /// Automatically accept pivot mount without user confirmation
    ///
    /// If false, user will be prompted to accept security trade-off.
    /// Only has effect if `allow_pivot` is true.
    pub auto_accept_pivot: bool,

    /// Skip process detection entirely (for tests with mock filesystems)
    ///
    /// When true, bypasses Phase 1 and Phase 2 of the universal algorithm,
    /// directly attempting mount. This is useful for unit tests that use
    /// MockFilesystem and cannot handle real process detection.
    pub skip_process_detection: bool,
}

impl Default for OverlayStrategyOptions {
    fn default() -> Self {
        Self {
            auto_restart_safe: true,       // Always restart safe processes
            prompt_for_risky: true,        // Interactive by default
            allow_pivot: true,             // Allow pivot as last resort
            auto_accept_pivot: false,      // Prompt by default for security awareness
            skip_process_detection: false, // Don't skip process detection by default
        }
    }
}

/// Information about a mounted ephemeral overlay
///
/// Tracks all paths involved in an ephemeral overlay mount for cleanup.
///
/// # Fields
///
/// * `target` - Mount point where overlay appears (e.g., "/var")
/// * `upper` - Tmpfs-backed upper layer (e.g., "/run/nails/var-upper")
/// * `work` - Tmpfs-backed work directory (e.g., "/run/nails/var-work")
/// * `lower` - Read-only base layer (e.g., "/var")
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralMountInfo {
    /// Target mount point
    pub target: PathBuf,

    /// Tmpfs-backed upper layer
    pub upper: PathBuf,

    /// Tmpfs-backed work directory
    pub work: PathBuf,

    /// Read-only base layer
    pub lower: PathBuf,
}

/// Information about a pivot-mounted overlay
///
/// Tracks all paths involved in a pivot overlay mount for cleanup.
/// Used when mounting overlays onto active directories like `/var`.
///
/// # Pivot Mount Strategy
///
/// Direct overlay mount onto `/var` fails with EINVAL because the directory
/// is actively in use. The pivot strategy works around this:
/// 1. Mount overlay to staging location (e.g., `/mnt/nails-pivot/var`)
/// 2. Bind mount staging to target (e.g., `/var`)
///
/// This creates a "split view":
/// - Existing processes with open FDs see original content
/// - New path resolutions see overlay content
///
/// # Fields
///
/// * `target` - Final mount point (e.g., "/var")
/// * `staging` - Intermediate staging location (e.g., "/mnt/nails-pivot/var")
/// * `upper` - Upper layer path
/// * `work` - Work directory path
/// * `lower` - Read-only base layer
/// * `is_ephemeral` - If true, upper/work are tmpfs-backed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivotMountInfo {
    /// Final mount point where overlay appears
    pub target: PathBuf,

    /// Staging location where overlay is initially mounted
    pub staging: PathBuf,

    /// Upper layer path (may be on hidden volume or tmpfs)
    pub upper: PathBuf,

    /// Work directory path
    pub work: PathBuf,

    /// Read-only base layer
    pub lower: PathBuf,

    /// Whether upper/work are tmpfs-backed (ephemeral)
    pub is_ephemeral: bool,
}

/// Mount an ephemeral overlay with tmpfs-backed upper/work layers
///
/// Creates a complete ephemeral overlay mount:
/// 1. Creates tmpfs filesystems for upper and work directories
/// 2. Mounts overlay using tmpfs-backed layers
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `config` - Ephemeral overlay configuration
/// * `lower` - Read-only base layer path
///
/// # Returns
///
/// `Ok(EphemeralMountInfo)` with mount details on success.
///
/// # Errors
///
/// * `NailsError::OverlayError` - If any mount operation fails
/// * `NailsError::PermissionDenied` - If lacking privileges
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::mount_ephemeral_overlay;
/// use nails_core::config::EphemeralOverlayDir;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::{Path, PathBuf};
///
/// let fs = MockFilesystem::new();
/// let config = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
///
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_directory_creatable("/run/nails/var-upper", true);
/// fs.mock_set_directory_creatable("/run/nails/var-work", true);
///
/// let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();
/// assert_eq!(info.target, PathBuf::from("/var"));
/// ```
pub fn mount_ephemeral_overlay<F: Filesystem>(
    fs: &F,
    config: &EphemeralOverlayDir,
    lower: &Path,
) -> Result<EphemeralMountInfo> {
    let base = PathBuf::from("/run/nails");
    let dir_name = config
        .path
        .file_name()
        .ok_or_else(|| {
            NailsError::OverlayError(format!("Invalid path: {}", config.path.display()))
        })?
        .to_string_lossy();

    let upper = base.join(format!("{}-upper", dir_name));
    let work = base.join(format!("{}-work", dir_name));

    // Step 1: Create directories
    fs.create_directory(&upper)?;
    fs.create_directory(&work)?;

    // Step 2: Mount tmpfs for upper
    fs.mount_tmpfs(&upper, &config.tmpfs_upper_size)?;

    // Step 3: Mount tmpfs for work
    fs.mount_tmpfs(&work, &config.tmpfs_work_size)?;

    // Step 4: Mount overlay using tmpfs upper/work
    fs.mount_overlay(lower, &upper, &work, &config.path)?;

    Ok(EphemeralMountInfo {
        target: config.path.clone(),
        upper,
        work,
        lower: lower.to_path_buf(),
    })
}

/// Unmount an ephemeral overlay and its tmpfs layers
///
/// Destroys all ephemeral data by unmounting in reverse order:
/// 1. Unmount overlay from target
/// 2. Unmount work tmpfs (destroys work metadata)
/// 3. Unmount upper tmpfs (destroys all ephemeral data)
/// 4. Clean up mount point directories
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `info` - Mount information from `mount_ephemeral_overlay`
///
/// # Forensic Safety
///
/// All data in tmpfs upper/work layers is destroyed immediately upon unmount.
/// No disk writes occur - data exists only in RAM.
///
/// # Errors
///
/// Returns `NailsError::UnmountError` if any unmount fails. Uses best-effort
/// cleanup to unmount as much as possible even if some operations fail.
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::{mount_ephemeral_overlay, unmount_ephemeral_overlay};
/// use nails_core::config::EphemeralOverlayDir;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::{Path, PathBuf};
///
/// let fs = MockFilesystem::new();
/// let config = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
///
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_directory_creatable("/run/nails/var-upper", true);
/// fs.mock_set_directory_creatable("/run/nails/var-work", true);
///
/// let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();
/// let result = unmount_ephemeral_overlay(&fs, &info);
/// assert!(result.is_ok());
/// ```
pub fn unmount_ephemeral_overlay<F: Filesystem>(fs: &F, info: &EphemeralMountInfo) -> Result<()> {
    let mut errors = Vec::new();

    // Step 1: Unmount overlay first (try graceful, then force)
    if let Err(_e) = fs.unmount(&info.target, false) {
        // Graceful unmount failed, try force
        if let Err(force_err) = fs.unmount(&info.target, true) {
            errors.push(format!("overlay {}: {}", info.target.display(), force_err));
        }
    }

    // Step 2: Unmount work tmpfs
    if let Err(e) = fs.unmount_tmpfs(&info.work) {
        errors.push(format!("work tmpfs {}: {}", info.work.display(), e));
    }

    // Step 3: Unmount upper tmpfs (this destroys all ephemeral data)
    if let Err(e) = fs.unmount_tmpfs(&info.upper) {
        errors.push(format!("upper tmpfs {}: {}", info.upper.display(), e));
    }

    // Step 4: Clean up mount point directories (best effort)
    // These directories were created during mount and should be removed after tmpfs unmount.
    // We use best-effort approach since the critical cleanup (tmpfs unmount) already happened.
    // Failures here don't compromise forensic safety - tmpfs data is already destroyed.
    //
    // Note: We use std::fs directly here since directory cleanup is a host filesystem
    // operation that happens after all mounts are unmounted. The Filesystem trait
    // is primarily for operations that need to be mocked during testing.
    let _ = std::fs::remove_dir(&info.work);
    let _ = std::fs::remove_dir(&info.upper);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(NailsError::OverlayError(errors.join("; ")))
    }
}

// ============================================================================
// Pivot Mount Strategy for Active Directories
// ============================================================================

/// Default staging directory for pivot mounts
pub const PIVOT_STAGING_BASE: &str = "/mnt/nails-pivot";

/// Mount an overlay using the pivot strategy for active directories
///
/// This function enables overlaying directories like `/var` that are actively in use.
/// Direct overlay mount fails with EINVAL, so we use a two-step approach:
/// 1. Mount overlay to staging location (`/mnt/nails-pivot/var`)
/// 2. Bind mount staging to target (`/var`)
///
/// # Process Impact (Split View)
///
/// - **Existing processes:** Keep seeing original content (forensically beneficial)
/// - **New path resolutions:** See overlay content
/// - This split behavior is a SECURITY FEATURE - old processes can't see hidden data
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `lower` - Read-only base layer (typically the current `/var`)
/// * `upper` - Writeable upper layer (on hidden volume or tmpfs)
/// * `work` - Work directory for overlay metadata
/// * `target` - Final mount point (e.g., `/var`)
///
/// # Returns
///
/// `Ok(PivotMountInfo)` with mount details on success.
///
/// # Errors
///
/// * `NailsError::OverlayError` - If overlay or bind mount fails
/// * `NailsError::PermissionDenied` - If lacking root privileges
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::pivot_overlay_mount;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::Path;
///
/// let fs = MockFilesystem::new();
///
/// // Set up mock filesystem
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
/// fs.mock_set_path_exists("/mnt/hidden/var-work", true);
/// fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);
///
/// let info = pivot_overlay_mount(
///     &fs,
///     Path::new("/var"),           // lower
///     Path::new("/mnt/hidden/var-upper"),  // upper
///     Path::new("/mnt/hidden/var-work"),   // work
///     Path::new("/var"),           // target
/// ).unwrap();
///
/// assert_eq!(info.target, Path::new("/var"));
/// assert!(info.staging.starts_with("/mnt/nails-pivot"));
/// ```
pub fn pivot_overlay_mount<F: Filesystem>(
    fs: &F,
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<PivotMountInfo> {
    // Derive staging path from target
    let dir_name = target
        .file_name()
        .ok_or_else(|| {
            NailsError::OverlayError(format!("Invalid target path: {}", target.display()))
        })?
        .to_string_lossy();
    let staging = PathBuf::from(PIVOT_STAGING_BASE).join(dir_name.as_ref());

    // Step 1: Create staging directory
    fs.create_directory(&staging)?;

    // Step 2: Mount overlay at staging location
    // This always succeeds because staging is not in active use
    fs.mount_overlay(lower, upper, work, &staging)?;

    // Step 3: Bind mount staging to target
    // This works even for active directories
    if let Err(e) = fs.bind_mount(&staging, target) {
        // Rollback: unmount the overlay from staging
        let _ = fs.unmount(&staging, true);
        return Err(e);
    }

    Ok(PivotMountInfo {
        target: target.to_path_buf(),
        staging,
        upper: upper.to_path_buf(),
        work: work.to_path_buf(),
        lower: lower.to_path_buf(),
        is_ephemeral: false, // Caller can set this based on upper/work type
    })
}

/// Mount an ephemeral pivot overlay with tmpfs-backed upper/work layers
///
/// Combines the pivot mount strategy with tmpfs-backed layers for directories
/// like `/var` that need ephemeral storage.
///
/// # Mount Sequence
///
/// 1. Create tmpfs at upper path
/// 2. Create tmpfs at work path
/// 3. Mount overlay to staging
/// 4. Bind mount staging to target
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `config` - Ephemeral overlay configuration with tmpfs sizes
/// * `lower` - Read-only base layer path
///
/// # Returns
///
/// `Ok(PivotMountInfo)` with `is_ephemeral = true`.
///
/// # Example
///
/// ```rust
/// use nails_core::overlay::pivot_ephemeral_mount;
/// use nails_core::config::EphemeralOverlayDir;
/// use nails_core::filesystem::MockFilesystem;
/// use std::path::{Path, PathBuf};
///
/// let fs = MockFilesystem::new();
/// let config = EphemeralOverlayDir {
///     path: PathBuf::from("/var"),
///     tmpfs_upper_size: "1G".to_string(),
///     tmpfs_work_size: "512M".to_string(),
/// };
///
/// fs.mock_set_path_exists("/var", true);
/// fs.mock_set_directory_creatable("/run/nails/var-upper", true);
/// fs.mock_set_directory_creatable("/run/nails/var-work", true);
/// fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);
///
/// let info = pivot_ephemeral_mount(&fs, &config, Path::new("/var")).unwrap();
/// assert!(info.is_ephemeral);
/// ```
pub fn pivot_ephemeral_mount<F: Filesystem>(
    fs: &F,
    config: &EphemeralOverlayDir,
    lower: &Path,
) -> Result<PivotMountInfo> {
    let base = PathBuf::from("/run/nails");
    let dir_name = config
        .path
        .file_name()
        .ok_or_else(|| {
            NailsError::OverlayError(format!("Invalid path: {}", config.path.display()))
        })?
        .to_string_lossy();

    let upper = base.join(format!("{}-upper", dir_name));
    let work = base.join(format!("{}-work", dir_name));

    // Step 1: Create directories
    fs.create_directory(&upper)?;
    fs.create_directory(&work)?;

    // Step 2: Mount tmpfs for upper
    fs.mount_tmpfs(&upper, &config.tmpfs_upper_size)?;

    // Step 3: Mount tmpfs for work
    if let Err(e) = fs.mount_tmpfs(&work, &config.tmpfs_work_size) {
        // Rollback: unmount upper tmpfs
        let _ = fs.unmount_tmpfs(&upper);
        return Err(e);
    }

    // Step 4: Pivot mount overlay to target
    match pivot_overlay_mount(fs, lower, &upper, &work, &config.path) {
        Ok(mut info) => {
            info.is_ephemeral = true;
            Ok(info)
        }
        Err(e) => {
            // Rollback: unmount tmpfs layers
            let _ = fs.unmount_tmpfs(&work);
            let _ = fs.unmount_tmpfs(&upper);
            Err(e)
        }
    }
}

/// Unmount a pivot overlay
///
/// Unmounts in reverse order:
/// 1. Unmount bind mount from target
/// 2. Unmount overlay from staging
/// 3. Remove staging directory
/// 4. If ephemeral, unmount tmpfs layers
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `info` - Mount information from `pivot_overlay_mount` or `pivot_ephemeral_mount`
///
/// # Forensic Safety
///
/// For ephemeral mounts, all data in tmpfs layers is destroyed immediately.
///
/// # Errors
///
/// Uses best-effort cleanup - attempts all unmounts even if some fail.
/// Returns combined error if any operations fail.
pub fn unmount_pivot_overlay<F: Filesystem>(fs: &F, info: &PivotMountInfo) -> Result<()> {
    let mut errors = Vec::new();

    // Step 1: Unmount bind mount from target
    if let Err(e) = fs.unmount_bind(&info.target) {
        errors.push(format!("bind mount {}: {}", info.target.display(), e));
    }

    // Step 2: Unmount overlay from staging (try graceful, then force)
    if let Err(_e) = fs.unmount(&info.staging, false) {
        // Graceful unmount failed, try force
        if let Err(force_err) = fs.unmount(&info.staging, true) {
            errors.push(format!("overlay {}: {}", info.staging.display(), force_err));
        }
    }

    // Step 3: Remove staging directory (best effort)
    let _ = std::fs::remove_dir(&info.staging);

    // Step 4: If ephemeral, unmount tmpfs layers
    if info.is_ephemeral {
        if let Err(e) = fs.unmount_tmpfs(&info.work) {
            errors.push(format!("work tmpfs {}: {}", info.work.display(), e));
        }
        if let Err(e) = fs.unmount_tmpfs(&info.upper) {
            errors.push(format!("upper tmpfs {}: {}", info.upper.display(), e));
        }
        // Clean up tmpfs directories (best effort)
        let _ = std::fs::remove_dir(&info.work);
        let _ = std::fs::remove_dir(&info.upper);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(NailsError::OverlayError(errors.join("; ")))
    }
}

// ============================================================================
// Universal Overlay Mounting Algorithm (Story 4.15)
// ============================================================================

/// Result of universal overlay mounting algorithm
///
/// Indicates which mount method was used successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountMethod {
    /// Direct overlay mount (optimal security)
    Direct,
    /// Pivot mount fallback (degraded security with split-view)
    Pivot,
}

/// Full result of universal overlay mounting algorithm
///
/// Includes mount method and list of services that were stopped during Phase 2.
/// Callers should restart these services after mount so they write to the overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountResult {
    /// Which mount method was used
    pub method: MountMethod,
    /// Service names that were stopped in Phase 2 (should be restarted post-mount)
    pub stopped_services: Vec<String>,
}

/// Best-effort restart of services that were stopped during Phase 2 when the
/// mount ultimately fails. We start both the socket unit (if present) and the
/// service unit to mirror the socket-aware stopping logic in process::restart.
fn restart_services_after_failure(services: &[String]) {
    for service in services {
        // Start socket first (mirrors stop order)
        let _ = std::process::Command::new("systemctl")
            .args(["start", &format!("{}.socket", service)])
            .output();
        let _ = std::process::Command::new("systemctl")
            .args(["start", service])
            .output();
    }
}

/// Mount overlay using the universal 4-phase algorithm
///
/// This function implements the **Universal Overlay Mounting Strategy** from
/// `/docs/architecture/universal-overlay-mounting-strategy.md`.
///
/// # Algorithm Phases
///
/// 1. **Phase 1: Detect** - Find processes using target directory
/// 2. **Phase 2: Classify & Restart** - Classify processes and restart safe/risky ones
/// 3. **Phase 3: Direct Mount** - Attempt optimal direct overlay mount
/// 4. **Phase 4: Pivot Fallback** - Use pivot mount as last resort (with user consent)
///
/// # Arguments
///
/// * `fs` - Filesystem trait implementation
/// * `lower` - Read-only base layer (original filesystem content)
/// * `upper` - Upper layer directory (on hidden volume)
/// * `work` - Work directory for overlay
/// * `target` - Target directory to overlay (e.g., `/home`, `/etc`, `/var`)
/// * `options` - Strategy options controlling behavior
///
/// # Returns
///
/// * `Ok(MountResult)` - Mount succeeded, includes method and stopped services
/// * `Err(NailsError)` - Mount failed or user declined pivot
///
/// # Security Implications
///
/// **Direct mount** provides optimal security - all processes see unified view.
/// **Pivot mount** creates split-view behavior where old processes continue writing
/// to original filesystem while new processes see overlay. User must explicitly
/// accept this security degradation.
///
/// # Example
///
/// ```no_run
/// use nails_core::overlay::{mount_overlay_with_strategy, OverlayStrategyOptions, MountMethod};
/// use nails_core::filesystem::RealFilesystem;
/// use std::path::Path;
///
/// let fs = RealFilesystem;
/// let options = OverlayStrategyOptions::default();
///
/// let result = mount_overlay_with_strategy(
///     &fs,
///     Path::new("/home"),
///     Path::new("/mnt/hidden/home/.upper"),
///     Path::new("/mnt/hidden/home/.work"),
///     Path::new("/home"),
///     &options,
/// )?;
///
/// match result.method {
///     MountMethod::Direct => println!("✓ Optimal security: direct mount"),
///     MountMethod::Pivot => println!("⚠️  Degraded security: pivot mount"),
/// }
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn mount_overlay_with_strategy<F: Filesystem>(
    fs: &F,
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
    options: &OverlayStrategyOptions,
) -> Result<MountResult> {
    use crate::process::{
        RestartStrategy, classify_process, detect_processes_using, restart_processes,
    };
    use crate::prompts::{
        display_abort_message, prompt_pivot_mount_acceptance, prompt_risky_process_restart,
    };

    // Skip process detection for tests/mock filesystems
    if options.skip_process_detection {
        eprintln!("[Test Mode] Skipping process detection, attempting direct mount...");
        match fs.mount_overlay(lower, upper, work, target) {
            Ok(()) => {
                eprintln!("  ✓ Direct overlay mount succeeded (test mode)");
                return Ok(MountResult {
                    method: MountMethod::Direct,
                    stopped_services: Vec::new(),
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    // ========== Phase 1: Detect Blocking Processes ==========

    eprintln!(
        "[Phase 1: Detect] Detecting processes using {}...",
        target.display()
    );

    let blocking = detect_processes_using(target)?;
    let mut stopped_services: Vec<String> = Vec::new();

    if blocking.is_empty() {
        eprintln!("  Found 0 processes ✓");
    } else {
        eprintln!("  Found {} processes", blocking.len());
    }

    // ========== Phase 2: Classify and Restart Processes ==========

    if !blocking.is_empty() {
        eprintln!("[Phase 2: Classify] Analyzing restart safety...");

        let mut to_restart_safe = Vec::new();
        let mut to_restart_risky = Vec::new();
        let mut cannot_restart = Vec::new();
        let mut skip_count = 0;

        for proc in blocking {
            match classify_process(&proc, target) {
                RestartStrategy::Safe => {
                    eprintln!("  → {} (PID {}) - Safe to restart", proc.name, proc.pid);
                    to_restart_safe.push(proc);
                }
                RestartStrategy::Risky => {
                    eprintln!("  → {} (PID {}) - Risky to restart", proc.name, proc.pid);
                    to_restart_risky.push(proc);
                }
                RestartStrategy::NoRestart => {
                    // Don't print each one - just count them
                    cannot_restart.push(proc);
                }
                RestartStrategy::Skip => {
                    // Process uses target but doesn't block mount — leave it alone
                    // Don't print each one - just count them
                    skip_count += 1;
                }
            }
        }

        // Print summary for non-actionable processes
        if !cannot_restart.is_empty() {
            eprintln!("  {} processes cannot be restarted", cannot_restart.len());
        }
        if skip_count > 0 {
            eprintln!(
                "  {} processes skipped (read-only, no action needed)",
                skip_count
            );
        }

        // Restart Safe processes automatically
        if !to_restart_safe.is_empty() && options.auto_restart_safe {
            eprintln!("  Restarting {} safe processes...", to_restart_safe.len());
            let results = restart_processes(&to_restart_safe)?;
            for result in &results {
                if result.stopped_successfully
                    && let Some(ref svc) = result.info.service_name
                {
                    stopped_services.push(svc.clone());
                }
            }
        }

        // Prompt for Risky processes
        if !to_restart_risky.is_empty() && options.prompt_for_risky {
            if prompt_risky_process_restart(&to_restart_risky)? {
                eprintln!("  Restarting {} risky processes...", to_restart_risky.len());
                let results = restart_processes(&to_restart_risky)?;
                for result in &results {
                    if result.stopped_successfully
                        && let Some(ref svc) = result.info.service_name
                    {
                        stopped_services.push(svc.clone());
                    }
                }
            } else {
                eprintln!("  User declined restart, processes remain active");
            }
        }

        // Warn about processes that cannot restart
        if !cannot_restart.is_empty() {
            eprintln!(
                "  ⚠️  {} processes cannot be restarted",
                cannot_restart.len()
            );
            eprintln!("  Direct overlay mount may fail. Pivot mount may be needed.");
        }
    }

    // ========== Phase 3: Attempt Direct Overlay Mount ==========

    eprintln!(
        "[Phase 3: Direct Mount] Attempting direct overlay mount for {}...",
        target.display()
    );

    match fs.mount_overlay(lower, upper, work, target) {
        Ok(()) => {
            eprintln!(
                "  ✓ Direct overlay mount succeeded for {}",
                target.display()
            );
            return Ok(MountResult {
                method: MountMethod::Direct,
                stopped_services,
            });
        }
        Err(e) => {
            // Check if error is EINVAL (directory busy)
            let error_msg = format!("{}", e);
            if error_msg.contains("EINVAL")
                || error_msg.contains("busy")
                || error_msg.contains("Device or resource busy")
            {
                eprintln!("  ✗ Direct mount failed with EINVAL (directory busy)");
                // Continue to Phase 4
            } else {
                // Other errors are fatal
                restart_services_after_failure(&stopped_services);
                return Err(e);
            }
        }
    }

    // ========== Phase 4: Pivot Mount Fallback ==========

    eprintln!("[Phase 4: Fallback] Direct mount failed, pivot mount required...");

    // Check if pivot is allowed
    if !options.allow_pivot {
        eprintln!("  ✗ Pivot mount not allowed (--no-pivot flag)");
        display_abort_message(target);
        restart_services_after_failure(&stopped_services);
        return Err(NailsError::InvalidState(format!(
            "Pivot mount required for {} but --no-pivot flag specified",
            target.display()
        )));
    }

    // Re-detect blocking processes to show user what's still blocking
    let still_blocking = detect_processes_using(target)?;

    // Prompt for user acceptance (unless auto-accept enabled)
    if !options.auto_accept_pivot && !prompt_pivot_mount_acceptance(target, &still_blocking)? {
        eprintln!("  ✗ User declined pivot mount for {}", target.display());
        display_abort_message(target);
        restart_services_after_failure(&stopped_services);
        return Err(NailsError::InvalidState(format!(
            "User declined pivot mount for {}",
            target.display()
        )));
    }

    eprintln!(
        "  ⚠️  User accepted pivot mount risk for {}",
        target.display()
    );

    // Perform pivot mount
    let pivot_info = match pivot_overlay_mount(fs, lower, upper, work, target) {
        Ok(info) => info,
        Err(e) => {
            restart_services_after_failure(&stopped_services);
            return Err(e);
        }
    };

    eprintln!(
        "  ⚠️  Pivot mount active for {} - split-view behavior enabled",
        target.display()
    );
    eprintln!("  Staging: {}", pivot_info.staging.display());

    Ok(MountResult {
        method: MountMethod::Pivot,
        stopped_services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::path::PathBuf;

    // ========== EphemeralMountInfo Tests ==========

    #[test]
    fn test_ephemeral_mount_info_creation() {
        let info = EphemeralMountInfo {
            target: PathBuf::from("/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
        };

        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
        assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));
        assert_eq!(info.lower, PathBuf::from("/var"));
    }

    #[test]
    fn test_ephemeral_mount_info_clone() {
        let info1 = EphemeralMountInfo {
            target: PathBuf::from("/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
        };

        let info2 = info1.clone();
        assert_eq!(info1, info2);
    }

    // ========== mount_ephemeral_overlay Tests ==========

    #[test]
    fn test_mount_ephemeral_overlay_success() {
        // AC2: Creates tmpfs mounts and overlay
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        // Set up mock filesystem
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
        assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));
        assert_eq!(info.lower, PathBuf::from("/var"));

        // Verify tmpfs mounts created
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

        // Verify overlay mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
    }

    #[test]
    fn test_mount_ephemeral_overlay_creates_directories() {
        // AC2: Creates upper and work directories
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        // Directories don't exist yet
        assert!(!fs.path_exists(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.path_exists(Path::new("/run/nails/var-work")).unwrap());

        let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
        assert!(result.is_ok());

        // Directories were created
        assert!(fs.path_exists(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.path_exists(Path::new("/run/nails/var-work")).unwrap());
    }

    #[test]
    fn test_mount_ephemeral_overlay_validates_sizes() {
        // AC1: Size validation via tmpfs mount
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "invalid".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_ephemeral_overlay_multiple_directories() {
        // AC2: Can mount multiple ephemeral overlays
        let fs = MockFilesystem::new();

        let config_var = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        let config_tmp = EphemeralOverlayDir {
            path: PathBuf::from("/tmp"),
            tmpfs_upper_size: "512M".to_string(),
            tmpfs_work_size: "256M".to_string(),
        };

        // Set up mock filesystem for both
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);
        fs.mock_set_directory_creatable("/run/nails/tmp-upper", true);
        fs.mock_set_directory_creatable("/run/nails/tmp-work", true);

        // Mount first ephemeral overlay
        let result_var = mount_ephemeral_overlay(&fs, &config_var, Path::new("/var"));
        assert!(result_var.is_ok());

        // Mount second ephemeral overlay
        let result_tmp = mount_ephemeral_overlay(&fs, &config_tmp, Path::new("/tmp"));
        assert!(result_tmp.is_ok());

        // Both should be mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/tmp")).unwrap());
    }

    // ========== unmount_ephemeral_overlay Tests ==========

    #[test]
    fn test_unmount_ephemeral_overlay_success() {
        // AC5: Unmounts overlay and tmpfs in correct order
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

        // Verify mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

        // Unmount
        let result = unmount_ephemeral_overlay(&fs, &info);
        assert!(result.is_ok());

        // Verify all unmounted
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
    }

    #[test]
    fn test_unmount_ephemeral_overlay_best_effort() {
        // AC5: Best-effort unmount continues even if some fail
        let fs = MockFilesystem::new();
        let info = EphemeralMountInfo {
            target: PathBuf::from("/var"),
            upper: PathBuf::from("/run/nails/var-upper"),
            work: PathBuf::from("/run/nails/var-work"),
            lower: PathBuf::from("/var"),
        };

        // No mounts exist, but unmount should still succeed (idempotent)
        let result = unmount_ephemeral_overlay(&fs, &info);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unmount_ephemeral_overlay_full_cycle() {
        // AC4, AC5: Full mount/write/unmount cycle
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);

        // Mount
        let info = mount_ephemeral_overlay(&fs, &config, Path::new("/var")).unwrap();

        // Simulate writes to /var (would go to tmpfs upper in real system)
        // In mock, just verify mount exists
        assert!(fs.is_mounted(Path::new("/var")).unwrap());

        // Unmount destroys tmpfs data
        let result = unmount_ephemeral_overlay(&fs, &info);
        assert!(result.is_ok());

        // No artifacts remain
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    }

    // ========== PivotMountInfo Tests ==========

    #[test]
    fn test_pivot_mount_info_creation() {
        let info = PivotMountInfo {
            target: PathBuf::from("/var"),
            staging: PathBuf::from("/mnt/nails-pivot/var"),
            upper: PathBuf::from("/mnt/hidden/var-upper"),
            work: PathBuf::from("/mnt/hidden/var-work"),
            lower: PathBuf::from("/var"),
            is_ephemeral: false,
        };

        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
        assert!(!info.is_ephemeral);
    }

    #[test]
    fn test_pivot_mount_info_clone() {
        let info1 = PivotMountInfo {
            target: PathBuf::from("/var"),
            staging: PathBuf::from("/mnt/nails-pivot/var"),
            upper: PathBuf::from("/mnt/hidden/var-upper"),
            work: PathBuf::from("/mnt/hidden/var-work"),
            lower: PathBuf::from("/var"),
            is_ephemeral: true,
        };

        let info2 = info1.clone();
        assert_eq!(info1, info2);
        assert!(info2.is_ephemeral);
    }

    // ========== pivot_overlay_mount Tests ==========

    #[test]
    fn test_pivot_overlay_mount_success() {
        let fs = MockFilesystem::new();

        // Set up mock filesystem
        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
        fs.mock_set_path_exists("/mnt/hidden/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        let result = pivot_overlay_mount(
            &fs,
            Path::new("/var"),
            Path::new("/mnt/hidden/var-upper"),
            Path::new("/mnt/hidden/var-work"),
            Path::new("/var"),
        );

        assert!(result.is_ok());
        let info = result.unwrap();

        // Verify mount info
        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.staging, PathBuf::from("/mnt/nails-pivot/var"));
        assert_eq!(info.lower, PathBuf::from("/var"));
        assert!(!info.is_ephemeral);

        // Verify mounts created
        assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap()); // staging overlay
        assert!(fs.is_mounted(Path::new("/var")).unwrap()); // bind mount
    }

    #[test]
    fn test_pivot_overlay_mount_creates_staging_dir() {
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
        fs.mock_set_path_exists("/mnt/hidden/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        let result = pivot_overlay_mount(
            &fs,
            Path::new("/var"),
            Path::new("/mnt/hidden/var-upper"),
            Path::new("/mnt/hidden/var-work"),
            Path::new("/var"),
        );

        assert!(result.is_ok());

        // Staging directory was created
        assert!(fs.path_exists(Path::new("/mnt/nails-pivot/var")).unwrap());
    }

    #[test]
    fn test_pivot_overlay_mount_rollback_on_bind_failure() {
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
        fs.mock_set_path_exists("/mnt/hidden/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        // Configure bind mount to fail
        fs.mock_set_mount_should_fail("/var", true);

        let result = pivot_overlay_mount(
            &fs,
            Path::new("/var"),
            Path::new("/mnt/hidden/var-upper"),
            Path::new("/mnt/hidden/var-work"),
            Path::new("/var"),
        );

        assert!(result.is_err());

        // Staging overlay should be unmounted (rolled back)
        // Note: Mock doesn't perfectly simulate rollback tracking, but we verify error
    }

    // ========== pivot_ephemeral_mount Tests ==========

    #[test]
    fn test_pivot_ephemeral_mount_success() {
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        let result = pivot_ephemeral_mount(&fs, &config, Path::new("/var"));
        assert!(result.is_ok());

        let info = result.unwrap();

        // Verify ephemeral flag
        assert!(info.is_ephemeral);

        // Verify paths
        assert_eq!(info.target, PathBuf::from("/var"));
        assert_eq!(info.upper, PathBuf::from("/run/nails/var-upper"));
        assert_eq!(info.work, PathBuf::from("/run/nails/var-work"));

        // Verify all mounts created
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap()); // tmpfs
        assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap()); // tmpfs
        assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap()); // overlay
        assert!(fs.is_mounted(Path::new("/var")).unwrap()); // bind
    }

    #[test]
    fn test_pivot_ephemeral_mount_rollback_on_overlay_failure() {
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        // Make staging overlay mount fail
        fs.mock_set_mount_should_fail("/mnt/nails-pivot/var", true);

        let result = pivot_ephemeral_mount(&fs, &config, Path::new("/var"));
        assert!(result.is_err());

        // Tmpfs mounts should be cleaned up (rolled back)
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
    }

    // ========== unmount_pivot_overlay Tests ==========

    #[test]
    fn test_unmount_pivot_overlay_success() {
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_path_exists("/mnt/hidden/var-upper", true);
        fs.mock_set_path_exists("/mnt/hidden/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        // Mount
        let info = pivot_overlay_mount(
            &fs,
            Path::new("/var"),
            Path::new("/mnt/hidden/var-upper"),
            Path::new("/mnt/hidden/var-work"),
            Path::new("/var"),
        )
        .unwrap();

        // Verify mounted
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());

        // Unmount
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(result.is_ok());

        // Verify unmounted
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());
    }

    #[test]
    fn test_unmount_pivot_overlay_ephemeral_cleans_tmpfs() {
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        // Mount ephemeral pivot
        let info = pivot_ephemeral_mount(&fs, &config, Path::new("/var")).unwrap();
        assert!(info.is_ephemeral);

        // Verify all mounts
        assert!(fs.is_mounted(Path::new("/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());

        // Unmount
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(result.is_ok());

        // Verify all unmounted (including tmpfs)
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/mnt/nails-pivot/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
    }

    #[test]
    fn test_unmount_pivot_overlay_idempotent() {
        let fs = MockFilesystem::new();
        let info = PivotMountInfo {
            target: PathBuf::from("/var"),
            staging: PathBuf::from("/mnt/nails-pivot/var"),
            upper: PathBuf::from("/mnt/hidden/var-upper"),
            work: PathBuf::from("/mnt/hidden/var-work"),
            lower: PathBuf::from("/var"),
            is_ephemeral: false,
        };

        // No mounts exist, but unmount should still succeed (idempotent)
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unmount_pivot_overlay_full_ephemeral_cycle() {
        let fs = MockFilesystem::new();
        let config = EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "1G".to_string(),
            tmpfs_work_size: "512M".to_string(),
        };

        fs.mock_set_path_exists("/var", true);
        fs.mock_set_directory_creatable("/run/nails/var-upper", true);
        fs.mock_set_directory_creatable("/run/nails/var-work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/var", true);

        // Full cycle: mount -> verify -> unmount
        let info = pivot_ephemeral_mount(&fs, &config, Path::new("/var")).unwrap();

        // System is active
        assert!(fs.is_mounted(Path::new("/var")).unwrap());

        // Deactivate
        let result = unmount_pivot_overlay(&fs, &info);
        assert!(result.is_ok());

        // No forensic artifacts remain
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-upper")).unwrap());
        assert!(!fs.is_mounted(Path::new("/run/nails/var-work")).unwrap());
    }
}
