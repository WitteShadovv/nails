//! Universal overlay mounting strategy with automatic process management
//!
//! Implements a 4-phase algorithm to mount overlays intelligently:
//! 1. Detect blocking processes
//! 2. Classify and restart safe/risky processes
//! 3. Attempt direct mount (optimal security)
//! 4. Fall back to pivot mount if needed (with user consent)

use crate::{Filesystem, NailsError, Result};
use std::path::Path;

use super::pivot::{pivot_overlay_mount, snapshot_pivot_overlay_mount};
use super::types::{MountMethod, MountResult, OverlayStrategyOptions};

/// Filesystems that do not support overlayfs as a lower layer.
///
/// These lack POSIX semantics overlayfs requires (xattrs, d_type, etc.).
/// When the target mount point uses one of these, the snapshot pivot strategy
/// is used instead: copy contents to tmpfs, overlay the tmpfs, bind mount back.
pub const OVERLAY_INCOMPATIBLE_FSTYPES: &[&str] = &[
    "vfat",
    "fat",
    "msdos",
    "exfat",
    "ntfs",
    "ntfs3",
    "fuse.ntfs-3g",
];

/// Check whether a filesystem type supports overlayfs
fn fstype_supports_overlay(fstype: &str) -> bool {
    !OVERLAY_INCOMPATIBLE_FSTYPES.contains(&fstype)
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
///     &[Path::new("/home")],
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
    lower: &[&Path],
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

    // ========== Pre-check: Filesystem compatibility ==========
    //
    // Some filesystems (vfat, exfat, ntfs) lack POSIX semantics that overlayfs
    // requires — not just as mount target, but also as a lower layer (missing d_type).
    // Neither direct overlay nor plain pivot works. Instead, we use the "snapshot pivot":
    // copy target contents to a tmpfs in RAM, use that as the overlay lower layer,
    // then bind mount over the original.
    //
    // No --accept-pivot-risks flag needed because there's no split-view security concern
    // (no active processes on these mounts). Also bypasses --no-pivot for the same reason.
    let target_fstype = fs.get_filesystem_type(target)?;
    let fs_incompatible = target_fstype
        .as_deref()
        .is_some_and(|ft| !fstype_supports_overlay(ft));

    if fs_incompatible {
        let fstype = target_fstype.as_deref().unwrap_or("unknown");
        eprintln!(
            "[Snapshot Pivot] {} is on {} (overlay-incompatible), copying to tmpfs",
            target.display(),
            fstype,
        );

        let pivot_info = snapshot_pivot_overlay_mount(fs, lower, upper, work, target)?;

        eprintln!(
            "  ✓ Snapshot pivot succeeded for {} (snapshot: {})",
            target.display(),
            pivot_info.lower.display()
        );

        return Ok(MountResult {
            method: MountMethod::Pivot,
            stopped_services: Vec::new(),
        });
    }

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
    // (fs_incompatible targets already returned via pivot above)

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
            let error_msg = format!("{}", e);
            if error_msg.contains("Invalid argument")
                || error_msg.contains("Device or resource busy")
                || error_msg.contains("not supported")
            {
                eprintln!(
                    "  ✗ Direct mount failed ({}), trying pivot fallback",
                    error_msg.lines().next().unwrap_or("unknown error")
                );
                // Continue to Phase 4
            } else {
                // Other errors are fatal
                restart_services_after_failure(&stopped_services);
                return Err(e);
            }
        }
    }

    // ========== Phase 4: Pivot Mount Fallback (busy directory) ==========
    //
    // Reached only when direct mount failed on a compatible filesystem (busy dir).
    // This creates split-view behavior — respect --no-pivot and prompt user.

    eprintln!("[Phase 4: Fallback] Direct mount failed, pivot mount required...");

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

    #[test]
    fn test_fstype_supports_overlay_compatible() {
        assert!(fstype_supports_overlay("ext4"));
        assert!(fstype_supports_overlay("xfs"));
        assert!(fstype_supports_overlay("btrfs"));
        assert!(fstype_supports_overlay("tmpfs"));
        assert!(fstype_supports_overlay("overlay"));
    }

    #[test]
    fn test_fstype_supports_overlay_incompatible() {
        assert!(!fstype_supports_overlay("vfat"));
        assert!(!fstype_supports_overlay("fat"));
        assert!(!fstype_supports_overlay("msdos"));
        assert!(!fstype_supports_overlay("exfat"));
        assert!(!fstype_supports_overlay("ntfs"));
        assert!(!fstype_supports_overlay("ntfs3"));
        assert!(!fstype_supports_overlay("fuse.ntfs-3g"));
    }

    /// Helper: set up a MockFilesystem for snapshot pivot tests
    fn setup_vfat_boot(fs: &crate::filesystem::MockFilesystem) {
        use std::path::Path;
        fs.mock_set_filesystem_type(Path::new("/boot"), "vfat");
        fs.mock_set_path_exists("/boot", true);
        fs.mock_set_path_exists("/mnt/hidden/boot/.upper", true);
        fs.mock_set_path_exists("/mnt/hidden/boot/.work", true);
        // Snapshot pivot needs: snapshot dir + staging dir creatable
        fs.mock_set_directory_creatable("/mnt/nails-pivot/boot-snapshot", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/boot", true);
    }

    #[test]
    fn test_vfat_boot_uses_snapshot_pivot_bypassing_no_pivot() {
        use crate::filesystem::MockFilesystem;

        let fs = MockFilesystem::new();
        setup_vfat_boot(&fs);

        // --no-pivot set, but vfat should bypass it via snapshot pivot
        let options = OverlayStrategyOptions {
            allow_pivot: false,
            auto_accept_pivot: false,
            skip_process_detection: true,
            ..Default::default()
        };

        let result = mount_overlay_with_strategy(
            &fs,
            &[std::path::Path::new("/boot")],
            std::path::Path::new("/mnt/hidden/boot/.upper"),
            std::path::Path::new("/mnt/hidden/boot/.work"),
            std::path::Path::new("/boot"),
            &options,
        );

        assert!(
            result.is_ok(),
            "vfat target should use snapshot pivot: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().method, MountMethod::Pivot);
    }

    #[test]
    fn test_exfat_target_uses_snapshot_pivot() {
        use crate::filesystem::MockFilesystem;
        use std::path::Path;

        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/boot"), "exfat");
        fs.mock_set_path_exists("/boot", true);
        fs.mock_set_path_exists("/mnt/hidden/boot/.upper", true);
        fs.mock_set_path_exists("/mnt/hidden/boot/.work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/boot-snapshot", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/boot", true);

        let options = OverlayStrategyOptions {
            allow_pivot: false,
            skip_process_detection: true,
            ..Default::default()
        };

        let result = mount_overlay_with_strategy(
            &fs,
            &[Path::new("/boot")],
            Path::new("/mnt/hidden/boot/.upper"),
            Path::new("/mnt/hidden/boot/.work"),
            Path::new("/boot"),
            &options,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, MountMethod::Pivot);
    }

    #[test]
    fn test_ext4_target_uses_direct_mount() {
        use crate::filesystem::MockFilesystem;
        use std::path::Path;

        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/home"), "ext4");
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/mnt/hidden/home/.upper", true);
        fs.mock_set_path_exists("/mnt/hidden/home/.work", true);

        let options = OverlayStrategyOptions {
            allow_pivot: false,
            skip_process_detection: true,
            ..Default::default()
        };

        let result = mount_overlay_with_strategy(
            &fs,
            &[Path::new("/home")],
            Path::new("/mnt/hidden/home/.upper"),
            Path::new("/mnt/hidden/home/.work"),
            Path::new("/home"),
            &options,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, MountMethod::Direct);
    }

    #[test]
    fn test_no_fstype_info_attempts_direct_mount() {
        use crate::filesystem::MockFilesystem;
        use std::path::Path;

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/data", true);
        fs.mock_set_path_exists("/mnt/hidden/data/.upper", true);
        fs.mock_set_path_exists("/mnt/hidden/data/.work", true);

        let options = OverlayStrategyOptions {
            skip_process_detection: true,
            ..Default::default()
        };

        let result = mount_overlay_with_strategy(
            &fs,
            &[Path::new("/data")],
            Path::new("/mnt/hidden/data/.upper"),
            Path::new("/mnt/hidden/data/.work"),
            Path::new("/data"),
            &options,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, MountMethod::Direct);
    }

    #[test]
    fn test_ntfs_target_uses_snapshot_pivot() {
        use crate::filesystem::MockFilesystem;
        use std::path::Path;

        let fs = MockFilesystem::new();
        fs.mock_set_filesystem_type(Path::new("/mnt/windows"), "ntfs3");
        fs.mock_set_path_exists("/mnt/windows", true);
        fs.mock_set_path_exists("/mnt/hidden/windows/.upper", true);
        fs.mock_set_path_exists("/mnt/hidden/windows/.work", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/windows-snapshot", true);
        fs.mock_set_directory_creatable("/mnt/nails-pivot/windows", true);

        let options = OverlayStrategyOptions {
            allow_pivot: false,
            skip_process_detection: true,
            ..Default::default()
        };

        let result = mount_overlay_with_strategy(
            &fs,
            &[Path::new("/mnt/windows")],
            Path::new("/mnt/hidden/windows/.upper"),
            Path::new("/mnt/hidden/windows/.work"),
            Path::new("/mnt/windows"),
            &options,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, MountMethod::Pivot);
    }

    #[test]
    fn test_restart_services_after_failure_empty_list() {
        // Should not panic with empty list - no systemctl calls made
        restart_services_after_failure(&[]);
    }

    #[test]
    fn test_overlay_incompatible_fstypes_constant_not_empty() {
        assert!(!OVERLAY_INCOMPATIBLE_FSTYPES.is_empty());
        assert!(OVERLAY_INCOMPATIBLE_FSTYPES.contains(&"vfat"));
        assert!(OVERLAY_INCOMPATIBLE_FSTYPES.contains(&"ntfs3"));
    }

    #[test]
    fn test_mount_overlay_with_strategy_direct_mount_succeeds_when_no_fstype() {
        use crate::filesystem::MockFilesystem;
        use std::path::Path;

        // No filesystem type set (None) → fstype_supports_overlay returns true → direct mount
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/data", true);
        fs.mock_set_path_exists("/mnt/upper", true);
        fs.mock_set_path_exists("/mnt/work", true);

        let options = super::OverlayStrategyOptions {
            skip_process_detection: true,
            allow_pivot: false,
            ..Default::default()
        };

        let result = mount_overlay_with_strategy(
            &fs,
            &[Path::new("/data")],
            Path::new("/mnt/upper"),
            Path::new("/mnt/work"),
            Path::new("/data"),
            &options,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().method, MountMethod::Direct);
    }
}
