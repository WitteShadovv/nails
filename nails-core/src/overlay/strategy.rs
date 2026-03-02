//! Universal overlay mounting strategy with automatic process management
//!
//! Implements a 4-phase algorithm to mount overlays intelligently:
//! 1. Detect blocking processes
//! 2. Classify and restart safe/risky processes
//! 3. Attempt direct mount (optimal security)
//! 4. Fall back to pivot mount if needed (with user consent)

use crate::{Filesystem, NailsError, Result};
use std::path::Path;

use super::pivot::pivot_overlay_mount;
use super::types::{MountMethod, MountResult, OverlayStrategyOptions};

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
