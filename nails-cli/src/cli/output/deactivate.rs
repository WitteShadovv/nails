//! Output formatting for the deactivate command

/// JSON output structure for deactivate command (AC7)
#[allow(dead_code)]
#[derive(serde::Serialize)]
struct DeactivateJsonOutput {
    /// "success" or "error"
    status: String,
    /// Duration in seconds
    duration: f64,
    /// System state after deactivation (UPPERCASE per AC7: "INACTIVE" or "ACTIVE")
    state: String,
    /// List of cleaned items (history files, temp files, logs)
    cleaned_items: Vec<String>,
    /// Error messages (if any)
    errors: Vec<String>,
    /// Shell cleanup instructions
    #[serde(skip_serializing_if = "Option::is_none")]
    shell_cleanup: Option<ShellCleanupJson>,
}

#[allow(dead_code)]
#[derive(serde::Serialize)]
pub struct ShellCleanupJson {
    pub shell_type: String,
    pub instructions: Vec<String>,
    pub note: String,
}

/// Print deactivation result in JSON format (AC7)
#[allow(dead_code)]
pub fn print_deactivate_json<F: nails_core::Filesystem>(
    result: &Result<nails_core::DeactivationReport, nails_core::NailsError>,
    manager: &std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<F>>>,
    shell_cleanup: Option<&nails_core::ShellCleanupResult>,
) {
    let state = manager
        .lock()
        .unwrap()
        .current_state()
        .map(|s| format!("{:?}", s).to_uppercase())
        .unwrap_or_else(|_| "UNKNOWN".to_string());

    // Convert shell cleanup result to JSON structure
    let shell_cleanup_json = shell_cleanup.and_then(|cleanup| {
        cleanup
            .shell_type
            .as_ref()
            .map(|shell_type| ShellCleanupJson {
                shell_type: format!("{:?}", shell_type).to_lowercase(),
                instructions: cleanup.instructions.clone(),
                note: "Shell prompt may still show (NAILS-ACTIVE) until next login".to_string(),
            })
    });

    let output = match result {
        Ok(report) => DeactivateJsonOutput {
            status: if report.is_successful() {
                "success"
            } else {
                "error"
            }
            .to_string(),
            duration: report.duration.as_secs_f64(),
            state: format!("{:?}", report.final_state).to_uppercase(),
            cleaned_items: report.cleanup_report.cleaned_items.clone(),
            errors: report.cleanup_report.errors.clone(),
            shell_cleanup: shell_cleanup_json,
        },
        Err(e) => DeactivateJsonOutput {
            status: "error".to_string(),
            duration: 0.0,
            state,
            cleaned_items: vec![],
            errors: vec![e.to_string()],
            shell_cleanup: None,
        },
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
    );
}

/// Print deactivation result in human-readable format (AC3, AC4, AC5)
///
/// ## Error Path Testing (AC4, AC5)
/// Error paths are tested at the orchestrator level in nails-core.
/// CLI-level error path testing would require:
/// - Mocking DeactivationOrchestrator (not feasible without dependency injection)
/// - E2E test environment with LUKS volumes and overlayfs (requires VM/container)
/// - Simulating filesystem permission errors (requires root/sudo)
///
/// Current test coverage:
/// - Argument parsing and flag handling (unit tests)
/// - Success path E2E (integration tests verify idempotent behavior)
/// - Error formatting logic (covered by orchestrator tests in nails-core)
#[allow(dead_code)]
pub fn print_deactivate_human(
    result: &Result<nails_core::DeactivationReport, nails_core::NailsError>,
    verbosity: nails_core::Verbosity,
    no_color: bool,
    shell_cleanup: Option<&nails_core::ShellCleanupResult>,
    quiet: bool,
) {
    use colored::Colorize;
    use nails_core::{NailsError, Verbosity};

    match result {
        Ok(report) => {
            let check = if no_color { "[OK]" } else { "✓" };
            let duration = report.duration.as_secs_f64();

            if report.was_already_inactive {
                println!("{} Already inactive - no action needed", check);
                return;
            }

            // AC3: Print success message with duration (2 decimal places per spec)
            if no_color {
                println!("[OK] deactivation complete in {:.2}s", duration);
            } else {
                println!(
                    "{}",
                    format!("✓ deactivation complete in {:.2}s", duration)
                        .green()
                        .bold()
                );
            }

            // AC3: Print cleanup summary with cleaned items (UXR13)
            if verbosity >= Verbosity::Normal && !report.cleanup_report.cleaned_items.is_empty() {
                println!();
                println!("Cleanup Summary:");
                for item in &report.cleanup_report.cleaned_items {
                    println!("  {} {}", check, item);
                }
            }

            // Show unmounted overlays
            if verbosity >= Verbosity::Normal && !report.unmounted_overlays.is_empty() {
                println!();
                println!("Unmounted Overlays:");
                for overlay in &report.unmounted_overlays {
                    println!("  {} {}", check, overlay);
                }
            }

            // AC8: -vv shows debug info including state transitions
            if verbosity >= Verbosity::Debug {
                println!();
                println!("Final State: {:?}", report.final_state);
            }

            // Shell cleanup instructions (unless quiet mode)
            if !quiet
                && let Some(cleanup) = shell_cleanup
                && let Some(_shell_type) = cleanup.shell_type
            {
                println!();
                if no_color {
                    println!("Shell Cleanup:");
                    println!("Shell prompt will be restored in new terminals automatically.");
                    println!("To remove from this terminal now, run:");
                } else {
                    println!("{}", "Shell Cleanup:".cyan().bold());
                    println!(
                        "{}",
                        "Shell prompt will be restored in new terminals automatically.".green()
                    );
                    println!("{}", "To remove from this terminal now, run:".dimmed());
                }
                for cmd in &cleanup.instructions {
                    if no_color {
                        println!("  {}", cmd);
                    } else {
                        println!("  {}", cmd.bright_white());
                    }
                }
            }
        }
        Err(e) => {
            let cross = if no_color { "[FAIL]" } else { "✗" };

            // AC4, AC5: Detect error type and show appropriate message
            let (category, details, guidance) = match e {
                NailsError::PermissionDenied(msg) => (
                    "cleanup error",
                    msg.clone(),
                    "Check file permissions and retry with sudo".to_string(),
                ),
                NailsError::MountBusy { path, suggestion } => (
                    "unmount error",
                    format!("Overlay busy: {}", path.display()),
                    suggestion.clone(),
                ),
                NailsError::UnmountError { path, reason } => (
                    "unmount error",
                    format!("{}: {}", path.display(), reason),
                    "Check if overlay is in use and retry".to_string(),
                ),
                NailsError::InvalidState(msg) => (
                    "state error",
                    msg.clone(),
                    "Verify system is in ACTIVE state".to_string(),
                ),
                _ => (
                    "deactivation error",
                    e.to_string(),
                    "Check system state and retry".to_string(),
                ),
            };

            // Print error message
            if no_color {
                eprintln!("[FAIL] deactivation failed: {}", category);
            } else {
                eprintln!(
                    "{}",
                    format!("{} deactivation failed: {}", cross, category)
                        .red()
                        .bold()
                );
            }

            eprintln!();
            eprintln!("Details: {}", details);
            eprintln!();

            // AC4, AC5: Show state (ACTIVE after rollback)
            eprintln!("State: ACTIVE (rollback occurred)");
            eprintln!("Overlays: Remain mounted (safe state preserved)");
            eprintln!();

            // Show fix guidance
            if no_color {
                eprintln!("Fix: {}", guidance);
            } else {
                eprintln!("Fix: {}", guidance.yellow());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::{
        CleanupMode, CleanupReport, DeactivationReport, NailsError, ShellCleanupResult,
        SystemState, Verbosity,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn make_cleanup_report() -> CleanupReport {
        CleanupReport {
            cleaned_items: vec!["bash history".to_string(), "/tmp/nails-*".to_string()],
            errors: vec![],
            duration: Duration::from_millis(50),
            mode: CleanupMode::Fast,
            verification_passed: Some(true),
        }
    }

    fn make_success_report() -> DeactivationReport {
        DeactivationReport {
            cleanup_report: make_cleanup_report(),
            unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
            duration: Duration::from_millis(1234),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
        }
    }

    fn make_already_inactive_report() -> DeactivationReport {
        DeactivationReport {
            cleanup_report: make_cleanup_report(),
            unmounted_overlays: vec![],
            duration: Duration::from_millis(5),
            final_state: SystemState::Inactive,
            was_already_inactive: true,
        }
    }

    fn make_manager()
    -> std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<nails_core::MockFilesystem>>> {
        let fs = nails_core::MockFilesystem::new();
        let config = nails_core::Config::default();
        let manager =
            nails_core::NailsManager::new(fs, config, PathBuf::from("/tmp/test-state.json"));
        std::sync::Arc::new(std::sync::Mutex::new(manager))
    }

    // ── print_deactivate_human ─────────────────────────────────────────────────

    #[test]
    fn test_human_success_normal_verbosity() {
        let report = make_success_report();
        print_deactivate_human(&Ok(report), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_success_no_color() {
        let report = make_success_report();
        print_deactivate_human(&Ok(report), Verbosity::Normal, true, None, false);
    }

    #[test]
    fn test_human_success_debug_verbosity() {
        let report = make_success_report();
        print_deactivate_human(&Ok(report), Verbosity::Debug, false, None, false);
    }

    #[test]
    fn test_human_success_quiet_mode() {
        let report = make_success_report();
        print_deactivate_human(&Ok(report), Verbosity::Normal, false, None, true);
    }

    #[test]
    fn test_human_already_inactive() {
        let report = make_already_inactive_report();
        print_deactivate_human(&Ok(report), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_already_inactive_no_color() {
        let report = make_already_inactive_report();
        print_deactivate_human(&Ok(report), Verbosity::Normal, true, None, false);
    }

    #[test]
    fn test_human_with_shell_cleanup_color() {
        use nails_core::shell::ShellType;
        let report = make_success_report();
        let shell_cleanup = ShellCleanupResult {
            shell_type: Some(ShellType::Bash),
            instructions: vec!["source /tmp/cleanup.sh".to_string()],
            message: None,
        };
        print_deactivate_human(
            &Ok(report),
            Verbosity::Normal,
            false,
            Some(&shell_cleanup),
            false,
        );
    }

    #[test]
    fn test_human_with_shell_cleanup_no_color() {
        use nails_core::shell::ShellType;
        let report = make_success_report();
        let shell_cleanup = ShellCleanupResult {
            shell_type: Some(ShellType::Bash),
            instructions: vec!["unset NAILS_ACTIVE".to_string()],
            message: None,
        };
        print_deactivate_human(
            &Ok(report),
            Verbosity::Normal,
            true,
            Some(&shell_cleanup),
            false,
        );
    }

    #[test]
    fn test_human_with_shell_cleanup_no_shell_type() {
        let report = make_success_report();
        let shell_cleanup = ShellCleanupResult {
            shell_type: None,
            instructions: vec![],
            message: None,
        };
        print_deactivate_human(
            &Ok(report),
            Verbosity::Normal,
            false,
            Some(&shell_cleanup),
            false,
        );
    }

    #[test]
    fn test_human_error_permission_denied() {
        let err = NailsError::PermissionDenied("cannot remove /etc".to_string());
        print_deactivate_human(&Err(err), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_error_permission_denied_no_color() {
        let err = NailsError::PermissionDenied("cannot remove /etc".to_string());
        print_deactivate_human(&Err(err), Verbosity::Normal, true, None, false);
    }

    #[test]
    fn test_human_error_mount_busy() {
        let err = NailsError::MountBusy {
            path: PathBuf::from("/home"),
            suggestion: "Close your browser".to_string(),
        };
        print_deactivate_human(&Err(err), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_error_unmount_error() {
        let err = NailsError::UnmountError {
            path: PathBuf::from("/etc"),
            reason: "device busy".to_string(),
        };
        print_deactivate_human(&Err(err), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_error_invalid_state() {
        let err = NailsError::InvalidState("no active session".to_string());
        print_deactivate_human(&Err(err), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_error_other() {
        let err = NailsError::IoError(std::io::Error::other("unexpected"));
        print_deactivate_human(&Err(err), Verbosity::Normal, false, None, false);
    }

    #[test]
    fn test_human_success_empty_cleanup_and_overlays() {
        let report = DeactivationReport {
            cleanup_report: CleanupReport {
                cleaned_items: vec![],
                errors: vec![],
                duration: Duration::from_millis(0),
                mode: CleanupMode::Fast,
                verification_passed: None,
            },
            unmounted_overlays: vec![],
            duration: Duration::from_millis(100),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
        };
        print_deactivate_human(&Ok(report), Verbosity::Normal, false, None, false);
    }

    // ── print_deactivate_json ──────────────────────────────────────────────────

    #[test]
    fn test_json_success() {
        let manager = make_manager();
        let report = make_success_report();
        print_deactivate_json(&Ok(report), &manager, None);
    }

    #[test]
    fn test_json_already_inactive() {
        let manager = make_manager();
        let report = make_already_inactive_report();
        print_deactivate_json(&Ok(report), &manager, None);
    }

    #[test]
    fn test_json_with_shell_cleanup() {
        use nails_core::shell::ShellType;
        let manager = make_manager();
        let report = make_success_report();
        let shell_cleanup = ShellCleanupResult {
            shell_type: Some(ShellType::Bash),
            instructions: vec!["source /tmp/cleanup.sh".to_string()],
            message: None,
        };
        print_deactivate_json(&Ok(report), &manager, Some(&shell_cleanup));
    }

    #[test]
    fn test_json_with_shell_cleanup_no_type() {
        let manager = make_manager();
        let report = make_success_report();
        let shell_cleanup = ShellCleanupResult {
            shell_type: None,
            instructions: vec![],
            message: None,
        };
        print_deactivate_json(&Ok(report), &manager, Some(&shell_cleanup));
    }

    #[test]
    fn test_json_error() {
        let manager = make_manager();
        let err = NailsError::InvalidState("failed".to_string());
        print_deactivate_json(&Err(err), &manager, None);
    }
}
