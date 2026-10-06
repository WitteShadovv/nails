// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn test_deactivation_report_new() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    assert!(report.is_successful());
    assert_eq!(report.unmounted_overlays.len(), 2);
    assert!(!report.was_already_inactive);
}
#[test]
fn test_deactivation_report_display_already_inactive() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: Vec::new(),
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(5),
        final_state: SystemState::Inactive,
        was_already_inactive: true,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    let output = format!("{}", report);
    assert!(output.contains("Already inactive"));
}
#[test]
fn test_deactivation_report_display_with_items() {
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Removed 3 history entries"));
    assert!(output.contains("/home"));
    assert!(output.contains("/etc"));
    assert!(output.contains("Deactivation complete"));
}
#[test]
fn test_deactivation_orchestrator_new() {
    let _manager = setup_active_manager();
    let config = CleanupConfig::default();

    let _orchestrator = DeactivationOrchestrator::new(config.clone());

    // Verify orchestrator is created successfully (no panic)
    // Config is private but we can test it works via run()
}
#[test]
fn test_deactivation_report_display_lists_cleanup_and_unrecorded_state() {
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: vec!["inactive: read-only file system".to_string()],
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Overlay Cleanup:"));
    assert!(output.contains("Removed 3 history entries"));
    assert!(output.contains("Unmounted Overlays:"));
    assert!(output.contains("/home"));
    assert!(output.contains("/etc"));
    assert!(output.contains("State Not Recorded"));
    assert!(output.contains("inactive: read-only file system"));
    assert!(!output.contains("Real Disk"));
    assert!(output.contains("✓ Deactivation complete"));
}
#[test]
fn test_deactivation_report_is_successful_with_inactive_state() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec![],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(100),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    assert!(report.is_successful());
}
#[test]
fn test_deactivation_report_is_not_successful_with_active_state() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec![],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(100),
        final_state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        was_already_inactive: false,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    assert!(!report.is_successful());
}
