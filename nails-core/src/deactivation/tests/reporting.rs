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
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
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
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
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
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
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
fn test_deactivation_report_display_with_post_unmount_cleanup() {
    // Test Display implementation for DeactivationReport with post_unmount_cleanup
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let post_unmount_cleanup = PostUnmountCleanupReport {
        cleaned_items: vec![
            "~/.bash_history (real disk)".to_string(),
            "~/.zsh_history (real disk)".to_string(),
        ],
        warnings: vec!["Failed to clean ~/.fish_history: Permission denied".to_string()],
        was_performed: true,
    };

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Phase 1 - Overlay Cleanup:"));
    assert!(output.contains("Removed 3 history entries"));
    assert!(output.contains("Unmounted Overlays:"));
    assert!(output.contains("/home"));
    assert!(output.contains("/etc"));
    assert!(output.contains("Phase 2 - Real Disk Cleanup:"));
    assert!(output.contains("~/.bash_history (real disk)"));
    assert!(output.contains("~/.zsh_history (real disk)"));
    assert!(output.contains("⚠ Failed to clean ~/.fish_history: Permission denied"));
    assert!(output.contains("✓ Deactivation complete"));
}
#[test]
fn test_deactivation_report_display_without_post_unmount_cleanup() {
    // Test Display implementation when post_unmount_cleanup.was_performed is false
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let post_unmount_cleanup = PostUnmountCleanupReport {
        cleaned_items: vec![], // Even if items exist, they shouldn't be shown
        warnings: vec![],
        was_performed: false,
    };

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup,
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Phase 1 - Overlay Cleanup:"));
    // Phase 2 should NOT appear when was_performed is false
    assert!(!output.contains("Phase 2 - Real Disk Cleanup:"));
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
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
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
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
        runtime_journal_scrubbed: false,
        reboot_recommended: false,
        state_write_errors: Vec::new(),
    };

    assert!(!report.is_successful());
}
#[test]
fn test_post_unmount_cleanup_report_default() {
    let report = PostUnmountCleanupReport::default();
    assert_eq!(report.cleaned_items.len(), 0);
    assert_eq!(report.warnings.len(), 0);
    assert!(!report.was_performed);
}
#[test]
fn test_post_unmount_cleanup_report_with_data() {
    let report = PostUnmountCleanupReport {
        cleaned_items: vec!["file1".to_string(), "file2".to_string()],
        warnings: vec!["warning1".to_string()],
        was_performed: true,
    };

    assert_eq!(report.cleaned_items.len(), 2);
    assert_eq!(report.warnings.len(), 1);
    assert!(report.was_performed);
}
