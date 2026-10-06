// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[tracing_test::traced_test]
fn test_deactivation_emits_structured_events() {
    let manager = setup_active_manager();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Deactivation should succeed");

    // Verify structured deactivation events
    assert!(logs_contain("Deactivation started"));
    assert!(logs_contain("phase"));
    assert!(logs_contain("Deactivation complete"));
    assert!(logs_contain("duration_ms"));
}
#[test]
#[tracing_test::traced_test]
fn test_deactivation_cleanup_event_includes_count() {
    let manager = setup_active_manager();
    // Cleanup resolves the history files from HOME, so it points at the fake
    // home for the whole test.

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);

        // Add some cleanup items
        let bash_history = Path::new(TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();

        // Validate path safety before using
        assert_path_is_safe(bash_history_str);

        m.filesystem().mock_set_path_exists(bash_history_str, true);
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails activate\nsome command\n");
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Deactivation should succeed");

    // Verify cleanup event includes count
    assert!(logs_contain("Cleanup complete") || logs_contain("cleaned_items"));
}
#[test]
#[tracing_test::traced_test]
fn test_deactivation_unmount_event_includes_overlay_list() {
    let manager = setup_active_manager();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Deactivation should succeed");

    // Verify unmount event includes overlay list
    assert!(logs_contain("Overlays unmounted") || logs_contain("overlays"));
    assert!(logs_contain("count") || logs_contain("unmounted"));
}
#[test]
#[tracing_test::traced_test]
fn test_deactivation_idempotent_log() {
    // Test idempotent deactivation logging
    let manager = setup_active_manager();

    // Set state to Inactive
    {
        let mut m = manager.lock().unwrap();
        m.force_state(SystemState::Inactive)
            .expect("Should set inactive");
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Idempotent deactivation should succeed");

    // Verify idempotent message with structured fields
    assert!(logs_contain("Already inactive") || logs_contain("already_inactive"));
}
