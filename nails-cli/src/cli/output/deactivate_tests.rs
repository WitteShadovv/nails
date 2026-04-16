use super::{print_deactivate_human, print_deactivate_json};
use nails_core::{
    CleanupMode, CleanupReport, DeactivationReport, NailsError, ShellCleanupResult, SystemState,
    Verbosity,
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
        memory_sanitized: false,
        canary_findings_count: 0,
    }
}

fn make_success_report() -> DeactivationReport {
    DeactivationReport {
        cleanup_report: make_cleanup_report(),
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        duration: Duration::from_millis(1234),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup: nails_core::PostUnmountCleanupReport::default(),
    }
}

fn make_already_inactive_report() -> DeactivationReport {
    DeactivationReport {
        cleanup_report: make_cleanup_report(),
        unmounted_overlays: vec![],
        duration: Duration::from_millis(5),
        final_state: SystemState::Inactive,
        was_already_inactive: true,
        post_unmount_cleanup: nails_core::PostUnmountCleanupReport::default(),
    }
}

fn make_manager()
-> std::sync::Arc<std::sync::Mutex<nails_core::NailsManager<nails_core::MockFilesystem>>> {
    let fs = nails_core::MockFilesystem::new();
    let config = nails_core::Config::default();
    let manager = nails_core::NailsManager::new(fs, config, PathBuf::from("/tmp/test-state.json"));
    std::sync::Arc::new(std::sync::Mutex::new(manager))
}

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
            memory_sanitized: false,
            canary_findings_count: 0,
        },
        unmounted_overlays: vec![],
        duration: Duration::from_millis(100),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup: nails_core::PostUnmountCleanupReport::default(),
    };

    print_deactivate_human(&Ok(report), Verbosity::Normal, false, None, false);
}

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

#[test]
fn test_json_error_with_poisoned_manager_falls_back_to_unknown_state() {
    let manager = make_manager();
    let poison_target = std::sync::Arc::clone(&manager);
    let _ = std::thread::spawn(move || {
        let _guard = poison_target.lock().unwrap();
        panic!("poison manager lock for test");
    })
    .join();

    let err = NailsError::InvalidState("failed".to_string());
    print_deactivate_json(&Err(err), &manager, None);
}
