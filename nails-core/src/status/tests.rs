//! Tests for status module

use super::*;
use crate::MockFilesystem;
use crate::StateFile;
use crate::state::OverlayInfo;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[derive(Clone, Default)]
struct FailingMountCheckFilesystem {
    inner: MockFilesystem,
}

impl crate::Filesystem for FailingMountCheckFilesystem {
    fn is_mounted(&self, target: &Path) -> crate::Result<bool> {
        if target == Path::new("/etc") {
            return Err(crate::NailsError::IoError(std::io::Error::other(
                "mount table unreadable",
            )));
        }
        self.inner.is_mounted(target)
    }

    fn mount_overlay(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> crate::Result<()> {
        self.inner.mount_overlay(lower, upper, work, target)
    }
    fn unmount(&self, target: &Path, force: bool) -> crate::Result<()> {
        self.inner.unmount(target, force)
    }
    fn get_filesystem_type(&self, target: &Path) -> crate::Result<Option<String>> {
        self.inner.get_filesystem_type(target)
    }
    fn is_overlay_mounted(&self, target: &Path) -> crate::Result<bool> {
        self.inner.is_overlay_mounted(target)
    }
    fn get_mount_info(&self, target: &Path) -> Option<crate::filesystem::MountInfo> {
        self.inner.get_mount_info(target)
    }
    fn swap_is_enabled(&self) -> crate::Result<bool> {
        self.inner.swap_is_enabled()
    }
    fn swap_disable(&self) -> crate::Result<()> {
        self.inner.swap_disable()
    }
    fn bind_mount(&self, source: &Path, target: &Path) -> crate::Result<()> {
        self.inner.bind_mount(source, target)
    }
    fn unmount_bind(&self, target: &Path) -> crate::Result<()> {
        self.inner.unmount_bind(target)
    }
    fn mount_tmpfs(&self, target: &Path, size: &str) -> crate::Result<()> {
        self.inner.mount_tmpfs(target, size)
    }
    fn unmount_tmpfs(&self, target: &Path) -> crate::Result<()> {
        self.inner.unmount_tmpfs(target)
    }
    fn path_exists(&self, path: &Path) -> crate::Result<bool> {
        self.inner.path_exists(path)
    }
    fn is_directory(&self, path: &Path) -> crate::Result<bool> {
        self.inner.is_directory(path)
    }
    fn is_symlink(&self, path: &Path) -> crate::Result<bool> {
        self.inner.is_symlink(path)
    }
    fn create_symlink(&self, target: &Path, link: &Path) -> crate::Result<()> {
        self.inner.create_symlink(target, link)
    }
    fn get_free_space(&self, path: &Path) -> crate::Result<u64> {
        self.inner.get_free_space(path)
    }
    fn create_directory(&self, path: &Path) -> crate::Result<()> {
        self.inner.create_directory(path)
    }
    fn set_permissions(&self, path: &Path, mode: u32) -> crate::Result<()> {
        self.inner.set_permissions(path, mode)
    }
    fn get_permissions(&self, path: &Path) -> crate::Result<u32> {
        self.inner.get_permissions(path)
    }
    fn is_readable(&self, path: &Path) -> crate::Result<bool> {
        self.inner.is_readable(path)
    }
    fn is_writable(&self, path: &Path) -> crate::Result<bool> {
        self.inner.is_writable(path)
    }
    fn nixos_profile_exists(&self, profile: &str) -> crate::Result<bool> {
        self.inner.nixos_profile_exists(profile)
    }
    fn nixos_build_profile(&self, profile: &str) -> crate::Result<()> {
        self.inner.nixos_build_profile(profile)
    }
    fn nixos_switch_profile(&self, profile: &str) -> crate::Result<()> {
        self.inner.nixos_switch_profile(profile)
    }
    fn nixos_get_current_profile(&self) -> crate::Result<String> {
        self.inner.nixos_get_current_profile()
    }
    fn nails_process_running(&self) -> crate::Result<bool> {
        self.inner.nails_process_running()
    }
    fn read_file_content(&self, path: &Path) -> crate::Result<String> {
        self.inner.read_file_content(path)
    }
    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> crate::Result<Vec<PathBuf>> {
        self.inner.find_files_with_pattern(dir, pattern)
    }
    fn write_file_content(&self, path: &Path, content: &str) -> crate::Result<()> {
        self.inner.write_file_content(path, content)
    }
    fn list_directory(&self, dir: &Path) -> crate::Result<Vec<PathBuf>> {
        self.inner.list_directory(dir)
    }
    fn enumerate_root_directories(&self) -> crate::Result<Vec<PathBuf>> {
        self.inner.enumerate_root_directories()
    }
    fn file_size(&self, path: &Path) -> crate::Result<u64> {
        self.inner.file_size(path)
    }
    fn rename_file(&self, from: &Path, to: &Path) -> crate::Result<()> {
        self.inner.rename_file(from, to)
    }
    fn remove_file(&self, path: &Path) -> crate::Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_directory(&self, path: &Path) -> crate::Result<()> {
        self.inner.remove_directory(path)
    }
    fn remove_dir_all(&self, path: &Path) -> crate::Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn secure_delete(&self, path: &Path) -> crate::Result<()> {
        self.inner.secure_delete(path)
    }
    fn secure_delete_dir_all(&self, path: &Path) -> crate::Result<()> {
        self.inner.secure_delete_dir_all(path)
    }
    fn read_directory(&self, path: &Path) -> crate::Result<Vec<std::fs::DirEntry>> {
        self.inner.read_directory(path)
    }
    fn supports_symlinks(&self, dir: &Path) -> crate::Result<bool> {
        self.inner.supports_symlinks(dir)
    }
    fn modified_time(&self, path: &Path) -> crate::Result<chrono::DateTime<chrono::Utc>> {
        self.inner.modified_time(path)
    }
    fn copy_tree(&self, src: &Path, dst: &Path) -> crate::Result<()> {
        self.inner.copy_tree(src, dst)
    }
    fn get_directory_size(&self, path: &Path) -> crate::Result<u64> {
        self.inner.get_directory_size(path)
    }
    fn find_submount_sources(&self, target: &Path) -> crate::Result<Vec<(PathBuf, PathBuf)>> {
        self.inner.find_submount_sources(target)
    }
}

/// Helper function to check if logs contain a specific string
/// This works with tracing-test's captured output
#[allow(dead_code)]
fn logs_contain(s: &str) -> bool {
    tracing_test::internal::logs_with_scope_contain("", s)
}

/// Helper to create a temporary state file
fn create_temp_state_file(state_file: &StateFile) -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().unwrap();
    let json = serde_json::to_string_pretty(state_file).unwrap();
    temp_file.write_all(json.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    temp_file
}

/// Helper to create overlay info
fn create_overlay_info(mount_path: &str) -> OverlayInfo {
    OverlayInfo {
        mount_path: PathBuf::from(mount_path),
        lower_dir: PathBuf::from(format!("{}-lower", mount_path)),
        upper_dir: PathBuf::from(format!("{}-upper", mount_path)),
        work_dir: PathBuf::from(format!("{}-work", mount_path)),
        mounted_at: Utc::now(),
    }
}

#[test]
fn test_verification_status_is_verified() {
    assert!(VerificationStatus::Verified.is_verified());
    assert!(
        !VerificationStatus::Mismatch {
            errors: vec!["error".to_string()]
        }
        .is_verified()
    );
    assert!(!VerificationStatus::Skipped.is_verified());
    assert!(!VerificationStatus::NotApplicable.is_verified());
}

// Task 6: Unit tests for INACTIVE state
#[test]
fn test_status_command_inactive() {
    let fs = MockFilesystem::new();

    let config = Config::default();
    let state_file = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.state, SystemState::Inactive);
    assert!(report.overlays.is_empty());
    assert_eq!(
        report.overlay_verification,
        VerificationStatus::NotApplicable
    );
    assert!(report.uptime.is_none());
    assert!(report.activated_at.is_none());
    assert!(report.nixos_generation.is_none());
}

#[test]
fn test_status_command_propagates_permission_denied_for_unreadable_state() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");
    std::fs::write(
        &state_path,
        serde_json::to_string(&StateFile::default()).unwrap(),
    )
    .unwrap();

    let mut perms = std::fs::metadata(&state_path).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&state_path, perms).unwrap();

    let cmd = StatusCommand::new(MockFilesystem::new(), Config::default(), state_path.clone());
    let result = cmd.run_truthful();

    let mut restore = std::fs::metadata(&state_path).unwrap().permissions();
    restore.set_mode(0o600);
    std::fs::set_permissions(&state_path, restore).unwrap();

    match result.unwrap_err() {
        crate::NailsError::PermissionDenied(msg) => {
            assert!(msg.contains("Cannot read state file"), "msg={msg}");
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

// Task 7: Unit tests for ACTIVE state
#[test]
fn test_status_command_active_verified() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_mounted(Path::new("/etc"), true);

    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::hours(2);
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
        },
        overlay_status,
        nixos_generation: Some("generation-123".to_string()),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Active { .. }));
    assert_eq!(report.overlays, overlays);
    assert_eq!(report.overlay_verification, VerificationStatus::Verified);
    assert!(report.uptime.is_some());
    assert_eq!(report.activated_at, Some(activated_at));
    assert_eq!(report.nixos_generation, Some("generation-123".to_string()));

    // Verify uptime is approximately 2 hours
    let uptime = report.uptime.unwrap();
    assert!(uptime.num_hours() >= 1 && uptime.num_hours() <= 3);
}

#[test]
fn test_status_command_active_mismatch() {
    let fs = MockFilesystem::new();
    // First overlay mounted, second not
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_mounted(Path::new("/etc"), false);

    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::minutes(30);
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Active { .. }));
    assert_eq!(report.overlays, overlays);

    // Should have mismatch with /etc error
    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].contains("/etc"));
            assert!(errors[0].contains("should be mounted"));
        }
        _ => panic!("Expected Mismatch verification status"),
    }
}

// Task 8: Unit tests for transitional states
#[test]
fn test_status_command_activating() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let started_at = Utc::now();

    let state_file = StateFile {
        state: SystemState::Activating { started_at },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Activating { .. }));
    assert!(report.overlays.is_empty());
    assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
    assert!(report.uptime.is_none());
    assert!(report.activated_at.is_none());
}

#[test]
fn test_status_command_deactivating() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let started_at = Utc::now();

    let state_file = StateFile {
        state: SystemState::Deactivating { started_at },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Deactivating { .. }));
    assert!(report.overlays.is_empty());
    assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
    assert!(report.uptime.is_none());
    assert!(report.activated_at.is_none());
}

#[test]
fn test_status_command_emergency() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let triggered_at = Utc::now();

    let state_file = StateFile {
        state: SystemState::Emergency { triggered_at },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Emergency { .. }));
    assert!(report.overlays.is_empty());
    assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
    assert!(report.uptime.is_none());
    assert!(report.activated_at.is_none());
}

// Task 9: Unit tests for overlay verification edge cases
#[test]
fn test_status_command_active_all_overlays_mounted() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_mounted(Path::new("/etc"), true);
    fs.mock_set_mounted(Path::new("/var"), true);

    let config = Config::default();
    let overlays = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ];

    let mut overlay_status = std::collections::HashMap::new();
    for overlay in &overlays {
        overlay_status.insert(
            overlay.clone(),
            create_overlay_info(overlay.to_str().unwrap()),
        );
    }

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: overlays.clone(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.overlay_verification, VerificationStatus::Verified);
    assert_eq!(report.overlays.len(), 3);
}

#[test]
fn test_status_command_active_no_overlays() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        },
        overlay_status: std::collections::HashMap::new(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.overlay_verification, VerificationStatus::Verified);
    assert!(report.overlays.is_empty());
}

#[test]
fn test_status_command_active_multiple_mismatches() {
    let fs = MockFilesystem::new();
    // None mounted
    fs.mock_set_mounted(Path::new("/home"), false);
    fs.mock_set_mounted(Path::new("/etc"), false);
    fs.mock_set_mounted(Path::new("/var"), false);

    let config = Config::default();
    let overlays = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ];

    let mut overlay_status = std::collections::HashMap::new();
    for overlay in &overlays {
        overlay_status.insert(
            overlay.clone(),
            create_overlay_info(overlay.to_str().unwrap()),
        );
    }

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: overlays.clone(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert_eq!(errors.len(), 3);
            assert!(errors.iter().any(|e| e.contains("/home")));
            assert!(errors.iter().any(|e| e.contains("/etc")));
            assert!(errors.iter().any(|e| e.contains("/var")));
        }
        _ => panic!("Expected Mismatch with 3 errors"),
    }
}

#[test]
fn test_status_report_serialization() {
    let report = StatusReport {
        state: SystemState::Inactive,
        overlays: vec![],
        overlay_verification: VerificationStatus::NotApplicable,
        nixos_generation: None,
        activated_at: None,
        uptime: None,
        formatted_uptime: String::new(),
        opsec_reminders: vec![],
        overlay_details: None,
        overlay_mount_statuses: vec![],
        load_outcome: crate::LoadOutcome::FreshDefault,
    };

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: StatusReport = serde_json::from_str(&json).unwrap();

    assert_eq!(report, deserialized);
}

#[test]
fn test_uptime_calculation_with_recent_activation() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::minutes(5);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    let uptime = report.uptime.unwrap();
    assert!(uptime.num_minutes() >= 4 && uptime.num_minutes() <= 6);
}

#[test]
fn test_uptime_calculation_with_long_activation() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::days(7);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    let uptime = report.uptime.unwrap();
    assert_eq!(uptime.num_days(), 7);
}

// Security posture tests (Story 7.2)

#[test]
fn test_security_posture_active_verified() {
    let report = StatusReport {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_verification: VerificationStatus::Verified,
        ..Default::default()
    };

    let posture = report.security_posture();
    assert_eq!(posture, SecurityPosture::Secure);
    assert!(format!("{}", posture).contains('🟢'));
    let plain = posture.to_plain();
    assert!(plain.contains("[SECURE]"));
}

#[test]
fn test_security_posture_active_mismatch() {
    let report = StatusReport {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_verification: VerificationStatus::Mismatch {
            errors: vec!["Overlay not mounted".to_string()],
        },
        ..Default::default()
    };

    let posture = report.security_posture();
    assert_eq!(posture, SecurityPosture::Warning);
    assert!(format!("{}", posture).contains('🟡'));
    let plain = posture.to_plain();
    assert!(plain.contains("[WARNING]"));
}

#[test]
fn test_security_posture_activating() {
    let report = StatusReport {
        state: SystemState::Activating {
            started_at: Utc::now(),
        },
        overlay_verification: VerificationStatus::Skipped,
        ..Default::default()
    };

    let posture = report.security_posture();
    assert_eq!(posture, SecurityPosture::Warning);
    assert!(format!("{}", posture).contains('🟡'));
    let plain = posture.to_plain();
    assert!(plain.contains("[WARNING]"));
}

#[test]
fn test_security_posture_deactivating() {
    let report = StatusReport {
        state: SystemState::Deactivating {
            started_at: Utc::now(),
        },
        overlay_verification: VerificationStatus::Skipped,
        ..Default::default()
    };

    let posture = report.security_posture();
    assert_eq!(posture, SecurityPosture::Warning);
    assert!(format!("{}", posture).contains('🟡'));
    let plain = posture.to_plain();
    assert!(plain.contains("[WARNING]"));
}

#[test]
fn test_security_posture_inactive() {
    let report = StatusReport {
        state: SystemState::Inactive,
        overlay_verification: VerificationStatus::NotApplicable,
        ..Default::default()
    };

    let posture = report.security_posture();
    assert_eq!(posture, SecurityPosture::Decoy);
    assert!(format!("{}", posture).contains('🔴'));
    assert!(format!("{}", posture).contains("DECOY"));
    assert!(format!("{}", posture).contains("Decoy system"));
    assert!(!format!("{}", posture).contains("CRITICAL"));
    let plain = posture.to_plain();
    assert!(plain.contains("[DECOY]"));
    assert!(!plain.contains("[CRITICAL]"));
}

#[test]
fn test_security_posture_emergency() {
    let report = StatusReport {
        state: SystemState::Emergency {
            triggered_at: Utc::now(),
        },
        overlay_verification: VerificationStatus::Skipped,
        ..Default::default()
    };

    let posture = report.security_posture();
    assert_eq!(posture, SecurityPosture::Critical);
    assert!(format!("{}", posture).contains('🔴'));
    assert!(format!("{}", posture).contains("CRITICAL"));
    assert!(format!("{}", posture).contains("Emergency deactivation"));
    let plain = posture.to_plain();
    assert!(plain.contains("[CRITICAL]"));
}

#[test]
fn test_security_posture_display_secure() {
    let posture = SecurityPosture::Secure;
    let display = format!("{}", posture);

    assert!(display.contains('🟢'));
    assert!(display.contains("SECURE"));
    assert!(display.contains("Hidden environment active"));
}

#[test]
fn test_security_posture_display_warning() {
    let posture = SecurityPosture::Warning;
    let display = format!("{}", posture);

    assert!(display.contains('🟡'));
    assert!(display.contains("WARNING"));
    assert!(display.contains("transitional state"));
}

#[test]
fn test_security_posture_display_critical() {
    let posture = SecurityPosture::Critical;
    let display = format!("{}", posture);

    assert!(display.contains('🔴'));
    assert!(display.contains("CRITICAL"));
    assert!(display.contains("Emergency deactivation"));
}

#[test]
fn test_security_posture_display_decoy() {
    let posture = SecurityPosture::Decoy;
    let display = format!("{}", posture);

    assert!(display.contains('🔴'));
    assert!(display.contains("DECOY"));
    assert!(display.contains("Decoy system"));
    assert!(!display.contains("CRITICAL"));
}

#[test]
fn test_security_posture_to_plain_secure() {
    let posture = SecurityPosture::Secure;
    let plain = posture.to_plain();

    assert!(!plain.contains('🟢')); // No emoji
    assert!(plain.contains("[SECURE]"));
    assert!(plain.contains("Hidden environment active"));
    assert_eq!(
        plain,
        "[SECURE] Hidden environment active, overlays verified"
    );
}

#[test]
fn test_security_posture_to_plain_warning() {
    let posture = SecurityPosture::Warning;
    let plain = posture.to_plain();

    assert!(!plain.contains('🟡')); // No emoji
    assert!(plain.contains("[WARNING]"));
    assert!(plain.contains("transitional state"));
    assert_eq!(
        plain,
        "[WARNING] System in transitional state - wait for completion"
    );
}

#[test]
fn test_security_posture_to_plain_decoy() {
    let posture = SecurityPosture::Decoy;
    let plain = posture.to_plain();

    assert!(!plain.contains('🔴')); // No emoji
    assert!(plain.contains("[DECOY]"));
    assert!(plain.contains("Decoy system"));
    assert!(!plain.contains("[CRITICAL]"));
    assert_eq!(plain, "[DECOY] Decoy system - no sensitive data accessible");
}

#[test]
fn test_security_posture_to_plain_critical() {
    let posture = SecurityPosture::Critical;
    let plain = posture.to_plain();

    assert!(!plain.contains('🔴')); // No emoji
    assert!(plain.contains("[CRITICAL]"));
    assert!(plain.contains("Emergency deactivation"));
    assert_eq!(
        plain,
        "[CRITICAL] Emergency deactivation occurred - reboot recommended"
    );
}

#[test]
fn test_security_posture_screenreader_compatibility() {
    let postures = [
        SecurityPosture::Secure,
        SecurityPosture::Warning,
        SecurityPosture::Decoy,
        SecurityPosture::Critical,
    ];

    for posture in postures {
        let display = format!("{}", posture);
        let plain = posture.to_plain();

        // All should have text labels (not just emoji)
        assert!(
            display.len() > 5,
            "Posture should have more than just emoji: {}",
            display
        );
        assert!(
            plain.len() > 10,
            "Plain text should be descriptive: {}",
            plain
        );
    }
}

// ========== Uptime Formatting Tests (Story 7.3) ==========

#[test]
fn test_uptime_formatting_less_than_hour() {
    // Test <1 hour: "45 minutes"
    let duration = Duration::minutes(45);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "45 minutes");
}

#[test]
fn test_uptime_formatting_one_minute() {
    // Test edge case: 1 minute (singular)
    let duration = Duration::minutes(1);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "1 minute");
}

#[test]
fn test_uptime_formatting_hours_only() {
    // Test 1-24 hours: "5 hours" (omits minutes if zero)
    let duration = Duration::hours(5);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "5 hours");
}

#[test]
fn test_uptime_formatting_hours_and_minutes() {
    // Test 1-24 hours: "3 hours 30 minutes"
    let duration = Duration::hours(3) + Duration::minutes(30);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "3 hours 30 minutes");
}

#[test]
fn test_uptime_formatting_one_hour() {
    // Test edge case: exactly 1 hour (singular)
    let duration = Duration::hours(1);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "1 hour");
}

#[test]
fn test_uptime_formatting_days_only() {
    // Test >24 hours: "3 days" (omits hours if zero)
    let duration = Duration::days(3);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "3 days");
}

#[test]
fn test_uptime_formatting_days_and_hours() {
    // Test >24 hours: "2 days 5 hours"
    let duration = Duration::days(2) + Duration::hours(5);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "2 days 5 hours");
}

#[test]
fn test_uptime_formatting_rounding() {
    // Test rounding to nearest minute (Duration already handles this)
    let duration = Duration::seconds(90); // 1.5 minutes
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "1 minute"); // rounds to 1 minute (singular)
}

#[test]
fn test_uptime_formatting_one_day() {
    // Test edge case: exactly 1 day (singular)
    let duration = Duration::days(1);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "1 day");
}

#[test]
fn test_uptime_formatting_one_hour_one_minute() {
    // Test edge case: 1 hour 1 minute (both singular)
    let duration = Duration::hours(1) + Duration::minutes(1);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "1 hour 1 minute");
}

#[test]
fn test_uptime_formatting_negative_duration() {
    // Test negative duration protection (clock skew)
    let duration = Duration::minutes(-100);
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "0 minutes"); // Clamps to zero
}

#[test]
fn test_uptime_formatting_zero_duration() {
    // Test zero duration
    let duration = Duration::zero();
    let formatted = format_uptime(duration);
    assert_eq!(formatted, "0 minutes");
}

// ========== OpSec Reminder Generation Tests (Story 7.3) ==========

#[test]
fn test_opsec_reminders_less_than_6_hours() {
    // Test <6 hours → no reminders
    let uptime = Duration::hours(5);
    let reminders = generate_opsec_reminders(uptime, true);
    assert_eq!(reminders.len(), 0);
}

#[test]
fn test_opsec_reminders_exactly_6_hours() {
    // Test 6+ hours → Info reminder
    let uptime = Duration::hours(6);
    let reminders = generate_opsec_reminders(uptime, true);
    assert_eq!(reminders.len(), 1);
    assert_eq!(reminders[0].severity, ReminderSeverity::Info);
    assert!(
        reminders[0]
            .message
            .contains("Consider taking breaks for operational security")
    );
}

#[test]
fn test_opsec_reminders_12_hours() {
    // Test 12+ hours → Info + Warning reminders (cumulative)
    let uptime = Duration::hours(12);
    let reminders = generate_opsec_reminders(uptime, true);
    assert_eq!(reminders.len(), 2);
    assert_eq!(reminders[0].severity, ReminderSeverity::Info);
    assert_eq!(reminders[1].severity, ReminderSeverity::Warning);
}

#[test]
fn test_opsec_reminders_24_hours() {
    // Test 24+ hours → All three reminders (cumulative)
    let uptime = Duration::hours(26);
    let reminders = generate_opsec_reminders(uptime, true);
    assert_eq!(reminders.len(), 3);
    assert_eq!(reminders[0].severity, ReminderSeverity::Info);
    assert_eq!(reminders[1].severity, ReminderSeverity::Warning);
    assert_eq!(reminders[2].severity, ReminderSeverity::Critical);
}

#[test]
fn test_opsec_reminders_disabled() {
    // Test with show_opsec_reminders = false → no reminders
    let uptime = Duration::hours(26);
    let reminders = generate_opsec_reminders(uptime, false);
    assert_eq!(reminders.len(), 0);
}

// ========== OpSec Reminder Struct Tests (Story 7.3) ==========

#[test]
fn test_opsec_reminder_display_info() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Info,
        message: "Test message".to_string(),
    };
    let display = format!("{}", reminder);
    assert!(display.contains('💡')); // Info uses lightbulb emoji
    assert!(display.contains("Test message"));
}

#[test]
fn test_opsec_reminder_display_warning() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Warning,
        message: "Warning message".to_string(),
    };
    let display = format!("{}", reminder);
    assert!(display.contains('⚠')); // Warning uses warning triangle
    assert!(display.contains("Warning message"));
}

#[test]
fn test_opsec_reminder_display_critical() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Critical,
        message: "Critical message".to_string(),
    };
    let display = format!("{}", reminder);
    assert!(display.contains('🛑')); // Critical uses stop sign
    assert!(display.contains("Critical message"));
}

#[test]
fn test_opsec_reminder_to_plain() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Critical,
        message: "Session >24 hours".to_string(),
    };
    let plain = reminder.to_plain();
    assert!(!plain.contains('⚠')); // No emoji
    assert!(plain.contains("[CRITICAL]"));
    assert!(plain.contains("Session >24 hours"));
}

#[test]
fn test_opsec_reminder_serialization() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Warning,
        message: "Test".to_string(),
    };

    let json = serde_json::to_string(&reminder).unwrap();
    let deserialized: OpSecReminder = serde_json::from_str(&json).unwrap();

    assert_eq!(reminder, deserialized);
}

// ========== ReminderSeverity Tests (Story 7.3) ==========

#[test]
fn test_reminder_severity_display() {
    assert_eq!(format!("{}", ReminderSeverity::Info), "INFO");
    assert_eq!(format!("{}", ReminderSeverity::Warning), "WARNING");
    assert_eq!(format!("{}", ReminderSeverity::Critical), "CRITICAL");
}

#[test]
fn test_reminder_severity_to_plain() {
    assert_eq!(ReminderSeverity::Info.to_plain(), "[INFO]");
    assert_eq!(ReminderSeverity::Warning.to_plain(), "[WARNING]");
    assert_eq!(ReminderSeverity::Critical.to_plain(), "[CRITICAL]");
}

// ========== Integration Tests (Story 7.3) ==========

#[test]
fn test_status_command_includes_formatted_uptime() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::hours(3) - chrono::Duration::minutes(30);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.formatted_uptime, "3 hours 30 minutes");
    assert!(report.uptime.is_some());
}

#[test]
fn test_status_command_includes_opsec_reminders_when_enabled() {
    let fs = MockFilesystem::new();
    let config = Config::default(); // show_opsec_reminders = true by default
    let activated_at = Utc::now() - chrono::Duration::hours(26);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.opsec_reminders.len(), 3); // All three reminders
    assert_eq!(report.opsec_reminders[0].severity, ReminderSeverity::Info);
    assert_eq!(
        report.opsec_reminders[1].severity,
        ReminderSeverity::Warning
    );
    assert_eq!(
        report.opsec_reminders[2].severity,
        ReminderSeverity::Critical
    );
}

#[test]
fn test_status_command_suppresses_opsec_reminders_when_disabled() {
    let fs = MockFilesystem::new();
    let config = Config {
        show_opsec_reminders: false,
        ..Config::default()
    };
    let activated_at = Utc::now() - chrono::Duration::hours(26);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.opsec_reminders.len(), 0); // No reminders when disabled
}

#[test]
fn test_status_command_no_reminders_for_short_uptime() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::hours(3); // Only 3 hours

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.opsec_reminders.len(), 0); // No reminders for <6 hours
    assert_eq!(report.formatted_uptime, "3 hours");
}

#[test]
fn test_status_command_inactive_has_empty_uptime() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    let state_file = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.formatted_uptime, "");
    assert!(report.uptime.is_none());
    assert_eq!(report.opsec_reminders.len(), 0);
}

// ========== Code Review Fixes: Additional Test Coverage ==========

#[test]
fn test_uptime_calculation_handles_future_timestamp() {
    // Bug fix: Handle clock skew where activated_at is in the future
    let fs = MockFilesystem::new();
    let config = Config::default();
    let future_time = Utc::now() + chrono::Duration::hours(1); // 1 hour in future

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: future_time,
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    // Should return None for future timestamps (clock skew protection)
    assert!(report.uptime.is_none());
    assert_eq!(report.formatted_uptime, "");
    assert_eq!(report.opsec_reminders.len(), 0);
}

#[test]
fn test_verification_detects_active_overlays_missing_from_overlay_status() {
    // Bug fix: Detect when Active.overlays contains paths not in overlay_status
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config::default();
    let activated_at = Utc::now();
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    // Missing /etc in overlay_status!

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    // Should detect the mismatch
    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("/etc")
                        && e.contains("missing from overlay_status tracking"))
            );
        }
        _ => panic!("Expected Mismatch verification status"),
    }
}

#[test]
fn test_verification_detects_overlay_status_not_in_active_overlays() {
    // Bug fix: Detect when overlay_status has entries not in Active.overlays
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_mounted(Path::new("/var"), true);

    let config = Config::default();
    let activated_at = Utc::now();
    let overlays = vec![PathBuf::from("/home")]; // Only /home in Active

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    overlay_status.insert(PathBuf::from("/var"), create_overlay_info("/var")); // Extra!

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    // Should detect the mismatch
    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("/var") && e.contains("not listed in Active state"))
            );
        }
        _ => panic!("Expected Mismatch verification status"),
    }
}

#[test]
fn test_status_command_surfaces_load_outcome_for_missing_and_migrated_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing_path = temp_dir.path().join("missing-state.json");

    let missing_report = StatusCommand::new(
        MockFilesystem::new(),
        Config::default(),
        missing_path.clone(),
    )
    .run()
    .unwrap();
    assert_eq!(
        missing_report.load_outcome,
        crate::LoadOutcome::FreshDefault
    );

    let state_file = StateFile {
        version: "0.0.5".to_string(),
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);
    let migrated_report = StatusCommand::new(
        MockFilesystem::new(),
        Config::default(),
        temp_file.path().to_path_buf(),
    )
    .run()
    .unwrap();

    assert_eq!(
        migrated_report.load_outcome,
        crate::LoadOutcome::Migrated {
            from_version: "0.0.5".to_string()
        }
    );
}

#[test]
fn test_status_command_recovers_from_corrupt_state_file() {
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), "{ definitely-not-json").unwrap();

    let report = StatusCommand::new(
        MockFilesystem::new(),
        Config::default(),
        temp_file.path().to_path_buf(),
    )
    .run()
    .unwrap();

    assert_eq!(report.state, SystemState::Inactive);
    assert_eq!(
        report.load_outcome,
        crate::LoadOutcome::RecoveredFromCorruption
    );
    assert_eq!(
        report.overlay_verification,
        VerificationStatus::NotApplicable
    );
}

#[test]
fn test_status_command_populates_overlay_details_only_for_active_state_with_tracked_overlays() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status: overlay_status.clone(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let report = StatusCommand::new(fs, Config::default(), temp_file.path().to_path_buf())
        .run()
        .unwrap();

    assert_eq!(report.overlay_details, Some(overlay_status));

    let inactive_state_file = create_temp_state_file(&StateFile::default());
    let inactive_report = StatusCommand::new(
        MockFilesystem::new(),
        Config::default(),
        inactive_state_file.path().to_path_buf(),
    )
    .run()
    .unwrap();
    assert_eq!(inactive_report.overlay_details, None);
}

#[test]
fn test_status_command_reports_mount_check_errors_as_mismatch_and_status_false() {
    let fs = FailingMountCheckFilesystem::default();
    fs.inner.mock_set_mounted(Path::new("/home"), true);

    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays,
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let report = StatusCommand::new(fs, Config::default(), temp_file.path().to_path_buf())
        .run()
        .unwrap();

    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert!(errors.iter().any(|error| {
                error.contains("Failed to check mount status for /etc")
                    && error.contains("mount table unreadable")
            }));
        }
        other => panic!("expected mismatch, got {other:?}"),
    }

    let etc_status = report
        .overlay_mount_statuses
        .iter()
        .find(|status| status.path == Path::new("/etc"))
        .unwrap();
    assert!(!etc_status.actually_mounted);
}

// ============================================================================
// Story 9.3: Structured Logging Tests for Status
// ============================================================================

#[test]
#[tracing_test::traced_test]
fn test_status_emits_structured_debug_events() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_file = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let result = cmd.run();
    assert!(result.is_ok(), "Status should succeed");

    // Verify structured debug events (AC implicit)
    assert!(logs_contain("Status query executed"));
    assert!(logs_contain("state") || logs_contain("Inactive"));
    assert!(logs_contain("phase") || logs_contain("status"));
}

#[test]
#[tracing_test::traced_test]
fn test_status_logs_verification_result() {
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config::default();
    let activated_at = Utc::now();
    let overlays = vec![PathBuf::from("/home")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays,
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let result = cmd.run();
    assert!(result.is_ok(), "Status should succeed");

    // Verify verification result is logged with structured fields
    assert!(logs_contain("Overlay verification performed"));
    assert!(logs_contain("verification_result"));
    assert!(logs_contain("phase") || logs_contain("status"));
}

// ============================================================================
// Task 3: Per-Overlay Mount Status Display Tests
// ============================================================================

#[test]
fn test_overlay_mount_statuses_populated_for_active_state() {
    // Test that overlay_mount_statuses is populated with actual mount status
    let fs = MockFilesystem::new();
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_mounted(Path::new("/etc"), false); // Not mounted

    let config = Config::default();
    let activated_at = Utc::now();
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    // Verify overlay_mount_statuses is populated
    assert_eq!(report.overlay_mount_statuses.len(), 2);

    // Verify /home status (mounted)
    let home_status = report
        .overlay_mount_statuses
        .iter()
        .find(|s| s.path == Path::new("/home"))
        .expect("/home should be in statuses");
    assert!(home_status.expected_mounted);
    assert!(home_status.actually_mounted);

    // Verify /etc status (not mounted)
    let etc_status = report
        .overlay_mount_statuses
        .iter()
        .find(|s| s.path == Path::new("/etc"))
        .expect("/etc should be in statuses");
    assert!(etc_status.expected_mounted);
    assert!(!etc_status.actually_mounted);
}

#[test]
fn test_overlay_mount_statuses_empty_for_inactive_state() {
    // Test that overlay_mount_statuses is empty for Inactive state
    let fs = MockFilesystem::new();
    let config = Config::default();

    let state_file = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.overlay_mount_statuses.len(), 0);
}

#[test]
fn test_overlay_mount_statuses_empty_for_transitional_states() {
    // Test that overlay_mount_statuses is empty for transitional states
    let fs = MockFilesystem::new();
    let config = Config::default();

    // Activating state
    let state_file = StateFile {
        state: SystemState::Activating {
            started_at: Utc::now(),
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs.clone(), config.clone(), temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.overlay_mount_statuses.len(), 0);

    // Deactivating state
    let state_file2 = StateFile {
        state: SystemState::Deactivating {
            started_at: Utc::now(),
        },
        ..StateFile::default()
    };
    let temp_file2 = create_temp_state_file(&state_file2);

    let cmd2 = StatusCommand::new(fs.clone(), config.clone(), temp_file2.path().to_path_buf());
    let report2 = cmd2.run().unwrap();

    assert_eq!(report2.overlay_mount_statuses.len(), 0);
}
