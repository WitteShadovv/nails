//! Tests for status module

use super::*;
use crate::MockFilesystem;
use crate::StateFile;
use crate::state::OverlayInfo;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

/// Helper function to check if logs contain a specific string
/// This works with tracing-test's captured output
#[allow(dead_code)]
fn logs_contain(s: &str) -> bool {
    tracing_test::internal::logs_with_scope_contain("", s)
}

/// Helper to create a temporary state file
fn create_temp_state_file(state_file: &StateFile) -> NamedTempFile {
    // Seal with the same integrity digest the production save path writes, so the
    // loader accepts the file instead of treating it as corrupt.
    let mut sealed = state_file.clone();
    sealed.integrity_sha256 = None;
    let hash_input = serde_json::to_value(&sealed).unwrap().to_string();
    use sha2::Digest;
    sealed.integrity_sha256 = Some(hex::encode(sha2::Sha256::digest(hash_input.as_bytes())));

    let mut temp_file = NamedTempFile::new().unwrap();
    let json = serde_json::to_string_pretty(&sealed).unwrap();
    temp_file.write_all(json.as_bytes()).unwrap();
    temp_file.flush().unwrap();
    temp_file
}

/// Helper to create overlay info
fn create_overlay_info(mount_path: &str) -> OverlayInfo {
    OverlayInfo {
        mount_method: Default::default(),
        mount_path: PathBuf::from(mount_path),
        lower_dir: PathBuf::from(format!("{}-lower", mount_path)),
        upper_dir: PathBuf::from(format!("{}-upper", mount_path)),
        work_dir: PathBuf::from(format!("{}-work", mount_path)),
        mounted_at: Utc::now(),
    }
}

/// A fixed hidden-root for the reconcile-driven tests, so a mounted overlay's
/// upperdir can live under it and be classified as a genuine NAILS overlay.
const HIDDEN_ROOT: &str = "/mnt/hidden";

/// A config whose hidden root is the fixed [`HIDDEN_ROOT`], so ownership
/// discovery is deterministic rather than binary-path-derived.
fn config_hidden() -> Config {
    Config {
        hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
        ..Config::default()
    }
}

/// Register a genuinely NAILS-owned overlay at `target` with the mock (its
/// upper/work live under [`HIDDEN_ROOT`], so `discover_nails_mounts` classifies
/// it as persistent) and return the matching [`OverlayInfo`] for the state file.
fn mount_nails_overlay(fs: &MockFilesystem, target: &str) -> OverlayInfo {
    let upper = format!("{HIDDEN_ROOT}/overlays{target}/upper");
    let work = format!("{HIDDEN_ROOT}/overlays{target}/work");
    fs.mock_mount_nails_overlay(Path::new(target), Path::new(&upper), Path::new(&work));
    OverlayInfo {
        mount_method: Default::default(),
        mount_path: PathBuf::from(target),
        lower_dir: PathBuf::from(target),
        upper_dir: PathBuf::from(upper),
        work_dir: PathBuf::from(work),
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

// Unit tests for INACTIVE state
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
    assert!(report.hidden_toplevel.is_none());
}

#[test]
fn test_status_report_carries_hidden_root_disk_usage() {
    let fs = MockFilesystem::new();

    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/hidden-volume"),
        ..Config::default()
    };

    // Seed the hidden root with 10 GiB total and 4 GiB available via one
    // statvfs-equivalent seam; the status path must report these without
    // walking any directories.
    let total = 10 * 1024 * 1024 * 1024;
    let available = 4 * 1024 * 1024 * 1024;
    fs.mock_set_disk_usage(&config.hidden_volume_root, total, available);

    let state_file = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.hidden_root_total, Some(total));
    assert_eq!(report.hidden_root_available, Some(available));
    assert_eq!(report.hidden_root_used, Some(total - available));
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
    let result = cmd.run();

    let mut restore = std::fs::metadata(&state_path).unwrap().permissions();
    restore.set_mode(0o600);
    std::fs::set_permissions(&state_path, restore).unwrap();

    assert!(
        matches!(result.unwrap_err(), crate::NailsError::PermissionDenied(_)),
        "an unreadable state file must surface as PermissionDenied"
    );
}

// Unit tests for ACTIVE state
#[test]
fn test_status_command_active_verified() {
    let fs = MockFilesystem::new();
    let config = config_hidden();
    let activated_at = Utc::now() - chrono::Duration::hours(2);
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), mount_nails_overlay(&fs, "/home"));
    overlay_status.insert(PathBuf::from("/etc"), mount_nails_overlay(&fs, "/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
            decoy_writers: Vec::new(),
        },
        overlay_status,
        hidden_toplevel: Some("generation-123".to_string()),
        last_switch_warning: Some("hidden NixOS configuration was not applied (boom)".to_string()),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Active { .. }));
    assert_eq!(report.posture, Posture::Active);
    assert_eq!(report.overlays, overlays);
    assert_eq!(report.overlay_verification, VerificationStatus::Verified);
    assert!(report.overlay_mount_statuses.iter().all(|s| s.owned));
    assert!(report.uptime.is_some());
    assert_eq!(report.activated_at, Some(activated_at));
    assert_eq!(report.hidden_toplevel, Some("generation-123".to_string()));
    assert_eq!(
        report.last_switch_warning,
        Some("hidden NixOS configuration was not applied (boom)".to_string()),
        "a persisted switch warning is surfaced in the status report"
    );

    // Verify uptime is approximately 2 hours
    let uptime = report.uptime.unwrap();
    assert!(uptime.num_hours() >= 1 && uptime.num_hours() <= 3);
}

#[test]
fn test_status_command_active_mismatch() {
    let fs = MockFilesystem::new();
    let config = config_hidden();
    // First overlay is a genuine NAILS overlay; the second is absent.
    let activated_at = Utc::now() - chrono::Duration::minutes(30);
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), mount_nails_overlay(&fs, "/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
            decoy_writers: Vec::new(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Active { .. }));
    assert_eq!(report.posture, Posture::Degraded);
    assert_eq!(report.overlays, overlays);

    // Should have mismatch with /etc error
    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert_eq!(errors.len(), 1);
            assert!(errors[0].contains("/etc"));
            assert!(errors[0].contains("NAILS overlay"));
        }
        _ => panic!("Expected Mismatch verification status"),
    }
}

// Unit tests for transitional states
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
fn test_status_command_degraded() {
    let fs = MockFilesystem::new();
    let config = Config::default();

    let state_file = StateFile {
        state: SystemState::Degraded {
            since: Utc::now(),
            reason: "unmount of /home failed".into(),
            remaining_mounts: vec![],
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert!(matches!(report.state, SystemState::Degraded { .. }));
    assert!(report.overlays.is_empty());
    assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
    assert!(report.uptime.is_none());
    assert!(report.activated_at.is_none());
}

// Unit tests for overlay verification edge cases
#[test]
fn test_status_command_active_all_overlays_mounted() {
    let fs = MockFilesystem::new();
    let config = config_hidden();
    let overlays = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ];

    let mut overlay_status = std::collections::HashMap::new();
    for overlay in &overlays {
        overlay_status.insert(
            overlay.clone(),
            mount_nails_overlay(&fs, overlay.to_str().unwrap()),
        );
    }

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: overlays.clone(),
            decoy_writers: Vec::new(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.posture, Posture::Active);
    assert_eq!(report.overlay_verification, VerificationStatus::Verified);
    assert_eq!(report.overlays.len(), 3);
}

#[test]
fn test_status_command_active_recording_no_overlays_is_degraded() {
    // An Active state that records no overlays is inconsistent with reality: the
    // reconciler flags it degraded rather than treating empty as verified.
    let fs = MockFilesystem::new();
    let config = config_hidden();

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
            decoy_writers: Vec::new(),
        },
        overlay_status: std::collections::HashMap::new(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.posture, Posture::Degraded);
    assert!(report.overlays.is_empty());
}

#[test]
fn test_status_command_active_multiple_mismatches() {
    // None of the recorded overlays is actually a NAILS overlay in the kernel.
    let fs = MockFilesystem::new();
    let config = config_hidden();
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
            decoy_writers: Vec::new(),
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.posture, Posture::Degraded);
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
        posture: Posture::Decoy,
        remaining_mounts: vec![],
        overlays: vec![],
        overlay_verification: VerificationStatus::NotApplicable,
        hidden_toplevel: None,
        last_switch_warning: None,
        activated_at: None,
        uptime: None,
        formatted_uptime: String::new(),
        opsec_reminders: vec![],
        overlay_details: None,
        overlay_mount_statuses: vec![],
        hidden_root_total: Some(4 * 1024 * 1024 * 1024),
        hidden_root_used: Some(1024 * 1024 * 1024),
        hidden_root_available: Some(3 * 1024 * 1024 * 1024),
        load_outcome: crate::LoadOutcome::Missing,
        persona_mode: crate::config::PersonaMode::FreshHome,
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
            decoy_writers: Vec::new(),
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
            decoy_writers: Vec::new(),
        },
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    let uptime = report.uptime.unwrap();
    assert_eq!(uptime.num_days(), 7);
}

// ========== Posture Tests ==========

#[test]
fn posture_maps_each_effective_state() {
    use crate::state::{DegradedKind, EffectiveState, InterruptedPhase};

    assert_eq!(
        Posture::from_effective(&EffectiveState::Inactive, false),
        Posture::Decoy
    );
    assert_eq!(
        Posture::from_effective(&EffectiveState::VerifiedActive { overlays: vec![] }, true),
        Posture::Active
    );
    assert_eq!(
        Posture::from_effective(
            &EffectiveState::Degraded {
                kind: DegradedKind::ActiveOverlaysMissing,
                reason: String::new(),
                remaining: vec![],
            },
            false
        ),
        Posture::Degraded
    );
    assert_eq!(
        Posture::from_effective(
            &EffectiveState::Degraded {
                kind: DegradedKind::InactiveMountsLive,
                reason: String::new(),
                remaining: vec![],
            },
            true
        ),
        Posture::Inconsistent
    );
    assert_eq!(
        Posture::from_effective(
            &EffectiveState::Interrupted {
                phase: InterruptedPhase::Activating,
                owner_alive: false,
            },
            false
        ),
        Posture::Inconsistent
    );
    // A transition whose owner process is still alive is in progress, not a
    // crash: it is the benign Transitioning posture, for both phases.
    assert_eq!(
        Posture::from_effective(
            &EffectiveState::Interrupted {
                phase: InterruptedPhase::Activating,
                owner_alive: true,
            },
            false
        ),
        Posture::Transitioning
    );
    assert_eq!(
        Posture::from_effective(
            &EffectiveState::Interrupted {
                phase: InterruptedPhase::Deactivating,
                owner_alive: true,
            },
            true
        ),
        Posture::Transitioning
    );
    assert_eq!(
        Posture::from_effective(&EffectiveState::StaleFromPreviousBoot, false),
        Posture::Decoy
    );
    assert_eq!(
        Posture::from_effective(&EffectiveState::StaleFromPreviousBoot, true),
        Posture::Inconsistent
    );
    assert_eq!(
        Posture::from_effective(&EffectiveState::Unknown, false),
        Posture::Unknown
    );
}

/// A writer that opened `/var` before the overlay and keeps writing to the decoy.
fn tail_on_var() -> crate::DecoyWriter {
    crate::DecoyWriter {
        pid: 812,
        name: "tail".to_string(),
        service: None,
        targets: vec![PathBuf::from("/var")],
    }
}

#[test]
fn decoy_writers_empty_outside_active_state() {
    let report = StatusReport::default();
    assert!(report.decoy_writers().is_empty());
}

#[test]
fn status_command_reports_decoy_writers_recorded_at_activation() {
    // status runs as its own process, so the writers must come from the state
    // file written at activation, not from a fresh /proc scan.
    let fs = MockFilesystem::new();

    let overlays = vec![PathBuf::from("/var")];
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/var"), mount_nails_overlay(&fs, "/var"));
    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays,
            decoy_writers: vec![tail_on_var()],
        },
        overlay_status,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config_hidden(), temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    assert_eq!(report.overlay_verification, VerificationStatus::Verified);
    assert_eq!(report.decoy_writers(), &[tail_on_var()]);
}

#[test]
fn posture_safety_and_remediation() {
    assert!(Posture::Decoy.is_safe());
    assert!(Posture::Active.is_safe());
    assert!(Posture::Transitioning.is_safe());
    assert!(!Posture::Degraded.is_safe());
    assert!(!Posture::Inconsistent.is_safe());
    assert!(!Posture::Unknown.is_safe());

    assert!(Posture::Decoy.remediation().is_none());
    assert!(Posture::Active.remediation().is_none());
    assert!(Posture::Transitioning.remediation().is_none());
    assert!(
        Posture::Degraded
            .remediation()
            .unwrap()
            .contains("nails emergency")
    );
    assert!(
        Posture::Inconsistent
            .remediation()
            .unwrap()
            .contains("nails emergency")
    );
    assert!(Posture::Unknown.remediation().is_some());
}

#[test]
fn posture_marks_distinguish_safe_from_dangerous() {
    use crate::output::Mark;
    assert_eq!(Posture::Decoy.mark(), Mark::Neutral);
    assert_eq!(Posture::Active.mark(), Mark::Pass);
    assert_eq!(Posture::Degraded.mark(), Mark::Fail);
    assert_eq!(Posture::Inconsistent.mark(), Mark::Fail);
    assert_eq!(Posture::Unknown.mark(), Mark::Warn);
}

#[test]
fn posture_labels_and_plain_are_stable() {
    assert_eq!(Posture::Decoy.as_str(), "decoy");
    assert_eq!(Posture::Active.as_str(), "active");
    assert_eq!(Posture::Degraded.as_str(), "degraded");
    assert_eq!(Posture::Inconsistent.as_str(), "inconsistent");
    assert_eq!(Posture::Unknown.as_str(), "unknown");

    assert!(Posture::Degraded.to_plain().starts_with("[DEGRADED]"));
    assert!(
        Posture::Inconsistent
            .to_plain()
            .starts_with("[INCONSISTENT]")
    );
}

#[test]
fn posture_render_is_ascii_in_ascii_style() {
    use crate::output::Style;
    let ascii = Style {
        color: true,
        ascii: true,
    };
    for posture in [
        Posture::Decoy,
        Posture::Active,
        Posture::Degraded,
        Posture::Inconsistent,
        Posture::Unknown,
    ] {
        assert!(posture.render(ascii).is_ascii(), "{posture:?}");
        assert_eq!(posture.render(ascii), posture.to_plain());
    }

    // Only the dangerous postures are painted red; the decoy is never coloured.
    let color = Style {
        color: true,
        ascii: false,
    };
    assert!(Posture::Degraded.render(color).contains("\x1b[1;31m"));
    assert!(Posture::Inconsistent.render(color).contains("\x1b[1;31m"));
    assert!(!Posture::Decoy.render(color).contains('\x1b'));
}

// ========== Reconcile-Driven Posture Tests ==========

#[test]
fn test_status_degraded_when_active_overlay_missing() {
    // Active state records two overlays but only one is a live NAILS overlay:
    // the posture is degraded and the remediation names emergency.
    let fs = MockFilesystem::new();
    let config = config_hidden();
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), mount_nails_overlay(&fs, "/home"));
    overlay_status.insert(PathBuf::from("/var"), create_overlay_info("/var"));

    let state_file = StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/var")],
        },
        overlay_status,
        boot_id: crate::state::read_boot_id(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let report = StatusCommand::new(fs, config, temp_file.path().to_path_buf())
        .run()
        .unwrap();

    assert_eq!(report.posture, Posture::Degraded);
    assert!(!report.posture.is_safe());
    assert!(
        report
            .posture
            .remediation()
            .unwrap()
            .contains("nails emergency")
    );
    let var = report
        .overlay_mount_statuses
        .iter()
        .find(|s| s.path == Path::new("/var"))
        .unwrap();
    assert!(!var.owned);
}

#[test]
fn test_status_unknown_for_truncated_state_file() {
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), "{ definitely-not-json").unwrap();

    let report = StatusCommand::new(
        MockFilesystem::new(),
        config_hidden(),
        temp_file.path().to_path_buf(),
    )
    .run()
    .unwrap();

    assert_eq!(report.posture, Posture::Unknown);
    assert_eq!(report.load_outcome, crate::LoadOutcome::Corrupt);
}

#[test]
fn test_status_inconsistent_when_state_missing_but_overlay_live() {
    // The dangerous lazily-unmounted-backend case: the state file is gone (the
    // backend was torn down) but a NAILS overlay is still serving hidden data.
    // Status must report inconsistent, never decoy.
    let fs = MockFilesystem::new();
    let config = config_hidden();
    mount_nails_overlay(&fs, "/home");

    let temp_dir = tempfile::tempdir().unwrap();
    let missing_path = temp_dir.path().join("state.json");

    let report = StatusCommand::new(fs, config, missing_path).run().unwrap();

    assert_eq!(report.posture, Posture::Inconsistent);
    assert!(report.remaining_mounts.contains(&PathBuf::from("/home")));
}

#[test]
fn test_status_plain_ext4_home_is_not_a_verified_overlay() {
    // A plain foreign mount at an overlay target must never read as verified.
    let fs = MockFilesystem::new();
    let config = config_hidden();
    fs.mock_set_mount_unmanaged(Path::new("/home"));

    let state_file = StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status: {
            let mut m = std::collections::HashMap::new();
            m.insert(PathBuf::from("/home"), create_overlay_info("/home"));
            m
        },
        boot_id: crate::state::read_boot_id(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let report = StatusCommand::new(fs, config, temp_file.path().to_path_buf())
        .run()
        .unwrap();

    assert_eq!(report.posture, Posture::Degraded);
    let home = report
        .overlay_mount_statuses
        .iter()
        .find(|s| s.path == Path::new("/home"))
        .unwrap();
    assert!(!home.owned, "plain ext4 /home must not be owned");
    assert!(!home.actually_mounted);
    assert_ne!(report.overlay_verification, VerificationStatus::Verified);
}

// ========== Uptime Formatting Tests ==========

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

// ========== OpSec Reminder Generation Tests ==========

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

// ========== OpSec Reminder Struct Tests ==========

#[test]
fn test_opsec_reminder_display_info() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Info,
        message: "Test message".to_string(),
    };
    let display = format!("{}", reminder);
    assert!(display.contains('ℹ'));
    assert!(display.contains("Test message"));
}

#[test]
fn test_opsec_reminder_display_warning() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Warning,
        message: "Warning message".to_string(),
    };
    let display = format!("{}", reminder);
    assert!(display.contains('⚠'));
    assert!(display.contains("Warning message"));
}

#[test]
fn test_opsec_reminder_display_critical() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Critical,
        message: "Critical message".to_string(),
    };
    let display = format!("{}", reminder);
    assert!(display.contains('✗'));
    assert!(display.contains("Critical message"));
}

#[test]
fn test_opsec_reminder_to_plain() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Critical,
        message: "Session >24 hours".to_string(),
    };
    let plain = reminder.to_plain();
    assert!(plain.is_ascii());
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

// ========== ReminderSeverity Tests ==========

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

// ========== Integration Tests ==========

#[test]
fn test_status_command_includes_formatted_uptime() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let activated_at = Utc::now() - chrono::Duration::hours(3) - chrono::Duration::minutes(30);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: vec![],
            decoy_writers: Vec::new(),
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
            decoy_writers: Vec::new(),
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
            decoy_writers: Vec::new(),
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
            decoy_writers: Vec::new(),
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
            decoy_writers: Vec::new(),
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
fn test_verification_flags_overlay_absent_from_kernel() {
    // Verification is judged against the kernel, not the state file: a live NAILS
    // overlay passes, while one that is merely recorded but not mounted is flagged.
    let fs = MockFilesystem::new();
    let config = config_hidden();
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), mount_nails_overlay(&fs, "/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: overlays.clone(),
            decoy_writers: Vec::new(),
        },
        overlay_status,
        boot_id: crate::state::read_boot_id(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    match report.overlay_verification {
        VerificationStatus::Mismatch { errors } => {
            assert!(errors.iter().any(|e| e.contains("/etc")));
            assert!(!errors.iter().any(|e| e.contains("/home")));
        }
        other => panic!("Expected Mismatch verification status, got {other:?}"),
    }
}

#[test]
fn test_status_command_surfaces_load_outcome_for_missing_and_loaded_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing_path = temp_dir.path().join("missing-state.json");

    let missing_report = StatusCommand::new(
        MockFilesystem::new(),
        Config::default(),
        missing_path.clone(),
    )
    .run()
    .unwrap();
    assert_eq!(missing_report.load_outcome, crate::LoadOutcome::Missing);

    // A compatible (same-major) version loads cleanly; there is no migration.
    let state_file = StateFile {
        version: "0.0.5".to_string(),
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);
    let loaded_report = StatusCommand::new(
        MockFilesystem::new(),
        Config::default(),
        temp_file.path().to_path_buf(),
    )
    .run()
    .unwrap();

    assert_eq!(loaded_report.load_outcome, crate::LoadOutcome::Loaded);
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
    assert_eq!(report.load_outcome, crate::LoadOutcome::Corrupt);
    // A corrupt file collapses to the safe default on disk but the posture fails
    // closed: unknown, not decoy.
    assert_eq!(report.posture, Posture::Unknown);
    assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
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
            decoy_writers: Vec::new(),
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
fn test_status_reports_upperdir_and_ownership_per_overlay() {
    // The per-overlay identity carries the upperdir from the state file and the
    // ownership verdict from the kernel.
    let fs = MockFilesystem::new();
    let config = config_hidden();
    let home_info = mount_nails_overlay(&fs, "/home");

    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), home_info.clone());
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays,
            decoy_writers: Vec::new(),
        },
        overlay_status,
        boot_id: crate::state::read_boot_id(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let report = StatusCommand::new(fs, config, temp_file.path().to_path_buf())
        .run()
        .unwrap();

    let home = report
        .overlay_mount_statuses
        .iter()
        .find(|status| status.path == Path::new("/home"))
        .unwrap();
    assert!(home.owned);
    assert_eq!(home.upperdir, Some(home_info.upper_dir));

    let etc = report
        .overlay_mount_statuses
        .iter()
        .find(|status| status.path == Path::new("/etc"))
        .unwrap();
    assert!(!etc.owned);
    assert!(!etc.actually_mounted);
}

// ============================================================================
// Structured Logging Tests for Status
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
            decoy_writers: Vec::new(),
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
// Per-Overlay Mount Status Display Tests
// ============================================================================

#[test]
fn test_overlay_mount_statuses_populated_for_active_state() {
    // Test that overlay_mount_statuses is populated with actual mount status
    let fs = MockFilesystem::new();
    let config = config_hidden();
    mount_nails_overlay(&fs, "/home"); // live NAILS overlay
    // /etc is recorded but never mounted as a NAILS overlay

    let activated_at = Utc::now();
    let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
    overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at,
            overlays: overlays.clone(),
            decoy_writers: Vec::new(),
        },
        overlay_status,
        boot_id: crate::state::read_boot_id(),
        ..StateFile::default()
    };
    let temp_file = create_temp_state_file(&state_file);

    let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
    let report = cmd.run().unwrap();

    // Verify overlay_mount_statuses is populated
    assert_eq!(report.overlay_mount_statuses.len(), 2);

    // Verify /home status (a live NAILS overlay)
    let home_status = report
        .overlay_mount_statuses
        .iter()
        .find(|s| s.path == Path::new("/home"))
        .expect("/home should be in statuses");
    assert!(home_status.expected_mounted);
    assert!(home_status.actually_mounted);

    // Verify /etc status (not a NAILS overlay)
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

#[test]
fn test_decoy_and_dangerous_postures_render_distinctly() {
    use crate::output::Style;

    for style in [
        Style::default(),
        Style {
            color: true,
            ascii: false,
        },
        Style {
            color: false,
            ascii: true,
        },
    ] {
        let decoy = Posture::Decoy.render(style);
        let degraded = Posture::Degraded.render(style);
        assert_ne!(
            decoy.split_whitespace().next(),
            degraded.split_whitespace().next(),
            "{style:?}: {decoy} / {degraded}"
        );
    }
}

#[test]
fn test_reminder_ascii_render_is_ascii() {
    use crate::output::Style;

    let ascii = Style {
        color: true,
        ascii: true,
    };
    for severity in [
        ReminderSeverity::Info,
        ReminderSeverity::Warning,
        ReminderSeverity::Critical,
    ] {
        let reminder = OpSecReminder {
            severity,
            message: "m".to_string(),
        };
        assert_eq!(reminder.render(ascii), reminder.to_plain());
    }
}
