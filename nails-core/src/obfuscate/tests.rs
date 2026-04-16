use super::*;

#[test]
fn test_obfuscate_deobfuscate_roundtrip() {
    let original = "test string";
    let obfuscated = crate::obfuscate_str!("test string");
    let recovered = deobfuscate(&obfuscated);
    assert_eq!(recovered, original);
}

#[test]
fn test_env_skip_detach() {
    assert_eq!(env_skip_detach(), "NAILS_SKIP_DETACH");
}

#[test]
fn test_env_detached() {
    assert_eq!(env_detached(), "NAILS_DETACHED");
}

#[test]
fn test_hidden_volume_root() {
    assert_eq!(hidden_volume_root(), "/mnt/hidden-volume");
}

#[test]
fn test_hidden_path_pattern() {
    assert_eq!(hidden_path_pattern(), "/mnt/hidden");
}

#[test]
fn test_log_file_name() {
    assert_eq!(log_file_name(), "nails.log");
}

#[test]
fn test_config_file_name() {
    assert_eq!(config_file_name(), "nails.toml");
}

#[test]
fn test_default_cleanup_patterns() {
    let patterns = default_cleanup_patterns();
    assert!(patterns.contains(&"nails".to_string()));
    assert!(patterns.contains(&"veracrypt".to_string()));
    assert!(patterns.contains(&"cryptsetup".to_string()));
    assert!(patterns.contains(&"tcrypt".to_string()));
    assert!(patterns.contains(&"/mnt/hidden".to_string()));
    assert!(patterns.contains(&"hidden-volume".to_string()));
    assert!(patterns.contains(&"hidden_volume".to_string()));
}

#[test]
fn test_default_canary_patterns() {
    let patterns = default_canary_patterns();
    assert!(patterns.contains(&"nails".to_string()));
    assert!(patterns.contains(&"secret-project".to_string()));
    assert!(patterns.contains(&"NAILS_CANARY".to_string()));
}

#[test]
fn test_pre_activation_cleanup_patterns() {
    let patterns = pre_activation_cleanup_patterns();
    assert!(patterns.contains(&"nails".to_string()));
    assert!(patterns.contains(&"cryptsetup".to_string()));
    assert!(patterns.contains(&"luks".to_string()));
    assert!(patterns.contains(&"/dev/mapper".to_string()));
}

#[test]
fn test_artifact_paths() {
    let paths = artifact_paths();
    assert!(paths.contains(&"/tmp/nails.log".to_string()));
    assert!(paths.contains(&"/tmp/nails.toml".to_string()));
    assert!(paths.contains(&"/var/log/nails.log".to_string()));
}

#[test]
fn test_obfuscated_bytes_not_contain_original() {
    let obfuscated = &strings::ENV_SKIP_DETACH;
    let original = b"NAILS_SKIP_DETACH";

    let mut all_same = true;
    for (i, &byte) in obfuscated.iter().enumerate() {
        if byte != original[i] {
            all_same = false;
            break;
        }
    }
    assert!(!all_same, "Obfuscated bytes should differ from original");
}

#[test]
fn test_systemd_unit_prefix() {
    assert_eq!(systemd_unit_prefix(), "nails-activate-");
}

#[test]
fn test_env_force_detach() {
    assert_eq!(env_force_detach(), "NAILS_FORCE_DETACH");
}

#[test]
fn test_env_session_vars() {
    assert_eq!(env_session_id(), "NAILS_SESSION_ID");
    assert_eq!(env_display_manager(), "NAILS_DISPLAY_MANAGER");
    assert_eq!(env_target_uid(), "NAILS_TARGET_UID");
    assert_eq!(env_target_user(), "NAILS_TARGET_USER");
    assert_eq!(env_logind_available(), "NAILS_LOGIND_AVAILABLE");
}

#[test]
fn test_env_additional_vars() {
    assert_eq!(env_no_color(), "NAILS_NO_COLOR");
    assert_eq!(env_disable_notifications(), "NAILS_DISABLE_NOTIFICATIONS");
    assert_eq!(env_system_profile_path(), "NAILS_SYSTEM_PROFILE_PATH");
}
