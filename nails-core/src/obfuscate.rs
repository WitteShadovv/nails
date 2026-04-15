//! String Obfuscation for Forensic Resistance (Finding C4)
//!
//! This module provides compile-time string obfuscation to prevent sensitive
//! string literals from appearing in plaintext in the binary. This addresses
//! forensic finding C4: NAILS binary strings visible in raw disk scans.
//!
//! # Approach
//!
//! Uses XOR-based obfuscation with a compile-time key derivation. The key is
//! derived from the string length and position, making it deterministic but
//! not obvious. At runtime, strings are deobfuscated on demand.
//!
//! # Security Model
//!
//! This is NOT encryption - it's obfuscation to defeat simple string scanning.
//! An attacker with access to the binary and knowledge of this technique can
//! still extract the strings. However, it prevents:
//! - Casual `strings` command scanning
//! - Automated forensic tools looking for specific keywords
//! - Disk sector scanning for unencrypted string patterns
//!
//! # Usage
//!
//! ```rust,ignore
//! use nails_core::obfuscate::deobfuscate;
//!
//! // Sensitive strings are stored obfuscated
//! const OBFUSCATED_ENV_VAR: &[u8] = &[/* obfuscated bytes */];
//!
//! // Deobfuscate at runtime when needed
//! let env_var = deobfuscate(OBFUSCATED_ENV_VAR);
//! ```
//!
//! # Obfuscated Strings Registry
//!
//! All sensitive strings are centralized in this module for:
//! - Easy auditing of what is obfuscated
//! - Consistent obfuscation approach
//! - Single point of maintenance

/// XOR key derivation constant (arbitrary prime for mixing)
const XOR_KEY_BASE: u8 = 0x5A;

/// Derive XOR key for a given position in the string
///
/// Uses position-dependent key derivation to avoid simple XOR attacks.
/// The formula combines the base key with position using prime multiplication.
#[inline]
const fn derive_key(position: usize) -> u8 {
    // Use wrapping arithmetic to handle overflow gracefully
    let pos_component = ((position as u8).wrapping_mul(31)).wrapping_add(17);
    XOR_KEY_BASE ^ pos_component
}

/// Obfuscate a string at compile time
///
/// This macro takes a string literal and produces an obfuscated byte array.
/// The result is a const array that can be stored in the binary without
/// the original string appearing in plaintext.
///
/// # Example
///
/// ```rust,ignore
/// const HIDDEN_PATH: [u8; 12] = obfuscate_str!("/mnt/hidden");
/// ```
#[macro_export]
macro_rules! obfuscate_str {
    ($s:literal) => {{
        const LEN: usize = $s.len();
        const fn obfuscate_bytes() -> [u8; LEN] {
            let bytes = $s.as_bytes();
            let mut result = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                let key = $crate::obfuscate::derive_key(i);
                result[i] = bytes[i] ^ key;
                i += 1;
            }
            result
        }
        obfuscate_bytes()
    }};
}

/// Deobfuscate a byte slice back to a String
///
/// Takes the obfuscated bytes and returns the original string.
/// This is called at runtime when the string value is needed.
///
/// # Panics
///
/// Panics if the deobfuscated bytes are not valid UTF-8.
/// This should never happen if the obfuscation was applied to valid strings.
#[inline]
pub fn deobfuscate(obfuscated: &[u8]) -> String {
    let mut result = Vec::with_capacity(obfuscated.len());
    for (i, &byte) in obfuscated.iter().enumerate() {
        let key = derive_key(i);
        result.push(byte ^ key);
    }
    String::from_utf8(result).expect("deobfuscation produced invalid UTF-8")
}

/// Deobfuscate to a static string (for const contexts where possible)
///
/// Returns an owned String since we can't return &'static str from runtime deobfuscation.
#[inline]
pub fn deobfuscate_to_string(obfuscated: &[u8]) -> String {
    deobfuscate(obfuscated)
}

// ============================================================================
// SENSITIVE STRINGS REGISTRY
// ============================================================================
// All sensitive strings that should be obfuscated are defined here.
// This provides a central location for auditing and maintenance.
// ============================================================================

/// Module containing all obfuscated sensitive strings
///
/// Access these via the getter functions below, which deobfuscate on demand.
pub mod strings {
    // Note: The obfuscate_str! macro is exported at the crate root, so we use crate::obfuscate_str

    // -------------------------------------------------------------------------
    // Environment Variables (NAILS_SKIP_DETACH, NAILS_DETACHED)
    // -------------------------------------------------------------------------

    /// NAILS_SKIP_DETACH environment variable (obfuscated)
    pub const ENV_SKIP_DETACH: [u8; 17] = crate::obfuscate_str!("NAILS_SKIP_DETACH");

    /// NAILS_DETACHED environment variable (obfuscated)
    pub const ENV_DETACHED: [u8; 14] = crate::obfuscate_str!("NAILS_DETACHED");

    /// NAILS_FORCE_DETACH environment variable (obfuscated)
    pub const ENV_FORCE_DETACH: [u8; 18] = crate::obfuscate_str!("NAILS_FORCE_DETACH");

    /// NAILS_SESSION_ID environment variable (obfuscated)
    pub const ENV_SESSION_ID: [u8; 16] = crate::obfuscate_str!("NAILS_SESSION_ID");

    /// NAILS_DISPLAY_MANAGER environment variable (obfuscated)
    pub const ENV_DISPLAY_MANAGER: [u8; 21] = crate::obfuscate_str!("NAILS_DISPLAY_MANAGER");

    /// NAILS_TARGET_UID environment variable (obfuscated)
    pub const ENV_TARGET_UID: [u8; 16] = crate::obfuscate_str!("NAILS_TARGET_UID");

    /// NAILS_TARGET_USER environment variable (obfuscated)
    pub const ENV_TARGET_USER: [u8; 17] = crate::obfuscate_str!("NAILS_TARGET_USER");

    /// NAILS_LOGIND_AVAILABLE environment variable (obfuscated)
    pub const ENV_LOGIND_AVAILABLE: [u8; 22] = crate::obfuscate_str!("NAILS_LOGIND_AVAILABLE");

    // -------------------------------------------------------------------------
    // Hidden Volume Paths
    // -------------------------------------------------------------------------

    /// Default hidden volume root path (obfuscated)
    pub const HIDDEN_VOLUME_ROOT: [u8; 18] = crate::obfuscate_str!("/mnt/hidden-volume");

    /// Hidden path pattern for cleanup (obfuscated)
    pub const HIDDEN_PATH_PATTERN: [u8; 11] = crate::obfuscate_str!("/mnt/hidden");

    // -------------------------------------------------------------------------
    // Log/Config File Names
    // -------------------------------------------------------------------------

    /// Log file name (obfuscated)
    pub const LOG_FILE_NAME: [u8; 9] = crate::obfuscate_str!("nails.log");

    /// Config file name (obfuscated)
    pub const CONFIG_FILE_NAME: [u8; 10] = crate::obfuscate_str!("nails.toml");

    // -------------------------------------------------------------------------
    // Cleanup Filter Patterns (Case-sensitive strings used in history filtering)
    // -------------------------------------------------------------------------

    /// "nails" pattern for cleanup (obfuscated)
    pub const PATTERN_NAILS: [u8; 5] = crate::obfuscate_str!("nails");

    /// "veracrypt" pattern for cleanup (obfuscated)
    pub const PATTERN_VERACRYPT: [u8; 9] = crate::obfuscate_str!("veracrypt");

    /// "cryptsetup" pattern for cleanup (obfuscated)
    pub const PATTERN_CRYPTSETUP: [u8; 10] = crate::obfuscate_str!("cryptsetup");

    /// "tcrypt" pattern for cleanup (obfuscated)
    pub const PATTERN_TCRYPT: [u8; 6] = crate::obfuscate_str!("tcrypt");

    /// "hidden-volume" pattern for cleanup (obfuscated)
    pub const PATTERN_HIDDEN_VOLUME_DASH: [u8; 13] = crate::obfuscate_str!("hidden-volume");

    /// "hidden_volume" pattern for cleanup (obfuscated)
    pub const PATTERN_HIDDEN_VOLUME_UNDERSCORE: [u8; 13] = crate::obfuscate_str!("hidden_volume");

    /// "secret-project" pattern for cleanup (obfuscated)
    pub const PATTERN_SECRET_PROJECT: [u8; 14] = crate::obfuscate_str!("secret-project");

    /// "financial-data" pattern for cleanup (obfuscated)
    pub const PATTERN_FINANCIAL_DATA: [u8; 14] = crate::obfuscate_str!("financial-data");

    /// "NAILS_CANARY" pattern for cleanup (obfuscated)
    pub const PATTERN_NAILS_CANARY: [u8; 12] = crate::obfuscate_str!("NAILS_CANARY");

    /// "luks" pattern for cleanup (obfuscated)
    pub const PATTERN_LUKS: [u8; 4] = crate::obfuscate_str!("luks");

    /// "luksOpen" pattern for cleanup (obfuscated)
    pub const PATTERN_LUKS_OPEN: [u8; 8] = crate::obfuscate_str!("luksOpen");

    /// "luksClose" pattern for cleanup (obfuscated)
    pub const PATTERN_LUKS_CLOSE: [u8; 9] = crate::obfuscate_str!("luksClose");

    /// "/dev/mapper" pattern for cleanup (obfuscated)
    pub const PATTERN_DEV_MAPPER: [u8; 11] = crate::obfuscate_str!("/dev/mapper");

    // -------------------------------------------------------------------------
    // NixOS Config Verification Patterns (for detecting leaks in base config)
    // -------------------------------------------------------------------------

    /// "hidden/nixos" pattern for config verification (obfuscated)
    pub const PATTERN_HIDDEN_NIXOS: [u8; 12] = crate::obfuscate_str!("hidden/nixos");

    /// "/hidden/" pattern for config verification (obfuscated)
    pub const PATTERN_HIDDEN_SLASH: [u8; 8] = crate::obfuscate_str!("/hidden/");

    // -------------------------------------------------------------------------
    // Additional Environment Variables (for session detection, notifications, etc.)
    // -------------------------------------------------------------------------

    /// NAILS_NO_COLOR environment variable (obfuscated)
    pub const ENV_NO_COLOR: [u8; 14] = crate::obfuscate_str!("NAILS_NO_COLOR");

    /// NAILS_DISABLE_NOTIFICATIONS environment variable (obfuscated)
    pub const ENV_DISABLE_NOTIFICATIONS: [u8; 27] =
        crate::obfuscate_str!("NAILS_DISABLE_NOTIFICATIONS");

    /// NAILS_SYSTEM_PROFILE_PATH environment variable (obfuscated)
    pub const ENV_SYSTEM_PROFILE_PATH: [u8; 25] =
        crate::obfuscate_str!("NAILS_SYSTEM_PROFILE_PATH");

    // -------------------------------------------------------------------------
    // Systemd Unit Name Prefix
    // -------------------------------------------------------------------------

    /// Systemd unit name prefix for detached activation (obfuscated)
    pub const SYSTEMD_UNIT_PREFIX: [u8; 15] = crate::obfuscate_str!("nails-activate-");

    // -------------------------------------------------------------------------
    // Artifact Paths for Verification
    // -------------------------------------------------------------------------

    /// "/tmp/nails.log" artifact path (obfuscated)
    pub const ARTIFACT_TMP_LOG: [u8; 14] = crate::obfuscate_str!("/tmp/nails.log");

    /// "/tmp/nails.toml" artifact path (obfuscated)
    pub const ARTIFACT_TMP_TOML: [u8; 15] = crate::obfuscate_str!("/tmp/nails.toml");

    /// "/var/log/nails.log" artifact path (obfuscated)
    pub const ARTIFACT_VAR_LOG: [u8; 18] = crate::obfuscate_str!("/var/log/nails.log");

    /// "/etc/nails" artifact path (obfuscated)
    pub const ARTIFACT_ETC: [u8; 10] = crate::obfuscate_str!("/etc/nails");

    /// "/home/.nails" artifact path (obfuscated)
    pub const ARTIFACT_HOME: [u8; 12] = crate::obfuscate_str!("/home/.nails");

    /// "/root/.nails" artifact path (obfuscated)
    pub const ARTIFACT_ROOT: [u8; 12] = crate::obfuscate_str!("/root/.nails");
}

// ============================================================================
// GETTER FUNCTIONS
// ============================================================================
// These functions provide deobfuscated strings at runtime.
// Use these instead of accessing the raw obfuscated bytes directly.
// ============================================================================

/// Get NAILS_SKIP_DETACH environment variable name
#[inline]
pub fn env_skip_detach() -> String {
    deobfuscate(&strings::ENV_SKIP_DETACH)
}

/// Get NAILS_DETACHED environment variable name
#[inline]
pub fn env_detached() -> String {
    deobfuscate(&strings::ENV_DETACHED)
}

/// Get NAILS_FORCE_DETACH environment variable name
#[inline]
pub fn env_force_detach() -> String {
    deobfuscate(&strings::ENV_FORCE_DETACH)
}

/// Get NAILS_SESSION_ID environment variable name
#[inline]
pub fn env_session_id() -> String {
    deobfuscate(&strings::ENV_SESSION_ID)
}

/// Get NAILS_DISPLAY_MANAGER environment variable name
#[inline]
pub fn env_display_manager() -> String {
    deobfuscate(&strings::ENV_DISPLAY_MANAGER)
}

/// Get NAILS_TARGET_UID environment variable name
#[inline]
pub fn env_target_uid() -> String {
    deobfuscate(&strings::ENV_TARGET_UID)
}

/// Get NAILS_TARGET_USER environment variable name
#[inline]
pub fn env_target_user() -> String {
    deobfuscate(&strings::ENV_TARGET_USER)
}

/// Get NAILS_LOGIND_AVAILABLE environment variable name
#[inline]
pub fn env_logind_available() -> String {
    deobfuscate(&strings::ENV_LOGIND_AVAILABLE)
}

/// Get default hidden volume root path
#[inline]
pub fn hidden_volume_root() -> String {
    deobfuscate(&strings::HIDDEN_VOLUME_ROOT)
}

/// Get hidden path pattern for cleanup
#[inline]
pub fn hidden_path_pattern() -> String {
    deobfuscate(&strings::HIDDEN_PATH_PATTERN)
}

/// Get log file name
#[inline]
pub fn log_file_name() -> String {
    deobfuscate(&strings::LOG_FILE_NAME)
}

/// Get config file name
#[inline]
pub fn config_file_name() -> String {
    deobfuscate(&strings::CONFIG_FILE_NAME)
}

/// Get systemd unit name prefix
#[inline]
pub fn systemd_unit_prefix() -> String {
    deobfuscate(&strings::SYSTEMD_UNIT_PREFIX)
}

/// Get NAILS_NO_COLOR environment variable name
#[inline]
pub fn env_no_color() -> String {
    deobfuscate(&strings::ENV_NO_COLOR)
}

/// Get NAILS_DISABLE_NOTIFICATIONS environment variable name
#[inline]
pub fn env_disable_notifications() -> String {
    deobfuscate(&strings::ENV_DISABLE_NOTIFICATIONS)
}

/// Get NAILS_SYSTEM_PROFILE_PATH environment variable name
#[inline]
pub fn env_system_profile_path() -> String {
    deobfuscate(&strings::ENV_SYSTEM_PROFILE_PATH)
}

/// Get "hidden/nixos" pattern for config verification
#[inline]
pub fn pattern_hidden_nixos() -> String {
    deobfuscate(&strings::PATTERN_HIDDEN_NIXOS)
}

/// Get "/hidden/" pattern for config verification
#[inline]
pub fn pattern_hidden_slash() -> String {
    deobfuscate(&strings::PATTERN_HIDDEN_SLASH)
}

/// Get default cleanup patterns (deobfuscated)
///
/// Returns the default set of patterns used for history cleanup and canary scanning.
/// These patterns identify sensitive commands and paths that should not remain
/// in shell history or other artifacts.
pub fn default_cleanup_patterns() -> Vec<String> {
    vec![
        deobfuscate(&strings::PATTERN_NAILS),
        deobfuscate(&strings::PATTERN_VERACRYPT),
        deobfuscate(&strings::PATTERN_CRYPTSETUP),
        deobfuscate(&strings::PATTERN_TCRYPT),
        deobfuscate(&strings::HIDDEN_PATH_PATTERN),
        deobfuscate(&strings::PATTERN_HIDDEN_VOLUME_DASH),
        deobfuscate(&strings::PATTERN_HIDDEN_VOLUME_UNDERSCORE),
    ]
}

/// Get default canary patterns (deobfuscated)
///
/// Returns the extended set of patterns used for canary scanning.
/// Includes additional patterns beyond basic cleanup patterns.
pub fn default_canary_patterns() -> Vec<String> {
    vec![
        deobfuscate(&strings::PATTERN_NAILS),
        deobfuscate(&strings::PATTERN_VERACRYPT),
        deobfuscate(&strings::PATTERN_CRYPTSETUP),
        deobfuscate(&strings::PATTERN_TCRYPT),
        deobfuscate(&strings::HIDDEN_PATH_PATTERN),
        deobfuscate(&strings::PATTERN_HIDDEN_VOLUME_DASH),
        deobfuscate(&strings::PATTERN_HIDDEN_VOLUME_UNDERSCORE),
        deobfuscate(&strings::PATTERN_SECRET_PROJECT),
        deobfuscate(&strings::PATTERN_FINANCIAL_DATA),
        deobfuscate(&strings::PATTERN_NAILS_CANARY),
    ]
}

/// Get pre-activation cleanup patterns (deobfuscated)
///
/// Returns patterns used for cleaning shell history before activation.
/// These are more aggressive than regular cleanup patterns.
pub fn pre_activation_cleanup_patterns() -> Vec<String> {
    vec![
        deobfuscate(&strings::PATTERN_NAILS),
        deobfuscate(&strings::PATTERN_CRYPTSETUP),
        deobfuscate(&strings::PATTERN_VERACRYPT),
        deobfuscate(&strings::PATTERN_LUKS),
        deobfuscate(&strings::PATTERN_LUKS_OPEN),
        deobfuscate(&strings::PATTERN_LUKS_CLOSE),
        deobfuscate(&strings::PATTERN_DEV_MAPPER),
    ]
}

/// Get artifact paths for verification (deobfuscated)
///
/// Returns paths that should be checked during forensic verification.
pub fn artifact_paths() -> Vec<String> {
    vec![
        deobfuscate(&strings::ARTIFACT_TMP_LOG),
        deobfuscate(&strings::ARTIFACT_TMP_TOML),
        deobfuscate(&strings::ARTIFACT_VAR_LOG),
        deobfuscate(&strings::ARTIFACT_ETC),
        deobfuscate(&strings::ARTIFACT_HOME),
        deobfuscate(&strings::ARTIFACT_ROOT),
    ]
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscate_deobfuscate_roundtrip() {
        // Test that obfuscation and deobfuscation are inverses
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
        // Verify that obfuscated bytes don't contain the original string
        let obfuscated = &strings::ENV_SKIP_DETACH;
        let original = b"NAILS_SKIP_DETACH";

        // Check that at least one byte is different
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
}
