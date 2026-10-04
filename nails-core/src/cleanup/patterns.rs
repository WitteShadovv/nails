// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Substring patterns used to filter shell history and scan for leaks.
//!
//! These are plain literals. Hiding them from a `strings` scan of the binary
//! never provided real protection, so they live here in the open beside the
//! cleanup code that consumes them.

/// Patterns stripped from shell history during cleanup.
const DEFAULT_CLEANUP_PATTERNS: &[&str] = &[
    "nails",
    "veracrypt",
    "cryptsetup",
    "tcrypt",
    "/mnt/hidden",
    "hidden-volume",
    "hidden_volume",
];

/// Patterns that must not appear in scanned files (superset of the cleanup set).
const DEFAULT_CANARY_PATTERNS: &[&str] = &[
    "nails",
    "veracrypt",
    "cryptsetup",
    "tcrypt",
    "/mnt/hidden",
    "hidden-volume",
    "hidden_volume",
    "secret-project",
    "financial-data",
    "NAILS_CANARY",
];

/// Patterns cleaned from history before activation (crypto tooling traces).
const PRE_ACTIVATION_CLEANUP_PATTERNS: &[&str] = &[
    "nails",
    "cryptsetup",
    "veracrypt",
    "luks",
    "luksOpen",
    "luksClose",
    "/dev/mapper",
];

/// Default patterns stripped from shell history during cleanup.
pub fn default_cleanup_patterns() -> Vec<String> {
    DEFAULT_CLEANUP_PATTERNS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Default canary patterns that should not appear in scanned files.
pub fn default_canary_patterns() -> Vec<String> {
    DEFAULT_CANARY_PATTERNS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Patterns cleaned from shell history before activation.
pub fn pre_activation_cleanup_patterns() -> Vec<String> {
    PRE_ACTIVATION_CLEANUP_PATTERNS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_patterns_match_expected_set() {
        assert_eq!(
            default_cleanup_patterns(),
            vec![
                "nails",
                "veracrypt",
                "cryptsetup",
                "tcrypt",
                "/mnt/hidden",
                "hidden-volume",
                "hidden_volume",
            ]
        );
    }

    #[test]
    fn canary_patterns_match_expected_set() {
        assert_eq!(
            default_canary_patterns(),
            vec![
                "nails",
                "veracrypt",
                "cryptsetup",
                "tcrypt",
                "/mnt/hidden",
                "hidden-volume",
                "hidden_volume",
                "secret-project",
                "financial-data",
                "NAILS_CANARY",
            ]
        );
    }

    #[test]
    fn pre_activation_patterns_match_expected_set() {
        assert_eq!(
            pre_activation_cleanup_patterns(),
            vec![
                "nails",
                "cryptsetup",
                "veracrypt",
                "luks",
                "luksOpen",
                "luksClose",
                "/dev/mapper",
            ]
        );
    }
}
