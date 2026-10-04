// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared string constants used across the crate.
//!
//! These are the environment-variable names the tool reads to coordinate
//! detached activation, session detection and notifications.
//! They are plain literals: the binary is identifiable, and hiding these
//! names from a `strings` scan never offered real protection.

/// Overrides the target user for privilege-dropped operations.
pub const ENV_TARGET_USER: &str = "NAILS_TARGET_USER";

/// Overrides the target UID for privilege-dropped operations.
pub const ENV_TARGET_UID: &str = "NAILS_TARGET_UID";

/// Points at the system profile path used when building the NixOS generation.
pub const ENV_SYSTEM_PROFILE_PATH: &str = "NAILS_SYSTEM_PROFILE_PATH";

/// Suppresses desktop notifications.
pub const ENV_DISABLE_NOTIFICATIONS: &str = "NAILS_DISABLE_NOTIFICATIONS";

/// Signals whether logind is available for session detection.
pub const ENV_LOGIND_AVAILABLE: &str = "NAILS_LOGIND_AVAILABLE";

/// Overrides the detected session id.
pub const ENV_SESSION_ID: &str = "NAILS_SESSION_ID";

/// Overrides the detected display manager.
pub const ENV_DISPLAY_MANAGER: &str = "NAILS_DISPLAY_MANAGER";

/// Marks a process re-exec'd into the detached (systemd-run) context.
pub const ENV_DETACHED: &str = "NAILS_DETACHED";

/// Forces detachment even when heuristics would skip it.
pub const ENV_FORCE_DETACH: &str = "NAILS_FORCE_DETACH";

/// Skips detachment entirely (used by tests and non-interactive runs).
pub const ENV_SKIP_DETACH: &str = "NAILS_SKIP_DETACH";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_names_match_their_literals() {
        assert_eq!(ENV_TARGET_USER, "NAILS_TARGET_USER");
        assert_eq!(ENV_TARGET_UID, "NAILS_TARGET_UID");
        assert_eq!(ENV_SYSTEM_PROFILE_PATH, "NAILS_SYSTEM_PROFILE_PATH");
        assert_eq!(ENV_DISABLE_NOTIFICATIONS, "NAILS_DISABLE_NOTIFICATIONS");
        assert_eq!(ENV_LOGIND_AVAILABLE, "NAILS_LOGIND_AVAILABLE");
        assert_eq!(ENV_SESSION_ID, "NAILS_SESSION_ID");
        assert_eq!(ENV_DISPLAY_MANAGER, "NAILS_DISPLAY_MANAGER");
        assert_eq!(ENV_DETACHED, "NAILS_DETACHED");
        assert_eq!(ENV_FORCE_DETACH, "NAILS_FORCE_DETACH");
        assert_eq!(ENV_SKIP_DETACH, "NAILS_SKIP_DETACH");
    }
}
