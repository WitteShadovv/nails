// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared string constants used across the crate.
//!
//! These are the environment-variable names that name the target user.
//! They are plain literals: the binary is identifiable, and hiding these
//! names from a `strings` scan never offered real protection.

/// Overrides the target user for privilege-dropped operations.
pub const ENV_TARGET_USER: &str = "NAILS_TARGET_USER";

/// Overrides the target UID for privilege-dropped operations.
pub const ENV_TARGET_UID: &str = "NAILS_TARGET_UID";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_names_match_their_literals() {
        assert_eq!(ENV_TARGET_USER, "NAILS_TARGET_USER");
        assert_eq!(ENV_TARGET_UID, "NAILS_TARGET_UID");
    }
}
