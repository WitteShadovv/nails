// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared string constants used across the crate.
//!
//! The environment-variable names that name the target user, and the NixOS
//! system profile's binary directory. They are plain literals: the binary is identifiable, and hiding these
//! names from a `strings` scan never offered real protection.

/// Overrides the target user for privilege-dropped operations.
pub const ENV_TARGET_USER: &str = "NAILS_TARGET_USER";

/// Overrides the target UID for privilege-dropped operations.
pub const ENV_TARGET_UID: &str = "NAILS_TARGET_UID";

/// The NixOS system profile's binary directory.
///
/// The one place this store path is written as a literal; every other site that
/// needs it (the process runner's search list, the NixOS platform's host-command
/// directories) refers to this constant.
pub const NIXOS_SYSTEM_PROFILE_BIN: &str = "/run/current-system/sw/bin";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_names_match_their_literals() {
        assert_eq!(ENV_TARGET_USER, "NAILS_TARGET_USER");
        assert_eq!(ENV_TARGET_UID, "NAILS_TARGET_UID");
    }
}
