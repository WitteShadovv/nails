//! Shell alias management for NAILS command
//!
//! This module provides alias script generation that adds a 'nails' command alias
//! during activation. The alias points to the NAILS binary on the hidden volume,
//! allowing users to run commands without path prefixes.
//!
//! # Session-Only Aliases
//!
//! Following the UX anti-pattern guidance (no shell config modifications), these
//! scripts are designed to be sourced into the current shell session only. They
//! do NOT modify `.bashrc`, `.zshrc`, or `config.fish`.
//!
//! # Architecture Alignment
//!
//! Implementation follows the Shell Alias Management section of the architecture
//! document, with the critical modification that aliases are session-only.
//!
//! # Alias Lifecycle
//!
//! | Command | Alias Added? | Alias Removed? |
//! |---------|--------------|----------------|
//! | `nails activate` | Yes (if not present) | No |
//! | `nails deactivate` | No | No (left for convenience) |
//! | `nails emergency` | No | Yes (best-effort) |
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::shell::alias::{generate_bash_zsh_alias_script, generate_fish_alias_script};
//!
//! let hidden_volume = DEFAULT_HIDDEN_VOLUME_ROOT;
//!
//! // Generate bash/zsh alias script
//! let bash_script = generate_bash_zsh_alias_script(hidden_volume);
//!
//! // Generate fish alias script
//! let fish_script = generate_fish_alias_script(hidden_volume);
//! ```

/// Generate bash/zsh alias script that adds 'nails' command alias
///
/// Creates a script that:
/// - Checks if alias already exists (idempotency)
/// - Adds `alias nails='sudo {binary_path}'`
/// - Designed to be sourced via `eval` or `. script.sh`
///
/// # Arguments
///
/// * `binary_path` - Path to the nails binary (from current_exe or fallback)
///
/// # Returns
///
/// Bash/Zsh script content as a String
///
/// # Example
///
/// ```rust,ignore
/// let script = generate_bash_zsh_alias_script("/usr/local/bin/nails");
/// ```
pub fn generate_bash_zsh_alias_script(binary_path: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# NAILS Shell Alias Management - Bash/Zsh
# Sourced during activation, adds 'nails' command alias

# Guard: Don't re-add if alias exists
if alias nails >/dev/null 2>&1; then
    return 0
fi

# Add alias to current session
alias nails='sudo {binary_path}'
"#,
        binary_path = binary_path
    )
}

/// Generate fish alias script that adds 'nails' command alias
///
/// Creates a script that:
/// - Checks if nails function exists (idempotency)
/// - Adds alias using fish syntax: `alias nails 'sudo {binary_path}'`
/// - Designed to be sourced in fish shell
///
/// # Arguments
///
/// * `binary_path` - Path to the nails binary (from current_exe or fallback)
///
/// # Returns
///
/// Fish script content as a String
///
/// # Example
///
/// ```rust,ignore
/// let script = generate_fish_alias_script("/usr/local/bin/nails");
/// ```
pub fn generate_fish_alias_script(binary_path: &str) -> String {
    format!(
        r#"#!/usr/bin/env fish
# NAILS Shell Alias Management - Fish
# Sourced during activation

# Guard: Don't re-add if alias exists
if functions -q nails
    exit 0
end

# Add alias to current session
alias nails 'sudo {binary_path}'
"#,
        binary_path = binary_path
    )
}

/// Generate bash/zsh alias cleanup script
///
/// Creates a best-effort script that removes the 'nails' alias from the current
/// session. Uses `|| true` to ensure the script never fails.
///
/// # Alias Lifecycle Context
///
/// Per architecture (docs/architecture.md:1837-1841):
/// - Normal deactivation: alias is NOT removed (left for convenience)
/// - Emergency deactivation: alias removal IS attempted (this script)
///
/// # Returns
///
/// Bash/Zsh cleanup script content as a String
///
/// # Example
///
/// ```rust,ignore
/// let cleanup = generate_bash_zsh_alias_cleanup();
/// // Removes alias with best-effort (never fails)
/// ```
pub fn generate_bash_zsh_alias_cleanup() -> String {
    r#"#!/usr/bin/env bash
# NAILS Alias Cleanup - Bash/Zsh (Emergency Only)
# Removes 'nails' alias from current session (best-effort)
# Used during emergency deactivation per architecture lifecycle
unalias nails 2>/dev/null || true
"#
    .to_string()
}

/// Generate fish alias cleanup script
///
/// Creates a best-effort script that removes the 'nails' alias from the current
/// fish session. Uses `; or true` to ensure the script never fails.
///
/// # Alias Lifecycle Context
///
/// Per architecture (docs/architecture.md:1837-1841):
/// - Normal deactivation: alias is NOT removed (left for convenience)
/// - Emergency deactivation: alias removal IS attempted (this script)
///
/// # Returns
///
/// Fish cleanup script content as a String
///
/// # Example
///
/// ```rust,ignore
/// let cleanup = generate_fish_alias_cleanup();
/// // Removes alias with best-effort (never fails)
/// ```
pub fn generate_fish_alias_cleanup() -> String {
    r#"#!/usr/bin/env fish
# NAILS Alias Cleanup - Fish (Emergency Only)
# Removes 'nails' alias from current session (best-effort)
# Used during emergency deactivation per architecture lifecycle
functions -e nails 2>/dev/null; or true
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_zsh_alias_script_content() {
        let script = generate_bash_zsh_alias_script("/usr/local/bin/nails");

        // Verify shebang
        assert!(script.starts_with("#!/usr/bin/env bash"));

        // Verify no .nails guard check
        assert!(!script.contains(".nails"));

        // Verify idempotency check (alias command returns non-zero if not found)
        assert!(script.contains("alias nails >/dev/null 2>&1"));

        // Verify alias command
        assert!(script.contains(r#"alias nails='sudo /usr/local/bin/nails'"#));
    }

    #[test]
    fn test_bash_zsh_alias_script_custom_path() {
        let script = generate_bash_zsh_alias_script("/custom/bin/nails");

        // Verify custom path in alias
        assert!(script.contains(r#"alias nails='sudo /custom/bin/nails'"#));
    }

    #[test]
    fn test_fish_alias_script_content() {
        let script = generate_fish_alias_script("/usr/local/bin/nails");

        // Verify shebang
        assert!(script.starts_with("#!/usr/bin/env fish"));

        // Verify no .nails guard check
        assert!(!script.contains(".nails"));

        // Verify idempotency check
        assert!(script.contains("if functions -q nails"));

        // Verify alias command
        assert!(script.contains(r#"alias nails 'sudo /usr/local/bin/nails'"#));
    }

    #[test]
    fn test_fish_alias_script_custom_path() {
        let script = generate_fish_alias_script("/custom/bin/nails");

        // Verify custom path in alias
        assert!(script.contains(r#"alias nails 'sudo /custom/bin/nails'"#));
    }

    #[test]
    fn test_bash_zsh_cleanup_script() {
        let cleanup = generate_bash_zsh_alias_cleanup();

        // Verify shebang
        assert!(cleanup.starts_with("#!/usr/bin/env bash"));

        // Verify best-effort unalias command
        assert!(cleanup.contains("unalias nails 2>/dev/null || true"));
    }

    #[test]
    fn test_fish_cleanup_script() {
        let cleanup = generate_fish_alias_cleanup();

        // Verify shebang
        assert!(cleanup.starts_with("#!/usr/bin/env fish"));

        // Verify best-effort removal command
        assert!(cleanup.contains("functions -e nails 2>/dev/null; or true"));
    }

    #[test]
    fn test_bash_zsh_script_idempotency_guard() {
        let script = generate_bash_zsh_alias_script("/usr/local/bin/nails");

        // Verify idempotency check exists (alias returns non-zero if not found)
        assert!(script.contains("alias nails >/dev/null 2>&1"));
    }

    #[test]
    fn test_fish_script_idempotency_guard() {
        let script = generate_fish_alias_script("/usr/local/bin/nails");

        // Verify idempotency check exists
        assert!(script.contains("functions -q nails"));
    }

    #[test]
    fn test_cleanup_scripts_never_fail() {
        let bash_cleanup = generate_bash_zsh_alias_cleanup();
        let fish_cleanup = generate_fish_alias_cleanup();

        // Verify bash/zsh cleanup uses || true
        assert!(bash_cleanup.contains("|| true"));

        // Verify fish cleanup uses ; or true
        assert!(fish_cleanup.contains("; or true"));
    }

    // Edge case tests for AC8 100% coverage

    #[test]
    fn test_bash_alias_script_with_path_containing_spaces() {
        let script = generate_bash_zsh_alias_script("/usr/local/my nails/bin/nails");

        // Verify path with spaces is properly quoted in alias
        assert!(script.contains(r#"alias nails='sudo /usr/local/my nails/bin/nails'"#));
    }

    #[test]
    fn test_fish_alias_script_with_path_containing_spaces() {
        let script = generate_fish_alias_script("/usr/local/my nails/bin/nails");

        // Verify path with spaces is properly quoted in alias
        assert!(script.contains(r#"alias nails 'sudo /usr/local/my nails/bin/nails'"#));
    }

    #[test]
    fn test_bash_alias_script_with_special_characters() {
        let script = generate_bash_zsh_alias_script("/usr/local/nails-2024_v1/bin/nails");

        // Verify path with underscore is included
        assert!(script.contains("sudo /usr/local/nails-2024_v1/bin/nails"));
    }

    #[test]
    fn test_bash_alias_script_empty_path() {
        let script = generate_bash_zsh_alias_script("");

        // Empty path should still generate valid script structure
        assert!(script.contains("#!/usr/bin/env bash"));
        assert!(script.contains("alias nails='sudo '"));
    }
}
