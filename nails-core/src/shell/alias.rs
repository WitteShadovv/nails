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
//! let hidden_volume = "/mnt/hidden-volume";
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
/// - Checks if hidden volume is mounted before adding alias
/// - Checks if alias already exists (idempotency)
/// - Adds `alias nails='sudo {hidden_volume}/bin/nails'`
/// - Designed to be sourced via `eval` or `. script.sh`
///
/// # Arguments
///
/// * `hidden_volume_path` - Path to the hidden volume root (e.g., "/mnt/hidden-volume")
///
/// # Returns
///
/// Bash/Zsh script content as a String
///
/// # Example
///
/// ```rust,ignore
/// let script = generate_bash_zsh_alias_script("/mnt/hidden-volume");
/// // Script checks for /mnt/hidden-volume/.nails before adding alias
/// ```
pub fn generate_bash_zsh_alias_script(hidden_volume_path: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# NAILS Shell Alias Management - Bash/Zsh
# Sourced during activation, adds 'nails' command alias

# Guard: Only add if hidden volume is mounted
if [ ! -d "{hidden_volume_path}/.nails" ]; then
    return 0
fi

# Guard: Don't re-add if alias already exists
if alias nails 2>/dev/null | grep -q 'nails'; then
    return 0
fi

# Add alias to current session
alias nails='sudo {hidden_volume_path}/bin/nails'
"#,
        hidden_volume_path = hidden_volume_path
    )
}

/// Generate fish alias script that adds 'nails' command alias
///
/// Creates a script that:
/// - Checks if hidden volume is mounted before adding alias
/// - Checks if nails function exists (idempotency)
/// - Adds alias using fish syntax: `alias nails 'sudo {hidden_volume}/bin/nails'`
/// - Designed to be sourced in fish shell
///
/// # Arguments
///
/// * `hidden_volume_path` - Path to the hidden volume root (e.g., "/mnt/hidden-volume")
///
/// # Returns
///
/// Fish script content as a String
///
/// # Example
///
/// ```rust,ignore
/// let script = generate_fish_alias_script("/mnt/hidden-volume");
/// // Script checks for /mnt/hidden-volume/.nails before adding alias
/// ```
pub fn generate_fish_alias_script(hidden_volume_path: &str) -> String {
    format!(
        r#"#!/usr/bin/env fish
# NAILS Shell Alias Management - Fish
# Sourced during activation

# Guard: Only add if hidden volume is mounted
if not test -d "{hidden_volume_path}/.nails"
    exit 0
end

# Guard: Don't re-add if alias exists
if functions -q nails
    exit 0
end

# Add alias to current session
alias nails 'sudo {hidden_volume_path}/bin/nails'
"#,
        hidden_volume_path = hidden_volume_path
    )
}

/// Generate bash/zsh alias cleanup script
///
/// Creates a best-effort script that removes the 'nails' alias from the current
/// session. Uses `|| true` to ensure the script never fails.
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
# Remove nails alias from current session (best-effort)
unalias nails 2>/dev/null || true
"#
    .to_string()
}

/// Generate fish alias cleanup script
///
/// Creates a best-effort script that removes the 'nails' alias from the current
/// fish session. Uses `; or true` to ensure the script never fails.
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
# Remove nails alias from current session (best-effort)
functions -e nails 2>/dev/null; or true
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_zsh_alias_script_content() {
        let script = generate_bash_zsh_alias_script("/mnt/hidden-volume");

        // Verify shebang
        assert!(script.starts_with("#!/usr/bin/env bash"));

        // Verify hidden volume mount check
        assert!(script.contains(r#"if [ ! -d "/mnt/hidden-volume/.nails" ]"#));
        assert!(script.contains("return 0"));

        // Verify idempotency check
        assert!(script.contains(r#"if alias nails 2>/dev/null | grep -q 'nails'"#));

        // Verify alias command
        assert!(script.contains(r#"alias nails='sudo /mnt/hidden-volume/bin/nails'"#));
    }

    #[test]
    fn test_bash_zsh_alias_script_custom_path() {
        let script = generate_bash_zsh_alias_script("/custom/hidden");

        // Verify custom path in mount check
        assert!(script.contains(r#"if [ ! -d "/custom/hidden/.nails" ]"#));

        // Verify custom path in alias
        assert!(script.contains(r#"alias nails='sudo /custom/hidden/bin/nails'"#));
    }

    #[test]
    fn test_fish_alias_script_content() {
        let script = generate_fish_alias_script("/mnt/hidden-volume");

        // Verify shebang
        assert!(script.starts_with("#!/usr/bin/env fish"));

        // Verify hidden volume mount check
        assert!(script.contains(r#"if not test -d "/mnt/hidden-volume/.nails""#));
        assert!(script.contains("exit 0"));

        // Verify idempotency check
        assert!(script.contains("if functions -q nails"));

        // Verify alias command
        assert!(script.contains(r#"alias nails 'sudo /mnt/hidden-volume/bin/nails'"#));
    }

    #[test]
    fn test_fish_alias_script_custom_path() {
        let script = generate_fish_alias_script("/custom/hidden");

        // Verify custom path in mount check
        assert!(script.contains(r#"if not test -d "/custom/hidden/.nails""#));

        // Verify custom path in alias
        assert!(script.contains(r#"alias nails 'sudo /custom/hidden/bin/nails'"#));
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
    fn test_bash_zsh_script_has_mount_guard() {
        let script = generate_bash_zsh_alias_script("/mnt/hidden-volume");

        // Verify the script checks mount before proceeding
        assert!(script.contains(".nails"));
        assert!(script.contains("return 0"));
    }

    #[test]
    fn test_fish_script_has_mount_guard() {
        let script = generate_fish_alias_script("/mnt/hidden-volume");

        // Verify the script checks mount before proceeding
        assert!(script.contains(".nails"));
        assert!(script.contains("exit 0"));
    }

    #[test]
    fn test_bash_zsh_script_idempotency_guard() {
        let script = generate_bash_zsh_alias_script("/mnt/hidden-volume");

        // Verify idempotency check exists
        assert!(script.contains("alias nails 2>/dev/null"));
        assert!(script.contains("grep -q 'nails'"));
    }

    #[test]
    fn test_fish_script_idempotency_guard() {
        let script = generate_fish_alias_script("/mnt/hidden-volume");

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
}
