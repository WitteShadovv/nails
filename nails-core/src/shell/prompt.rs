//! Prompt script generation for bash, zsh, and fish
//!
//! This module generates shell-specific prompt instrumentation scripts that
//! add a "(NAILS-ACTIVE)" prefix to the shell prompt when the hidden environment
//! is active.
//!
//! All scripts include:
//! - Hidden volume mount check before modification
//! - NO_COLOR environment variable support
//! - Idempotency guards to prevent double-prefixing
//! - Original prompt save/restore mechanism

/// Generate bash prompt instrumentation script
///
/// Creates a script that modifies PS1 to prepend "(NAILS-ACTIVE)" with
/// optional green color.
///
/// # Arguments
///
/// * `hidden_volume_root` - Path to hidden volume root for mount check
///
/// # Returns
///
/// Complete bash script content as a String
pub fn generate_bash_prompt_script(hidden_volume_root: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# NAILS Shell Prompt Instrumentation - Bash
# Sourced during activation, adds (NAILS-ACTIVE) prefix to PS1

# Guard: Only modify if hidden volume is mounted
if [ ! -d "{hidden_volume_root}/.nails" ]; then
    return 0
fi

# Guard: Don't double-prefix
if [[ "$PS1" == *"NAILS-ACTIVE"* ]]; then
    return 0
fi

# Save original PS1
export _NAILS_ORIG_PS1="$PS1"

# Apply prefix with optional color
# Braces below are escaped for Rust format! macro
# NO_COLOR check: if NO_COLOR is unset, use green color; otherwise plain text
if [ -z "${{NO_COLOR+x}}" ]; then
    PS1="\[\033[32m\](NAILS-ACTIVE)\[\033[0m\] $PS1"
else
    PS1="(NAILS-ACTIVE) $PS1"
fi
"#,
        hidden_volume_root = hidden_volume_root
    )
}

/// Generate bash prompt cleanup script
///
/// Creates a script that restores the original PS1 variable.
///
/// # Returns
///
/// Complete bash cleanup script content as a String
pub fn generate_bash_prompt_cleanup() -> String {
    r#"#!/usr/bin/env bash
# NAILS Shell Prompt Cleanup - Bash
# Restore original PS1

if [ -n "${_NAILS_ORIG_PS1+x}" ]; then
    PS1="$_NAILS_ORIG_PS1"
    unset _NAILS_ORIG_PS1
fi
"#
    .to_string()
}

/// Generate zsh prompt instrumentation script
///
/// Creates a script that modifies PROMPT to prepend "(NAILS-ACTIVE)" with
/// optional green color using zsh color codes.
///
/// # Arguments
///
/// * `hidden_volume_root` - Path to hidden volume root for mount check
///
/// # Returns
///
/// Complete zsh script content as a String
pub fn generate_zsh_prompt_script(hidden_volume_root: &str) -> String {
    format!(
        r#"#!/usr/bin/env zsh
# NAILS Shell Prompt Instrumentation - Zsh
# Sourced during activation, adds (NAILS-ACTIVE) prefix to PROMPT

# Guard: Only modify if hidden volume is mounted
if [ ! -d "{hidden_volume_root}/.nails" ]; then
    return 0
fi

# Guard: Don't double-prefix
if [[ "$PROMPT" == *"NAILS-ACTIVE"* ]]; then
    return 0
fi

# Save original PROMPT
export _NAILS_ORIG_PROMPT="$PROMPT"

# Apply prefix with optional color
# Braces below are escaped for Rust format! macro
# NO_COLOR check: if NO_COLOR is unset, use green color; otherwise plain text
if [ -z "${{NO_COLOR+x}}" ]; then
    PROMPT="%F{{green}}(NAILS-ACTIVE)%f $PROMPT"
else
    PROMPT="(NAILS-ACTIVE) $PROMPT"
fi
"#,
        hidden_volume_root = hidden_volume_root
    )
}

/// Generate zsh prompt cleanup script
///
/// Creates a script that restores the original PROMPT variable.
///
/// # Returns
///
/// Complete zsh cleanup script content as a String
pub fn generate_zsh_prompt_cleanup() -> String {
    r#"#!/usr/bin/env zsh
# NAILS Shell Prompt Cleanup - Zsh
# Restore original PROMPT

if [ -n "${_NAILS_ORIG_PROMPT+x}" ]; then
    PROMPT="$_NAILS_ORIG_PROMPT"
    unset _NAILS_ORIG_PROMPT
fi
"#
    .to_string()
}

/// Generate fish prompt instrumentation script
///
/// Creates a script that wraps the fish_prompt function to prepend
/// "(NAILS-ACTIVE)" with optional green color using set_color.
///
/// # Arguments
///
/// * `hidden_volume_root` - Path to hidden volume root for mount check
///
/// # Returns
///
/// Complete fish script content as a String
pub fn generate_fish_prompt_script(hidden_volume_root: &str) -> String {
    format!(
        r#"#!/usr/bin/env fish
# NAILS Shell Prompt Instrumentation - Fish
# Sourced during activation, adds (NAILS-ACTIVE) prefix to fish_prompt

# Guard: Only modify if hidden volume is mounted
if not test -d "{hidden_volume_root}/.nails"
    exit 0
end

# Guard: Don't re-wrap if already wrapped
if functions -q _nails_orig_prompt
    exit 0
end

# Save original fish_prompt
functions -c fish_prompt _nails_orig_prompt

# Define new prompt function
function fish_prompt
    if set -q NO_COLOR
        echo -n "(NAILS-ACTIVE) "
    else
        set_color green
        echo -n "(NAILS-ACTIVE) "
        set_color normal
    end
    _nails_orig_prompt
end
"#,
        hidden_volume_root = hidden_volume_root
    )
}

/// Generate fish prompt cleanup script
///
/// Creates a script that restores the original fish_prompt function.
///
/// # Returns
///
/// Complete fish cleanup script content as a String
pub fn generate_fish_prompt_cleanup() -> String {
    r#"#!/usr/bin/env fish
# NAILS Shell Prompt Cleanup - Fish
# Restore original fish_prompt

if functions -q _nails_orig_prompt
    functions -c _nails_orig_prompt fish_prompt
    functions -e _nails_orig_prompt
end
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_script_contains_mount_check() {
        let script = generate_bash_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("if [ ! -d \"/mnt/hidden-volume/.nails\" ]"));
    }

    #[test]
    fn test_bash_script_contains_idempotency_check() {
        let script = generate_bash_prompt_script("/mnt/hidden-volume");
        assert!(script.contains(r#"if [[ "$PS1" == *"NAILS-ACTIVE"* ]]"#));
    }

    #[test]
    fn test_bash_script_contains_no_color_check() {
        let script = generate_bash_prompt_script("/mnt/hidden-volume");
        assert!(script.contains(r#"if [ -z "${NO_COLOR+x}" ]"#));
    }

    #[test]
    fn test_bash_script_contains_color_codes() {
        let script = generate_bash_prompt_script("/mnt/hidden-volume");
        assert!(script.contains(r#"\[\033[32m\](NAILS-ACTIVE)\[\033[0m\]"#));
    }

    #[test]
    fn test_bash_script_saves_original_ps1() {
        let script = generate_bash_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("export _NAILS_ORIG_PS1="));
    }

    #[test]
    fn test_bash_cleanup_restores_ps1() {
        let cleanup = generate_bash_prompt_cleanup();
        assert!(cleanup.contains(r#"PS1="$_NAILS_ORIG_PS1""#));
        assert!(cleanup.contains("unset _NAILS_ORIG_PS1"));
    }

    #[test]
    fn test_zsh_script_contains_mount_check() {
        let script = generate_zsh_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("if [ ! -d \"/mnt/hidden-volume/.nails\" ]"));
    }

    #[test]
    fn test_zsh_script_contains_idempotency_check() {
        let script = generate_zsh_prompt_script("/mnt/hidden-volume");
        assert!(script.contains(r#"if [[ "$PROMPT" == *"NAILS-ACTIVE"* ]]"#));
    }

    #[test]
    fn test_zsh_script_contains_no_color_check() {
        let script = generate_zsh_prompt_script("/mnt/hidden-volume");
        assert!(script.contains(r#"if [ -z "${NO_COLOR+x}" ]"#));
    }

    #[test]
    fn test_zsh_script_contains_color_codes() {
        let script = generate_zsh_prompt_script("/mnt/hidden-volume");
        assert!(script.contains(r#"%F{green}(NAILS-ACTIVE)%f"#));
    }

    #[test]
    fn test_zsh_script_saves_original_prompt() {
        let script = generate_zsh_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("export _NAILS_ORIG_PROMPT="));
    }

    #[test]
    fn test_zsh_cleanup_restores_prompt() {
        let cleanup = generate_zsh_prompt_cleanup();
        assert!(cleanup.contains(r#"PROMPT="$_NAILS_ORIG_PROMPT""#));
        assert!(cleanup.contains("unset _NAILS_ORIG_PROMPT"));
    }

    #[test]
    fn test_fish_script_contains_mount_check() {
        let script = generate_fish_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("if not test -d \"/mnt/hidden-volume/.nails\""));
    }

    #[test]
    fn test_fish_script_contains_idempotency_check() {
        let script = generate_fish_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("if functions -q _nails_orig_prompt"));
    }

    #[test]
    fn test_fish_script_contains_no_color_check() {
        let script = generate_fish_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("if set -q NO_COLOR"));
    }

    #[test]
    fn test_fish_script_contains_color_command() {
        let script = generate_fish_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("set_color green"));
        assert!(script.contains("set_color normal"));
    }

    #[test]
    fn test_fish_script_saves_original_function() {
        let script = generate_fish_prompt_script("/mnt/hidden-volume");
        assert!(script.contains("functions -c fish_prompt _nails_orig_prompt"));
    }

    #[test]
    fn test_fish_cleanup_restores_function() {
        let cleanup = generate_fish_prompt_cleanup();
        assert!(cleanup.contains("functions -c _nails_orig_prompt fish_prompt"));
        assert!(cleanup.contains("functions -e _nails_orig_prompt"));
    }

    #[test]
    fn test_bash_script_uses_custom_hidden_volume_path() {
        let script = generate_bash_prompt_script("/custom/path");
        assert!(script.contains("if [ ! -d \"/custom/path/.nails\" ]"));
    }

    #[test]
    fn test_zsh_script_uses_custom_hidden_volume_path() {
        let script = generate_zsh_prompt_script("/custom/path");
        assert!(script.contains("if [ ! -d \"/custom/path/.nails\" ]"));
    }

    #[test]
    fn test_fish_script_uses_custom_hidden_volume_path() {
        let script = generate_fish_prompt_script("/custom/path");
        assert!(script.contains("if not test -d \"/custom/path/.nails\""));
    }

    // AC8: Integration tests - Syntax validation

    #[test]
    fn test_bash_script_syntax_valid() {
        let script = generate_bash_prompt_script("/mnt/hidden-volume");

        // Write script to a temp file and validate with bash -n
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("nails_prompt_test.bash");

        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(script.as_bytes());

            // Use bash -n for syntax check if bash is available
            if let Ok(output) = std::process::Command::new("bash")
                .arg("-n")
                .arg(&script_path)
                .output()
            {
                // bash -n returns 0 if syntax is valid
                assert!(
                    output.status.success(),
                    "bash script syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let _ = std::fs::remove_file(&script_path);
        }
    }

    #[test]
    fn test_zsh_script_syntax_valid() {
        let script = generate_zsh_prompt_script("/mnt/hidden-volume");

        // Write script to a temp file and validate with zsh -n
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("nails_prompt_test.zsh");

        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(script.as_bytes());

            // Use zsh -n for syntax check if zsh is available
            if let Ok(output) = std::process::Command::new("zsh")
                .arg("-n")
                .arg(&script_path)
                .output()
            {
                // zsh -n returns 0 if syntax is valid
                assert!(
                    output.status.success(),
                    "zsh script syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let _ = std::fs::remove_file(&script_path);
        }
    }

    #[test]
    fn test_fish_script_syntax_valid() {
        let script = generate_fish_prompt_script("/mnt/hidden-volume");

        // Write script to a temp file and validate with fish --no-execute
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("nails_prompt_test.fish");

        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(script.as_bytes());

            // Use fish --no-execute for syntax check if fish is available
            if let Ok(output) = std::process::Command::new("fish")
                .arg("--no-execute")
                .arg(&script_path)
                .output()
            {
                // fish --no-execute returns 0 if syntax is valid
                assert!(
                    output.status.success(),
                    "fish script syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let _ = std::fs::remove_file(&script_path);
        }
    }

    #[test]
    fn test_bash_cleanup_script_syntax_valid() {
        let cleanup = generate_bash_prompt_cleanup();

        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("nails_cleanup_test.bash");

        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(cleanup.as_bytes());

            if let Ok(output) = std::process::Command::new("bash")
                .arg("-n")
                .arg(&script_path)
                .output()
            {
                assert!(
                    output.status.success(),
                    "bash cleanup script syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let _ = std::fs::remove_file(&script_path);
        }
    }

    #[test]
    fn test_zsh_cleanup_script_syntax_valid() {
        let cleanup = generate_zsh_prompt_cleanup();

        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("nails_cleanup_test.zsh");

        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(cleanup.as_bytes());

            if let Ok(output) = std::process::Command::new("zsh")
                .arg("-n")
                .arg(&script_path)
                .output()
            {
                assert!(
                    output.status.success(),
                    "zsh cleanup script syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let _ = std::fs::remove_file(&script_path);
        }
    }

    #[test]
    fn test_fish_cleanup_script_syntax_valid() {
        let cleanup = generate_fish_prompt_cleanup();

        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join("nails_cleanup_test.fish");

        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(cleanup.as_bytes());

            if let Ok(output) = std::process::Command::new("fish")
                .arg("--no-execute")
                .arg(&script_path)
                .output()
            {
                assert!(
                    output.status.success(),
                    "fish cleanup script syntax validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            let _ = std::fs::remove_file(&script_path);
        }
    }
}
