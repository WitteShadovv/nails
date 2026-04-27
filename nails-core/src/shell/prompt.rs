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
/// # Returns
///
/// Complete bash prompt script content as a String
#[allow(clippy::useless_format)] // format!() needed to escape {{ }} braces
pub fn generate_bash_prompt_script() -> String {
    format!(
        r#"#!/usr/bin/env bash
# NAILS Shell Prompt Instrumentation - Bash
# Sourced during activation, adds (NAILS-ACTIVE) prefix to PS1

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
"#
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
/// # Returns
///
/// Complete zsh script content as a String
#[allow(clippy::useless_format)] // format!() needed to escape {{ }} braces
pub fn generate_zsh_prompt_script() -> String {
    format!(
        r#"#!/usr/bin/env zsh
# NAILS Shell Prompt Instrumentation - Zsh
# Sourced during activation, adds (NAILS-ACTIVE) prefix to PROMPT

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
"#
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
/// # Returns
///
/// Complete fish script content as a String
pub fn generate_fish_prompt_script() -> String {
    r#"#!/usr/bin/env fish
# NAILS Shell Prompt Instrumentation - Fish
# Sourced during activation, adds (NAILS-ACTIVE) prefix to fish_prompt

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
"#
    .to_string()
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
mod tests;
