//! Prompt script generation for bash, zsh, and fish
//!
//! This module generates shell-specific prompt instrumentation scripts that
//! optionally prepend a configurable label to the shell prompt while the hidden
//! environment is active.
//!
//! The label text comes from the `prompt_label` configuration value. When it is
//! empty (the default) the generated scripts are harmless no-ops: they keep the
//! `source .../nails_prompt.*` contract intact but never touch `PS1`/`PROMPT`.
//! When it is set, the scripts:
//! - Save the original prompt before modification
//! - Honour the `NO_COLOR` environment variable
//! - Guard against double-prefixing via the saved-original sentinel

/// Escape a label for interpolation inside a bash/zsh double-quoted string.
///
/// Inside double quotes the shell still expands `$`, command substitution via
/// backticks, and processes backslashes, so those plus the closing quote are
/// escaped. The backslash is escaped first to avoid double-processing.
fn escape_double_quoted(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out
}

/// Escape a label for a zsh prompt string.
///
/// In addition to the double-quoted shell escapes, `%` begins a prompt escape
/// in zsh and must be doubled to render literally.
fn escape_zsh_prompt(label: &str) -> String {
    escape_double_quoted(label).replace('%', "%%")
}

/// Escape a label for interpolation inside a fish double-quoted string.
///
/// Within fish double quotes only `$`, `\` and `"` are special; backticks carry
/// no meaning, so they are left untouched.
fn escape_fish_double_quoted(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            other => out.push(other),
        }
    }
    out
}

/// Generate bash prompt instrumentation script
///
/// When `label` is empty the script is a no-op that leaves `PS1` untouched.
/// Otherwise it prepends the (optionally green) label to `PS1`.
///
/// # Returns
///
/// Complete bash prompt script content as a String
pub fn generate_bash_prompt_script(label: &str) -> String {
    if label.is_empty() {
        return "#!/usr/bin/env bash\n\
                # Shell prompt instrumentation - Bash\n\
                # No prompt label configured; nothing to apply.\n"
            .to_string();
    }

    let escaped = escape_double_quoted(label);
    format!(
        r#"#!/usr/bin/env bash
# Shell prompt instrumentation - Bash
# Sourced during activation; prepends the configured label to PS1.

# Guard: don't double-prefix (keyed on the saved-original sentinel)
if [ -n "${{_NAILS_ORIG_PS1+x}}" ]; then
    return 0
fi

# Save original PS1
export _NAILS_ORIG_PS1="$PS1"

# Apply prefix with optional color
# NO_COLOR check: if NO_COLOR is unset, use green color; otherwise plain text
if [ -z "${{NO_COLOR+x}}" ]; then
    PS1="\[\033[32m\]{escaped}\[\033[0m\] $PS1"
else
    PS1="{escaped} $PS1"
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
# Shell prompt cleanup - Bash
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
/// When `label` is empty the script is a no-op that leaves `PROMPT` untouched.
/// Otherwise it prepends the (optionally green) label to `PROMPT`.
///
/// # Returns
///
/// Complete zsh script content as a String
pub fn generate_zsh_prompt_script(label: &str) -> String {
    if label.is_empty() {
        return "#!/usr/bin/env zsh\n\
                # Shell prompt instrumentation - Zsh\n\
                # No prompt label configured; nothing to apply.\n"
            .to_string();
    }

    let escaped = escape_zsh_prompt(label);
    format!(
        r#"#!/usr/bin/env zsh
# Shell prompt instrumentation - Zsh
# Sourced during activation; prepends the configured label to PROMPT.

# Guard: don't double-prefix (keyed on the saved-original sentinel)
if [ -n "${{_NAILS_ORIG_PROMPT+x}}" ]; then
    return 0
fi

# Save original PROMPT
export _NAILS_ORIG_PROMPT="$PROMPT"

# Apply prefix with optional color
# NO_COLOR check: if NO_COLOR is unset, use green color; otherwise plain text
if [ -z "${{NO_COLOR+x}}" ]; then
    PROMPT="%F{{green}}{escaped}%f $PROMPT"
else
    PROMPT="{escaped} $PROMPT"
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
# Shell prompt cleanup - Zsh
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
/// When `label` is empty the script is a no-op that leaves `fish_prompt`
/// untouched. Otherwise it wraps `fish_prompt` to prepend the (optionally
/// green) label.
///
/// # Returns
///
/// Complete fish script content as a String
pub fn generate_fish_prompt_script(label: &str) -> String {
    if label.is_empty() {
        return "#!/usr/bin/env fish\n\
                # Shell prompt instrumentation - Fish\n\
                # No prompt label configured; nothing to apply.\n"
            .to_string();
    }

    let escaped = escape_fish_double_quoted(label);
    format!(
        r#"#!/usr/bin/env fish
# Shell prompt instrumentation - Fish
# Sourced during activation; wraps fish_prompt to prepend the configured label.

# Guard: don't re-wrap if already wrapped (saved-original sentinel)
if functions -q _nails_orig_prompt
    exit 0
end

# Save original fish_prompt
functions -c fish_prompt _nails_orig_prompt

# Define new prompt function
function fish_prompt
    if set -q NO_COLOR
        echo -n "{escaped} "
    else
        set_color green
        echo -n "{escaped} "
        set_color normal
    end
    _nails_orig_prompt
end
"#
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
# Shell prompt cleanup - Fish
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
