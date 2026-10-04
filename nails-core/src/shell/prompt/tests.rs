// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

const SAMPLE_LABEL: &str = "ctx";

// ---------------------------------------------------------------------------
// Empty label: the generated scripts are harmless no-ops.
// ---------------------------------------------------------------------------

#[test]
fn test_bash_empty_label_is_noop() {
    let script = generate_bash_prompt_script("");
    assert!(script.starts_with("#!/usr/bin/env bash"));
    assert!(!script.contains("PS1="));
    assert!(!script.contains("_NAILS_ORIG_PS1"));
}

#[test]
fn test_zsh_empty_label_is_noop() {
    let script = generate_zsh_prompt_script("");
    assert!(script.starts_with("#!/usr/bin/env zsh"));
    assert!(!script.contains("PROMPT="));
    assert!(!script.contains("_NAILS_ORIG_PROMPT"));
}

#[test]
fn test_fish_empty_label_is_noop() {
    let script = generate_fish_prompt_script("");
    assert!(script.starts_with("#!/usr/bin/env fish"));
    assert!(!script.contains("function fish_prompt"));
    assert!(!script.contains("set_color"));
}

// ---------------------------------------------------------------------------
// Non-empty label: content, color codes, and sentinel-based guard.
// ---------------------------------------------------------------------------

#[test]
fn test_bash_script_guard_keys_on_saved_original_sentinel() {
    let script = generate_bash_prompt_script(SAMPLE_LABEL);
    assert!(script.contains(r#"if [ -n "${_NAILS_ORIG_PS1+x}" ]"#));
}

#[test]
fn test_bash_script_contains_no_color_check() {
    let script = generate_bash_prompt_script(SAMPLE_LABEL);
    assert!(script.contains(r#"if [ -z "${NO_COLOR+x}" ]"#));
}

#[test]
fn test_bash_script_contains_label_with_color_codes() {
    let script = generate_bash_prompt_script(SAMPLE_LABEL);
    assert!(script.contains(r#"\[\033[32m\]ctx\[\033[0m\]"#));
}

#[test]
fn test_bash_script_saves_original_ps1() {
    let script = generate_bash_prompt_script(SAMPLE_LABEL);
    assert!(script.contains("export _NAILS_ORIG_PS1="));
}

#[test]
fn test_bash_cleanup_restores_ps1() {
    let cleanup = generate_bash_prompt_cleanup();
    assert!(cleanup.contains(r#"PS1="$_NAILS_ORIG_PS1""#));
    assert!(cleanup.contains("unset _NAILS_ORIG_PS1"));
}

#[test]
fn test_zsh_script_guard_keys_on_saved_original_sentinel() {
    let script = generate_zsh_prompt_script(SAMPLE_LABEL);
    assert!(script.contains(r#"if [ -n "${_NAILS_ORIG_PROMPT+x}" ]"#));
}

#[test]
fn test_zsh_script_contains_no_color_check() {
    let script = generate_zsh_prompt_script(SAMPLE_LABEL);
    assert!(script.contains(r#"if [ -z "${NO_COLOR+x}" ]"#));
}

#[test]
fn test_zsh_script_contains_label_with_color_codes() {
    let script = generate_zsh_prompt_script(SAMPLE_LABEL);
    assert!(script.contains(r#"%F{green}ctx%f"#));
}

#[test]
fn test_zsh_script_saves_original_prompt() {
    let script = generate_zsh_prompt_script(SAMPLE_LABEL);
    assert!(script.contains("export _NAILS_ORIG_PROMPT="));
}

#[test]
fn test_zsh_cleanup_restores_prompt() {
    let cleanup = generate_zsh_prompt_cleanup();
    assert!(cleanup.contains(r#"PROMPT="$_NAILS_ORIG_PROMPT""#));
    assert!(cleanup.contains("unset _NAILS_ORIG_PROMPT"));
}

#[test]
fn test_fish_script_guard_keys_on_saved_original_sentinel() {
    let script = generate_fish_prompt_script(SAMPLE_LABEL);
    assert!(script.contains("if functions -q _nails_orig_prompt"));
}

#[test]
fn test_fish_script_contains_no_color_check() {
    let script = generate_fish_prompt_script(SAMPLE_LABEL);
    assert!(script.contains("if set -q NO_COLOR"));
}

#[test]
fn test_fish_script_contains_label_and_color_command() {
    let script = generate_fish_prompt_script(SAMPLE_LABEL);
    assert!(script.contains("set_color green"));
    assert!(script.contains("set_color normal"));
    assert!(script.contains(r#"echo -n "ctx ""#));
}

#[test]
fn test_fish_script_saves_original_function() {
    let script = generate_fish_prompt_script(SAMPLE_LABEL);
    assert!(script.contains("functions -c fish_prompt _nails_orig_prompt"));
}

#[test]
fn test_fish_cleanup_restores_function() {
    let cleanup = generate_fish_prompt_cleanup();
    assert!(cleanup.contains("functions -c _nails_orig_prompt fish_prompt"));
    assert!(cleanup.contains("functions -e _nails_orig_prompt"));
}

// ---------------------------------------------------------------------------
// Escaping: a label with shell-special characters cannot break out of the
// quoting context it is interpolated into.
// ---------------------------------------------------------------------------

#[test]
fn test_bash_label_special_chars_are_escaped() {
    // backslash, double-quote, dollar, backtick
    let script = generate_bash_prompt_script("a\"b\\c$d`e");
    assert!(script.contains(r#"a\"b\\c\$d\`e"#));
    // No raw unescaped double-quote from the label sits inside the PS1 assignment.
    assert!(!script.contains(r#"a"b"#));
}

#[test]
fn test_zsh_label_special_chars_and_percent_are_escaped() {
    let script = generate_zsh_prompt_script("a\"b\\c$d%e");
    assert!(script.contains(r#"a\"b\\c\$d%%e"#));
}

#[test]
fn test_fish_label_special_chars_are_escaped() {
    // fish treats backtick as ordinary inside double quotes; escape \ " $ only.
    let script = generate_fish_prompt_script("a\"b\\c$d");
    assert!(script.contains(r#"a\"b\\c\$d"#));
}

// These syntax-validation tests shell out to real bash/zsh/fish binaries. They
// run as part of the normal suite: wherever a shell is installed it validates
// the generated script, and where it is absent the test skips with a visible
// message (CI installs all three, so nothing is silently skipped there).

/// Write `script` to a temporary file and run `program args... <file>` to check
/// its syntax. Returns `None` after printing a skip notice when `program` is not
/// installed, so a missing shell never fails the suite.
fn run_shell_syntax_check(
    program: &str,
    args: &[&str],
    script: &str,
    extension: &str,
) -> Option<std::process::Output> {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().expect("create temp dir for shell script");
    let script_path = temp_dir
        .path()
        .join(format!("nails_prompt_test.{extension}"));
    let mut file = std::fs::File::create(&script_path).expect("create temp script file");
    file.write_all(script.as_bytes())
        .expect("write generated script");

    match std::process::Command::new(program)
        .args(args)
        .arg(&script_path)
        .output()
    {
        Ok(output) => Some(output),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping {program} syntax check: {program} is not installed");
            None
        }
        Err(e) => panic!("failed to execute {program}: {e}"),
    }
}

#[test]
fn test_bash_script_syntax_valid() {
    let script = generate_bash_prompt_script(SAMPLE_LABEL);
    let Some(output) = run_shell_syntax_check("bash", &["-n"], &script, "bash") else {
        return;
    };

    assert!(
        output.status.success(),
        "bash script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_zsh_script_syntax_valid() {
    let script = generate_zsh_prompt_script(SAMPLE_LABEL);
    let Some(output) = run_shell_syntax_check("zsh", &["-n"], &script, "zsh") else {
        return;
    };

    assert!(
        output.status.success(),
        "zsh script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_fish_script_syntax_valid() {
    let script = generate_fish_prompt_script(SAMPLE_LABEL);
    let Some(output) = run_shell_syntax_check("fish", &["--no-execute"], &script, "fish") else {
        return;
    };

    assert!(
        output.status.success(),
        "fish script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_bash_cleanup_script_syntax_valid() {
    let cleanup = generate_bash_prompt_cleanup();
    let Some(output) = run_shell_syntax_check("bash", &["-n"], &cleanup, "bash") else {
        return;
    };

    assert!(
        output.status.success(),
        "bash cleanup script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_zsh_cleanup_script_syntax_valid() {
    let cleanup = generate_zsh_prompt_cleanup();
    let Some(output) = run_shell_syntax_check("zsh", &["-n"], &cleanup, "zsh") else {
        return;
    };

    assert!(
        output.status.success(),
        "zsh cleanup script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_fish_cleanup_script_syntax_valid() {
    let cleanup = generate_fish_prompt_cleanup();
    let Some(output) = run_shell_syntax_check("fish", &["--no-execute"], &cleanup, "fish") else {
        return;
    };

    assert!(
        output.status.success(),
        "fish cleanup script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
