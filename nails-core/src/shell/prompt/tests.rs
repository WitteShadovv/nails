use super::*;

#[test]
fn test_bash_script_contains_idempotency_check() {
    let script = generate_bash_prompt_script();
    assert!(script.contains(r#"if [[ "$PS1" == *"NAILS-ACTIVE"* ]]"#));
}

#[test]
fn test_bash_script_contains_no_color_check() {
    let script = generate_bash_prompt_script();
    assert!(script.contains(r#"if [ -z "${NO_COLOR+x}" ]"#));
}

#[test]
fn test_bash_script_contains_color_codes() {
    let script = generate_bash_prompt_script();
    assert!(script.contains(r#"\[\033[32m\](NAILS-ACTIVE)\[\033[0m\]"#));
}

#[test]
fn test_bash_script_saves_original_ps1() {
    let script = generate_bash_prompt_script();
    assert!(script.contains("export _NAILS_ORIG_PS1="));
}

#[test]
fn test_bash_cleanup_restores_ps1() {
    let cleanup = generate_bash_prompt_cleanup();
    assert!(cleanup.contains(r#"PS1="$_NAILS_ORIG_PS1""#));
    assert!(cleanup.contains("unset _NAILS_ORIG_PS1"));
}

#[test]
fn test_zsh_script_contains_idempotency_check() {
    let script = generate_zsh_prompt_script();
    assert!(script.contains(r#"if [[ "$PROMPT" == *"NAILS-ACTIVE"* ]]"#));
}

#[test]
fn test_zsh_script_contains_no_color_check() {
    let script = generate_zsh_prompt_script();
    assert!(script.contains(r#"if [ -z "${NO_COLOR+x}" ]"#));
}

#[test]
fn test_zsh_script_contains_color_codes() {
    let script = generate_zsh_prompt_script();
    assert!(script.contains(r#"%F{green}(NAILS-ACTIVE)%f"#));
}

#[test]
fn test_zsh_script_saves_original_prompt() {
    let script = generate_zsh_prompt_script();
    assert!(script.contains("export _NAILS_ORIG_PROMPT="));
}

#[test]
fn test_zsh_cleanup_restores_prompt() {
    let cleanup = generate_zsh_prompt_cleanup();
    assert!(cleanup.contains(r#"PROMPT="$_NAILS_ORIG_PROMPT""#));
    assert!(cleanup.contains("unset _NAILS_ORIG_PROMPT"));
}

#[test]
fn test_fish_script_contains_idempotency_check() {
    let script = generate_fish_prompt_script();
    assert!(script.contains("if functions -q _nails_orig_prompt"));
}

#[test]
fn test_fish_script_contains_no_color_check() {
    let script = generate_fish_prompt_script();
    assert!(script.contains("if set -q NO_COLOR"));
}

#[test]
fn test_fish_script_contains_color_command() {
    let script = generate_fish_prompt_script();
    assert!(script.contains("set_color green"));
    assert!(script.contains("set_color normal"));
}

#[test]
fn test_fish_script_saves_original_function() {
    let script = generate_fish_prompt_script();
    assert!(script.contains("functions -c fish_prompt _nails_orig_prompt"));
}

#[test]
fn test_fish_cleanup_restores_function() {
    let cleanup = generate_fish_prompt_cleanup();
    assert!(cleanup.contains("functions -c _nails_orig_prompt fish_prompt"));
    assert!(cleanup.contains("functions -e _nails_orig_prompt"));
}

// These syntax-validation tests are intentionally ignored because they
// shell out to real bash/zsh/fish executables. The non-ignored tests above
// validate generated script content in hermetic CI; these are opt-in host
// compatibility checks for environments that actually have those shells.

#[test]
#[ignore = "Requires a real bash binary for syntax validation; skipped in hermetic CI"]
fn test_bash_script_syntax_valid() {
    let script = generate_bash_prompt_script();

    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("nails_prompt_test.bash");

    let mut file = std::fs::File::create(&script_path).expect("Failed to create temp script file");
    file.write_all(script.as_bytes())
        .expect("Failed to write script");

    let output = std::process::Command::new("bash")
        .arg("-n")
        .arg(&script_path)
        .output()
        .expect("Failed to execute bash -n");

    let _ = std::fs::remove_file(&script_path);

    assert!(
        output.status.success(),
        "bash script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Requires a real zsh binary for syntax validation; skipped in hermetic CI"]
fn test_zsh_script_syntax_valid() {
    let script = generate_zsh_prompt_script();

    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("nails_prompt_test.zsh");

    let mut file = std::fs::File::create(&script_path).expect("Failed to create temp script file");
    file.write_all(script.as_bytes())
        .expect("Failed to write script");

    let output = std::process::Command::new("zsh")
        .arg("-n")
        .arg(&script_path)
        .output()
        .expect("Failed to execute zsh -n");

    let _ = std::fs::remove_file(&script_path);

    assert!(
        output.status.success(),
        "zsh script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Requires a real fish binary for syntax validation; skipped in hermetic CI"]
fn test_fish_script_syntax_valid() {
    let script = generate_fish_prompt_script();

    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("nails_prompt_test.fish");

    let mut file = std::fs::File::create(&script_path).expect("Failed to create temp script file");
    file.write_all(script.as_bytes())
        .expect("Failed to write script");

    let output = std::process::Command::new("fish")
        .arg("--no-execute")
        .arg(&script_path)
        .output()
        .expect("Failed to execute fish --no-execute");

    let _ = std::fs::remove_file(&script_path);

    assert!(
        output.status.success(),
        "fish script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Requires a real bash binary for syntax validation; skipped in hermetic CI"]
fn test_bash_cleanup_script_syntax_valid() {
    let cleanup = generate_bash_prompt_cleanup();

    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("nails_cleanup_test.bash");

    let mut file = std::fs::File::create(&script_path).expect("Failed to create temp script file");
    file.write_all(cleanup.as_bytes())
        .expect("Failed to write script");

    let output = std::process::Command::new("bash")
        .arg("-n")
        .arg(&script_path)
        .output()
        .expect("Failed to execute bash -n");

    let _ = std::fs::remove_file(&script_path);

    assert!(
        output.status.success(),
        "bash cleanup script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Requires a real zsh binary for syntax validation; skipped in hermetic CI"]
fn test_zsh_cleanup_script_syntax_valid() {
    let cleanup = generate_zsh_prompt_cleanup();

    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("nails_cleanup_test.zsh");

    let mut file = std::fs::File::create(&script_path).expect("Failed to create temp script file");
    file.write_all(cleanup.as_bytes())
        .expect("Failed to write script");

    let output = std::process::Command::new("zsh")
        .arg("-n")
        .arg(&script_path)
        .output()
        .expect("Failed to execute zsh -n");

    let _ = std::fs::remove_file(&script_path);

    assert!(
        output.status.success(),
        "zsh cleanup script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Requires a real fish binary for syntax validation; skipped in hermetic CI"]
fn test_fish_cleanup_script_syntax_valid() {
    let cleanup = generate_fish_prompt_cleanup();

    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join("nails_cleanup_test.fish");

    let mut file = std::fs::File::create(&script_path).expect("Failed to create temp script file");
    file.write_all(cleanup.as_bytes())
        .expect("Failed to write script");

    let output = std::process::Command::new("fish")
        .arg("--no-execute")
        .arg(&script_path)
        .output()
        .expect("Failed to execute fish --no-execute");

    let _ = std::fs::remove_file(&script_path);

    assert!(
        output.status.success(),
        "fish cleanup script syntax validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
