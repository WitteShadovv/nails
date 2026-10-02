use super::*;
use std::io::Cursor;
use std::path::PathBuf;

/// Helper to create a test ProcessInfo
fn make_test_process(pid: u32, name: &str, cmdline: &str, service: Option<String>) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: cmdline.to_string(),
        cwd: PathBuf::from("/tmp"),
        has_cwd_in_target: false,
        has_open_fds_in_target: false,
        has_mmap_in_target: false,
        service_name: service,
        is_interactive: false,
    }
}

// ==================== prompt_yes_no_with_io tests ====================

#[test]
fn test_prompt_yes_no_accepts_y() {
    let mut input = Cursor::new("y\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(result.unwrap());
}

#[test]
fn test_prompt_yes_no_accepts_yes() {
    let mut input = Cursor::new("yes\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(result.unwrap());
}

#[test]
fn test_prompt_yes_no_accepts_n() {
    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_yes_no_accepts_no() {
    let mut input = Cursor::new("no\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_yes_no_case_insensitive() {
    let mut input = Cursor::new("Y\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(result.unwrap());

    let mut input = Cursor::new("YES\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(result.unwrap());

    let mut input = Cursor::new("N\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(!result.unwrap());

    let mut input = Cursor::new("NO\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_yes_no_default_no_empty_input() {
    let mut input = Cursor::new("\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    // default_no = true, so empty input returns false (no)
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_yes_no_default_yes_empty_input() {
    let mut input = Cursor::new("\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", false, &mut input, &mut output);
    // default_no = false, so empty input returns true (yes)
    assert!(result.unwrap());
}

#[test]
fn test_prompt_yes_no_invalid_then_valid() {
    // First input is invalid, second is valid
    let mut input = Cursor::new("maybe\ny\n");
    let mut output = Vec::new();
    let result = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);
    assert!(result.unwrap());

    // Check that error message was written
    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Please answer 'y' or 'n'"));
}

#[test]
fn test_prompt_yes_no_displays_correct_suffix_default_no() {
    let mut input = Cursor::new("y\n");
    let mut output = Vec::new();
    let _ = prompt_yes_no_with_io("Continue?", true, &mut input, &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("[y/N]"));
}

#[test]
fn test_prompt_yes_no_displays_correct_suffix_default_yes() {
    let mut input = Cursor::new("y\n");
    let mut output = Vec::new();
    let _ = prompt_yes_no_with_io("Continue?", false, &mut input, &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("[Y/n]"));
}

#[test]
fn test_prompt_yes_no_displays_message() {
    let mut input = Cursor::new("y\n");
    let mut output = Vec::new();
    let _ = prompt_yes_no_with_io("Do you want to proceed?", true, &mut input, &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Do you want to proceed?"));
}

// ==================== prompt_risky_process_restart_with_io tests ====================

#[test]
fn test_prompt_risky_process_restart_accepts_yes() {
    let processes = vec![make_test_process(
        100,
        "NetworkManager",
        "",
        Some("network-manager.service".to_string()),
    )];

    let mut input = Cursor::new("y\n");
    let mut output = Vec::new();
    let result =
        prompt_risky_process_restart_with_io(&processes, Style::default(), &mut input, &mut output);
    assert!(result.unwrap());
}

#[test]
fn test_prompt_risky_process_restart_accepts_no() {
    let processes = vec![make_test_process(
        100,
        "NetworkManager",
        "",
        Some("network-manager.service".to_string()),
    )];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let result =
        prompt_risky_process_restart_with_io(&processes, Style::default(), &mut input, &mut output);
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_risky_process_restart_default_no() {
    let processes = vec![make_test_process(100, "test", "", None)];

    let mut input = Cursor::new("\n");
    let mut output = Vec::new();
    let result =
        prompt_risky_process_restart_with_io(&processes, Style::default(), &mut input, &mut output);
    // Should default to no (safe option)
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_risky_process_restart_displays_warning() {
    let processes = vec![make_test_process(
        100,
        "NetworkManager",
        "",
        Some("network-manager.service".to_string()),
    )];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let _ =
        prompt_risky_process_restart_with_io(&processes, Style::default(), &mut input, &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Risky processes detected"));
    assert!(output_str.contains("NetworkManager"));
    assert!(output_str.contains("network-manager.service"));
}

#[test]
fn test_prompt_risky_process_restart_shows_pid_when_no_service() {
    let processes = vec![make_test_process(999, "custom-app", "", None)];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let _ =
        prompt_risky_process_restart_with_io(&processes, Style::default(), &mut input, &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("custom-app"));
    assert!(output_str.contains("PID 999"));
}

#[test]
fn test_prompt_risky_process_restart_shows_disruption_warnings() {
    let processes = vec![make_test_process(100, "test", "", None)];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let _ =
        prompt_risky_process_restart_with_io(&processes, Style::default(), &mut input, &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Network connectivity"));
    assert!(output_str.contains("Desktop notifications"));
    assert!(output_str.contains("Some application features"));
}

// ==================== prompt_pivot_mount_acceptance_with_io tests ====================

#[test]
fn test_prompt_pivot_mount_acceptance_accepts_yes() {
    let processes = vec![make_test_process(1234, "sway", "Wayland compositor", None)];

    let mut input = Cursor::new("y\n");
    let mut output = Vec::new();
    let result = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );
    assert!(result.unwrap());
}

#[test]
fn test_prompt_pivot_mount_acceptance_accepts_no() {
    let processes = vec![make_test_process(1234, "sway", "Wayland compositor", None)];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let result = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_pivot_mount_acceptance_default_no() {
    let processes = vec![make_test_process(1234, "sway", "", None)];

    let mut input = Cursor::new("\n");
    let mut output = Vec::new();
    let result = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );
    // Should default to no (safe option)
    assert!(!result.unwrap());
}

#[test]
fn test_prompt_pivot_mount_acceptance_displays_target_path() {
    let processes = vec![make_test_process(1234, "sway", "", None)];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let _ = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("/home"));
    assert!(output_str.contains("CANNOT mount /home overlay directly"));
}

#[test]
fn test_prompt_pivot_mount_acceptance_displays_blocking_processes() {
    let processes = vec![
        make_test_process(1234, "sway", "Wayland compositor", None),
        make_test_process(
            5678,
            "firefox",
            "Web browser",
            Some("firefox.service".to_string()),
        ),
    ];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let _ = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("sway"));
    assert!(output_str.contains("PID 1234"));
    assert!(output_str.contains("Wayland compositor"));
    assert!(output_str.contains("firefox"));
    assert!(output_str.contains("PID 5678"));
}

#[test]
fn test_prompt_pivot_mount_acceptance_displays_security_warnings() {
    let processes = vec![make_test_process(1234, "test", "", None)];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let _ = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("PIVOT MOUNT FALLBACK"));
    assert!(output_str.contains("split-view"));
    assert!(output_str.contains("SECURITY RISK"));
    assert!(output_str.contains("LAST RESORT"));
}

#[test]
fn test_prompt_pivot_mount_with_empty_cmdline() {
    let processes = vec![make_test_process(100, "test", "", None)];

    let mut input = Cursor::new("n\n");
    let mut output = Vec::new();
    let result = prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        Style::default(),
        &mut input,
        &mut output,
    );

    assert!(!result.unwrap());
    let output_str = String::from_utf8(output).unwrap();
    // Should show PID without cmdline
    assert!(output_str.contains("test (PID 100)"));
    // Should NOT contain " - " after PID when cmdline is empty
    assert!(!output_str.contains("test (PID 100) -"));
}

// ==================== display_abort_message_with_io tests ====================

#[test]
fn test_display_abort_message_does_not_panic() {
    let mut output = Vec::new();
    let result = display_abort_message_with_io(Path::new("/home"), Style::default(), &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_display_abort_message_contains_target() {
    let mut output = Vec::new();
    let _ = display_abort_message_with_io(Path::new("/home"), Style::default(), &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("/home"));
    assert!(output_str.contains("Activation aborted"));
}

#[test]
fn test_display_abort_message_contains_suggestions() {
    let mut output = Vec::new();
    let _ = display_abort_message_with_io(Path::new("/home"), Style::default(), &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("Suggestions:"));
    assert!(output_str.contains("nails activate"));
    assert!(output_str.contains("--session kill"));
    assert!(output_str.contains("--pivot allow"));
}

#[test]
fn test_display_abort_message_shows_inactive_state() {
    let mut output = Vec::new();
    let _ = display_abort_message_with_io(Path::new("/home"), Style::default(), &mut output);

    let output_str = String::from_utf8(output).unwrap();
    assert!(output_str.contains("INACTIVE (unchanged)"));
}

#[test]
fn test_display_abort_message_different_targets() {
    let targets = vec!["/home", "/etc", "/var", "/opt", "/usr/local"];
    for target in targets {
        let mut output = Vec::new();
        let result =
            display_abort_message_with_io(Path::new(target), Style::default(), &mut output);
        assert!(result.is_ok());

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains(target));
    }
}

// ==================== ProcessInfo tests ====================

#[test]
fn test_process_info_with_empty_service_name() {
    let proc = make_test_process(999, "test_process", "test command", None);

    assert_eq!(proc.pid, 999);
    assert_eq!(proc.name, "test_process");
    assert!(proc.service_name.is_none());
}

#[test]
fn test_process_info_with_service_name() {
    let proc = make_test_process(888, "systemd-service", "", Some("test.service".to_string()));

    assert_eq!(proc.pid, 888);
    assert_eq!(proc.service_name, Some("test.service".to_string()));
}

// ==================== ASCII rendering ====================

const ASCII: Style = Style {
    color: false,
    ascii: true,
};

#[test]
fn test_prompts_render_ascii_only_in_ascii_style() {
    let processes = vec![
        make_test_process(1, "sway", "Wayland compositor", None),
        make_test_process(2, "NetworkManager", "", Some("nm.service".to_string())),
    ];

    let mut output = Vec::new();
    prompt_risky_process_restart_with_io(&processes, ASCII, &mut Cursor::new("n\n"), &mut output)
        .unwrap();
    prompt_pivot_mount_acceptance_with_io(
        Path::new("/home"),
        &processes,
        ASCII,
        &mut Cursor::new("n\n"),
        &mut output,
    )
    .unwrap();
    display_abort_message_with_io(Path::new("/home"), ASCII, &mut output).unwrap();

    let text = String::from_utf8(output).unwrap();
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("[WARN] Risky processes detected"), "{text}");
    assert!(text.contains("[FAIL] Activation aborted"), "{text}");
}

// ==================== stdout isolation (real streams) ====================

const PROMPT_SUBPROCESS_TEST: &str = "prompts::tests::subprocess_prompt_entrypoint";
const PROMPT_SUBPROCESS_ENV: &str = "NAILS_PROMPT_SUBPROCESS";

/// Runs inside a child process whose stdout and stderr the parent captures;
/// it drives every prompt against the real stdin/stderr wiring.
#[test]
fn subprocess_prompt_entrypoint() {
    if std::env::var_os(PROMPT_SUBPROCESS_ENV).is_none() {
        return;
    }

    let processes = vec![make_test_process(7, "pipewire", "", None)];
    assert!(prompt_yes_no_on_terminal("Proceed with the stream check?", true).unwrap());
    assert!(prompt_risky_process_restart_on_terminal(&processes).unwrap());
    assert!(prompt_pivot_mount_acceptance_on_terminal(Path::new("/home"), &processes).unwrap());
    display_abort_message(Path::new("/home"));
}

#[test]
fn test_prompts_never_write_to_stdout() {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            PROMPT_SUBPROCESS_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROMPT_SUBPROCESS_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"y\ny\ny\n").unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stdout={stdout}\nstderr={stderr}");
    for prompt_text in [
        "Proceed with the stream check?",
        "Risky processes detected",
        "Accept pivot mount",
        "Activation aborted",
    ] {
        assert!(
            stderr.contains(prompt_text),
            "missing {prompt_text:?}: {stderr}"
        );
        assert!(
            !stdout.contains(prompt_text),
            "{prompt_text:?} leaked to stdout: {stdout}"
        );
    }
}
