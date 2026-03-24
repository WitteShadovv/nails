//! User Prompt Functions
//!
//! Provides interactive user prompts for activation decisions including:
//! - Yes/No confirmations
//! - Risky process restart warnings
//! - Pivot mount security trade-off acceptance
//!
//! Part of Story 4.15: User Prompts and CLI Flags for Overlay Strategy
//!
//! # Testing Support
//!
//! All prompt functions have `_with_io` variants that accept generic `BufRead`
//! and `Write` implementations, enabling deterministic testing without real stdin/stdout.

use crate::Result;
use crate::process::ProcessInfo;
use std::io::{self, BufRead, Write};
use std::path::Path;

/// Internal implementation of yes/no prompt with injectable I/O for testing
///
/// This function allows tests to provide mock input/output streams.
///
/// # Arguments
///
/// * `message` - Prompt message to display
/// * `default_no` - If true, default answer is "no" (shown as `[y/N]`)
/// * `reader` - Input source implementing `BufRead`
/// * `writer` - Output destination implementing `Write`
///
/// # Returns
///
/// * `Ok(true)` - User confirmed (yes)
/// * `Ok(false)` - User declined (no)
/// * `Err` - I/O error reading input
pub fn prompt_yes_no_with_io<R: BufRead, W: Write>(
    message: &str,
    default_no: bool,
    reader: &mut R,
    writer: &mut W,
) -> Result<bool> {
    let suffix = if default_no { "[y/N]" } else { "[Y/n]" };
    write!(writer, "{} {}: ", message, suffix)?;
    writer.flush()?;

    let mut input = String::new();
    reader.read_line(&mut input)?;

    let input = input.trim().to_lowercase();
    match input.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        "" => Ok(!default_no), // Empty means use default
        _ => {
            writeln!(writer, "Please answer 'y' or 'n'")?;
            prompt_yes_no_with_io(message, default_no, reader, writer) // Recurse until valid answer
        }
    }
}

/// Prompt user for yes/no confirmation
///
/// Displays a message and waits for user input. Accepts various forms of
/// yes/no answers and validates input.
///
/// # Arguments
///
/// * `message` - Prompt message to display
/// * `default_no` - If true, default answer is "no" (shown as `[y/N]`)
///
/// # Returns
///
/// * `Ok(true)` - User confirmed (yes)
/// * `Ok(false)` - User declined (no)
/// * `Err` - I/O error reading input
///
/// # Examples
///
/// ```no_run
/// use nails_core::prompts::prompt_yes_no;
///
/// // Default to no
/// let confirmed = prompt_yes_no("Continue?", true)?;
/// if confirmed {
///     println!("Proceeding...");
/// }
///
/// // Default to yes
/// let confirmed = prompt_yes_no("Apply changes?", false)?;
/// # Ok::<(), nails_core::NailsError>(())
/// ```
#[cfg(not(test))]
pub fn prompt_yes_no(message: &str, default_no: bool) -> Result<bool> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut writer = io::stdout();
    prompt_yes_no_with_io(message, default_no, &mut reader, &mut writer)
}

/// Test-only version that panics if called during tests
/// This ensures tests use the `_with_io` variant instead
#[cfg(test)]
pub fn prompt_yes_no(message: &str, _default_no: bool) -> Result<bool> {
    panic!(
        "prompt_yes_no called during test with message: '{}'. Use prompt_yes_no_with_io instead.",
        message
    )
}

/// Internal implementation of risky process restart prompt with injectable I/O
///
/// # Arguments
///
/// * `risky_processes` - List of processes classified as risky to restart
/// * `reader` - Input source implementing `BufRead`
/// * `writer` - Output destination implementing `Write`
///
/// # Returns
///
/// * `Ok(true)` - User confirmed restart
/// * `Ok(false)` - User declined
/// * `Err` - I/O error
pub fn prompt_risky_process_restart_with_io<R: BufRead, W: Write>(
    risky_processes: &[ProcessInfo],
    reader: &mut R,
    writer: &mut W,
) -> Result<bool> {
    writeln!(writer)?;
    writeln!(
        writer,
        "⚠️  Risky processes detected that may cause service disruption:"
    )?;

    for proc in risky_processes {
        if let Some(ref service_name) = proc.service_name {
            writeln!(writer, "    • {} ({})", proc.name, service_name)?;
        } else {
            writeln!(writer, "    • {} (PID {})", proc.name, proc.pid)?;
        }
    }

    writeln!(writer)?;
    writeln!(writer, "    Restarting these may briefly interrupt:")?;
    writeln!(writer, "    • Network connectivity")?;
    writeln!(writer, "    • Desktop notifications")?;
    writeln!(writer, "    • Some application features")?;
    writeln!(writer)?;

    prompt_yes_no_with_io("    Restart these processes?", true, reader, writer)
}

/// Prompt for risky process restart confirmation
///
/// Displays detailed information about risky processes and asks for confirmation
/// before restarting them. Shows:
/// - Process names and service names
/// - Potential service disruptions
///
/// # Arguments
///
/// * `risky_processes` - List of processes classified as risky to restart
///
/// # Returns
///
/// * `Ok(true)` - User confirmed restart
/// * `Ok(false)` - User declined
/// * `Err` - I/O error
///
/// # Example Output
///
/// ```text
/// ⚠️  Risky processes detected that may cause service disruption:
///     • NetworkManager (network-manager.service)
///     • dbus-daemon (dbus.service)
///
///     Restarting these may briefly interrupt:
///     • Network connectivity
///     • Desktop notifications
///     • Some application features
///
///     Restart these processes? [y/N]:
/// ```
#[cfg(not(test))]
pub fn prompt_risky_process_restart(risky_processes: &[ProcessInfo]) -> Result<bool> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut writer = io::stdout();
    prompt_risky_process_restart_with_io(risky_processes, &mut reader, &mut writer)
}

/// Test-only version that panics if called during tests
#[cfg(test)]
pub fn prompt_risky_process_restart(risky_processes: &[ProcessInfo]) -> Result<bool> {
    panic!(
        "prompt_risky_process_restart called during test with {} processes. Use prompt_risky_process_restart_with_io instead.",
        risky_processes.len()
    )
}

/// Internal implementation of pivot mount acceptance prompt with injectable I/O
///
/// # Arguments
///
/// * `target` - Target path being mounted (e.g., `/home`)
/// * `blocking_processes` - Processes preventing direct mount
/// * `reader` - Input source implementing `BufRead`
/// * `writer` - Output destination implementing `Write`
///
/// # Returns
///
/// * `Ok(true)` - User accepted pivot mount risks
/// * `Ok(false)` - User declined
/// * `Err` - I/O error
pub fn prompt_pivot_mount_acceptance_with_io<R: BufRead, W: Write>(
    target: &Path,
    blocking_processes: &[ProcessInfo],
    reader: &mut R,
    writer: &mut W,
) -> Result<bool> {
    writeln!(writer)?;
    writeln!(
        writer,
        "⚠️  CANNOT mount {} overlay directly.",
        target.display()
    )?;
    writeln!(writer)?;
    writeln!(
        writer,
        "The following processes are still using {}:",
        target.display()
    )?;

    for proc in blocking_processes {
        if !proc.cmdline.is_empty() {
            writeln!(
                writer,
                "  • {} (PID {}) - {}",
                proc.name, proc.pid, proc.cmdline
            )?;
        } else {
            writeln!(writer, "  • {} (PID {})", proc.name, proc.pid)?;
        }
    }

    writeln!(writer)?;
    writeln!(writer, "PIVOT MOUNT FALLBACK:")?;
    writeln!(
        writer,
        "  A pivot mount uses a staging location and bind mount."
    )?;
    writeln!(writer, "  This creates 'split-view' behavior:")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  ⚠️  OLD processes (listed above) continue writing to ORIGINAL {}",
        target.display()
    )?;
    writeln!(
        writer,
        "  ✓  NEW processes will write to the hidden overlay"
    )?;
    writeln!(writer)?;
    writeln!(writer, "  SECURITY RISK:")?;
    writeln!(
        writer,
        "    Old processes may leak information about new (hidden) processes"
    )?;
    writeln!(writer, "    to the original filesystem. For example:")?;
    writeln!(writer, "      - Browser writing downloads to original home")?;
    writeln!(writer, "      - Text editor saving files to original home")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  This is a LAST RESORT option with reduced security guarantees."
    )?;
    writeln!(writer)?;

    prompt_yes_no_with_io(
        "Accept pivot mount with split-view risk?",
        true,
        reader,
        writer,
    )
}

/// Prompt for pivot mount acceptance with security warnings
///
/// Displays comprehensive security warnings about pivot mount risks and
/// asks user to explicitly accept the degraded security posture.
///
/// Shows:
/// - Blocking processes preventing direct mount
/// - Split-view behavior explanation
/// - Security risks with concrete examples
/// - Alternative options
///
/// # Arguments
///
/// * `target` - Target path being mounted (e.g., `/home`)
/// * `blocking_processes` - Processes preventing direct mount
///
/// # Returns
///
/// * `Ok(true)` - User accepted pivot mount risks
/// * `Ok(false)` - User declined
/// * `Err` - I/O error
///
/// # Example Output
///
/// ```text
/// ⚠️  CANNOT mount /home overlay directly.
///
/// The following processes are still using /home:
///   • sway (PID 1234) - Wayland compositor
///   • firefox (PID 5678) - Web browser (23 tabs)
///   • code (PID 9012) - Text editor
///
/// PIVOT MOUNT FALLBACK:
///   A pivot mount uses a staging location and bind mount.
///   This creates 'split-view' behavior:
///
///   ⚠️  OLD processes (listed above) continue writing to ORIGINAL /home
///   ✓  NEW processes will write to the hidden overlay
///
///   SECURITY RISK:
///     Old processes may leak information about new (hidden) processes
///     to the original filesystem. For example:
///       - Browser writing downloads to original home
///       - Text editor saving files to original home
///
///   This is a LAST RESORT option with reduced security guarantees.
///
/// Accept pivot mount with split-view risk? [y/N]:
/// ```
#[cfg(not(test))]
pub fn prompt_pivot_mount_acceptance(
    target: &Path,
    blocking_processes: &[ProcessInfo],
) -> Result<bool> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut writer = io::stdout();
    prompt_pivot_mount_acceptance_with_io(target, blocking_processes, &mut reader, &mut writer)
}

/// Test-only version that panics if called during tests
#[cfg(test)]
pub fn prompt_pivot_mount_acceptance(
    target: &Path,
    blocking_processes: &[ProcessInfo],
) -> Result<bool> {
    panic!(
        "prompt_pivot_mount_acceptance called during test for target '{}' with {} processes. Use prompt_pivot_mount_acceptance_with_io instead.",
        target.display(),
        blocking_processes.len()
    )
}

/// Internal implementation of abort message display with injectable I/O
///
/// # Arguments
///
/// * `target` - Target path that failed (e.g., `/home`)
/// * `writer` - Output destination implementing `Write`
pub fn display_abort_message_with_io<W: Write>(target: &Path, writer: &mut W) -> Result<()> {
    writeln!(writer)?;
    writeln!(
        writer,
        "✗ Activation aborted: User declined pivot mount for {}",
        target.display()
    )?;
    writeln!(writer)?;
    writeln!(writer, "Suggestions:")?;
    writeln!(
        writer,
        "  1. Close all applications and log out, then activate from TTY:"
    )?;
    writeln!(writer, "     $ nails activate")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  2. Kill your graphical session (will lose unsaved work):"
    )?;
    writeln!(writer, "     $ nails activate --kill-session")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "  3. Accept security trade-off and use pivot mount:"
    )?;
    writeln!(writer, "     $ nails activate --accept-pivot-risks")?;
    writeln!(writer)?;
    writeln!(writer, "Current state: INACTIVE (unchanged)")?;
    Ok(())
}

/// Display abort message with suggestions
///
/// Shows user-friendly message when activation is aborted due to pivot mount
/// decline. Provides actionable suggestions for achieving successful activation.
///
/// # Arguments
///
/// * `target` - Target path that failed (e.g., `/home`)
///
/// # Example Output
///
/// ```text
/// ✗ Activation aborted: User declined pivot mount for /home
///
/// Suggestions:
///   1. Close all applications and log out, then activate from TTY:
///      $ nails activate
///
///   2. Kill your graphical session (will lose unsaved work):
///      $ nails activate --kill-session
///
///   3. Accept security trade-off and use pivot mount:
///      $ nails activate --accept-pivot-risks
///
/// Current state: INACTIVE (unchanged)
/// ```
pub fn display_abort_message(target: &Path) {
    let mut writer = io::stdout();
    // Ignore errors from display function - it's just informational output
    let _ = display_abort_message_with_io(target, &mut writer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    /// Helper to create a test ProcessInfo
    fn make_test_process(
        pid: u32,
        name: &str,
        cmdline: &str,
        service: Option<String>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            cmdline: cmdline.to_string(),
            cwd: PathBuf::from("/tmp"),
            has_cwd_in_target: false,
            has_open_fds_in_target: false,
            has_mmap_in_target: false,
            service_name: service,
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
        let result = prompt_risky_process_restart_with_io(&processes, &mut input, &mut output);
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
        let result = prompt_risky_process_restart_with_io(&processes, &mut input, &mut output);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_prompt_risky_process_restart_default_no() {
        let processes = vec![make_test_process(100, "test", "", None)];

        let mut input = Cursor::new("\n");
        let mut output = Vec::new();
        let result = prompt_risky_process_restart_with_io(&processes, &mut input, &mut output);
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
        let _ = prompt_risky_process_restart_with_io(&processes, &mut input, &mut output);

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
        let _ = prompt_risky_process_restart_with_io(&processes, &mut input, &mut output);

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("custom-app"));
        assert!(output_str.contains("PID 999"));
    }

    #[test]
    fn test_prompt_risky_process_restart_shows_disruption_warnings() {
        let processes = vec![make_test_process(100, "test", "", None)];

        let mut input = Cursor::new("n\n");
        let mut output = Vec::new();
        let _ = prompt_risky_process_restart_with_io(&processes, &mut input, &mut output);

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
        let result = display_abort_message_with_io(Path::new("/home"), &mut output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_display_abort_message_contains_target() {
        let mut output = Vec::new();
        let _ = display_abort_message_with_io(Path::new("/home"), &mut output);

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("/home"));
        assert!(output_str.contains("Activation aborted"));
    }

    #[test]
    fn test_display_abort_message_contains_suggestions() {
        let mut output = Vec::new();
        let _ = display_abort_message_with_io(Path::new("/home"), &mut output);

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Suggestions:"));
        assert!(output_str.contains("nails activate"));
        assert!(output_str.contains("--kill-session"));
        assert!(output_str.contains("--accept-pivot-risks"));
    }

    #[test]
    fn test_display_abort_message_shows_inactive_state() {
        let mut output = Vec::new();
        let _ = display_abort_message_with_io(Path::new("/home"), &mut output);

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("INACTIVE (unchanged)"));
    }

    #[test]
    fn test_display_abort_message_different_targets() {
        let targets = vec!["/home", "/etc", "/var", "/opt", "/usr/local"];
        for target in targets {
            let mut output = Vec::new();
            let result = display_abort_message_with_io(Path::new(target), &mut output);
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
}
