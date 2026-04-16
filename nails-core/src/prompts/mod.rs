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
#[cfg(not(test))]
pub fn prompt_yes_no(message: &str, default_no: bool) -> Result<bool> {
    if crate::runtime_safety::should_skip_host_interaction() {
        let answer = !default_no;
        tracing::debug!(
            message,
            default_no,
            answer,
            "Auto-answering prompt in test/test-like runtime"
        );
        return Ok(answer);
    }

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
#[cfg(not(test))]
pub fn prompt_risky_process_restart(risky_processes: &[ProcessInfo]) -> Result<bool> {
    if crate::runtime_safety::should_skip_host_interaction() {
        tracing::debug!(
            process_count = risky_processes.len(),
            "Auto-declining risky process restart prompt in test/test-like runtime"
        );
        return Ok(false);
    }

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
#[cfg(not(test))]
pub fn prompt_pivot_mount_acceptance(
    target: &Path,
    blocking_processes: &[ProcessInfo],
) -> Result<bool> {
    if crate::runtime_safety::should_skip_host_interaction() {
        tracing::debug!(
            target = %target.display(),
            blocking_processes = blocking_processes.len(),
            "Auto-declining pivot mount prompt in test/test-like runtime"
        );
        return Ok(false);
    }

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
pub fn display_abort_message(target: &Path) {
    let mut writer = io::stdout();
    // Ignore errors from display function - it's just informational output
    let _ = display_abort_message_with_io(target, &mut writer);
}

#[cfg(test)]
mod tests;
