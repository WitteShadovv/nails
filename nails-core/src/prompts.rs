//! User Prompt Functions
//!
//! Provides interactive user prompts for activation decisions including:
//! - Yes/No confirmations
//! - Risky process restart warnings
//! - Pivot mount security trade-off acceptance
//!
//! Part of Story 4.15: User Prompts and CLI Flags for Overlay Strategy

use crate::Result;
use crate::process::ProcessInfo;
use std::io::{self, Write};
use std::path::Path;

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
pub fn prompt_yes_no(message: &str, default_no: bool) -> Result<bool> {
    let suffix = if default_no { "[y/N]" } else { "[Y/n]" };
    print!("{} {}: ", message, suffix);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let input = input.trim().to_lowercase();
    match input.as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        "" => Ok(!default_no), // Empty means use default
        _ => {
            println!("Please answer 'y' or 'n'");
            prompt_yes_no(message, default_no) // Recurse until valid answer
        }
    }
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
pub fn prompt_risky_process_restart(risky_processes: &[ProcessInfo]) -> Result<bool> {
    println!();
    println!("⚠️  Risky processes detected that may cause service disruption:");

    for proc in risky_processes {
        if let Some(ref service_name) = proc.service_name {
            println!("    • {} ({})", proc.name, service_name);
        } else {
            println!("    • {} (PID {})", proc.name, proc.pid);
        }
    }

    println!();
    println!("    Restarting these may briefly interrupt:");
    println!("    • Network connectivity");
    println!("    • Desktop notifications");
    println!("    • Some application features");
    println!();

    prompt_yes_no("    Restart these processes?", true)
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
pub fn prompt_pivot_mount_acceptance(
    target: &Path,
    blocking_processes: &[ProcessInfo],
) -> Result<bool> {
    println!();
    println!("⚠️  CANNOT mount {} overlay directly.", target.display());
    println!();
    println!(
        "The following processes are still using {}:",
        target.display()
    );

    for proc in blocking_processes {
        if !proc.cmdline.is_empty() {
            println!("  • {} (PID {}) - {}", proc.name, proc.pid, proc.cmdline);
        } else {
            println!("  • {} (PID {})", proc.name, proc.pid);
        }
    }

    println!();
    println!("PIVOT MOUNT FALLBACK:");
    println!("  A pivot mount uses a staging location and bind mount.");
    println!("  This creates 'split-view' behavior:");
    println!();
    println!(
        "  ⚠️  OLD processes (listed above) continue writing to ORIGINAL {}",
        target.display()
    );
    println!("  ✓  NEW processes will write to the hidden overlay");
    println!();
    println!("  SECURITY RISK:");
    println!("    Old processes may leak information about new (hidden) processes");
    println!("    to the original filesystem. For example:");
    println!("      - Browser writing downloads to original home");
    println!("      - Text editor saving files to original home");
    println!();
    println!("  This is a LAST RESORT option with reduced security guarantees.");
    println!();

    prompt_yes_no("Accept pivot mount with split-view risk?", true)
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
    println!();
    println!(
        "✗ Activation aborted: User declined pivot mount for {}",
        target.display()
    );
    println!();
    println!("Suggestions:");
    println!("  1. Close all applications and log out, then activate from TTY:");
    println!("     $ nails activate");
    println!();
    println!("  2. Kill your graphical session (will lose unsaved work):");
    println!("     $ nails activate --kill-session");
    println!();
    println!("  3. Accept security trade-off and use pivot mount:");
    println!("     $ nails activate --accept-pivot-risks");
    println!();
    println!("Current state: INACTIVE (unchanged)");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Testing interactive prompts is challenging because they read from stdin.
    // These tests verify the functions compile and have the correct signatures.
    // Full testing requires integration tests with mocked stdin/stdout.

    #[test]
    fn test_display_abort_message_does_not_panic() {
        // This function only prints output, so we just verify it doesn't panic
        let target = Path::new("/home");
        display_abort_message(target);
    }

    #[test]
    fn test_prompt_pivot_mount_acceptance_signature() {
        // Verify function signature is correct (will fail at runtime without stdin)
        let _: fn(&Path, &[ProcessInfo]) -> Result<bool> = prompt_pivot_mount_acceptance;
    }

    #[test]
    fn test_prompt_risky_process_restart_signature() {
        // Verify function signature is correct
        let _: fn(&[ProcessInfo]) -> Result<bool> = prompt_risky_process_restart;
    }

    #[test]
    fn test_prompt_yes_no_signature() {
        // Verify function signature is correct
        let _: fn(&str, bool) -> Result<bool> = prompt_yes_no;
    }
}
