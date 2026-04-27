//! Shell setup and cleanup operations for activation/deactivation

use crate::{Filesystem, Result, obfuscate};

use super::{ShellCleanupResult, ShellInstrumentation, ShellSetupResult, color_scheme};

impl<F: Filesystem> ShellInstrumentation<F> {
    /// Apply terminal color scheme via OSC sequences (best-effort, non-blocking)
    ///
    /// This is a private helper function used by shell_setup() and shell_cleanup()
    /// to write OSC escape sequences to stdout for terminal color scheme changes.
    ///
    /// # Arguments
    ///
    /// * `sequences` - The OSC escape sequences to write to stdout
    /// * `context` - Human-readable context for logging (e.g., "hidden mode", "decoy mode")
    ///
    /// # Behavior
    ///
    /// - Writes OSC sequences directly to stdout using write_all()
    /// - On success: Flushes stdout and logs debug message
    /// - On failure: Logs warning but does NOT propagate error (best-effort)
    /// - Empty sequences are silently ignored (no write attempt)
    ///
    /// This function embodies the "silent failure" requirement (AC8) where
    /// terminals that don't support OSC sequences ignore them, and write
    /// failures don't prevent activation/deactivation from continuing.
    fn apply_color_scheme_to_terminal(sequences: &str, context: &str) {
        if sequences.is_empty() {
            return;
        }

        use std::io::{IsTerminal, Write};

        // Only write OSC sequences when stdout is a real terminal.
        // When stdout is redirected (pipes, cargo test capture, scripts) the
        // sequences would corrupt the output stream without affecting any terminal.
        if !std::io::stdout().is_terminal() {
            tracing::debug!(
                "Skipping terminal color scheme ({}): stdout is not a terminal",
                context
            );
            return;
        }

        // Never mutate terminal colors during test builds. Unit tests exercise
        // shell_setup/shell_cleanup and would otherwise leak the hidden scheme
        // into the developer's terminal when running `cargo test`.
        if cfg!(test) {
            tracing::debug!("Skipping terminal color scheme ({}): test build", context);
            return;
        }

        // Respect the NO_COLOR convention and our own NAILS_NO_COLOR override.
        // This also ensures OSC sequences are suppressed when cargo test runs
        // with a PTY (where is_terminal() returns true but we still must not
        // mutate the developer's terminal colors).
        if std::env::var("NO_COLOR").is_ok() || std::env::var(obfuscate::env_no_color()).is_ok() {
            tracing::debug!(
                "Skipping terminal color scheme ({}): NO_COLOR / NAILS_NO_COLOR is set",
                context
            );
            return;
        }

        // Write OSC sequences directly to stdout
        if let Err(e) = std::io::stdout().write_all(sequences.as_bytes()) {
            tracing::warn!("Failed to apply terminal color scheme ({}): {}", context, e);
            // Non-critical failure, continue with activation/deactivation
        } else {
            // Flush to ensure sequences are sent immediately
            let _ = std::io::stdout().flush();
            tracing::debug!("Terminal color scheme applied ({})", context);
        }
    }

    /// Set up shell instrumentation during activation
    ///
    /// This method:
    /// 1. Detects the current shell from SHELL environment variable
    /// 2. Generates and writes prompt and alias scripts to hidden volume
    /// 3. Returns instructions for the user to source the scripts
    ///
    /// This operation is **non-critical** - errors are logged as warnings
    /// and returned in the result, but activation can still proceed.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(ShellSetupResult))` - Setup succeeded, scripts generated
    /// - `Ok(None)` - No shell detected or unsupported shell (gracefully handled)
    ///
    /// # Errors
    ///
    /// This method **never returns Err** - all failures are handled gracefully
    /// and converted to warnings in the result.
    pub fn shell_setup(&self) -> Result<Option<ShellSetupResult>> {
        // Generate and write scripts (best-effort, log failures)
        let mut warnings = Vec::new();

        // Try to write prompt scripts
        if let Err(e) = self.write_prompt_scripts() {
            let msg = format!("Shell prompt scripts could not be generated: {}", e);
            tracing::warn!("Shell instrumentation failed: {}", msg);
            warnings.push(msg);
        }

        // Try to write alias scripts
        if let Err(e) = self.write_alias_scripts() {
            let msg = format!("Shell alias scripts could not be generated: {}", e);
            tracing::warn!("Shell instrumentation failed: {}", msg);
            warnings.push(msg);
        }

        // Write XDG autostart entry for notify-dispatch (best-effort)
        match self.write_xdg_autostart_entry() {
            Ok(true) => {
                tracing::info!("XDG autostart entry written for nails notify-dispatch");
            }
            Ok(false) => {
                tracing::warn!(
                    "XDG autostart entry could not be written (best-effort, continuing)"
                );
            }
            Err(e) => {
                tracing::warn!("Failed to write XDG autostart entry: {} (continuing)", e);
            }
        }

        let shell_type = self.detect_current_shell();

        // Task 1: Inject rc integration (best-effort)
        let rc_modified = match shell_type {
            Some(shell) => self.inject_rc_integration(shell).unwrap_or(false),
            None => false,
        };

        // Apply hidden color scheme (Story 14-8, Task 3)
        // OSC sequences are written to stdout so the terminal processes them
        // This is best-effort and non-blocking - failures are logged but don't prevent activation
        let color_sequences = color_scheme::apply_hidden_color_scheme(&self.config.color_scheme);
        Self::apply_color_scheme_to_terminal(&color_sequences, "hidden mode");

        let Some(shell_type) = shell_type else {
            return Ok(None);
        };

        // Build result with source instructions
        let prompt_script = self.prompt_script_path(shell_type);
        let alias_script = self.alias_script_path(shell_type);

        // If script generation failed, return result with warning but no instructions
        if !warnings.is_empty() {
            let warning_msg = warnings.join("; ");
            return Ok(Some(ShellSetupResult {
                shell_type,
                prompt_script_path: prompt_script,
                alias_script_path: alias_script,
                instructions: Vec::new(),
                warning: Some(warning_msg),
                rc_modified,
            }));
        }

        let instructions = vec![
            format!("source {}", prompt_script.display()),
            format!("source {}", alias_script.display()),
        ];

        Ok(Some(ShellSetupResult {
            shell_type,
            prompt_script_path: prompt_script,
            alias_script_path: alias_script,
            instructions,
            warning: None,
            rc_modified,
        }))
    }

    /// Generate shell cleanup instructions for deactivation
    ///
    /// Returns instructions for the user to restore their shell prompt
    /// to the original state. Per architecture, normal deactivation does
    /// NOT remove aliases (only emergency deactivation does).
    ///
    /// This operation is **non-critical** and never fails.
    ///
    /// # Arguments
    ///
    /// * `include_alias_removal` - If true, include alias cleanup instructions
    ///   (used during emergency deactivation only)
    ///
    /// # Returns
    ///
    /// `ShellCleanupResult` with cleanup instructions, or empty if no shell detected
    pub fn shell_cleanup(&self, include_alias_removal: bool) -> ShellCleanupResult {
        // Detect current shell
        let shell_type = match self.detect_current_shell() {
            Some(shell) => shell,
            None => {
                // Shell cleanup skipped: SHELL env var not set or unsupported shell
                return ShellCleanupResult {
                    shell_type: None,
                    instructions: Vec::new(),
                    message: Some(
                        "Shell cleanup skipped - no supported shell detected".to_string(),
                    ),
                };
            }
        };

        let mut instructions = Vec::new();

        // Always include prompt cleanup instructions
        let cleanup_script = self.cleanup_script_path(shell_type);
        instructions.push(format!("source {}", cleanup_script.display()));

        // Optionally include alias removal (emergency only)
        if include_alias_removal {
            let alias_cleanup = self.alias_cleanup_script_path(shell_type);
            instructions.push(format!("source {}", alias_cleanup.display()));
        }

        // Apply decoy color scheme (Story 14-8, Task 4 & Task 5)
        // OSC reset sequences are written to stdout so the terminal processes them
        // This is best-effort and non-blocking - failures are logged but don't prevent deactivation
        let color_sequences = color_scheme::apply_decoy_color_scheme(&self.config.color_scheme);
        Self::apply_color_scheme_to_terminal(&color_sequences, "decoy mode");

        // Shell cleanup instructions provided

        ShellCleanupResult {
            shell_type: Some(shell_type),
            instructions,
            message: None,
        }
    }
}
