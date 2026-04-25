//! RC file integration and XDG autostart entry management

use crate::{Filesystem, Result};

use super::{ShellInstrumentation, ShellType, color_scheme};

impl<F: Filesystem> ShellInstrumentation<F> {
    /// Inject shell integration block into user's rc file
    ///
    /// Creates or appends to the user's shell rc file (`.bashrc`, `.zshrc`, or
    /// `.config/fish/config.fish`) in the overlaid `/home` directory. The integration
    /// block includes:
    /// - Source commands for prompt and alias scripts
    /// - OSC color scheme sequences
    /// - Marker comments for idempotency
    ///
    /// # Arguments
    ///
    /// * `shell_type` - The shell type to inject integration for
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if injection succeeded, `Ok(false)` if it failed (best-effort),
    /// or `Err` for unexpected errors.
    ///
    /// # Behavior
    ///
    /// - Determines real user from `SUDO_USER`, `NAILS_TARGET_USER`, or `USER` env var
    /// - Finds home directory: `/home/{user}` (now overlaid)
    /// - Creates rc file if it doesn't exist (with parent dirs for Fish)
    /// - Checks for existing integration marker before appending (idempotent)
    /// - Appends integration block with color scheme from config
    /// - Returns false (not error) on write failures (best-effort)
    ///
    /// # Task 1: Auto-source shell integration via overlay rc file
    pub fn inject_rc_integration(&self, shell_type: ShellType) -> Result<bool> {
        let home_dir = self.resolve_target_home_dir()?;

        // Determine rc file path based on shell type
        let rc_file_path = match shell_type {
            ShellType::Bash => home_dir.join(".bashrc"),
            ShellType::Zsh => home_dir.join(".zshrc"),
            ShellType::Fish => home_dir.join(".config/fish/config.fish"),
        };

        // Read existing content (or empty string if file doesn't exist)
        let existing_content = if self.filesystem.path_exists(&rc_file_path)? {
            self.filesystem
                .read_file_content(&rc_file_path)
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Check if integration block already exists (idempotency)
        if existing_content.contains("# >>> NAILS shell integration") {
            tracing::debug!(
                "NAILS shell integration already present in {}",
                rc_file_path.display()
            );
            return Ok(true);
        }

        // Generate integration block
        let integration_block = self.generate_rc_integration_block(shell_type);

        // Append integration block
        let new_content = if existing_content.is_empty() {
            integration_block
        } else {
            format!("{}\n{}", existing_content, integration_block)
        };

        // Create parent directories if needed (for Fish)
        if let Some(parent) = rc_file_path.parent()
            && !self.filesystem.path_exists(parent)?
            && let Err(e) = self.filesystem.create_directory(parent)
        {
            tracing::warn!(
                "Failed to create rc file parent directory {}: {}",
                parent.display(),
                e
            );
            return Ok(false);
        }

        // Write updated content (best-effort)
        match self
            .filesystem
            .write_file_content(&rc_file_path, &new_content)
        {
            Ok(_) => {
                tracing::info!("Injected NAILS integration into {}", rc_file_path.display());
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to inject NAILS integration into {}: {}",
                    rc_file_path.display(),
                    e
                );
                Ok(false)
            }
        }
    }

    /// Write XDG autostart desktop entry for `nails notify-dispatch`
    ///
    /// Creates `~/.config/autostart/nails-notify.desktop` so that pending
    /// NAILS notifications are dispatched via `notify-send` when the user
    /// logs in after activation.
    ///
    /// # Cleanup
    ///
    /// No explicit cleanup is needed on deactivation. This file is written to the
    /// **overlaid** home directory, so it only exists in the overlay's upper layer.
    /// When NAILS deactivates and unmounts the overlay filesystem, the file ceases
    /// to exist automatically — it is never persisted to the real (lower) filesystem.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the file was written successfully, `Ok(false)` if
    /// it failed (best-effort), or `Err` for unexpected errors (e.g. cannot
    /// determine the username).
    ///
    /// # Behavior
    ///
    /// - Determines real user from `SUDO_USER`, `NAILS_TARGET_USER`, or `USER` env var
    /// - Creates `~/.config/autostart/` directory if it doesn't exist
    /// - Writes a `.desktop` file that runs `nails notify-dispatch`
    /// - Idempotent: overwrites the file if it already exists
    pub fn write_xdg_autostart_entry(&self) -> Result<bool> {
        let home_dir = self.resolve_target_home_dir()?;
        let autostart_dir = home_dir.join(".config/autostart");
        let desktop_file_path = autostart_dir.join("nails-notify.desktop");

        // Create autostart directory if it doesn't exist
        if !self.filesystem.path_exists(&autostart_dir)?
            && let Err(e) = self.filesystem.create_directory(&autostart_dir)
        {
            tracing::warn!(
                "Failed to create autostart directory {}: {}",
                autostart_dir.display(),
                e
            );
            return Ok(false);
        }

        let binary_path = self.resolve_binary_path();
        let desktop_entry = "[Desktop Entry]\n\
            Type=Application\n\
            Name=NAILS Notification Dispatch\n\
            Comment=Dispatches pending NAILS notifications on login\n\
            Exec="
            .to_string()
            + &binary_path.display().to_string()
            + " notify-dispatch\n\
            Terminal=false\n\
            NoDisplay=true\n\
            X-GNOME-Autostart-enabled=true\n";

        // Write desktop file (best-effort)
        match self
            .filesystem
            .write_file_content(&desktop_file_path, &desktop_entry)
        {
            Ok(_) => {
                tracing::info!("Wrote XDG autostart entry: {}", desktop_file_path.display());
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to write XDG autostart entry {}: {}",
                    desktop_file_path.display(),
                    e
                );
                Ok(false)
            }
        }
    }

    /// Generate rc integration block with marker comments
    ///
    /// Creates the shell integration block content including:
    /// - Marker comments for idempotency
    /// - Source commands for prompt and alias scripts
    /// - OSC color scheme sequences from config
    ///
    /// # Arguments
    ///
    /// * `shell_type` - The shell type to generate integration for
    ///
    /// # Returns
    ///
    /// String containing the complete integration block
    pub(super) fn generate_rc_integration_block(&self, shell_type: ShellType) -> String {
        let scripts_dir = self.scripts_dir();
        let color_sequences = color_scheme::apply_hidden_color_scheme(&self.config.color_scheme);

        // Convert binary escape sequences to shell-escaped literals for printf
        // \x1b (ESC) -> \e
        // \x07 (BEL) -> \a
        let color_sequences_escaped = color_sequences
            .replace('\x1b', "\\e")
            .replace('\x07', "\\a")
            .replace('\'', "'\\''"); // Also escape single quotes for shell

        match shell_type {
            ShellType::Bash => {
                format!(
                    "# >>> NAILS shell integration (auto-removed on deactivation) >>>\n\
                     source {}/nails_prompt.bash\n\
                     source {}/nails_alias.sh\n\
                     printf '{}'\n\
                     # <<< NAILS shell integration <<<\n",
                    scripts_dir.display(),
                    scripts_dir.display(),
                    color_sequences_escaped
                )
            }
            ShellType::Zsh => {
                format!(
                    "# >>> NAILS shell integration (auto-removed on deactivation) >>>\n\
                     source {}/nails_prompt.zsh\n\
                     source {}/nails_alias.sh\n\
                     printf '{}'\n\
                     # <<< NAILS shell integration <<<\n",
                    scripts_dir.display(),
                    scripts_dir.display(),
                    color_sequences_escaped
                )
            }
            ShellType::Fish => {
                format!(
                    "# >>> NAILS shell integration (auto-removed on deactivation) >>>\n\
                     source {}/nails_prompt.fish\n\
                     source {}/nails_alias.fish\n\
                     printf '{}'\n\
                     # <<< NAILS shell integration <<<\n",
                    scripts_dir.display(),
                    scripts_dir.display(),
                    color_sequences_escaped
                )
            }
        }
    }
}
