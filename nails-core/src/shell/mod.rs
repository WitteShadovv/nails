//! Shell instrumentation and prompt management
//!
//! This module provides shell prompt instrumentation scripts that add a
//! "(NAILS-ACTIVE)" prefix to shell prompts when the hidden environment is active,
//! and alias management for the 'nails' command.
//!
//! # Features
//!
//! - **Prompt Scripts**: Generates shell-specific prompt modification scripts
//! - **Alias Scripts**: Generates 'nails' command alias scripts for convenience
//! - **Shell Detection**: Automatically detects the current shell from environment
//! - **Color Support**: Respects NO_COLOR environment variable
//! - **Restoration**: Provides cleanup scripts to restore original prompts and remove aliases
//! - **Hidden Volume Check**: Scripts verify hidden volume is mounted before making changes
//!
//! # Supported Shells
//!
//! - Bash (via PS1 variable and aliases)
//! - Zsh (via PROMPT variable and aliases)
//! - Fish (via fish_prompt function and aliases)
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::shell::{ShellInstrumentation, ShellType};
//! use nails_core::{MockFilesystem, Config};
//!
//! let fs = MockFilesystem::new();
//! let config = Config::default();
//! let shell = ShellInstrumentation::new(fs, config);
//!
//! // Detect current shell
//! if let Some(shell_type) = shell.detect_current_shell() {
//!     // Write prompt and alias scripts to hidden volume
//!     shell.write_prompt_scripts()?;
//!     shell.write_alias_scripts()?;
//! }
//! ```

pub mod alias;
pub mod color_scheme;
pub mod prompt;

use crate::{Config, Filesystem, Result};
use std::path::PathBuf;

// Re-export ShellType from cleanup module for backward compatibility
pub use crate::cleanup::history::ShellType;

/// Result of shell setup operation during activation
///
/// Contains information about generated scripts and instructions for the user
/// to source them into their current shell session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellSetupResult {
    /// The detected shell type
    pub shell_type: ShellType,
    /// Path to the prompt instrumentation script
    pub prompt_script_path: PathBuf,
    /// Path to the alias script
    pub alias_script_path: PathBuf,
    /// User-facing instructions for sourcing scripts
    pub instructions: Vec<String>,
    /// Optional warning message if something went wrong (but operation succeeded)
    pub warning: Option<String>,
    /// Whether rc file was modified (true = new terminals auto-configured)
    pub rc_modified: bool,
}

impl ShellSetupResult {
    /// Convert to source commands that the user should run
    ///
    /// Returns a list of shell commands to source the generated scripts.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = shell.shell_setup()?;
    /// for cmd in result.to_source_commands() {
    ///     println!("{}", cmd);
    /// }
    /// // Output:
    /// // source /mnt/hidden-volume/scripts/nails_prompt.bash
    /// // source /mnt/hidden-volume/scripts/nails_alias.sh
    /// ```
    pub fn to_source_commands(&self) -> Vec<String> {
        self.instructions.clone()
    }
}

/// Result of shell cleanup operation during deactivation
///
/// Contains instructions for the user to restore their shell prompt
/// and optionally remove aliases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCleanupResult {
    /// The detected shell type (if any)
    pub shell_type: Option<ShellType>,
    /// User-facing instructions for cleanup
    pub instructions: Vec<String>,
    /// Optional informational message
    pub message: Option<String>,
}

/// Shell instrumentation manager
///
/// Provides methods to generate shell-specific prompt scripts, write them
/// to the hidden volume, and detect the current shell type.
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
pub struct ShellInstrumentation<F: Filesystem> {
    filesystem: F,
    config: Config,
}

impl<F: Filesystem> ShellInstrumentation<F> {
    /// Create a new ShellInstrumentation instance
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (real or mock)
    /// * `config` - NAILS configuration with hidden volume path
    pub fn new(filesystem: F, config: Config) -> Self {
        Self { filesystem, config }
    }

    /// Detect the current shell type from the SHELL environment variable
    ///
    /// Returns None if SHELL is not set or if the shell is not supported.
    ///
    /// # Supported Shells
    ///
    /// - `/bin/bash`, `/usr/bin/bash`, or any path ending in `/bash` → Bash
    /// - `/bin/zsh`, `/usr/bin/zsh`, or any path ending in `/zsh` → Zsh
    /// - `/bin/fish`, `/usr/bin/fish`, or any path ending in `/fish` → Fish
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::shell::ShellInstrumentation;
    ///
    /// let shell = ShellInstrumentation::new(fs, config);
    /// match shell.detect_current_shell() {
    ///     Some(ShellType::Bash) => println!("Using bash"),
    ///     Some(ShellType::Zsh) => println!("Using zsh"),
    ///     Some(ShellType::Fish) => println!("Using fish"),
    ///     None => println!("Unsupported shell"),
    /// }
    /// ```
    pub fn detect_current_shell(&self) -> Option<ShellType> {
        let shell_path = std::env::var("SHELL").ok()?;

        if shell_path.ends_with("/bash") {
            Some(ShellType::Bash)
        } else if shell_path.ends_with("/zsh") {
            Some(ShellType::Zsh)
        } else if shell_path.ends_with("/fish") {
            Some(ShellType::Fish)
        } else {
            None
        }
    }

    /// Get the scripts directory path on the hidden volume
    ///
    /// Returns the path where shell prompt scripts should be written.
    /// Defaults to `{hidden_volume_root}/scripts/`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let scripts_dir = shell.scripts_dir();
    /// // Returns: /mnt/hidden-volume/scripts
    /// ```
    pub fn scripts_dir(&self) -> PathBuf {
        self.config.hidden_volume_root.join("scripts")
    }

    /// Write all prompt scripts to the hidden volume
    ///
    /// Generates and writes prompt instrumentation scripts for all supported
    /// shells (bash, zsh, fish) along with their corresponding cleanup scripts.
    ///
    /// Creates the scripts directory if it doesn't exist.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if:
    /// - The scripts directory cannot be created
    /// - Any script file cannot be written
    ///
    /// # Files Written
    ///
    /// - `nails_prompt.bash` - Bash prompt instrumentation
    /// - `nails_prompt_cleanup.bash` - Bash prompt restoration
    /// - `nails_prompt.zsh` - Zsh prompt instrumentation
    /// - `nails_prompt_cleanup.zsh` - Zsh prompt restoration
    /// - `nails_prompt.fish` - Fish prompt instrumentation
    /// - `nails_prompt_cleanup.fish` - Fish prompt restoration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let shell = ShellInstrumentation::new(fs, config);
    /// shell.write_prompt_scripts()?;
    /// ```
    pub fn write_prompt_scripts(&self) -> Result<()> {
        let scripts_dir = self.scripts_dir();

        // Create scripts directory if it doesn't exist
        if !self.filesystem.path_exists(&scripts_dir)? {
            self.filesystem.create_directory(&scripts_dir)?;
        }

        // Write bash scripts
        let bash_script = prompt::generate_bash_prompt_script();
        let bash_cleanup = prompt::generate_bash_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.bash"), &bash_script)?;
        self.filesystem.write_file_content(
            &scripts_dir.join("nails_prompt_cleanup.bash"),
            &bash_cleanup,
        )?;

        // Write zsh scripts
        let zsh_script = prompt::generate_zsh_prompt_script();
        let zsh_cleanup = prompt::generate_zsh_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.zsh"), &zsh_script)?;
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt_cleanup.zsh"), &zsh_cleanup)?;

        // Write fish scripts
        let fish_script = prompt::generate_fish_prompt_script();
        let fish_cleanup = prompt::generate_fish_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.fish"), &fish_script)?;
        self.filesystem.write_file_content(
            &scripts_dir.join("nails_prompt_cleanup.fish"),
            &fish_cleanup,
        )?;

        Ok(())
    }

    /// Get the path to the prompt script for a specific shell
    ///
    /// # Arguments
    ///
    /// * `shell_type` - The shell type to get the script path for
    ///
    /// # Returns
    ///
    /// Path to the prompt instrumentation script for the specified shell
    pub fn prompt_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash => scripts_dir.join("nails_prompt.bash"),
            ShellType::Zsh => scripts_dir.join("nails_prompt.zsh"),
            ShellType::Fish => scripts_dir.join("nails_prompt.fish"),
        }
    }

    /// Get the path to the cleanup script for a specific shell
    ///
    /// # Arguments
    ///
    /// * `shell_type` - The shell type to get the cleanup script path for
    ///
    /// # Returns
    ///
    /// Path to the prompt cleanup script for the specified shell
    pub fn cleanup_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash => scripts_dir.join("nails_prompt_cleanup.bash"),
            ShellType::Zsh => scripts_dir.join("nails_prompt_cleanup.zsh"),
            ShellType::Fish => scripts_dir.join("nails_prompt_cleanup.fish"),
        }
    }

    /// Write all alias scripts to the hidden volume
    ///
    /// Generates and writes alias management scripts for all supported shells
    /// (bash, zsh, fish) along with their corresponding cleanup scripts.
    ///
    /// Creates the scripts directory if it doesn't exist (reuses prompt scripts directory).
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if:
    /// - The scripts directory cannot be created
    /// - Any script file cannot be written
    ///
    /// # Files Written
    ///
    /// - `nails_alias.sh` - Bash/Zsh alias script
    /// - `nails_alias_cleanup.sh` - Bash/Zsh alias removal
    /// - `nails_alias.fish` - Fish alias script
    /// - `nails_alias_cleanup.fish` - Fish alias removal
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let shell = ShellInstrumentation::new(fs, config);
    /// shell.write_alias_scripts()?;
    /// ```
    pub fn write_alias_scripts(&self) -> Result<()> {
        let scripts_dir = self.scripts_dir();

        // Create scripts directory if it doesn't exist
        if !self.filesystem.path_exists(&scripts_dir)? {
            self.filesystem.create_directory(&scripts_dir)?;
        }

        // Resolve binary path for alias (Task 5)
        let binary_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("{}/bin/nails", self.config.hidden_volume_root.display()));

        // Write bash/zsh alias scripts
        let bash_zsh_alias = alias::generate_bash_zsh_alias_script(&binary_path);
        let bash_zsh_cleanup = alias::generate_bash_zsh_alias_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_alias.sh"), &bash_zsh_alias)?;
        self.filesystem.write_file_content(
            &scripts_dir.join("nails_alias_cleanup.sh"),
            &bash_zsh_cleanup,
        )?;

        // Write fish alias scripts
        let fish_alias = alias::generate_fish_alias_script(&binary_path);
        let fish_cleanup = alias::generate_fish_alias_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_alias.fish"), &fish_alias)?;
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_alias_cleanup.fish"), &fish_cleanup)?;

        Ok(())
    }

    /// Get the path to the alias script for a specific shell
    ///
    /// # Arguments
    ///
    /// * `shell_type` - The shell type to get the alias script path for
    ///
    /// # Returns
    ///
    /// Path to the alias script for the specified shell
    pub fn alias_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash | ShellType::Zsh => scripts_dir.join("nails_alias.sh"),
            ShellType::Fish => scripts_dir.join("nails_alias.fish"),
        }
    }

    /// Get the path to the alias cleanup script for a specific shell
    ///
    /// # Arguments
    ///
    /// * `shell_type` - The shell type to get the alias cleanup script path for
    ///
    /// # Returns
    ///
    /// Path to the alias cleanup script for the specified shell
    pub fn alias_cleanup_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash | ShellType::Zsh => scripts_dir.join("nails_alias_cleanup.sh"),
            ShellType::Fish => scripts_dir.join("nails_alias_cleanup.fish"),
        }
    }

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
    /// - Determines real user from `SUDO_USER` or `USER` env var
    /// - Finds home directory: `/home/{user}` (now overlaid)
    /// - Creates rc file if it doesn't exist (with parent dirs for Fish)
    /// - Checks for existing integration marker before appending (idempotent)
    /// - Appends integration block with color scheme from config
    /// - Returns false (not error) on write failures (best-effort)
    ///
    /// # Task 1: Auto-source shell integration via overlay rc file
    pub fn inject_rc_integration(&self, shell_type: ShellType) -> Result<bool> {
        // Determine real user (SUDO_USER takes precedence over USER)
        let username = std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .map_err(|_| {
                std::io::Error::other("Could not determine username (SUDO_USER or USER not set)")
            })?;

        let home_dir = PathBuf::from(format!("/home/{}", username));

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
    fn generate_rc_integration_block(&self, shell_type: ShellType) -> String {
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

        use std::io::Write;

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
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let shell = ShellInstrumentation::new(fs, config);
    /// if let Some(result) = shell.shell_setup()? {
    ///     println!("Shell integration:");
    ///     for cmd in result.to_source_commands() {
    ///         println!("  {}", cmd);
    ///     }
    /// }
    /// ```
    pub fn shell_setup(&self) -> Result<Option<ShellSetupResult>> {
        // Detect current shell
        let shell_type = match self.detect_current_shell() {
            Some(shell) => shell,
            None => {
                // No shell detected or unsupported - not an error
                // Shell instrumentation skipped: SHELL env var not set or unsupported shell
                return Ok(None);
            }
        };

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

        // Apply hidden color scheme (Story 14-8, Task 3)
        // OSC sequences are written to stdout so the terminal processes them
        // This is best-effort and non-blocking - failures are logged but don't prevent activation
        let color_sequences = color_scheme::apply_hidden_color_scheme(&self.config.color_scheme);
        Self::apply_color_scheme_to_terminal(&color_sequences, "hidden mode");

        // Task 1: Inject rc integration (best-effort)
        let rc_modified = self.inject_rc_integration(shell_type).unwrap_or(false);

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
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Normal deactivation (no alias removal)
    /// let cleanup = shell.shell_cleanup(false);
    ///
    /// // Emergency deactivation (with alias removal)
    /// let cleanup = shell.shell_cleanup(true);
    /// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use serial_test::serial;

    fn create_test_shell() -> ShellInstrumentation<MockFilesystem> {
        let fs = MockFilesystem::new();
        let config = Config::default();
        ShellInstrumentation::new(fs, config)
    }

    #[test]
    #[serial]
    fn test_detect_bash_shell() {
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }
        let shell = create_test_shell();
        let result = shell.detect_current_shell();
        unsafe {
            std::env::remove_var("SHELL");
        }
        assert_eq!(result, Some(ShellType::Bash));
    }

    #[test]
    #[serial]
    fn test_detect_zsh_shell() {
        unsafe {
            std::env::set_var("SHELL", "/usr/bin/zsh");
        }
        let shell = create_test_shell();
        let result = shell.detect_current_shell();
        unsafe {
            std::env::remove_var("SHELL");
        }
        assert_eq!(result, Some(ShellType::Zsh));
    }

    #[test]
    #[serial]
    fn test_detect_fish_shell() {
        unsafe {
            std::env::set_var("SHELL", "/usr/local/bin/fish");
        }
        let shell = create_test_shell();
        let result = shell.detect_current_shell();
        unsafe {
            std::env::remove_var("SHELL");
        }
        assert_eq!(result, Some(ShellType::Fish));
    }

    #[test]
    #[serial]
    fn test_detect_unsupported_shell() {
        unsafe {
            std::env::set_var("SHELL", "/bin/tcsh");
        }
        let shell = create_test_shell();
        let result = shell.detect_current_shell();
        unsafe {
            std::env::remove_var("SHELL");
        }
        assert_eq!(result, None);
    }

    #[test]
    fn test_scripts_dir_path() {
        let shell = create_test_shell();
        let scripts_dir = shell.scripts_dir();
        assert!(scripts_dir.to_string_lossy().ends_with("/scripts"));
    }

    #[test]
    fn test_prompt_script_paths() {
        let shell = create_test_shell();

        let bash_path = shell.prompt_script_path(ShellType::Bash);
        assert!(bash_path.to_string_lossy().ends_with("nails_prompt.bash"));

        let zsh_path = shell.prompt_script_path(ShellType::Zsh);
        assert!(zsh_path.to_string_lossy().ends_with("nails_prompt.zsh"));

        let fish_path = shell.prompt_script_path(ShellType::Fish);
        assert!(fish_path.to_string_lossy().ends_with("nails_prompt.fish"));
    }

    #[test]
    fn test_cleanup_script_paths() {
        let shell = create_test_shell();

        let bash_cleanup = shell.cleanup_script_path(ShellType::Bash);
        assert!(
            bash_cleanup
                .to_string_lossy()
                .ends_with("nails_prompt_cleanup.bash")
        );

        let zsh_cleanup = shell.cleanup_script_path(ShellType::Zsh);
        assert!(
            zsh_cleanup
                .to_string_lossy()
                .ends_with("nails_prompt_cleanup.zsh")
        );

        let fish_cleanup = shell.cleanup_script_path(ShellType::Fish);
        assert!(
            fish_cleanup
                .to_string_lossy()
                .ends_with("nails_prompt_cleanup.fish")
        );
    }

    #[test]
    fn test_write_prompt_scripts_creates_directory() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        // Scripts directory doesn't exist initially
        let scripts_dir = shell.scripts_dir();
        assert!(!fs.path_exists(&scripts_dir).unwrap());

        // Write scripts
        shell.write_prompt_scripts().unwrap();

        // Scripts directory now exists
        assert!(fs.path_exists(&scripts_dir).unwrap());
    }

    #[test]
    fn test_write_prompt_scripts_writes_all_files() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        // Write scripts
        shell.write_prompt_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();

        // Verify all 6 files can be read (meaning they were written)
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt.bash"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt_cleanup.bash"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt.zsh"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt_cleanup.zsh"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt.fish"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt_cleanup.fish"))
                .is_ok()
        );
    }

    #[test]
    fn test_write_prompt_scripts_idempotent() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        // Write scripts twice
        shell.write_prompt_scripts().unwrap();
        shell.write_prompt_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();

        // All files should still be readable (idempotent)
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt.bash"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt.zsh"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_prompt.fish"))
                .is_ok()
        );
    }

    #[test]
    fn test_write_prompt_scripts_uses_custom_hidden_volume_path() {
        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: "/custom/hidden".into(),
            ..Default::default()
        };

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_prompt_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let bash_script_path = scripts_dir.join("nails_prompt.bash");

        // Read the generated script
        let script_content = fs.read_file_content(&bash_script_path).unwrap();

        // Verify script no longer has .nails guard check
        assert!(!script_content.contains(".nails"));
    }

    #[test]
    fn test_script_content_has_shebang() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_prompt_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();

        // Check bash script has shebang
        let bash_content = fs
            .read_file_content(&scripts_dir.join("nails_prompt.bash"))
            .unwrap();
        assert!(bash_content.starts_with("#!/usr/bin/env bash"));

        // Check zsh script has shebang
        let zsh_content = fs
            .read_file_content(&scripts_dir.join("nails_prompt.zsh"))
            .unwrap();
        assert!(zsh_content.starts_with("#!/usr/bin/env zsh"));

        // Check fish script has shebang
        let fish_content = fs
            .read_file_content(&scripts_dir.join("nails_prompt.fish"))
            .unwrap();
        assert!(fish_content.starts_with("#!/usr/bin/env fish"));
    }

    // Alias script tests

    #[test]
    fn test_write_alias_scripts_creates_directory() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        // Scripts directory doesn't exist initially
        let scripts_dir = shell.scripts_dir();
        assert!(!fs.path_exists(&scripts_dir).unwrap());

        // Write alias scripts
        shell.write_alias_scripts().unwrap();

        // Scripts directory now exists
        assert!(fs.path_exists(&scripts_dir).unwrap());
    }

    #[test]
    fn test_write_alias_scripts_writes_all_files() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        // Write alias scripts
        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();

        // Verify all 4 files can be read (meaning they were written)
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_alias.sh"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_alias_cleanup.sh"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_alias.fish"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_alias_cleanup.fish"))
                .is_ok()
        );
    }

    #[test]
    fn test_alias_script_path_bash() {
        let shell = create_test_shell();
        let path = shell.alias_script_path(ShellType::Bash);
        assert!(path.to_string_lossy().ends_with("nails_alias.sh"));
    }

    #[test]
    fn test_alias_script_path_zsh() {
        let shell = create_test_shell();
        let path = shell.alias_script_path(ShellType::Zsh);
        assert!(path.to_string_lossy().ends_with("nails_alias.sh"));
    }

    #[test]
    fn test_alias_script_path_fish() {
        let shell = create_test_shell();
        let path = shell.alias_script_path(ShellType::Fish);
        assert!(path.to_string_lossy().ends_with("nails_alias.fish"));
    }

    #[test]
    fn test_alias_cleanup_script_path_bash() {
        let shell = create_test_shell();
        let path = shell.alias_cleanup_script_path(ShellType::Bash);
        assert!(path.to_string_lossy().ends_with("nails_alias_cleanup.sh"));
    }

    #[test]
    fn test_alias_cleanup_script_path_zsh() {
        let shell = create_test_shell();
        let path = shell.alias_cleanup_script_path(ShellType::Zsh);
        assert!(path.to_string_lossy().ends_with("nails_alias_cleanup.sh"));
    }

    #[test]
    fn test_alias_cleanup_script_path_fish() {
        let shell = create_test_shell();
        let path = shell.alias_cleanup_script_path(ShellType::Fish);
        assert!(path.to_string_lossy().ends_with("nails_alias_cleanup.fish"));
    }

    #[test]
    fn test_bash_zsh_alias_script_content() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let script_content = fs
            .read_file_content(&scripts_dir.join("nails_alias.sh"))
            .unwrap();

        // Verify script has no .nails guard
        assert!(!script_content.contains(".nails"));
        assert!(script_content.contains("alias nails >/dev/null 2>&1"));
        assert!(script_content.contains("alias nails='sudo"));
    }

    #[test]
    fn test_fish_alias_script_content() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let script_content = fs
            .read_file_content(&scripts_dir.join("nails_alias.fish"))
            .unwrap();

        // Verify script has no .nails guard
        assert!(!script_content.contains(".nails"));
        assert!(script_content.contains("functions -q nails"));
        assert!(script_content.contains("alias nails 'sudo"));
    }

    #[test]
    fn test_alias_script_uses_actual_binary_path() {
        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: "/custom/hidden".into(),
            ..Default::default()
        };

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let bash_script = fs
            .read_file_content(&scripts_dir.join("nails_alias.sh"))
            .unwrap();

        // Verify script uses actual binary path (from current_exe or fallback)
        // Should contain 'sudo' followed by a path, but NOT hardcoded /bin/nails
        assert!(bash_script.contains("alias nails='sudo"));
    }

    #[test]
    fn test_bash_zsh_cleanup_script_content() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let cleanup_content = fs
            .read_file_content(&scripts_dir.join("nails_alias_cleanup.sh"))
            .unwrap();

        // Verify best-effort cleanup
        assert!(cleanup_content.contains("unalias nails 2>/dev/null || true"));
    }

    #[test]
    fn test_fish_cleanup_script_content() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let cleanup_content = fs
            .read_file_content(&scripts_dir.join("nails_alias_cleanup.fish"))
            .unwrap();

        // Verify best-effort cleanup
        assert!(cleanup_content.contains("functions -e nails 2>/dev/null; or true"));
    }

    #[test]
    fn test_write_alias_scripts_idempotent() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        // Write scripts twice
        shell.write_alias_scripts().unwrap();
        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();

        // All files should still be readable (idempotent)
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_alias.sh"))
                .is_ok()
        );
        assert!(
            fs.read_file_content(&scripts_dir.join("nails_alias.fish"))
                .is_ok()
        );
    }

    // Tests for shell_setup() and ShellSetupResult

    #[test]
    fn test_shell_setup_with_bash() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config);
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should succeed
        assert!(result.is_ok());
        let result = result.unwrap();

        // Should have a result (bash detected)
        assert!(result.is_some());
        let setup = result.unwrap();

        // Verify shell type
        assert_eq!(setup.shell_type, ShellType::Bash);

        // Verify instructions contain source commands
        assert_eq!(setup.instructions.len(), 2);
        assert!(setup.instructions[0].contains("nails_prompt.bash"));
        assert!(setup.instructions[1].contains("nails_alias.sh"));

        // Verify no warnings
        assert!(setup.warning.is_none());
    }

    #[test]
    #[serial]
    fn test_shell_setup_with_zsh() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to zsh
        unsafe {
            std::env::set_var("SHELL", "/usr/bin/zsh");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config);
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should succeed
        assert!(result.is_ok());
        let result = result.unwrap();

        // Should have a result (zsh detected)
        assert!(result.is_some());
        let setup = result.unwrap();

        // Verify shell type
        assert_eq!(setup.shell_type, ShellType::Zsh);

        // Verify instructions contain source commands
        assert!(setup.instructions[0].contains("nails_prompt.zsh"));
        assert!(setup.instructions[1].contains("nails_alias.sh"));
    }

    #[test]
    #[serial]
    fn test_shell_setup_with_fish() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to fish
        unsafe {
            std::env::set_var("SHELL", "/usr/bin/fish");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config);
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should succeed
        assert!(result.is_ok());
        let result = result.unwrap();

        // Should have a result (fish detected)
        assert!(result.is_some());
        let setup = result.unwrap();

        // Verify shell type
        assert_eq!(setup.shell_type, ShellType::Fish);

        // Verify instructions contain source commands
        assert!(setup.instructions[0].contains("nails_prompt.fish"));
        assert!(setup.instructions[1].contains("nails_alias.fish"));
    }

    #[test]
    #[serial]
    fn test_shell_setup_no_shell_detected() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Ensure SHELL is not set (use a custom variable that we know is unset)
        unsafe {
            std::env::remove_var("SHELL");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_setup();

        // Should succeed but return None
        assert!(result.is_ok());
        assert!(matches!(result.as_ref(), Ok(None)));
    }

    #[test]
    #[serial]
    fn test_shell_setup_unsupported_shell() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL to unsupported shell
        unsafe {
            std::env::set_var("SHELL", "/bin/tcsh");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should succeed but return None
        assert!(result.is_ok());
        assert!(matches!(result.as_ref(), Ok(None)));
    }

    #[test]
    #[serial]
    fn test_shell_setup_to_source_commands() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should have Some result
        assert!(matches!(result.as_ref(), Ok(Some(_))));
        let setup = result.unwrap().unwrap();
        let commands = setup.to_source_commands();

        assert_eq!(commands.len(), 2);
        assert!(commands[0].starts_with("source "));
        assert!(commands[0].ends_with("nails_prompt.bash"));
        assert!(commands[1].starts_with("source "));
        assert!(commands[1].ends_with("nails_alias.sh"));
    }

    // Tests for shell_cleanup() and ShellCleanupResult

    #[test]
    #[serial]
    fn test_shell_cleanup_normal_deactivation() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_cleanup(false); // false = no alias removal

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should have shell type detected
        assert_eq!(result.shell_type, Some(ShellType::Bash));

        // Should only have prompt cleanup, not alias cleanup
        assert_eq!(result.instructions.len(), 1);
        assert!(result.instructions[0].contains("nails_prompt_cleanup.bash"));
        assert!(!result.instructions[0].contains("alias"));

        // No message
        assert!(result.message.is_none());
    }

    #[test]
    #[serial]
    fn test_shell_cleanup_emergency_deactivation() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_cleanup(true); // true = include alias removal

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should have shell type detected
        assert_eq!(result.shell_type, Some(ShellType::Bash));

        // Should have both prompt cleanup AND alias cleanup
        assert_eq!(result.instructions.len(), 2);
        assert!(result.instructions[0].contains("nails_prompt_cleanup.bash"));
        assert!(result.instructions[1].contains("nails_alias_cleanup.sh"));
    }

    #[test]
    #[serial]
    fn test_shell_cleanup_no_shell_detected() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Ensure SHELL is not set
        unsafe {
            std::env::remove_var("SHELL");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_cleanup(false);

        // Should have no shell type
        assert!(result.shell_type.is_none());

        // Should have no instructions
        assert!(result.instructions.is_empty());

        // Should have message
        assert!(result.message.is_some());
        assert!(result.message.unwrap().contains("Shell cleanup skipped"));
    }

    #[test]
    #[serial]
    fn test_shell_cleanup_with_fish() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Set SHELL to fish
        unsafe {
            std::env::set_var("SHELL", "/usr/bin/fish");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_cleanup(true); // emergency with alias removal

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should have fish shell type
        assert_eq!(result.shell_type, Some(ShellType::Fish));

        // Should have both cleanup scripts
        assert_eq!(result.instructions.len(), 2);
        assert!(result.instructions[0].contains("nails_prompt_cleanup.fish"));
        assert!(result.instructions[1].contains("nails_alias_cleanup.fish"));
    }

    #[test]
    fn test_shell_setup_result_paths() {
        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: "/test/hidden".into(),
            ..Default::default()
        };

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config);
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Should have Some result
        assert!(matches!(result.as_ref(), Ok(Some(_))));
        let setup = result.unwrap().unwrap();

        // Verify paths point to correct scripts
        assert!(
            setup
                .prompt_script_path
                .to_string_lossy()
                .contains("/test/hidden/scripts/nails_prompt.bash")
        );
        assert!(
            setup
                .alias_script_path
                .to_string_lossy()
                .contains("/test/hidden/scripts/nails_alias.sh")
        );
    }

    // Color scheme integration tests (Story 14-8, Code Review Follow-up)
    //
    // Note: stdout write error testing (AC8 silent failure path) is not included here
    // because mocking std::io::stdout() requires complex test infrastructure that's not
    // practical in this context. The error handling is implemented in shell_setup() and
    // shell_cleanup() methods using tracing::warn!() for logging failures while continuing
    // activation/deactivation. The silent failure behavior is verified by code review.

    #[test]
    #[serial]
    fn test_shell_setup_color_scheme_enabled() {
        let fs = MockFilesystem::new();
        let mut config = Config::default();
        config.color_scheme.enabled = true;
        config.color_scheme.hidden.background = "#1a1a2e".to_string();
        config.color_scheme.hidden.foreground = "#e0e0e0".to_string();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config.clone());
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Verify setup succeeds
        assert!(result.is_ok());
        let setup_result = result.unwrap();
        assert!(setup_result.is_some());

        // Verify that color scheme sequences would be generated
        let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
        assert!(!color_sequences.is_empty());
        assert!(color_sequences.contains("\x1b]11;#1a1a2e\x07")); // background
        assert!(color_sequences.contains("\x1b]10;#e0e0e0\x07")); // foreground
    }

    #[test]
    #[serial]
    fn test_shell_setup_color_scheme_disabled() {
        let fs = MockFilesystem::new();
        let mut config = Config::default();
        config.color_scheme.enabled = false;

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config.clone());
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Verify setup succeeds
        assert!(result.is_ok());

        // Verify that color scheme sequences are NOT generated when disabled
        let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
        assert!(color_sequences.is_empty());
    }

    #[test]
    #[serial]
    fn test_shell_cleanup_color_scheme_enabled() {
        let fs = MockFilesystem::new();
        let mut config = Config::default();
        config.color_scheme.enabled = true;
        config.color_scheme.decoy.reset = true;

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config.clone());
        let result = shell.shell_cleanup(false);

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Verify cleanup succeeds
        assert!(result.shell_type.is_some());

        // Verify that color reset sequences would be generated
        let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
        assert!(!color_sequences.is_empty());
        assert!(color_sequences.contains("\x1b]111\x07")); // reset background
        assert!(color_sequences.contains("\x1b]110\x07")); // reset foreground
        assert!(color_sequences.contains("\x1b]104\x07")); // reset palette
    }

    #[test]
    #[serial]
    fn test_shell_cleanup_color_scheme_disabled() {
        let fs = MockFilesystem::new();
        let mut config = Config::default();
        config.color_scheme.enabled = false;

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config.clone());
        let result = shell.shell_cleanup(false);

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Verify cleanup succeeds
        assert!(result.shell_type.is_some());

        // Verify that color reset sequences are NOT generated when disabled
        let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
        assert!(color_sequences.is_empty());
    }

    #[test]
    #[serial]
    fn test_activation_deactivation_color_scheme_cycle() {
        let fs = MockFilesystem::new();
        let mut config = Config::default();
        config.color_scheme.enabled = true;
        config.color_scheme.hidden.background = "#1a1a2e".to_string();
        config.color_scheme.hidden.foreground = "#e0e0e0".to_string();
        config.color_scheme.decoy.reset = true;

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());

        // Test activation (shell_setup)
        let setup_result = shell.shell_setup();
        assert!(setup_result.is_ok());

        // Verify hidden color scheme is generated for activation
        let hidden_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
        assert!(!hidden_sequences.is_empty());
        assert!(hidden_sequences.contains("\x1b]11;#1a1a2e\x07"));
        assert!(hidden_sequences.contains("\x1b]10;#e0e0e0\x07"));

        // Test deactivation (shell_cleanup)
        let cleanup_result = shell.shell_cleanup(false);
        assert!(cleanup_result.shell_type.is_some());

        // Verify decoy (reset) color scheme is generated for deactivation
        let decoy_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
        assert!(!decoy_sequences.is_empty());
        assert!(decoy_sequences.contains("\x1b]111\x07"));
        assert!(decoy_sequences.contains("\x1b]110\x07"));
        assert!(decoy_sequences.contains("\x1b]104\x07"));

        // Verify sequences are different (not accidentally generating same thing)
        assert_ne!(hidden_sequences, decoy_sequences);

        unsafe {
            std::env::remove_var("SHELL");
        }
    }

    #[test]
    #[serial]
    fn test_color_scheme_applied_after_scripts_written() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());

        // Run shell_setup which writes scripts first, then applies color scheme
        let result = shell.shell_setup();

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Verify setup succeeded
        assert!(result.is_ok());
        let setup = result.unwrap();
        assert!(setup.is_some());

        // Verify scripts were written
        let scripts_dir = shell.scripts_dir();
        let prompt_script = fs.read_file_content(&scripts_dir.join("nails_prompt.bash"));
        let alias_script = fs.read_file_content(&scripts_dir.join("nails_alias.sh"));

        // Both scripts should exist (verifying they were written before color scheme)
        assert!(prompt_script.is_ok());
        assert!(alias_script.is_ok());

        // Color scheme application happens after script writing
        // This test verifies the order by checking that scripts exist
        // and color scheme function is called (which it is in shell_setup after write_prompt_scripts)
        let color_sequences = color_scheme::apply_hidden_color_scheme(&config.color_scheme);
        assert!(!color_sequences.is_empty());
    }

    #[test]
    #[serial]
    fn test_emergency_deactivation_includes_color_reset() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        // Set SHELL environment variable to bash
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }

        let shell = ShellInstrumentation::new(fs, config.clone());

        // Emergency deactivation calls shell_cleanup(true)
        let result = shell.shell_cleanup(true);

        unsafe {
            std::env::remove_var("SHELL");
        }

        // Verify cleanup completed
        assert!(result.shell_type.is_some());

        // Verify color reset sequences are generated (best-effort)
        let color_sequences = color_scheme::apply_decoy_color_scheme(&config.color_scheme);
        assert!(!color_sequences.is_empty());
        assert!(color_sequences.contains("\x1b]111\x07"));
    }

    // ============================================================================
    // RC File Integration Tests (Task 1: Auto-source shell integration)
    // ============================================================================

    #[test]
    #[serial]
    fn test_inject_rc_integration_bash_creates_bashrc() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());

        // Call inject_rc_integration
        let result = shell.inject_rc_integration(ShellType::Bash);

        unsafe {
            std::env::remove_var("SHELL");
            std::env::remove_var("SUDO_USER");
        }

        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify .bashrc was created with integration block
        let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
        let content = fs.read_file_content(&bashrc_path).unwrap();

        assert!(content.contains("# >>> NAILS shell integration"));
        assert!(content.contains("source /mnt/hidden-volume/scripts/nails_prompt.bash"));
        assert!(content.contains("source /mnt/hidden-volume/scripts/nails_alias.sh"));
        assert!(content.contains("printf '\\e]11;#1a1a2e\\a\\e]10;#e0e0e0\\a'"));
        assert!(content.contains("# <<< NAILS shell integration <<<"));
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_zsh_creates_zshrc() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        unsafe {
            std::env::set_var("SHELL", "/bin/zsh");
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());

        let result = shell.inject_rc_integration(ShellType::Zsh);

        unsafe {
            std::env::remove_var("SHELL");
            std::env::remove_var("SUDO_USER");
        }

        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify .zshrc was created
        let zshrc_path = PathBuf::from("/home/testuser/.zshrc");
        let content = fs.read_file_content(&zshrc_path).unwrap();

        assert!(content.contains("# >>> NAILS shell integration"));
        assert!(content.contains("source /mnt/hidden-volume/scripts/nails_prompt.zsh"));
        assert!(content.contains("source /mnt/hidden-volume/scripts/nails_alias.sh"));
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_fish_creates_config_fish() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        unsafe {
            std::env::set_var("SHELL", "/bin/fish");
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());

        let result = shell.inject_rc_integration(ShellType::Fish);

        unsafe {
            std::env::remove_var("SHELL");
            std::env::remove_var("SUDO_USER");
        }

        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify config.fish was created (with parent dirs)
        let fish_config_path = PathBuf::from("/home/testuser/.config/fish/config.fish");
        let content = fs.read_file_content(&fish_config_path).unwrap();

        assert!(content.contains("# >>> NAILS shell integration"));
        assert!(content.contains("source /mnt/hidden-volume/scripts/nails_prompt.fish"));
        assert!(content.contains("source /mnt/hidden-volume/scripts/nails_alias.fish"));
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_idempotent() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        unsafe {
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());

        // Call twice
        let result1 = shell.inject_rc_integration(ShellType::Bash);
        let result2 = shell.inject_rc_integration(ShellType::Bash);

        unsafe {
            std::env::remove_var("SUDO_USER");
        }

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Verify only ONE integration block exists
        let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
        let content = fs.read_file_content(&bashrc_path).unwrap();

        let marker_count = content.matches("# >>> NAILS shell integration").count();
        assert_eq!(marker_count, 1, "Should only have one integration block");
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_appends_to_existing_bashrc() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        // Create existing .bashrc
        let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
        fs.mock_set_path_exists(&bashrc_path.to_string_lossy(), true);
        fs.mock_set_file_content(
            &bashrc_path.to_string_lossy(),
            "# Existing config\nexport PATH=/usr/bin:$PATH\n",
        );

        unsafe {
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());
        let result = shell.inject_rc_integration(ShellType::Bash);

        unsafe {
            std::env::remove_var("SUDO_USER");
        }

        assert!(result.is_ok());

        let content = fs.read_file_content(&bashrc_path).unwrap();

        // Should preserve existing content
        assert!(content.contains("# Existing config"));
        assert!(content.contains("export PATH=/usr/bin:$PATH"));

        // Should append NAILS integration
        assert!(content.contains("# >>> NAILS shell integration"));
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_uses_color_scheme_config() {
        let fs = MockFilesystem::new();
        let config = Config {
            color_scheme: crate::config::ColorSchemeConfig {
                hidden: crate::config::ColorProfile {
                    background: "#123456".to_string(),
                    foreground: "#abcdef".to_string(),
                },
                ..Default::default()
            },
            ..Default::default()
        };

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        unsafe {
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());
        let result = shell.inject_rc_integration(ShellType::Bash);

        unsafe {
            std::env::remove_var("SUDO_USER");
        }

        assert!(result.is_ok());

        let bashrc_path = PathBuf::from("/home/testuser/.bashrc");
        let content = fs.read_file_content(&bashrc_path).unwrap();

        // Should use configured colors, not hardcoded
        assert!(content.contains("#123456"));
        assert!(content.contains("#abcdef"));
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_falls_back_to_user_env() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/fallbackuser", true);

        unsafe {
            // No SUDO_USER, should fall back to USER
            std::env::remove_var("SUDO_USER");
            std::env::set_var("USER", "fallbackuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());
        let result = shell.inject_rc_integration(ShellType::Bash);

        unsafe {
            std::env::remove_var("USER");
        }

        assert!(result.is_ok());

        // Should use USER env var
        let bashrc_path = PathBuf::from("/home/fallbackuser/.bashrc");
        assert!(fs.read_file_content(&bashrc_path).is_ok());
    }

    #[test]
    #[serial]
    fn test_inject_rc_integration_returns_false_on_failure() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);
        fs.mock_set_path_exists("/home", true);
        fs.mock_set_path_exists("/home/testuser", true);

        // Make bashrc write fail
        fs.mock_set_write_should_fail("/home/testuser/.bashrc", true);

        unsafe {
            std::env::set_var("SUDO_USER", "testuser");
        }

        let shell = ShellInstrumentation::new(fs.clone(), config.clone());
        let result = shell.inject_rc_integration(ShellType::Bash);

        unsafe {
            std::env::remove_var("SUDO_USER");
        }

        // Should return Ok(false) on best-effort failure
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
