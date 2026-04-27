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
mod rc_integration;
mod setup;

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
    pub fn new(filesystem: F, config: Config) -> Self {
        Self { filesystem, config }
    }

    pub(crate) fn resolve_target_username(&self) -> Result<String> {
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var(crate::obfuscate::env_target_user()))
            .or_else(|_| std::env::var("USER"))
            .map_err(|_| {
                std::io::Error::other(
                    "Could not determine username (SUDO_USER, NAILS_TARGET_USER, or USER not set)",
                )
                .into()
            })
    }

    fn has_explicit_target_user_context() -> bool {
        std::env::var("SUDO_USER").is_ok()
            || std::env::var(crate::obfuscate::env_target_user()).is_ok()
    }

    fn home_matches_username(home: &std::path::Path, username: &str) -> bool {
        home.file_name().and_then(|component| component.to_str()) == Some(username)
    }

    fn resolve_home_from_current_environment(target_username: Option<&str>) -> Option<PathBuf> {
        if Self::has_explicit_target_user_context() {
            return None;
        }

        let home = PathBuf::from(std::env::var_os("HOME")?);

        if let Some(username) = target_username
            && !Self::home_matches_username(&home, username)
        {
            return None;
        }

        Some(home)
    }

    #[cfg(test)]
    pub(crate) fn resolve_target_home_dir(&self) -> Result<PathBuf> {
        let username = self.resolve_target_username().ok();

        if let Some(home) = Self::resolve_home_from_current_environment(username.as_deref()) {
            return Ok(home);
        }

        let username = username.ok_or_else(|| {
            std::io::Error::other(
                "Could not determine username (SUDO_USER, NAILS_TARGET_USER, or USER not set)",
            )
        })?;

        Ok(PathBuf::from(format!("/home/{}", username)))
    }

    #[cfg(not(test))]
    pub(crate) fn resolve_target_home_dir(&self) -> Result<PathBuf> {
        let username = self.resolve_target_username().ok();

        if let Some(home) = Self::resolve_home_from_current_environment(username.as_deref()) {
            return Ok(home);
        }

        let username = username.ok_or_else(|| {
            std::io::Error::other(
                "Could not determine username (SUDO_USER, NAILS_TARGET_USER, or USER not set)",
            )
        })?;

        match nix::unistd::User::from_name(&username).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to resolve home directory for user {}: {}",
                username, e
            ))
        })? {
            Some(user) => Ok(user.dir),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Could not determine home directory for user {}", username),
            )
            .into()),
        }
    }

    pub(crate) fn resolve_binary_path(&self) -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.canonicalize().ok().or(Some(path)))
            .unwrap_or_else(|| self.config.hidden_volume_root.join("bin/nails"))
    }

    /// Detect the current shell type from the SHELL environment variable
    ///
    /// Returns None if SHELL is not set or if the shell is not supported.
    pub fn detect_current_shell(&self) -> Option<ShellType> {
        if let Ok(shell_path) = std::env::var("SHELL") {
            return if shell_path.ends_with("/bash") {
                Some(ShellType::Bash)
            } else if shell_path.ends_with("/zsh") {
                Some(ShellType::Zsh)
            } else if shell_path.ends_with("/fish") {
                Some(ShellType::Fish)
            } else {
                None
            };
        }

        let home_dir = self.resolve_target_home_dir().ok()?;

        if self
            .filesystem
            .path_exists(&home_dir.join(".zshrc"))
            .ok()
            .unwrap_or(false)
        {
            Some(ShellType::Zsh)
        } else if self
            .filesystem
            .path_exists(&home_dir.join(".config/fish/config.fish"))
            .ok()
            .unwrap_or(false)
        {
            Some(ShellType::Fish)
        } else if Self::has_explicit_target_user_context() {
            Some(ShellType::Bash)
        } else {
            None
        }
    }

    /// Get the scripts directory path on the hidden volume
    pub fn scripts_dir(&self) -> PathBuf {
        self.config.hidden_volume_root.join("scripts")
    }

    /// Write all prompt scripts to the hidden volume
    ///
    /// Generates and writes prompt instrumentation scripts for all supported
    /// shells (bash, zsh, fish) along with their corresponding cleanup scripts.
    ///
    /// Creates the scripts directory if it doesn't exist.
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
    pub fn prompt_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash => scripts_dir.join("nails_prompt.bash"),
            ShellType::Zsh => scripts_dir.join("nails_prompt.zsh"),
            ShellType::Fish => scripts_dir.join("nails_prompt.fish"),
        }
    }

    /// Get the path to the cleanup script for a specific shell
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
    pub fn write_alias_scripts(&self) -> Result<()> {
        let scripts_dir = self.scripts_dir();

        // Create scripts directory if it doesn't exist
        if !self.filesystem.path_exists(&scripts_dir)? {
            self.filesystem.create_directory(&scripts_dir)?;
        }

        // Resolve binary path for alias (Task 5)
        let binary_path = self.resolve_binary_path().display().to_string();

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
    pub fn alias_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash | ShellType::Zsh => scripts_dir.join("nails_alias.sh"),
            ShellType::Fish => scripts_dir.join("nails_alias.fish"),
        }
    }

    /// Get the path to the alias cleanup script for a specific shell
    pub fn alias_cleanup_script_path(&self, shell_type: ShellType) -> PathBuf {
        let scripts_dir = self.scripts_dir();
        match shell_type {
            ShellType::Bash | ShellType::Zsh => scripts_dir.join("nails_alias_cleanup.sh"),
            ShellType::Fish => scripts_dir.join("nails_alias_cleanup.fish"),
        }
    }
}

#[cfg(test)]
mod tests;
