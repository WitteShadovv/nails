// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shell instrumentation and prompt management
//!
//! This module provides shell prompt instrumentation scripts that optionally
//! prepend a configurable label to shell prompts when the hidden environment is
//! active, and alias management for the 'nails' command.
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
mod overlay_guard;
pub mod prompt;
pub(crate) mod rc_integration;
mod setup;

#[cfg(test)]
use crate::constants::ENV_TARGET_USER;
use crate::target_user::TargetUser;
use crate::{Config, Filesystem, NailsError, Result};
use std::path::{Path, PathBuf};

// Re-export ShellType from cleanup module for backward compatibility
pub use crate::cleanup::history::ShellType;

/// Basename of the XDG autostart entry NAILS writes into the overlaid home for
/// login-time notification dispatch.
///
/// Shared so the persona inventory can skip NAILS' own entry when it lists the
/// decoy autostart state the hidden session inherits.
pub(crate) const NOTIFY_AUTOSTART_FILE: &str = "nails-notify.desktop";

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
    /// The operator the home writes belong to. When set, rc and autostart files
    /// are written through [`Filesystem::write_user_file`] so they end up
    /// symlink-safe and owned by the operator instead of root. When `None`
    /// (the default, used by unit tests) the writes fall back to a plain,
    /// root-owned write.
    target_user: Option<TargetUser>,
    /// Test-only override for the `/proc/self/mountinfo` snapshot consulted by
    /// the overlay guard, so unit tests can exercise the gate without a real
    /// overlay. `None` means "assume the home is on a hidden overlay" so that
    /// existing rc/autostart tests keep passing unchanged.
    #[cfg(test)]
    mountinfo_override: std::cell::RefCell<Option<String>>,
}

impl<F: Filesystem> ShellInstrumentation<F> {
    /// Create a new ShellInstrumentation instance
    pub fn new(filesystem: F, config: Config) -> Self {
        Self {
            filesystem,
            config,
            target_user: None,
            #[cfg(test)]
            mountinfo_override: std::cell::RefCell::new(None),
        }
    }

    /// Attach the operator whose home the integration writes into, so rc and
    /// autostart files are created symlink-safe and owned by that account.
    ///
    /// Production callers resolve the operator once (via [`TargetUser::resolve`])
    /// and pass it here; when it cannot be resolved they construct without it and
    /// the integration degrades to a best-effort root-owned write.
    pub fn with_target_user(mut self, target_user: TargetUser) -> Self {
        self.target_user = Some(target_user);
        self
    }

    /// Write a file into the operator's home, owned by the operator and
    /// symlink-safe, when the operator is known; otherwise fall back to a plain
    /// write. Returns whether the write succeeded (mirroring the best-effort
    /// contract of the shell integration).
    fn write_home_file(&self, path: &Path, content: &str, mode: u32) -> Result<()> {
        match self.target_user.as_ref() {
            Some(user) => self.filesystem.write_user_file(path, content, user, mode),
            None => self.filesystem.write_file_content(path, content),
        }
    }

    /// Whether home writes carry a resolved operator (and therefore create their
    /// own user-owned parent directories).
    fn owns_home_writes(&self) -> bool {
        self.target_user.is_some()
    }

    /// Set the mountinfo snapshot the overlay guard will parse (tests only).
    #[cfg(test)]
    pub(crate) fn set_mountinfo_override(&self, content: impl Into<String>) {
        *self.mountinfo_override.borrow_mut() = Some(content.into());
    }

    /// Confirm the target home sits on a NAILS overlay before the shell
    /// integration writes files into it.
    ///
    /// In non-test builds this reads `/proc/self/mountinfo` in the same process
    /// that performs the write, so it predicts the write destination in whatever
    /// mount namespace that process runs in. A read error is treated as "not on
    /// an overlay" so the integration fails safe (skips the decoy disk).
    #[cfg(not(test))]
    pub(crate) fn target_home_on_hidden_overlay(&self, home: &Path) -> bool {
        match std::fs::read_to_string("/proc/self/mountinfo") {
            Ok(content) => overlay_guard::path_on_hidden_overlay(
                &content,
                home,
                &self.config.hidden_volume_root,
            ),
            Err(e) => {
                tracing::warn!(
                    "Could not read /proc/self/mountinfo to confirm overlay for {}: {}",
                    home.display(),
                    e
                );
                false
            }
        }
    }

    /// Test build: consult the injected mountinfo override, defaulting to
    /// "on a hidden overlay" when no override is set.
    #[cfg(test)]
    pub(crate) fn target_home_on_hidden_overlay(&self, home: &Path) -> bool {
        match self.mountinfo_override.borrow().as_deref() {
            Some(content) => overlay_guard::path_on_hidden_overlay(
                content,
                home,
                &self.config.hidden_volume_root,
            ),
            None => true,
        }
    }

    /// The operator's login name, for the test-only home reconstruction below.
    ///
    /// Production resolves the operator once (via [`TargetUser::resolve`]) and
    /// attaches it with [`Self::with_target_user`], then reads the name straight
    /// off that attached operator, so this env-based path exists only to keep the
    /// hermetic unit tests — which inject identity through environment variables —
    /// exercising the integration without a real passwd entry.
    #[cfg(test)]
    pub(crate) fn resolve_target_username(&self) -> Result<String> {
        if let Some(user) = self.target_user.as_ref() {
            return Ok(user.name.clone());
        }

        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var(ENV_TARGET_USER))
            .or_else(|_| std::env::var("USER"))
            .map_err(|_| {
                NailsError::InvalidState(
                    "Could not determine username (SUDO_USER, NAILS_TARGET_USER, or USER not set)"
                        .to_string(),
                )
            })
    }

    /// The operator's home directory.
    ///
    /// Production uses the attached [`TargetUser`]'s home, which already honours
    /// the opt-in persona home; without an attached operator it errors.
    #[cfg(not(test))]
    pub(crate) fn resolve_target_home_dir(&self) -> Result<PathBuf> {
        self.target_user
            .as_ref()
            .map(|user| user.home().to_path_buf())
            .ok_or_else(|| {
                NailsError::InvalidState(
                    "Could not determine the target home directory for shell integration"
                        .to_string(),
                )
            })
    }

    /// Test build: prefer an attached operator's home, otherwise reconstruct it
    /// from the injected environment exactly as the historical resolver did.
    #[cfg(test)]
    pub(crate) fn resolve_target_home_dir(&self) -> Result<PathBuf> {
        if let Some(user) = self.target_user.as_ref() {
            return Ok(user.home().to_path_buf());
        }

        let username = self.resolve_target_username().ok();

        if let Some(home) = Self::resolve_home_from_current_environment(username.as_deref()) {
            return Ok(home);
        }

        let username = username.ok_or_else(|| {
            NailsError::InvalidState(
                "Could not determine username (SUDO_USER, NAILS_TARGET_USER, or USER not set)"
                    .to_string(),
            )
        })?;

        Ok(PathBuf::from(format!("/home/{}", username)))
    }

    /// Whether the integration knows which operator it is acting for.
    ///
    /// Production answers from the attached operator (checked by the caller). In
    /// test builds the historical environment heuristic is also consulted so the
    /// env-driven unit tests keep exercising the shell-detection fallbacks.
    #[cfg(not(test))]
    fn has_explicit_target_user_context() -> bool {
        false
    }

    #[cfg(test)]
    fn has_explicit_target_user_context() -> bool {
        std::env::var("SUDO_USER").is_ok() || std::env::var(ENV_TARGET_USER).is_ok()
    }

    #[cfg(test)]
    fn home_matches_username(home: &std::path::Path, username: &str) -> bool {
        home.file_name().and_then(|component| component.to_str()) == Some(username)
    }

    #[cfg(test)]
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
        } else if self.target_user.is_some() || Self::has_explicit_target_user_context() {
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

        let label = self.config.prompt_label.as_str();

        // Write bash scripts
        let bash_script = prompt::generate_bash_prompt_script(label);
        let bash_cleanup = prompt::generate_bash_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.bash"), &bash_script)?;
        self.filesystem.write_file_content(
            &scripts_dir.join("nails_prompt_cleanup.bash"),
            &bash_cleanup,
        )?;

        // Write zsh scripts
        let zsh_script = prompt::generate_zsh_prompt_script(label);
        let zsh_cleanup = prompt::generate_zsh_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.zsh"), &zsh_script)?;
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt_cleanup.zsh"), &zsh_cleanup)?;

        // Write fish scripts
        let fish_script = prompt::generate_fish_prompt_script(label);
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

        // Resolve binary path for alias
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
