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

        let hidden_volume_root = self.config.hidden_volume_root.to_string_lossy();

        // Write bash scripts
        let bash_script = prompt::generate_bash_prompt_script(&hidden_volume_root);
        let bash_cleanup = prompt::generate_bash_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.bash"), &bash_script)?;
        self.filesystem.write_file_content(
            &scripts_dir.join("nails_prompt_cleanup.bash"),
            &bash_cleanup,
        )?;

        // Write zsh scripts
        let zsh_script = prompt::generate_zsh_prompt_script(&hidden_volume_root);
        let zsh_cleanup = prompt::generate_zsh_prompt_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt.zsh"), &zsh_script)?;
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_prompt_cleanup.zsh"), &zsh_cleanup)?;

        // Write fish scripts
        let fish_script = prompt::generate_fish_prompt_script(&hidden_volume_root);
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

        let hidden_volume_root = self.config.hidden_volume_root.to_string_lossy();

        // Write bash/zsh alias scripts
        let bash_zsh_alias = alias::generate_bash_zsh_alias_script(&hidden_volume_root);
        let bash_zsh_cleanup = alias::generate_bash_zsh_alias_cleanup();
        self.filesystem
            .write_file_content(&scripts_dir.join("nails_alias.sh"), &bash_zsh_alias)?;
        self.filesystem.write_file_content(
            &scripts_dir.join("nails_alias_cleanup.sh"),
            &bash_zsh_cleanup,
        )?;

        // Write fish alias scripts
        let fish_alias = alias::generate_fish_alias_script(&hidden_volume_root);
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
        let mut warning = None;

        // Try to write prompt scripts
        if let Err(e) = self.write_prompt_scripts() {
            // Failed to write prompt scripts
            warning = Some(format!(
                "Shell prompt scripts could not be generated: {}",
                e
            ));
        }

        // Try to write alias scripts
        if let Err(e) = self.write_alias_scripts() {
            // Failed to write alias scripts
            if warning.is_none() {
                warning = Some(format!("Shell alias scripts could not be generated: {}", e));
            }
        }

        // If we have warnings, it means script generation failed
        // Return None to indicate no setup was successful
        if warning.is_some() {
            return Ok(None);
        }

        // Build result with source instructions
        let prompt_script = self.prompt_script_path(shell_type);
        let alias_script = self.alias_script_path(shell_type);

        let instructions = vec![
            format!("source {}", prompt_script.display()),
            format!("source {}", alias_script.display()),
        ];

        // Shell prompt and alias scripts generated successfully

        Ok(Some(ShellSetupResult {
            shell_type,
            prompt_script_path: prompt_script,
            alias_script_path: alias_script,
            instructions,
            warning: None,
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

    fn create_test_shell() -> ShellInstrumentation<MockFilesystem> {
        let fs = MockFilesystem::new();
        let config = Config::default();
        ShellInstrumentation::new(fs, config)
    }

    #[test]
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
        assert_eq!(fs.path_exists(&scripts_dir).unwrap(), false);

        // Write scripts
        shell.write_prompt_scripts().unwrap();

        // Scripts directory now exists
        assert_eq!(fs.path_exists(&scripts_dir).unwrap(), true);
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
        let mut config = Config::default();
        config.hidden_volume_root = "/custom/hidden".into();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_prompt_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let bash_script_path = scripts_dir.join("nails_prompt.bash");

        // Read the generated script
        let script_content = fs.read_file_content(&bash_script_path).unwrap();

        // Verify custom path is used in mount check
        assert!(script_content.contains("/custom/hidden/.nails"));
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
        assert_eq!(fs.path_exists(&scripts_dir).unwrap(), false);

        // Write alias scripts
        shell.write_alias_scripts().unwrap();

        // Scripts directory now exists
        assert_eq!(fs.path_exists(&scripts_dir).unwrap(), true);
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

        // Verify script has required guards
        assert!(script_content.contains(".nails"));
        assert!(script_content.contains("return 0"));
        assert!(script_content.contains("alias nails 2>/dev/null"));
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

        // Verify script has required guards
        assert!(script_content.contains(".nails"));
        assert!(script_content.contains("exit 0"));
        assert!(script_content.contains("functions -q nails"));
        assert!(script_content.contains("alias nails 'sudo"));
    }

    #[test]
    fn test_alias_script_custom_hidden_volume_path() {
        let fs = MockFilesystem::new();
        let mut config = Config::default();
        config.hidden_volume_root = "/custom/hidden".into();

        // Mock the parent directory to exist
        fs.mock_set_path_exists(&config.hidden_volume_root.to_string_lossy(), true);

        let shell = ShellInstrumentation::new(fs.clone(), config);

        shell.write_alias_scripts().unwrap();

        let scripts_dir = shell.scripts_dir();
        let bash_script = fs
            .read_file_content(&scripts_dir.join("nails_alias.sh"))
            .unwrap();

        // Verify custom path is used
        assert!(bash_script.contains("/custom/hidden/.nails"));
        assert!(bash_script.contains("sudo /custom/hidden/bin/nails"));
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
        let mut config = Config::default();
        config.hidden_volume_root = "/test/hidden".into();

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
        assert!(setup
            .prompt_script_path
            .to_string_lossy()
            .contains("/test/hidden/scripts/nails_prompt.bash"));
        assert!(setup
            .alias_script_path
            .to_string_lossy()
            .contains("/test/hidden/scripts/nails_alias.sh"));
    }
}
