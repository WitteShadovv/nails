//! Command Execution Abstraction
//!
//! Provides a testable abstraction for executing external commands during
//! NixOS profile building and activation.
//!
//! The `CommandExecutor` trait abstracts command execution to allow:
//! - Real command execution in production (`RealCommandExecutor`)
//! - Mock command execution in tests (`MockCommandExecutor`)
//!
//! This design pattern enables unit testing of the NixOS builder without
//! requiring actual nixos-rebuild or switch-to-configuration execution.

use crate::error::Result;
use std::path::Path;
use std::process::Command;

/// Trait for executing commands (for testability)
///
/// Abstracts command execution to allow mocking in tests.
/// Production code uses real Command execution, tests use mock.
pub trait CommandExecutor {
    /// Execute nixos-rebuild command
    ///
    /// # Arguments
    ///
    /// - `args`: Command arguments
    ///
    /// # Returns
    ///
    /// - `Ok((success, stdout, stderr))` with command output
    fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Execute switch-to-configuration script
    ///
    /// # Arguments
    ///
    /// - `script_path`: Full path to switch-to-configuration script
    /// - `args`: Arguments to pass to the script (e.g., ["switch"])
    ///
    /// # Returns
    ///
    /// - `Ok((success, stdout, stderr))` with command output
    fn execute_switch_to_configuration(
        &self,
        script_path: &Path,
        args: &[&str],
    ) -> Result<(bool, String, String)>;
}

/// Real command executor for production use
pub struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)> {
        let output = Command::new("nixos-rebuild").args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    fn execute_switch_to_configuration(
        &self,
        script_path: &Path,
        args: &[&str],
    ) -> Result<(bool, String, String)> {
        let output = Command::new(script_path).args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }
}
