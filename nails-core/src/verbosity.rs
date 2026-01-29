//! Verbosity level configuration for controlling output detail
//!
//! This module defines the verbosity levels used throughout NAILS
//! to control logging and progress output.

use tracing::Level;

/// Verbosity level for controlling output detail
///
/// Verbosity levels control how much information is displayed during
/// NAILS operations. The levels are hierarchical - higher levels
/// include all output from lower levels.
///
/// # Examples
///
/// ```
/// use nails_core::Verbosity;
///
/// let quiet = Verbosity::Quiet;
/// assert_eq!(quiet.to_tracing_level(), tracing::Level::ERROR);
///
/// let normal = Verbosity::Normal;
/// assert_eq!(normal.to_tracing_level(), tracing::Level::INFO);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    /// Quiet mode: Only show final result and errors
    ///
    /// Command line: `--quiet` or `-q`
    ///
    /// Output example:
    /// ```text
    /// ✓ Activation complete in 2.1s
    /// ```
    Quiet = 0,

    /// Normal mode: Show progress steps (default)
    ///
    /// Command line: (default, no flag)
    ///
    /// Output example:
    /// ```text
    /// Running pre-flight checks...
    /// ✓ Pre-flight checks passed (0.2s)
    /// Building NixOS profile...
    /// ✓ NixOS profile ready: generation 12345 (1.2s)
    /// ✓ Activation complete in 2.1s
    /// ```
    Normal = 1,

    /// Verbose mode: Show additional detail
    ///
    /// Command line: `-v`
    ///
    /// Output includes normal progress plus:
    /// - Individual overlay mount details
    /// - Detailed operation steps
    /// - Additional context information
    Verbose = 2,

    /// Debug mode: Show full diagnostic output
    ///
    /// Command line: `-vv`
    ///
    /// Output includes verbose mode plus:
    /// - Mount parameters and paths
    /// - NixOS command output
    /// - State file paths and content
    /// - All trace-level logging
    Debug = 3,
}

impl Verbosity {
    /// Convert verbosity level to tracing::Level
    ///
    /// This mapping controls which tracing events are displayed:
    ///
    /// | Verbosity | Tracing Level | Shows |
    /// |-----------|---------------|-------|
    /// | Quiet     | ERROR         | Only errors and final result |
    /// | Normal    | INFO          | Progress steps and info messages |
    /// | Verbose   | DEBUG         | Additional debugging detail |
    /// | Debug     | TRACE         | All diagnostic information |
    ///
    /// # Examples
    ///
    /// ```
    /// use nails_core::Verbosity;
    /// use tracing::Level;
    ///
    /// assert_eq!(Verbosity::Quiet.to_tracing_level(), Level::ERROR);
    /// assert_eq!(Verbosity::Normal.to_tracing_level(), Level::INFO);
    /// assert_eq!(Verbosity::Verbose.to_tracing_level(), Level::DEBUG);
    /// assert_eq!(Verbosity::Debug.to_tracing_level(), Level::TRACE);
    /// ```
    pub fn to_tracing_level(self) -> Level {
        match self {
            Verbosity::Quiet => Level::ERROR,
            Verbosity::Normal => Level::INFO,
            Verbosity::Verbose => Level::DEBUG,
            Verbosity::Debug => Level::TRACE,
        }
    }
}

impl Default for Verbosity {
    /// Default verbosity is Normal (show progress steps)
    fn default() -> Self {
        Verbosity::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbosity_ordering() {
        assert!(Verbosity::Quiet < Verbosity::Normal);
        assert!(Verbosity::Normal < Verbosity::Verbose);
        assert!(Verbosity::Verbose < Verbosity::Debug);
    }

    #[test]
    fn test_verbosity_to_tracing_level() {
        assert_eq!(Verbosity::Quiet.to_tracing_level(), Level::ERROR);
        assert_eq!(Verbosity::Normal.to_tracing_level(), Level::INFO);
        assert_eq!(Verbosity::Verbose.to_tracing_level(), Level::DEBUG);
        assert_eq!(Verbosity::Debug.to_tracing_level(), Level::TRACE);
    }

    #[test]
    fn test_verbosity_default() {
        assert_eq!(Verbosity::default(), Verbosity::Normal);
    }

    #[test]
    fn test_verbosity_clone() {
        let v1 = Verbosity::Verbose;
        let v2 = v1;
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_verbosity_eq() {
        assert_eq!(Verbosity::Normal, Verbosity::Normal);
        assert_ne!(Verbosity::Normal, Verbosity::Quiet);
    }
}
