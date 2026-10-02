//! Swap pre-flight check
//!
//! Validates that swap is disabled for memory security before activation.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};

/// Pre-flight check to validate swap is disabled
///
/// # Security
///
/// Swap must be disabled before activation because sensitive data
/// (including encryption keys) could be written to persistent storage,
/// defeating the plausible deniability guarantee.
///
/// # Rationale
///
/// - **Memory forensics**: Sensitive data in RAM could be written to swap partition
/// - **Persistence**: Swap contents persist after shutdown (unlike RAM)
/// - **Decryption keys**: Encryption keys in memory could leak to swap
/// - **Plausible deniability**: Swap could contain evidence of hidden environment usage
///
/// # Failure Guidance
///
/// When swap is enabled, the check provides actionable guidance:
/// - Clear explanation of the problem ("Swap is enabled")
/// - Exact command to fix it (`sudo swapoff -a`)
///
/// Error messages include fix guidance.
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{SwapCheck, PreFlightCheck};
/// use nails_core::filesystem::MockFilesystem;
///
/// let fs = MockFilesystem::new();
/// let check = SwapCheck::new();
///
/// // Simulate swap disabled
/// fs.mock_set_swap_enabled(false);
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Default)]
pub struct SwapCheck;

impl SwapCheck {
    /// Create a new SwapCheck
    pub fn new() -> Self {
        Self
    }
}

impl<F: Filesystem> PreFlightCheck<F> for SwapCheck {
    fn name(&self) -> &'static str {
        "swap"
    }

    fn description(&self) -> &'static str {
        "Validates swap is disabled for memory security"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        if fs.swap_is_enabled()? {
            Ok(CheckResult::Fail(
                "Swap is enabled. Disable swap: sudo swapoff -a".into(),
            ))
        } else {
            Ok(CheckResult::Pass(
                "Swap is disabled - memory is secure".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn test_swap_check_default_trait() {
        // SwapCheck implements Default
        let _check = SwapCheck;
    }

    #[test]
    fn test_swap_check_trait_metadata() {
        // Verifies SwapCheck implements PreFlightCheck trait
        // Verifies name() returns "swap" and description() is correct
        let check = SwapCheck::new();

        assert_eq!(
            <SwapCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "swap"
        );
        assert_eq!(
            <SwapCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates swap is disabled for memory security"
        );
    }

    #[test]
    fn test_swap_check_pass_when_swap_disabled() {
        // Given swap is disabled, When SwapCheck runs, Then returns Pass
        // Given MockFilesystem simulates swap disabled, Then test verifies Pass
        let fs = MockFilesystem::new();
        fs.mock_set_swap_enabled(false);

        let check = SwapCheck::new();
        let result = check.run(&fs).unwrap();

        assert!(result.is_pass());
        assert_eq!(result.message(), "Swap is disabled - memory is secure");
    }

    #[test]
    fn test_swap_check_fail_when_swap_enabled() {
        // Given swap is enabled, When SwapCheck runs, Then returns Fail with fix guidance
        // Given MockFilesystem simulates swap enabled, Then test verifies Fail with command
        let fs = MockFilesystem::new();
        fs.mock_set_swap_enabled(true);

        let check = SwapCheck::new();
        let result = check.run(&fs).unwrap();

        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "Swap is enabled. Disable swap: sudo swapoff -a"
        );
    }
}
