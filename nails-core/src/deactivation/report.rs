//! Deactivation report structure and formatting
//!
//! Provides `DeactivationReport` for tracking deactivation operation results,
//! including cleanup details, unmounted overlays, duration, and final state.

use crate::{CleanupReport, SystemState};
use std::time::Duration;

/// Report of deactivation operations
///
/// Provides detailed accounting of what was cleaned, which overlays were unmounted,
/// timing information, and the final system state after deactivation.
///
/// # Fields
///
/// - `cleanup_report`: Results from CleanupManager (history, temp files, logs)
/// - `unmounted_overlays`: List of overlay paths that were successfully unmounted
/// - `duration`: Total time taken for the deactivation operation
/// - `final_state`: System state after deactivation (should be Inactive on success)
/// - `was_already_inactive`: Whether system was already inactive (idempotent case)
///
/// # Requirements
///
/// - AC3: DeactivationReport with cleanup, unmounted overlays, duration, final state
/// - FR62: Idempotent deactivation tracking
#[derive(Debug, Clone)]
pub struct DeactivationReport {
    /// Cleanup operation results
    pub cleanup_report: CleanupReport,

    /// Overlays that were unmounted
    pub unmounted_overlays: Vec<String>,

    /// Total duration of deactivation
    pub duration: Duration,

    /// Final system state after deactivation
    pub final_state: SystemState,

    /// Whether deactivation was a no-op (already inactive)
    pub was_already_inactive: bool,
}

impl DeactivationReport {
    /// Check if deactivation completed successfully
    ///
    /// Returns true if the final state is Inactive, indicating successful deactivation.
    pub fn is_successful(&self) -> bool {
        self.final_state == SystemState::Inactive
    }
}

impl std::fmt::Display for DeactivationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.was_already_inactive {
            writeln!(f, "✓ Already inactive - no action needed")?;
            return Ok(());
        }

        writeln!(f, "Deactivation Report")?;
        writeln!(f, "===================")?;
        writeln!(f, "Duration: {:?}", self.duration)?;
        writeln!(f, "Final State: {:?}", self.final_state)?;
        writeln!(f)?;

        // Cleanup summary
        writeln!(f, "Cleanup:")?;
        for item in &self.cleanup_report.cleaned_items {
            writeln!(f, "  ✓ {}", item)?;
        }

        // Unmounted overlays
        writeln!(f)?;
        writeln!(f, "Unmounted Overlays:")?;
        for overlay in &self.unmounted_overlays {
            writeln!(f, "  ✓ {}", overlay)?;
        }

        if self.is_successful() {
            writeln!(f)?;
            writeln!(f, "✓ Deactivation complete")?;
        }

        Ok(())
    }
}
