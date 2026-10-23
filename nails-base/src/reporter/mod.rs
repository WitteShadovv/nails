// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Operator-facing reporting: actionable diagnostics and activation progress.
//!
//! [`progress`] carries the [`Reporter`](progress::Reporter) abstraction that
//! activation phases report through, separating what the operator watches
//! (steps, details, heartbeats) from the log. [`events`] adapts that reporter
//! into the typed event stream a window watches. The rest of this module renders
//! actionable diagnostics.
//!
//! This is the single place that turns a set of failures into the "what to do
//! next" output, so the human summary, the JSON envelope and any future surface
//! all draw the remediation text from one source instead of each inventing its
//! own hint strings.
//!
//! Two shapes are handled:
//!
//! - A list of failed pre-flight checks ([`PreFlightFailures`]): every check
//!   states its own problem, and the checks that named a concrete fix contribute
//!   to one ordered, deduplicated remediation list. A missing hidden volume that
//!   cascades into several dependent failures therefore yields a single "mount
//!   the hidden storage" step, not one per check.
//! - A single terminal [`NailsError`]: rendered as a [`Diagnostic`] pairing the
//!   error's message with its one [`NailsError::hint`], if it has one.

pub mod events;
pub mod progress;

pub use events::{CollectingSink, EventReporter, EventSink};

use crate::error::{NailsError, PreFlightFailures};

/// The neutral action shown when a failure named no specific remediation.
pub const GENERIC_REMEDIATION: &str = "Resolve the checks listed above and retry activation";

/// The ordered, deduplicated list of concrete remediation steps drawn from
/// `failures`.
///
/// Steps appear in check-execution order and each distinct action appears once,
/// so dependent failures that share a root cause collapse to a single step.
/// Checks that named no remediation contribute nothing here; the caller falls
/// back to [`GENERIC_REMEDIATION`] when the list comes back empty.
pub fn remediation_steps(failures: &PreFlightFailures) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    for (_name, _message, remediation) in failures {
        if let Some(fix) = remediation
            && !steps.iter().any(|existing| existing == fix)
        {
            steps.push(fix.clone());
        }
    }
    steps
}

/// A compact, renderable view of a single terminal error: its message plus the
/// one next step, when the error has advice to offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// The error text, as the error renders itself.
    pub message: String,
    /// The single concrete next step, if the error has one.
    pub hint: Option<String>,
}

impl Diagnostic {
    /// Build a diagnostic from a [`NailsError`], taking its message and
    /// [`hint`](NailsError::hint).
    pub fn from_error(err: &NailsError) -> Self {
        Self {
            message: err.to_string(),
            hint: err.hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remediation_steps_dedup_in_order() {
        let failures: PreFlightFailures = vec![
            (
                "hidden-root".to_string(),
                "not mounted".to_string(),
                Some("mount the hidden storage".to_string()),
            ),
            (
                "storage".to_string(),
                "unreadable".to_string(),
                Some("mount the hidden storage".to_string()),
            ),
            (
                "swap".to_string(),
                "enabled".to_string(),
                Some("sudo swapoff -a".to_string()),
            ),
            ("space".to_string(), "low".to_string(), None),
        ];

        let steps = remediation_steps(&failures);

        assert_eq!(
            steps,
            vec![
                "mount the hidden storage".to_string(),
                "sudo swapoff -a".to_string(),
            ]
        );
    }

    #[test]
    fn remediation_steps_empty_when_no_remediation() {
        let failures: PreFlightFailures = vec![("x".to_string(), "y".to_string(), None)];
        assert!(remediation_steps(&failures).is_empty());
    }

    #[test]
    fn diagnostic_carries_hint_when_present() {
        let diag = Diagnostic::from_error(&NailsError::SwapDisableFailed);
        assert!(diag.hint.is_some());

        let diag = Diagnostic::from_error(&NailsError::OverlayError("boom".to_string()));
        assert_eq!(diag.hint, None);
    }
}
