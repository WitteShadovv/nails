// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The typed progress events a front end can watch while an operation runs.
//!
//! An activation does not finish in one breath: it stages a runtime directory,
//! mounts the root overlay, builds and activates the hidden system, and arms the
//! switch, and it runs a list of pre-flight checks before any of that. The CLI
//! renders this as a spinner; a window renders it as a live list. Both draw from
//! the same stream so neither invents its own vocabulary of steps.
//!
//! An [`Event`] is one entry in that stream. Keeping the shapes here, beside the
//! envelope and the exit codes, lets a consumer deserialize the stream without
//! linking the tool (`nails-core/tests/crate_graph.rs` holds the boundary), and
//! an adapter over the library's progress reporter
//! (`nails-base/src/reporter`) is what turns a running operation into these
//! values.

use serde::{Deserialize, Serialize};

/// One entry in the progress stream of a running operation.
///
/// Tagged by `type` so a reader can match on the shape; the field names are the
/// contract. Serializable and deserializable because the stream is both written
/// (by the operation) and read (by a window over its helper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A numbered activation step started; the previous one, if any, finished.
    Step {
        /// The stable machine identifier of the phase (e.g. `overlay`).
        phase: String,
        /// The human-readable label (e.g. `Mounting the root overlay`).
        label: String,
        /// The 1-based index of this step among the steps this activation runs.
        index: u32,
        /// How many steps this activation runs.
        total: u32,
    },
    /// Finer-grained detail within the current step (the overlay being mounted,
    /// the store database being checked).
    Detail {
        /// The phase this detail belongs to.
        phase: String,
        /// The detail text.
        text: String,
    },
    /// The current step is still running after `elapsed_seconds`, so a watcher
    /// knows the operation has not stalled. Carries no build output: a build
    /// line widens the activity fingerprint if the stream is captured.
    Heartbeat {
        /// The phase that is still running.
        phase: String,
        /// How long it has run, in whole seconds.
        elapsed_seconds: u64,
    },
    /// A pre-flight check finished, in the order the checks ran.
    Check {
        /// The check's stable name.
        name: String,
        /// Its outcome.
        outcome: CheckOutcome,
        /// The one-line result message.
        message: String,
    },
    /// Something the operator should read before confirming the operation:
    /// a risk that does not refuse it, such as hidden sessions' package
    /// database no longer following the decoy's, with what to do about it.
    /// An activation reports its advisories before it asks to log the
    /// operator out.
    Advisory {
        /// The stable name of the check that found it (`package-drift`).
        name: String,
        /// What it found.
        message: String,
        /// What to do about it, when there is one thing to do.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fix: Option<String>,
    },
    /// An activation is past its point of no return: the entry is recorded,
    /// nothing cancels it any more, and the soft-reboot follows. A window that
    /// closes its pipe from here on no longer stops the switch.
    PointOfNoReturn,
    /// The operation ended. An activation ends once its soft-reboot is
    /// enqueued (`success`), or when it failed or was rolled back before that,
    /// a soft-reboot that could not be enqueued included.
    Finished {
        /// Whether it succeeded.
        success: bool,
    },
}

/// The outcome of one pre-flight check, as a [`Check`](Event::Check) event
/// carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    /// The check passed.
    Pass,
    /// The check warned: a risk worth naming, not a refusal.
    Warn,
    /// The check failed: activation refuses until it is resolved.
    Fail,
    /// The check did not run (a prerequisite, such as the hidden volume, was
    /// absent), so it neither passed nor failed.
    Skipped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_step_round_trips_through_json() {
        let event = Event::Step {
            phase: "overlay".to_string(),
            label: "Mounting the root overlay".to_string(),
            index: 2,
            total: 6,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"step\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn a_check_event_names_its_outcome() {
        let event = Event::Check {
            name: "swap".to_string(),
            outcome: CheckOutcome::Fail,
            message: "swap is on".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"check\""));
        assert!(json.contains("\"outcome\":\"fail\""));
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
    }

    #[test]
    fn an_advisory_carries_its_fix_only_when_it_has_one() {
        let event = Event::Advisory {
            name: "package-drift".to_string(),
            message: "hidden sessions' record is out of date".to_string(),
            fix: Some("update it in a hidden session".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"advisory\""), "{json}");
        assert!(json.contains("\"fix\":"), "{json}");
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);

        let without = Event::Advisory {
            name: "package-drift".to_string(),
            message: "could not tell".to_string(),
            fix: None,
        };
        let json = serde_json::to_string(&without).unwrap();
        assert!(!json.contains("fix"), "{json}");
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), without);
    }

    #[test]
    fn the_terminal_event_carries_the_verdict() {
        let json = serde_json::to_string(&Event::Finished { success: false }).unwrap();
        assert!(json.contains("\"type\":\"finished\""));
        assert!(json.contains("\"success\":false"));
    }

    #[test]
    fn the_point_of_no_return_is_a_bare_tag() {
        let json = serde_json::to_string(&Event::PointOfNoReturn).unwrap();
        assert_eq!(json, r#"{"type":"point_of_no_return"}"#);
        assert_eq!(
            serde_json::from_str::<Event>(&json).unwrap(),
            Event::PointOfNoReturn
        );
    }

    #[test]
    fn every_check_outcome_has_a_snake_case_tag() {
        for (outcome, tag) in [
            (CheckOutcome::Pass, "\"pass\""),
            (CheckOutcome::Warn, "\"warn\""),
            (CheckOutcome::Fail, "\"fail\""),
            (CheckOutcome::Skipped, "\"skipped\""),
        ] {
            assert_eq!(serde_json::to_string(&outcome).unwrap(), tag);
        }
    }
}
