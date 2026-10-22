// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Turning activation progress into the typed [`Event`] stream a front end
//! watches.
//!
//! The library reports progress through the [`Reporter`] trait
//! ([`super::progress`]): a running operation calls `step`, `detail`,
//! `heartbeat`, `check` and `finish`, and whatever reporter the caller
//! installed decides how they are presented. [`EventReporter`] is the reporter
//! a caller installs when it wants those calls as typed [`Event`] values rather
//! than terminal output: it maps each call to the matching event and hands it to
//! an [`EventSink`]. A window over its root helper installs one whose sink
//! serialises each event onto the pipe; a test installs one whose sink is a
//! [`CollectingSink`] it reads back afterwards.
//!
//! Keeping the adapter here, over the existing reporter, means the CLI's
//! progress lines and the window's event stream are the same steps from the same
//! emit points, so the two can never drift.

use super::progress::{Reporter, Step};
use nails_api::{CheckOutcome, Event};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A destination for typed progress [`Event`]s.
pub trait EventSink: Send {
    /// Receive one event. Called in order, on the thread the operation runs on.
    fn emit(&mut self, event: Event);
}

/// A sink that collects every event into a shared buffer a caller can read back
/// once the operation has finished. Cloning shares the buffer, so a caller
/// keeps one clone while the other is moved into the [`EventReporter`].
#[derive(Clone, Default)]
pub struct CollectingSink {
    events: Arc<Mutex<Vec<Event>>>,
}

impl CollectingSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every event received so far, in order.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl EventSink for CollectingSink {
    fn emit(&mut self, event: Event) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event);
    }
}

/// The reporter that converts progress calls into typed [`Event`]s for a sink.
///
/// Install it with [`super::progress::install`] for the duration of an
/// operation; the free progress functions the operation calls then reach it.
pub struct EventReporter<S: EventSink> {
    sink: S,
    /// The current step's phase, carried so a `detail` or `heartbeat` (which
    /// name no phase of their own) can be attributed to it.
    phase: String,
}

impl<S: EventSink> EventReporter<S> {
    /// An adapter feeding `sink`.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            phase: String::new(),
        }
    }
}

impl<S: EventSink> Reporter for EventReporter<S> {
    fn step(&mut self, step: Step<'_>) {
        self.phase = step.phase.to_string();
        self.sink.emit(Event::Step {
            phase: step.phase.to_string(),
            label: step.label.to_string(),
            index: step.index,
            total: step.total,
        });
    }

    fn detail(&mut self, detail: &str) {
        self.sink.emit(Event::Detail {
            phase: self.phase.clone(),
            text: detail.trim().to_string(),
        });
    }

    fn heartbeat(&mut self, _activity: &str, elapsed: Duration, _last_line: Option<&str>) {
        self.sink.emit(Event::Heartbeat {
            phase: self.phase.clone(),
            elapsed_seconds: elapsed.as_secs(),
        });
    }

    fn check(&mut self, name: &str, outcome: CheckOutcome, message: &str) {
        self.sink.emit(Event::Check {
            name: name.to_string(),
            outcome,
            message: message.trim().to_string(),
        });
    }

    fn finish(&mut self, success: bool) {
        self.sink.emit(Event::Finished { success });
    }
}

#[cfg(test)]
mod tests {
    use super::super::progress::{self, ActivationPhase};
    use super::*;

    /// Install an `EventReporter` over a collecting sink, run `body` with the
    /// reporter active, and return the events it produced in order.
    fn capture(body: impl FnOnce()) -> Vec<Event> {
        let sink = CollectingSink::new();
        {
            let reporter = EventReporter::new(sink.clone());
            let _scope = progress::install(progress::shared(reporter));
            body();
        }
        sink.events()
    }

    #[test]
    fn a_decoy_only_activation_emits_its_steps_and_a_finish() {
        let events = capture(|| {
            // The emit points of a decoy-only entry (no hidden build), in order.
            for phase in [
                ActivationPhase::Runtime,
                ActivationPhase::Overlay,
                ActivationPhase::MountPolicy,
                ActivationPhase::MaskUnits,
                ActivationPhase::WayBack,
                ActivationPhase::Arm,
            ] {
                progress::activation_step(phase, false);
            }
            progress::finish(true);
        });

        let steps: Vec<(String, u32, u32)> = events
            .iter()
            .filter_map(|event| match event {
                Event::Step {
                    phase,
                    index,
                    total,
                    ..
                } => Some((phase.clone(), *index, *total)),
                _ => None,
            })
            .collect();
        assert_eq!(
            steps,
            vec![
                ("runtime".to_string(), 1, 6),
                ("overlay".to_string(), 2, 6),
                ("mount_policy".to_string(), 3, 6),
                ("mask_units".to_string(), 4, 6),
                ("way_back".to_string(), 5, 6),
                ("arm".to_string(), 6, 6),
            ]
        );
        assert_eq!(events.last(), Some(&Event::Finished { success: true }));
    }

    #[test]
    fn a_build_activation_numbers_the_build_steps_in() {
        let events = capture(|| {
            progress::activation_step(ActivationPhase::BuildSystem, true);
        });
        assert_eq!(
            events,
            vec![Event::Step {
                phase: "build_system".to_string(),
                label: "Building the hidden system".to_string(),
                index: 4,
                total: 9,
            }]
        );
    }

    #[test]
    fn details_and_heartbeats_carry_the_current_phase() {
        let events = capture(|| {
            progress::activation_step(ActivationPhase::BuildSystem, true);
            progress::detail("build_system", "checking the hidden store database");
            progress::heartbeat("building", Duration::from_secs(12), Some("compiling"));
        });
        assert_eq!(
            &events[1..],
            &[
                Event::Detail {
                    phase: "build_system".to_string(),
                    text: "checking the hidden store database".to_string(),
                },
                Event::Heartbeat {
                    phase: "build_system".to_string(),
                    elapsed_seconds: 12,
                },
            ]
        );
    }

    #[test]
    fn a_refused_activation_emits_the_failing_check_then_a_failed_finish() {
        let events = capture(|| {
            progress::activation_step(ActivationPhase::Runtime, false);
            progress::check("hidden-volume", CheckOutcome::Pass, "mounted");
            progress::check("swap", CheckOutcome::Fail, "swap is on");
            progress::finish(false);
        });
        assert_eq!(
            events,
            vec![
                Event::Step {
                    phase: "runtime".to_string(),
                    label: "Staging the runtime".to_string(),
                    index: 1,
                    total: 6,
                },
                Event::Check {
                    name: "hidden-volume".to_string(),
                    outcome: CheckOutcome::Pass,
                    message: "mounted".to_string(),
                },
                Event::Check {
                    name: "swap".to_string(),
                    outcome: CheckOutcome::Fail,
                    message: "swap is on".to_string(),
                },
                Event::Finished { success: false },
            ]
        );
    }
}
