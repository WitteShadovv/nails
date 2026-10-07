// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # nails-teardown
//!
//! The emergency hot path and the teardown plan every teardown shares
//! (ADR 0007).
//!
//! Activation records each step it completes, with that step's fixed undo, in a
//! [`plan::Plan`] on the decoy's `/run` tmpfs. Rollback, deactivation and
//! emergency all undo that one plan through [`undo::run_plan`], reconciled
//! against the live mount table; when the plan is missing or unusable,
//! [`derive::derive_plan`] rebuilds it from the mount table. The emergency path
//! ([`emergency::run`]) adds the kills before the unmount: stop jobs,
//! `cgroup.kill` of the hidden units, pidfd kills, the interactive-shell kill.
//!
//! The crate depends on `rustix`, `libc` and `serde` only. It has no
//! configuration, no state file, no logging and no process runner, so the CLI
//! can run the whole hot path before it initialises any of those, and a review
//! of the panic path is a review of this crate.

pub mod cgroup;
pub mod derive;
pub mod emergency;
pub mod initns;
pub mod mountinfo;
pub mod mounts;
pub mod plan;
pub mod proc;
pub mod refs;
pub mod session;
pub mod shells;
pub mod undo;
pub mod units;

pub use emergency::{Host, HotReport, PlanSource};
pub use mounts::{KernelMountOps, MountOps, Presence};
pub use plan::{MountKind, Phase, Plan, PlanError, Undo};
pub use undo::{Action, Outcome, UndoReport};
