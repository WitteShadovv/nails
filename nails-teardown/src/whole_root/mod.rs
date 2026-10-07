// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root session: one overlay over the decoy root, entered and left
//! with `systemctl soft-reboot` through `/run/nextroot` (ADR 0008).
//!
//! - [`plan`]: the session plan on the decoy's `/run`, carried across every
//!   soft-reboot;
//! - [`nextroot`]: the mount primitives and the pre-switch init check;
//! - [`transition`]: the last userspace step before each switch (the arm
//!   check, the `current-system` repoint, the `/run` scrub, the kmsg cursor);
//! - [`run_scrub`]: the `/run` snapshot and scrub;
//! - [`ret`]: preparing the way back to the decoy;
//! - [`runtime_units`]: runtime units and masks in `/run`;
//! - [`kill`]: killing all of userspace but PID 1 and the invocation;
//! - [`emergency`]: the emergency hot path;
//! - [`tools`]: the bounded `systemctl` and `dmsetup` calls.

pub mod emergency;
pub mod kill;
pub mod nextroot;
pub mod plan;
pub mod ret;
pub mod run_scrub;
pub mod runtime_units;
pub mod tools;
pub mod transition;
