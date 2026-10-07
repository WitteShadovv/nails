// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # nails-teardown
//!
//! The whole-root session's mechanics that must run without the rest of the
//! tool (ADR 0008): the session plan in RAM, the next root, the transition step
//! systemd runs on each soft-reboot, the return scrub of `/run`, and the
//! emergency path that leaves the hidden root (see [`whole_root`]).
//!
//! The crate depends on `rustix`, `libc` and `serde` only. It has no
//! configuration, no state file, no logging and no process runner, so the CLI
//! can run the emergency path and the transition before it initialises any of
//! those, and a review of the panic path is a review of this crate.

pub mod cgroup;
pub mod mountinfo;
pub mod proc;
pub mod shells;
pub mod whole_root;
