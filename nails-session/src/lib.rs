// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS session library
//!
//! The parts of the whole-root soft-reboot session that need the
//! configuration: the entry, the fstab policy, the hidden NixOS build, the way
//! back, the session's pre-flight checks and the probes `status` uses
//! (`session`), the operator's persona in the hidden root (`persona`), and
//! the session's runtime units: the RAM copy reader (`runtime_copy`), the
//! backend watcher (`watcher`) and the sleep guard (`sleep_guard`).
//!
//! The mechanics that must run without any of this (the plan, the
//! transition, the emergency hot path) are in `nails-teardown`. This crate
//! builds on `nails-base`, `nails-platform` and `nails-teardown`; the
//! dependency direction is pinned by `nails-core/tests/crate_graph.rs`.

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

// This crate's unit tests never reach the host, like the base crate's own.
nails_base::unit_test_mode!();

// The foundation and platform modules the code below reaches through
// `crate::` paths.
#[cfg(test)]
use nails_base::kernel_fixtures;
use nails_base::{Filesystem, NailsError, Result};
use nails_base::{
    artifacts, cancel, config, error, filesystem, preflight, process, reporter, target_user,
};
use nails_platform::{nixos, platform};

// The whole-root session: entry, way back, fstab policy, probes.
pub mod session;

// Persona inventory: the decoy autostart/user-unit/linger/autologin state the
// hidden session would inherit from the decoy account.
pub mod persona;

// Readers of the RAM-backed runtime directory an entry writes under `/run`.
pub mod runtime_copy;

// The sleep guard: the session's suspend and hibernate policy.
pub mod sleep_guard;

// The in-session watcher over the hidden backend.
pub mod watcher;

pub use persona::{
    EntryStatus, InheritedSource, PersonaEntry, PersonaInventory, collect_inherited_persona,
};

#[cfg(test)]
mod tests {
    #[test]
    fn unit_tests_never_reach_the_host() {
        // `unit_test_mode!` marks this binary before the first test, so the
        // base crate's host switches answer as they do in its own unit tests.
        assert!(nails_base::runtime_safety::in_unit_tests());
        assert!(nails_base::runtime_safety::should_skip_host_interaction());
    }
}
