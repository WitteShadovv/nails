// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root session: the only session mode of NAILS.
//!
//! `activate` builds one overlay over the decoy root at `/run/nextroot`, with
//! the upper on the hidden volume, and soft-reboots into it: every process of
//! the hidden session starts inside the overlay, so its writes through the
//! decoy's mounts land in the upper (a disk the session mounts itself is a
//! residual channel of the threat model). `deactivate` soft-reboots back into
//! the plain decoy root; `emergency` kills all of userspace first. The
//! mechanics shared with the panic path live in `nails_teardown::whole_root`;
//! this module adds what needs the configuration and the host: the fstab
//! policy and the hidden root's other masks, the hidden NixOS toplevel, the
//! pre-flight checks and the probes.

pub mod checks;
pub mod entry;
pub mod fstab;
pub mod hidden_masks;
pub mod kernel_modules;
pub mod labels;
pub mod layout;
pub mod leave;
pub mod network_state;
pub mod nixos;
pub mod package_drift;
pub mod persona;
pub mod policy;
pub mod probe;
pub mod store;
pub mod systemd;
pub mod units;
pub mod way_back;
pub mod window_launcher;

pub use entry::{Entry, EntryHost, EntryInputs, RealEntryHost, decoy_root_of};
pub use layout::{Layout, Paths};
pub use leave::{LeaveReport, LeaveTo, RealTargetHost, TargetHost, leave};
pub use probe::{SessionView, probe};
pub use window_launcher::WindowLauncher;
