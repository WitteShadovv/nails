// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root session: one overlay over the decoy root, entered and left
//! with `systemctl soft-reboot` through `/run/nextroot`.
//!
//! - [`plan`]: the session plan on the decoy's `/run`, carried across every
//!   soft-reboot;
//! - [`nextroot`]: the mount primitives and the pre-switch init check;
//! - [`transition`]: the last userspace step before each switch (the arm
//!   check, the `current-system` repoint, the `/run` scrub, the kmsg cursor);
//! - [`run_scrub`]: the `/run` snapshot and scrub;
//! - [`run_records`]: the decoy's records in `/run` that its start writes to
//!   disk, put back on the way back;
//! - [`network`]: the decoy's network state (links, addresses and hostname),
//!   recorded at entry and put back on the way back, with
//!   [`network_policy`] (policy-routing rules, firewall tables and network
//!   settings) and [`network_run`] (the service manager's per-link runtime
//!   state);
//! - [`boot_records`]: making the decoy's login and boot records read as one
//!   clean power cycle after the way back;
//! - [`boot_writer`]: starting the decoy's wtmpdb boot writer so it records
//!   the way back as a power cycle would;
//! - [`fresh_pids`]: process numbers after the way back that read like a
//!   fresh boot;
//! - [`utab`]: libmount's `utab` lines that still name a mount after a switch;
//! - [`ret`]: preparing the way back to the decoy;
//! - [`carry`]: the decoy filesystems the hidden session holds for the way
//!   back;
//! - [`decoy_mounts`]: the decoy's mounts the way back makes again, in the
//!   decoy's order with their options;
//! - [`runtime_units`]: runtime units and masks in `/run`;
//! - [`switch_refusal`]: why the last switch was refused, kept on the hidden
//!   volume (a refused entry) or in the runtime directory (a refused way
//!   back) so `status` can say so;
//! - [`disk_guard`]: unused disks read-only for the session (opt-in);
//! - [`kill`]: killing all of userspace but PID 1 and the invocation;
//! - [`emergency`]: the emergency hot path;
//! - [`tools`]: the bounded `systemctl`, `dmsetup` and `ip` calls.

pub mod boot_records;
pub mod boot_writer;
pub mod carry;
pub mod decoy_mounts;
pub mod disk_guard;
pub mod emergency;
pub mod fresh_pids;
pub mod kernel_helpers;
pub mod kill;
pub mod network;
pub mod network_policy;
pub mod network_run;
pub mod nextroot;
pub mod plan;
pub mod ret;
pub mod run_records;
pub mod run_scrub;
pub mod runtime_units;
pub mod switch_refusal;
pub mod tools;
pub mod transition;
pub mod utab;
