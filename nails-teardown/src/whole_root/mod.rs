// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The whole-root session: one overlay over the decoy root, entered with
//! `systemctl soft-reboot` through `/run/nextroot`. A session never goes back
//! to the decoy's kernel: it ends in a power-off ([`session_end`]).
//!
//! The modules that served the way back (a second soft-reboot into the
//! decoy, which is gone) stay until a removal of their own, and nothing
//! reaches them any more: [`run_scrub`]'s scrub, [`run_records`]'s restore,
//! [`network`]'s restore, [`boot_records`], [`boot_writer`], [`fresh_pids`],
//! [`zram`], [`ret`]'s return, [`decoy_mounts`]'s making again, and
//! [`tail`]'s drain.
//!
//! - [`plan`]: the session plan on the decoy's `/run`, carried across every
//!   soft-reboot;
//! - [`nextroot`]: the mount primitives and the pre-switch init check;
//! - [`transition`]: the last userspace step before the switch into the
//!   hidden root (the arm check, the `current-system` repoint, the masks), and
//!   the power-off where it cannot do its work;
//! - [`session_end`]: how every hidden session ends, in one place;
//! - [`run_scrub`]: the `/run` snapshot and scrub;
//! - [`run_records`]: the decoy's records in `/run` that its start writes to
//!   disk, put back on the way back;
//! - [`network`]: the decoy's network state (links, addresses and hostname),
//!   recorded at entry and put back on the way back, with
//!   [`network_policy`] (policy-routing rules, firewall tables and network
//!   settings) and [`network_run`] (the service manager's per-link runtime
//!   state), asked of the kernel through [`net_kernel`];
//! - [`boot_records`]: making the decoy's login and boot records read as one
//!   clean power cycle after the way back;
//! - [`boot_writer`]: starting the decoy's wtmpdb boot writer so it records
//!   the way back as a power cycle would;
//! - [`fresh_pids`]: process numbers after the way back that read like a
//!   fresh boot;
//! - [`utab`]: libmount's `utab` lines that still name a mount after a switch;
//! - [`zram`]: the decoy's zram swap set up after the way back as a cold boot
//!   sets it up;
//! - [`ret`]: preparing the way back to the decoy;
//! - [`carry`]: the decoy filesystems the hidden session holds for the way
//!   back;
//! - [`decoy_mounts`]: the decoy's mounts the way back makes again, in the
//!   decoy's order with their options;
//! - [`runtime_units`]: runtime units and masks in `/run`;
//! - [`skips`]: runtime drop-ins that make the hidden systemd skip a unit a
//!   boot target requires, where a mask would keep the target from being
//!   reached;
//! - [`switch_refusal`]: why the last switch was refused, kept on the hidden
//!   volume (a refused entry) or in the runtime directory (a refused way
//!   back) so `status` can say so;
//! - [`tail`]: the hidden session's processes that PID 1 would kill at the
//!   switch but udevd's, journald's sockets and the hidden filesystem's
//!   unmount line, ended, emptied and quieted before the kmsg cursor, and
//!   the empty `/run/nextroot` the switch leaves;
//! - [`fence`]: the decoy disk read-only in the kernel for the whole session,
//!   with [`fence_bpf`] (the device program) and [`fence_kernel`] (the
//!   running kernel's side);
//! - [`disk_guard`]: unused disks read-only for the session (opt-in), with
//!   [`guard_policy`] (what the loaded SELinux policy lets the guard do);
//! - [`kill`]: killing all of userspace but PID 1 and the invocation;
//! - [`logind`]: the soft-reboot request of the entry and the way back, and
//!   what logind holds of it;
//! - [`emergency`]: the emergency hot path;
//! - [`program_label`]: the SELinux label of the RAM copies of the binary,
//!   which decides the domain PID 1 starts NAILS's own steps in, with
//!   [`selinux`] (what the running kernel's SELinux answers);
//! - [`tools`]: the bounded `systemctl` and `dmsetup` calls;
//! - [`unit_bus`]: a service's commands as PID 1 has them loaded, read over
//!   D-Bus.

pub mod boot_records;
pub mod boot_writer;
pub mod carry;
pub mod decoy_mounts;
pub mod disk_guard;
pub mod emergency;
pub mod fence;
pub mod fence_bpf;
pub mod fence_kernel;
pub mod fence_stack;
pub mod fresh_pids;
pub mod guard_policy;
pub mod kernel_helpers;
pub mod kill;
pub mod logind;
pub mod net_kernel;
pub mod network;
pub mod network_policy;
pub mod network_run;
pub mod nextroot;
pub mod plan;
pub mod program_label;
pub mod ret;
pub mod run_records;
pub mod run_scrub;
pub mod runtime_units;
pub mod selinux;
pub mod session_end;
pub mod skips;
pub mod switch_refusal;
pub mod tail;
pub mod tools;
pub mod transition;
pub mod unit_bus;
pub mod utab;
pub mod zram;
