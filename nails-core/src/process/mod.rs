// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Running external programs, and process hardening.

pub(crate) mod cgroup_unit;
pub mod hardening;
pub mod run;

pub use run::{ProcessCommand, ProcessRunner, Program, RealProcessRunner, SYSTEM_TOOL_DIRS};

/// The start time of `pid` in clock ticks since boot, as `/proc/<pid>/stat`
/// reports it.
pub(crate) fn proc_start_time(pid: u32) -> Option<u64> {
    nails_teardown::proc::stat(pid).map(|s| s.start_time)
}
