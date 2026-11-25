// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The write tripwire (`[session_mounts] write_tripwire`): the watcher's view
//! of the decoy disks' write counters.
//!
//! The entry's last step took the counters of the disks the plan records
//! ([`nails_teardown::whole_root::write_counters`]) after a `sync`, once every
//! decoy unit had stopped. At every poll the watcher reads them again: the
//! first write they show, outside the hidden volume's own partition or disk,
//! powers the machine off. Where the entry left no baseline, the watcher takes
//! its own when it starts, and what was written between the switch and that
//! start does not count.

use nails_teardown::whole_root::disk_guard::Sysfs;
use nails_teardown::whole_root::write_counters::{self, Baseline, Layout};
use std::path::Path;

/// Where the baseline the watcher compares with came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Since {
    /// The entry's last step, before the switch.
    Switch,
    /// The watcher's own start: the entry left none.
    WatcherStart,
}

/// The decoy disks' counters and the baseline they are held to.
#[derive(Debug)]
pub struct WriteWatch {
    layout: Layout,
    baseline: Baseline,
    since: Since,
}

impl WriteWatch {
    /// Watch `layout` against the entry's baseline in `runtime_dir`, or,
    /// without one, against the counters `sys` shows now. A counter that
    /// cannot be read now is left out of the baseline, so it shows as a
    /// write at the first check: the tripwire fails closed.
    pub fn start(layout: Layout, sys: &Sysfs, runtime_dir: &Path) -> Self {
        match Baseline::load(&runtime_dir.join(write_counters::BASELINE_NAME)) {
            Some(baseline) => Self {
                layout,
                baseline,
                since: Since::Switch,
            },
            None => {
                let baseline = Baseline::take(&layout, sys).unwrap_or_default();
                Self {
                    layout,
                    baseline,
                    since: Since::WatcherStart,
                }
            }
        }
    }

    /// Where the baseline came from.
    pub fn since(&self) -> Since {
        self.since
    }

    /// Every write the counters show since the baseline, one line each.
    pub fn writes(&self, sys: &Sysfs) -> Vec<String> {
        write_counters::check(&self.layout, &self.baseline, sys)
    }
}

/// One round of the tripwire: when `watch` shows a write and the tripwire has
/// not acted yet (`tripped`), power off through `power_off`, which says
/// whether it acted. Returns whether the tripwire has acted now. A power-off
/// that could not act is tried again at the next round.
pub fn trip(
    watch: &WriteWatch,
    sys: &Sysfs,
    tripped: bool,
    power_off: impl FnOnce(&[String]) -> bool,
) -> bool {
    if tripped {
        return true;
    }
    let writes = watch.writes(sys);
    if writes.is_empty() {
        return false;
    }
    power_off(&writes)
}

#[cfg(test)]
#[path = "writes_tests.rs"]
mod tests;
