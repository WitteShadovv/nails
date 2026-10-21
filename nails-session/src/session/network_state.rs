// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Recording the decoy's network identity at entry.
//!
//! Taken in the decoy before the first switch, the record holds the decoy's
//! links, hostname and the service manager's per-link runtime state, so the way
//! back can put them back once the hidden session has ended (see
//! [`nails_teardown::whole_root::network`]). It is written privately to the
//! runtime directory, carried across the soft-reboots like the rest of the
//! session state, and read on the way back.
//!
//! Recording is best effort: a session whose record cannot be written leaves
//! none, and the way back then does nothing about the network, exactly as a
//! session from before this existed.

use nails_teardown::whole_root::network::NetworkRecord;
use nails_teardown::whole_root::plan::write_private_atomic;
use std::path::Path;

/// Record the decoy's network identity to `out`, best effort.
///
/// `sys_class_net` is where the kernel lists the links, `proc_hostname` the
/// live hostname, `etc_hostname` the file whose presence decides whether the
/// decoy resets its own hostname, and `run` the `/run` root the runtime state
/// sits under. A failure to write removes any partial file and is otherwise
/// silent.
pub fn record(
    sys_class_net: &Path,
    proc_hostname: &Path,
    etc_hostname: &Path,
    run: &Path,
    out: &Path,
) {
    let record = NetworkRecord::capture(sys_class_net, proc_hostname, etc_hostname, run);
    if write_private_atomic(out, &record.encode()).is_err() {
        let _ = std::fs::remove_file(out);
    }
}

#[cfg(test)]
#[path = "network_state_tests.rs"]
mod tests;
