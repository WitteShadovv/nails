// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Recording the decoy's network state at entry.
//!
//! Taken in the decoy before the first switch, the record holds the decoy's
//! links, hostname, routing policy, firewall tables, network settings and the
//! service manager's per-link runtime state, so the way back can put them back
//! once the hidden session has ended (see
//! [`nails_teardown::whole_root::network`]). It is written privately to the
//! runtime directory, carried across the soft-reboots like the rest of the
//! session state, and read on the way back.
//!
//! Recording is best effort. A part that cannot be read is recorded as
//! unknown, and the way back leaves that part as the session leaves it. A
//! session whose record cannot be written leaves none, and the way back then
//! does nothing about the network, exactly as a session from before this
//! existed.

use nails_teardown::whole_root::network::{NetTools, NetworkRecord, Places};
use nails_teardown::whole_root::plan::write_private_atomic;
use std::path::Path;

/// Record the decoy's network state at `places` to `out`, best effort, with
/// the tools installed. A failure to write removes any partial file and is
/// otherwise silent.
pub fn record(places: &Places, out: &Path) {
    record_with(places, &NetTools::find(), out);
}

/// [`record`] with `tools`.
fn record_with(places: &Places, tools: &NetTools, out: &Path) {
    let record = NetworkRecord::capture(places, tools);
    write_record(out, &record.encode(), write_private_atomic);
}

/// Write `bytes` to `out` with `write`; on failure remove any file at `out`,
/// so a stale record from a PRIOR successful write is never left behind for
/// the way back to read and apply as a (now wrong) network state. The writer
/// is a parameter so a test can inject a failure with a stale file in place;
/// production always passes [`write_private_atomic`].
fn write_record(out: &Path, bytes: &[u8], write: impl Fn(&Path, &[u8]) -> std::io::Result<()>) {
    if write(out, bytes).is_err() {
        let _ = std::fs::remove_file(out);
    }
}

#[cfg(test)]
#[path = "network_state_tests.rs"]
mod tests;
