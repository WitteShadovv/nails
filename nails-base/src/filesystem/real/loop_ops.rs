// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The loop driver's record of what a loop device is bound to, read by the
//! teardown crate's reader ([`nails_teardown::loop_device::record`]).

use crate::filesystem::LoopRecord;
use crate::{IoResultExt, Result};
use std::path::Path;

/// The loop driver's record of the backing file of the loop device at
/// `node`. The node is opened read-only and never written.
pub(super) fn loop_record(node: &Path) -> Result<LoopRecord> {
    let record = nails_teardown::loop_device::record(node).at_path(node)?;
    Ok(LoopRecord {
        device: record.device,
        rdevice: record.rdevice,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_that_is_no_loop_device_has_no_backing_device() {
        // /dev/null opens, but the loop driver does not answer for it.
        assert!(loop_record(Path::new("/dev/null")).is_err());
        assert!(loop_record(Path::new("/dev/nails-no-such-loop")).is_err());
    }
}
