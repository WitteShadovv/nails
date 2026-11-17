// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The window of an entry (see [`super`]): from the first reload of the
//! service manager to the second, at the end of the entry, the decoy's
//! mounts that keep access times are `noatime` ([`QuietMounts`]), so that
//! nothing PID 1 reads for the entry gets a new access time.

use super::EntryHost;
use crate::error::{NailsError, Result};
use nails_teardown::noatime::QuietMounts;

/// Make the decoy's mounts that keep access times `noatime` for the rest of
/// the entry ([`QuietMounts`]); where they cannot be made so, the entry is
/// refused before anything is reloaded.
///
/// PID 1 reads the decoy's unit files and runs its generators for a reload,
/// and reads the files of a unit it has not loaded for a question about it.
/// Every mount the entry makes appears to PID 1 as a mount unit, and one of a
/// block device loads that device's `blockdev@.target` instance, whose
/// template PID 1 reads. A drop-in the entry writes changes a unit directory,
/// and PID 1 then lists every unit directory again at its next load of a
/// unit. All of that happens while the mounts are `noatime`, up to the
/// reload at the end of the entry ([`settle`]).
pub(super) fn quiet_mounts() -> Result<QuietMounts> {
    QuietMounts::open().map_err(|e| {
        NailsError::InvalidState(format!(
            "NAILS cannot keep the service manager's reload from setting access times on the \
             decoy disk: making its mounts noatime for it failed ({e})"
        ))
    })
}

/// Reload the service manager once more, as the last step of the entry while
/// the mounts are `noatime`: the reload reads the mount table and the unit
/// directories again, so PID 1 has made the unit of every mount the entry
/// made and listed its unit directories by the time it returns, and nothing
/// of it is left for a later load of a unit, after the mounts have their own
/// mode back.
pub(super) fn settle(host: &dyn EntryHost) -> Result<()> {
    host.daemon_reload()
}
