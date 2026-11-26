// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The window of an entry (see [`super`]): from the first reload of the
//! service manager to the second, at the end of the entry, the decoy's
//! local disk mounts that keep access times are `noatime` ([`QuietMounts`]),
//! so that nothing PID 1 reads on them for the entry gets a new access time.

use super::EntryHost;
use crate::error::{NailsError, Result};
use crate::session::layout::Paths;
use nails_teardown::noatime::QuietMounts;
use nails_teardown::whole_root::plan::Plan;

/// Make the decoy's local disk mounts that keep access times `noatime` for
/// the rest of the entry ([`QuietMounts`]); where one cannot be made so, the
/// entry is refused before anything is reloaded.
///
/// PID 1 reads the decoy's unit files and runs its generators for a reload,
/// and reads the files of a unit it has not loaded for a question about it.
/// Every mount the entry makes appears to PID 1 as a mount unit, and one of a
/// block device loads that device's `blockdev@.target` instance, whose
/// template PID 1 reads. A drop-in the entry writes changes a unit directory,
/// and PID 1 then lists every unit directory again at its next load of a
/// unit. PID 1 executing itself again and udevd starting again, where either
/// held a deleted file ([`super::deleted_file_releases`]), read their unit
/// files, generators, libraries, rules and hwdb. All of that happens while
/// the mounts are `noatime`, up to the reload at the end of the entry
/// ([`settle`]).
///
/// The mounts it changes and their modes go to the plan before any is
/// changed, so that a rollback or `nails recover` gives them their modes
/// back where the activation dies before it can ([`super::rollback`]). On the
/// system, an entry that may not change mounts (NAILS run in a user namespace
/// of its own) is refused too: nothing would keep PID 1's reads from setting
/// access times.
pub(super) fn quiet_mounts(paths: &Paths, plan: &mut Plan) -> Result<QuietMounts> {
    let refuse = |why: String| {
        NailsError::InvalidState(format!(
            "NAILS cannot keep the service manager's reload from setting access times on the \
             decoy disk: {why}"
        ))
    };
    if paths.is_system() && !nails_teardown::noatime::may_spawn_without_access_times() {
        return Err(refuse(
            "it runs as root of a user namespace of its own, which may not change the system's \
             mounts"
                .to_string(),
        ));
    }
    let plan_path = paths.plan();
    QuietMounts::open_recorded(|records| {
        plan.quiet_mounts = records.to_vec();
        plan.write_atomic(&plan_path)
    })
    .map_err(|e| refuse(format!("making its mounts noatime for it failed ({e})")))
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

/// Give each mount [`quiet_mounts`] changed its own mode back, after the last
/// reload ([`settle`]). A mode that does not take fails the entry, so that
/// the rollback tries again.
pub(super) fn give_modes_back(quiet: QuietMounts) -> Result<()> {
    quiet
        .close()
        .map_err(|e| NailsError::InvalidState(format!("a decoy mount stays noatime: {e}")))
}

/// Give each mount `plan` records as changed by an entry that died its own
/// mode back, where it is still `noatime`
/// ([`nails_teardown::noatime::restore`]); one it cannot give its mode back
/// is logged.
pub(super) fn restore_recorded(plan: &Plan) {
    for stuck in nails_teardown::noatime::restore(&plan.quiet_mounts) {
        tracing::warn!(mount = %stuck.display(), "a decoy mount stays noatime until reboot");
    }
}
