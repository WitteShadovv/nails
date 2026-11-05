// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the runtime guards hold once the service manager has loaded them
//! ([`transition::runtime_guards`]).
//!
//! systemd applies a unit's drop-ins in the order of their file names, so a
//! drop-in of the decoy's that sorts after a guard can undo it. The entry asks
//! PID 1 for the result after the reload and refuses when a guard does not
//! hold.

use super::EntryHost;
use crate::error::{NailsError, Result};
use nails_teardown::whole_root::transition;

/// `property` of `unit` as PID 1 has it loaded, with every drop-in:
/// `systemctl show --property=<property> --value <unit>`.
pub(super) fn show_property(unit: &str, property: &str) -> Result<String> {
    let systemctl = nails_teardown::whole_root::tools::find(None, "systemctl")
        .ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
    let property = format!("--property={property}");
    nails_teardown::whole_root::tools::run_output(
        &systemctl,
        &["show", &property, "--value", unit],
        std::time::Duration::from_secs(30),
    )
    .ok_or_else(|| NailsError::InvalidState(format!("systemctl show {unit} failed")))
}

/// Refuse the entry when the switch would not power off at its job timeout
/// once the drop-ins are loaded ([`transition::SWITCH_TIMEOUT_ACTION`]): a
/// drop-in that sorts after the timeout guard sets `JobTimeoutAction=` again.
/// A switch that hung that long would then go on by force without the
/// transition step, and the hidden session would start without the masks that
/// keep its systemd off the decoy's disks.
pub(super) fn check_switch_timeout(host: &dyn EntryHost) -> Result<()> {
    let unit = transition::SWITCH_TIMEOUT_UNIT;
    let action = host.job_timeout_action(unit)?;
    let action = action.trim();
    if action == transition::SWITCH_TIMEOUT_ACTION {
        return Ok(());
    }
    Err(NailsError::PreFlightCheckFailed(vec![(
        "switch-timeout".to_string(),
        format!(
            "{unit} would not power off if the switch hung until its job timeout \
             (JobTimeoutAction={action}): a drop-in that sorts after \
             /run/systemd/system/{unit}.d/{} sets JobTimeoutAction= again, and the switch \
             would then go on by force without its last step, which keeps the hidden \
             session's systemd off the decoy's disks",
            transition::STOP_GUARD_NAME
        ),
        Some(format!(
            "Remove the JobTimeoutAction= from that drop-in (`systemctl cat {unit}` shows \
             where it is) and activate again"
        )),
    )]))
}

/// Refuse the entry when a guarded unit still runs stop commands once the
/// drop-ins are loaded: a drop-in that sorts after the guard set `ExecStop=`
/// again, and that stop would undo what the switch needs (see
/// [`transition::STOP_GUARDED_UNITS`]). A prefix guard has no unit of its own
/// to ask about; its units carry their stop in the unit file, which every
/// drop-in follows.
pub(super) fn check_stop_guards(host: &dyn EntryHost) -> Result<()> {
    for unit in transition::STOP_GUARDED_UNITS
        .iter()
        .filter(|unit| !transition::is_unit_prefix(unit))
    {
        let stop = host.unit_stop_commands(unit)?;
        if !stop.trim().is_empty() {
            return Err(NailsError::PreFlightCheckFailed(vec![(
                "stop-guard".to_string(),
                format!(
                    "{unit} would still run a stop command during the switch ({}): a drop-in \
                     that sorts after /run/systemd/system/{unit}.d/{} sets ExecStop= again, \
                     and that stop undoes what the switch needs",
                    stop.trim(),
                    transition::STOP_GUARD_NAME
                ),
                Some(format!(
                    "Remove the ExecStop= from that drop-in (`systemctl cat {unit}` shows \
                     where it is) and activate again"
                )),
            )]));
        }
    }
    Ok(())
}
