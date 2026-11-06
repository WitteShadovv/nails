// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the runtime guards hold once the service manager has loaded them
//! ([`transition::runtime_guards`]), asked of PID 1 before each switch.
//!
//! systemd applies a unit's drop-ins in the order of their file names, so a
//! drop-in that sorts after a guard can undo it, and one of the guard's own
//! name in `/etc` takes its place. The entry asks the decoy's PID 1 once the
//! reload has loaded the guards ([`check_stop_guards`],
//! [`check_switch_timeout`]). The way back asks the hidden session's PID 1,
//! whose own configuration, and whatever the session changed, can undo a guard
//! as well, before it prepares anything ([`check_way_back`]). Each refuses
//! unless every guard holds.

use crate::error::{NailsError, Result};
use nails_teardown::whole_root::plan::Direction;
use nails_teardown::whole_root::transition;
use std::path::Path;

/// What PID 1 has loaded, as `systemctl show --property=<name> --value`
/// prints it: tests replace it.
pub trait GuardHost {
    /// The stop commands `unit` runs with every drop-in loaded (`ExecStop`):
    /// empty when it runs none, or when the unit does not exist.
    fn unit_stop_commands(&self, unit: &str) -> Result<String>;
    /// What `unit`'s job timeout does with every drop-in loaded
    /// (`JobTimeoutAction`).
    fn job_timeout_action(&self, unit: &str) -> Result<String>;
    /// `unit`'s job timeout with every drop-in loaded (`JobTimeoutUSec`):
    /// `30min`, say, or `infinity` where it has none.
    fn job_timeout(&self, unit: &str) -> Result<String>;
    /// Whether PID 1 acts on a watchdog, and so on a job timeout
    /// (`ServiceWatchdogs`): `yes` or `no`.
    fn service_watchdogs(&self) -> Result<String>;
    /// The drop-ins PID 1 applies to `unit`, in the order it applies them
    /// (`DropInPaths`, separated by spaces), for the entry's fix to name the
    /// one that undoes a guard. None by default: the fix then says where to
    /// look.
    fn unit_dropins(&self, _unit: &str) -> Result<String> {
        Ok(String::new())
    }
}

/// `property` of `unit`, or of PID 1 itself without one, as PID 1 has it
/// loaded with every drop-in, asked with `systemctl` (`None`: there is none):
/// `systemctl show --property=<property> --value [<unit>]`.
pub fn show_property(
    systemctl: Option<&Path>,
    unit: Option<&str>,
    property: &str,
) -> Result<String> {
    let systemctl =
        systemctl.ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
    let flag = format!("--property={property}");
    let mut args = vec!["show", flag.as_str(), "--value"];
    args.extend(unit);
    nails_teardown::whole_root::tools::run_output(
        systemctl,
        &args,
        std::time::Duration::from_secs(30),
    )
    .ok_or_else(|| {
        NailsError::InvalidState(format!("systemctl show {} failed", unit.unwrap_or(&flag)))
    })
}

/// A runtime guard that does not hold in PID 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unheld {
    /// The name the refusal goes by: `stop-guard` or `switch-timeout`.
    pub check: &'static str,
    /// What PID 1 reports, and what the switch would do then.
    pub reason: String,
    /// What the decoy's owner changes for the guard to hold, for the entry's
    /// refusal; the way back names the two other ways to end the session
    /// instead.
    pub remedy: String,
}

/// The name of the refusal over a stop guard.
const STOP_GUARD: &str = "stop-guard";
/// The name of the refusal over the switch's job timeout.
const SWITCH_TIMEOUT: &str = "switch-timeout";

/// Where `unit`'s guard lies.
fn guard_path(unit: &str) -> String {
    format!(
        "/run/{}/{}",
        transition::stop_guard_dir(unit).display(),
        transition::STOP_GUARD_NAME
    )
}

/// The first unit of [`transition::STOP_GUARDED_UNITS`] that still runs stop
/// commands with every drop-in loaded: its guard is not loaded, or a drop-in
/// that sorts after it set `ExecStop=` again, and that stop would undo what
/// the switch needs. A prefix guard has no unit of its own to ask about; its
/// units carry their stop in the unit file, which every drop-in follows.
pub fn stop_guards(host: &(impl GuardHost + ?Sized)) -> Result<Option<Unheld>> {
    for unit in transition::STOP_GUARDED_UNITS
        .iter()
        .filter(|unit| !transition::is_unit_prefix(unit))
    {
        let stop = host.unit_stop_commands(unit)?;
        let stop = stop.trim();
        if !stop.is_empty() {
            return Ok(Some(Unheld {
                check: STOP_GUARD,
                reason: format!(
                    "{unit} would still run a stop command during the switch ({stop}): \
                     {} is not loaded, or a drop-in that sorts after it sets ExecStop= again, \
                     and that stop undoes what the switch needs",
                    guard_path(unit)
                ),
                remedy: format!(
                    "Remove the ExecStop= from that drop-in (`systemctl cat {unit}` shows \
                     where it is)"
                ),
            }));
        }
    }
    Ok(None)
}

/// The last of `unit`'s drop-ins, in the order PID 1 applies them, that sets
/// `key` in its `[Unit]` section, so that its value holds once they are
/// loaded: the one to name in the entry's fix. The guard itself never counts.
/// `None` when PID 1 names none, or none that sets it can be read: the unit
/// file may set it. Each is read without touching its access time.
fn setter(host: &(impl GuardHost + ?Sized), unit: &str, key: &str) -> Option<String> {
    use crate::filesystem::{Filesystem, RealFilesystem};
    let guard = guard_path(unit);
    let dropins = host.unit_dropins(unit).ok()?;
    dropins
        .split_whitespace()
        .rev()
        .filter(|path| *path != guard)
        .find(|path| {
            RealFilesystem
                .read_file_content(Path::new(path))
                .is_ok_and(|text| sets_in_unit_section(&text, key))
        })
        .map(str::to_string)
}

/// Whether `text`, a unit file or a drop-in, sets `key` in its `[Unit]`
/// section, as systemd reads a `key=value` line there: blanks around the key
/// count for nothing, and a comment line sets nothing.
fn sets_in_unit_section(text: &str, key: &str) -> bool {
    let mut section = "";
    text.lines().map(str::trim).any(|line| {
        if line.starts_with('[') {
            section = line;
            return false;
        }
        section == "[Unit]"
            && !line.starts_with(['#', ';'])
            && line
                .split_once('=')
                .is_some_and(|(name, _)| name.trim() == key)
    })
}

/// The drop-in of the switch's unit that sets `key` last ([`setter`]), on the
/// way in, whose fix names it; the way back's refusal names no fix.
fn named(host: &(impl GuardHost + ?Sized), direction: Direction, key: &str) -> Option<String> {
    if direction == Direction::Enter {
        setter(host, transition::SWITCH_TIMEOUT_UNIT, key)
    } else {
        None
    }
}

/// What a switch forced through at its job timeout skips in `direction`: the
/// transition step, and what that step does.
fn skipped_step(direction: Direction) -> &'static str {
    match direction {
        Direction::Enter => {
            "without its last step, which keeps the hidden session's systemd off the decoy's \
             disks"
        }
        Direction::Leave => {
            "without its last step, and the decoy would start with the hidden session's files \
             in /run"
        }
    }
}

/// Whether a switch that hangs until its job timeout powers the machine off
/// ([`transition::SWITCH_TIMEOUT_ACTION`]) in `direction`, with every drop-in
/// loaded: `None` when it does.
///
/// It does not when the job timeout has another action: a drop-in that sorts
/// after the timeout guard sets `JobTimeoutAction=` again, or the guard is not
/// loaded. With the unit's own `soft-reboot-force` such a switch would go on
/// by force without the transition step, and `none`, or a plain action that
/// systemd skips while a shutdown runs, would leave it hung. Nor does it when
/// PID 1 has service watchdogs off (`systemd.service_watchdogs=0` on the
/// kernel command line, `systemctl service-watchdogs no`), in which case it
/// takes no action at a job timeout ("Watchdog disabled! Not acting on: job
/// timed out"), or when the unit has no timeout (`JobTimeoutSec=infinity`, or
/// `0`): the switch would then stay hung, the hidden volume's key in RAM,
/// until someone powers off. An answer it cannot read refuses as well.
pub fn switch_timeout(
    host: &(impl GuardHost + ?Sized),
    direction: Direction,
) -> Result<Option<Unheld>> {
    let unit = transition::SWITCH_TIMEOUT_UNIT;
    let guard = guard_path(unit);
    let action = host.job_timeout_action(unit)?;
    let action = action.trim();
    if action != transition::SWITCH_TIMEOUT_ACTION {
        return Ok(Some(Unheld {
            check: SWITCH_TIMEOUT,
            reason: format!(
                "{unit} has JobTimeoutAction={action} with every drop-in loaded, not the {} \
                 that {guard} sets: that drop-in is not loaded, or one that sorts after it \
                 sets the action again. With soft-reboot-force, the unit's own action, a \
                 switch that hung until the job timeout would go on by force {}",
                transition::SWITCH_TIMEOUT_ACTION,
                skipped_step(direction)
            ),
            remedy: match named(host, direction, "JobTimeoutAction") {
                Some(dropin) => format!("Remove the JobTimeoutAction= from {dropin}"),
                None => format!(
                    "Remove the JobTimeoutAction= from that drop-in (`systemctl cat {unit}` \
                     shows where it is)"
                ),
            },
        }));
    }
    let watchdogs = host.service_watchdogs()?;
    match watchdogs.trim() {
        "yes" => {}
        "no" => {
            return Ok(Some(Unheld {
                check: SWITCH_TIMEOUT,
                reason: format!(
                    "PID 1 has service watchdogs turned off (ServiceWatchdogs=no), and then \
                     takes no action at a job timeout: a switch that hung until {unit}'s job \
                     timeout would not power off as {guard} sets, and would stay where it \
                     stopped, the hidden volume's key in RAM, until the machine is powered off \
                     by hand"
                ),
                remedy: "Turn them on with `sudo systemctl service-watchdogs yes`".to_string(),
            }));
        }
        other => {
            return Err(NailsError::InvalidState(format!(
                "systemctl show printed ServiceWatchdogs={other}, neither yes nor no"
            )));
        }
    }
    let timeout = host.job_timeout(unit)?;
    match timeout.trim() {
        "" => Err(NailsError::InvalidState(format!(
            "systemctl show printed no JobTimeoutUSec for {unit}"
        ))),
        "infinity" => Ok(Some(Unheld {
            check: SWITCH_TIMEOUT,
            reason: format!(
                "{unit} has no job timeout with every drop-in loaded (JobTimeoutUSec=infinity): \
                 a switch that hung would never reach the timeout at which {guard} powers the \
                 machine off, and would stay where it stopped, the hidden volume's key in RAM, \
                 until the machine is powered off by hand"
            ),
            remedy: match named(host, direction, "JobTimeoutSec") {
                Some(dropin) => {
                    format!("Remove the JobTimeoutSec= that turns the timeout off from {dropin}")
                }
                None => format!(
                    "Remove the JobTimeoutSec= that turns the timeout off (`systemctl cat {unit}` \
                     shows the drop-in or unit file that has it)"
                ),
            },
        })),
        _ => Ok(None),
    }
}

/// The entry's refusal of `unheld`, a guard that does not hold in the decoy's
/// PID 1 once the reload has loaded it.
fn refuse_entry(unheld: Option<Unheld>) -> Result<()> {
    match unheld {
        None => Ok(()),
        Some(unheld) => Err(NailsError::PreFlightCheckFailed(vec![(
            unheld.check.to_string(),
            unheld.reason,
            Some(format!("{} and activate again", unheld.remedy)),
        )])),
    }
}

/// Refuse the entry when a guarded unit still runs stop commands once the
/// drop-ins are loaded ([`stop_guards`]; see
/// [`transition::STOP_GUARDED_UNITS`]).
pub fn check_stop_guards(host: &(impl GuardHost + ?Sized)) -> Result<()> {
    refuse_entry(stop_guards(host)?)
}

/// Refuse the entry when a switch that hangs until its job timeout would not
/// power the machine off once the drop-ins are loaded ([`switch_timeout`]):
/// another action, service watchdogs off, or no timeout.
pub fn check_switch_timeout(host: &(impl GuardHost + ?Sized)) -> Result<()> {
    refuse_entry(switch_timeout(host, Direction::Enter)?)
}

/// Refuse the way back unless every runtime guard holds in the hidden
/// session's PID 1, as the entry checked them in the decoy's: the stop
/// guards' units run no stop command ([`stop_guards`]), and a switch that
/// hangs until its job timeout powers the machine off ([`switch_timeout`]).
/// A PID 1 that cannot be asked refuses it too. The refusal names the two
/// other ways to end the session ([`way_back_endings`]).
pub fn check_way_back(host: &(impl GuardHost + ?Sized)) -> Result<()> {
    let asked = |check: &'static str, found: Result<Option<Unheld>>| {
        found.map_err(|error| match error {
            NailsError::InvalidState(why) => (check, why),
            other => (check, other.to_string()),
        })
    };
    let unheld = asked(STOP_GUARD, stop_guards(host)).and_then(|unheld| match unheld {
        Some(unheld) => Ok(Some(unheld)),
        None => asked(SWITCH_TIMEOUT, switch_timeout(host, Direction::Leave)),
    });
    let (check, reason) = match unheld {
        Ok(None) => return Ok(()),
        Ok(Some(unheld)) => (unheld.check, unheld.reason),
        Err((check, error)) => (
            check,
            format!(
                "the hidden session's PID 1 could not be asked whether its guards hold: {error}"
            ),
        ),
    };
    Err(NailsError::PreFlightCheckFailed(vec![(
        check.to_string(),
        reason,
        Some(way_back_endings()),
    )]))
}

/// The two other ways to end the session that a refused way back names:
/// `deactivate --poweroff`, whose power-off goes through no soft-reboot, and
/// `emergency`, which does not ask PID 1 about the guards.
fn way_back_endings() -> String {
    use nails_base::next_step::{NextStep, sudo_line};
    format!(
        "End the session with `{}`, which powers off, or with `{}`",
        sudo_line(NextStep::DeactivatePoweroff),
        sudo_line(NextStep::Emergency)
    )
}

#[cfg(test)]
#[path = "guards_tests.rs"]
mod tests;
