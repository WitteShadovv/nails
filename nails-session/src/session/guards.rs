// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether two of the runtime guards ([`transition::runtime_guards`]) hold
//! once the service manager has loaded them: the stop guard of
//! `blk-availability.service` ([`stop_guards`]) and the switch's timeout guard
//! ([`switch_timeout`]). PID 1 is asked before the entry and before the way
//! back that `deactivate` takes; a plain emergency asks nothing. The other
//! runtime guards, the stop guard of NixOS's static addresses
//! (`network-addresses-.service`) and the one that stops the D-Bus units at
//! `shutdown.target`, are asked about in neither direction.
//!
//! systemd applies a unit's drop-ins in the order of their file names, so a
//! drop-in that sorts after a guard can undo it, and one of the guard's own
//! name in `/etc` takes its place. The entry asks the decoy's PID 1 once the
//! reload has loaded the guards ([`check_stop_guards`],
//! [`check_switch_timeout`]). The way back asks the hidden session's PID 1,
//! whose own configuration, and whatever the session changed, can undo a guard
//! as well, before it prepares anything ([`check_way_back`]). Each refuses
//! unless both guards hold.

use crate::error::{NailsError, Result};
use nails_teardown::whole_root::plan::Direction;
use nails_teardown::whole_root::selinux::Selinux;
use nails_teardown::whole_root::transition;
pub use nails_teardown::whole_root::unit_bus::ExecCommand;
use std::path::Path;

/// A service's commands, or why they could not be read.
pub type Commands = Result<Vec<ExecCommand>>;

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
    /// `property` of `unit` with every drop-in loaded, as `systemctl show
    /// --property=<property> --value <unit>` prints it, for the properties
    /// the other methods do not name (the switch step's `ExecStart` and
    /// `FailureAction`, [`check_switch_step`]). A host that does not ask PID
    /// 1 fails, by default, so that such a switch is refused.
    fn unit_property(&self, unit: &str, property: &str) -> Result<String> {
        Err(NailsError::InvalidState(format!(
            "PID 1 was not asked for {property} of {unit}"
        )))
    }
    /// The commands of `unit`'s `property` (`ExecStart`) with every drop-in
    /// loaded, each with its program and its arguments apart. The entry's
    /// host asks PID 1 over D-Bus
    /// ([`nails_teardown::whole_root::unit_bus::commands`]), whose reply
    /// reads in one way only. By default they are read from the text of
    /// [`GuardHost::unit_property`] ([`commands`]), which fails on a listing
    /// an argument could have made up.
    fn unit_commands(&self, unit: &str, property: &str) -> Result<Vec<ExecCommand>> {
        commands(&self.unit_property(unit, property)?)
    }
    /// The SELinux context PID 1 starts `unit`'s processes in, with every
    /// drop-in loaded (`SELinuxContext`): empty where the policy picks it.
    /// Asked only where the RAM copies of the binary take a label
    /// ([`super::program_label`]). A host that does not ask PID 1 fails, by
    /// default, so that such a switch is refused.
    fn selinux_context(&self, unit: &str) -> Result<String> {
        Err(NailsError::InvalidState(format!(
            "PID 1 was not asked for SELinuxContext of {unit}"
        )))
    }
    /// The running kernel's SELinux, which the label of the RAM copies of the
    /// binary is written, read back and checked through
    /// ([`super::program_label`]): tests replace it.
    fn selinux(&self) -> &dyn Selinux {
        &nails_teardown::whole_root::selinux::KERNEL
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

/// The commands of `unit`'s `property` (`ExecStart`), asked of PID 1 over
/// D-Bus with the system's `busctl`
/// ([`nails_teardown::whole_root::unit_bus::commands`]): what the entry's host
/// answers for [`GuardHost::unit_commands`].
pub fn bus_commands(unit: &str, property: &str) -> Commands {
    use nails_teardown::whole_root::{logind, tools, unit_bus};
    let busctl = tools::find(None, logind::BUSCTL)
        .ok_or_else(|| NailsError::InvalidState("busctl not found".to_string()))?;
    unit_bus::commands(&busctl, unit, property).ok_or_else(|| {
        NailsError::InvalidState(format!(
            "PID 1 did not answer for {property} of {unit} over D-Bus"
        ))
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
    /// The one command with which the hidden session makes the guard hold,
    /// which a refused way back names before those two ways. Only service
    /// watchdogs turned off in the session have one, which needs no reload
    /// and lasts, as nothing reloads PID 1 before the way back
    /// (`systemctl service-watchdogs yes`). The session can also undo what a
    /// drop-in changed, with the guard written back or a drop-in of its own
    /// and a reload, but such a refusal names only the two ways.
    pub in_session: Option<String>,
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
                in_session: None,
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
/// way in, whose fix names it. The way back's refusal names no drop-in: its
/// fix names the other ways to end the session instead ([`way_back_fix`]).
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
/// PID 1 has service watchdogs off, in which case it takes no action at a job
/// timeout ("Watchdog disabled! Not acting on: job timed out"), or when the
/// unit has no timeout (`JobTimeoutSec=infinity`, or `0`): the switch would
/// then stay hung, the hidden volume's key in RAM, until someone powers off.
/// An answer it cannot read refuses as well, a timeout that reads as no span
/// of time ([`is_timespan`]) among them.
///
/// Every reload of PID 1 sets service watchdogs to what the kernel command
/// line says (`systemd.service_watchdogs=`, on by default), and with systemd
/// 257 and older the `SystemdOptions` EFI variable too, before it reloads. So
/// after the entry's reload a `systemctl service-watchdogs no` no longer
/// counts, and only those two can turn them off; the entry's fix names both.
/// The way back reloads nothing, so there a `systemctl service-watchdogs no`
/// in the session counts until the next reload, and a
/// `systemctl service-watchdogs yes` turns them back on just as well: the
/// way back's refusal names that.
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
            in_session: None,
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
                remedy: "Remove `systemd.service_watchdogs=` from the kernel command line, and \
                         with systemd 257 or older from the SystemdOptions EFI variable \
                         (`bootctl systemd-efi-options`): every reload of PID 1, the one \
                         activation makes included, sets service watchdogs to what those say, \
                         so `systemctl service-watchdogs yes` does not last. Then boot again"
                    .to_string(),
                in_session: (direction == Direction::Leave).then(|| {
                    "Turn service watchdogs back on with `sudo systemctl service-watchdogs yes` \
                     and deactivate again"
                        .to_string()
                }),
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
            in_session: None,
        })),
        timeout if is_timespan(timeout) => Ok(None),
        other => Err(NailsError::InvalidState(format!(
            "systemctl show printed JobTimeoutUSec={other} for {unit}, which reads as no span \
             of time"
        ))),
    }
}

/// Whether `text` reads as a span of time as `systemctl show` prints one
/// (systemd's `format_timespan()`): `0`, or numbers each followed by its unit
/// and set apart by a space, as in `30min`, `1min 30s` or `1.500000s`.
/// `infinity`, the one other answer, is no span.
fn is_timespan(text: &str) -> bool {
    timespan_usec(text).is_some()
}

/// The span of time `text` reads as ([`is_timespan`]), in microseconds, as
/// systemd counts its units (a year of 365.25 days, a month of a twelfth of
/// that). `None` when it reads as none, or does not fit.
fn timespan_usec(text: &str) -> Option<u128> {
    const UNITS: [(&str, u128); 9] = [
        ("y", 31_557_600_000_000),
        ("month", 2_629_800_000_000),
        ("w", 604_800_000_000),
        ("d", 86_400_000_000),
        ("h", 3_600_000_000),
        ("min", 60_000_000),
        ("s", 1_000_000),
        ("ms", 1_000),
        ("us", 1),
    ];
    let number = |digits: &str| {
        (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .then(|| digits.parse::<u128>().ok())
            .flatten()
    };
    if text == "0" {
        return Some(0);
    }
    if text.is_empty() {
        return None;
    }
    text.split(' ').try_fold(0u128, |sum, part| {
        let (amount, unit) =
            part.split_at(part.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(0));
        let (_, scale) = UNITS.iter().find(|(name, _)| *name == unit)?;
        let usec = match amount.split_once('.') {
            None => number(amount)?.checked_mul(*scale)?,
            Some((whole, fraction)) => {
                let digits = u32::try_from(fraction.len()).ok()?;
                let fraction = number(fraction)?
                    .checked_mul(*scale)?
                    .checked_div(10u128.checked_pow(digits)?)?;
                number(whole)?.checked_mul(*scale)?.checked_add(fraction)?
            }
        };
        sum.checked_add(usec)
    })
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

/// The service whose start is the switch's last step.
pub const SWITCH_STEP_UNIT: &str = "systemd-soft-reboot.service";

/// What `systemctl show --property=<property> --value` prints of
/// [`SWITCH_STEP_UNIT`] once PID 1 has loaded the step's drop-in as NAILS
/// writes it for `binary` ([`transition::dropin_text`]) over the unit systemd
/// ships: its one start command, the actions, type and timeouts
/// [`check_switch_step`] wants, and nothing for the other properties it asks
/// about. A test's PID 1 answers with these.
pub fn loaded_switch_step(binary: &Path, property: &str) -> String {
    let binary = binary.display();
    match property {
        "ExecStart" => format!(
            "{{ path={binary} ; argv[]={binary} {} ; ignore_errors=no ; start_time=[n/a] ; \
             stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            transition::TRANSITION_ARG
        ),
        "JobTimeoutUSec" | "JobRunningTimeoutUSec" => "infinity".to_string(),
        _ => SWITCH_STEP_VALUES
            .iter()
            .find(|(name, _, _)| *name == property)
            .map_or_else(String::new, |(_, value, _)| value.to_string()),
    }
}

/// The fields of one command as `systemctl show --value` prints it, in its
/// order: `{ path=... ; argv[]=... ; ignore_errors=... ; ... }`.
const COMMAND_FIELDS: [&str; 8] = [
    "path",
    "argv[]",
    "ignore_errors",
    "start_time",
    "stop_time",
    "pid",
    "code",
    "status",
];

/// The commands of `listing` as `systemctl show --value` prints them, one to
/// a line. That text does not set the program or an argument apart: an
/// argument that holds ` ; `, `{` or `}` reads as another field or another
/// command (`ExecStart=@"/opt/x} { path=/run/overlay-runtime/control" ...`
/// would print a second `path=`). So a line that is not one brace pair around
/// the fields systemd prints, each once and `path=` first, fails, and an
/// argument with a blank in it reads as two.
fn commands(listing: &str) -> Result<Vec<ExecCommand>> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let unreadable = || {
                NailsError::InvalidState(format!(
                    "systemctl show printed a command that does not read in one way only \
                     ({line})"
                ))
            };
            let inner = line
                .strip_prefix("{ ")
                .and_then(|inner| inner.strip_suffix(" }"))
                .filter(|inner| !inner.contains(['{', '}']))
                .ok_or_else(unreadable)?;
            let mut fields = Vec::new();
            for field in inner.split(" ; ") {
                let (name, value) = field.split_once('=').ok_or_else(unreadable)?;
                if !COMMAND_FIELDS.contains(&name) || fields.iter().any(|(seen, _)| *seen == name) {
                    return Err(unreadable());
                }
                fields.push((name, value));
            }
            let field = |name: &str| {
                fields
                    .iter()
                    .find_map(|(seen, value)| (*seen == name).then_some(*value))
                    .ok_or_else(unreadable)
            };
            if fields.first().map(|(name, _)| *name) != Some("path") {
                return Err(unreadable());
            }
            Ok(ExecCommand {
                path: field("path")?.to_string(),
                argv: field("argv[]")?.split(' ').map(str::to_string).collect(),
                ignores: match field("ignore_errors")? {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(unreadable()),
                },
            })
        })
        .collect()
}

/// `commands` as a refusal names them.
fn shown(commands: &[ExecCommand]) -> String {
    if commands.is_empty() {
        return "none".to_string();
    }
    commands
        .iter()
        .map(|command| {
            format!(
                "path={} argv=[{}] ignore_errors={}",
                command.path,
                command.argv.join(", "),
                if command.ignores { "yes" } else { "no" }
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The properties of [`SWITCH_STEP_UNIT`] that must be empty with every
/// drop-in loaded, each with what the switch would do otherwise.
const SWITCH_STEP_EMPTY: [(&str, &str); 10] = [
    (
        "ExecCondition",
        "a command around the switch's last step could skip it or end the service first",
    ),
    (
        "ExecStartPre",
        "a command around the switch's last step could skip it or end the service first",
    ),
    (
        "ExecStartPost",
        "a command around the switch's last step could skip it or end the service first",
    ),
    (
        "ExecStop",
        "a command that runs once the switch's last step has ended could undo what it did \
         before the switch goes on",
    ),
    (
        "ExecStopPost",
        "a command that runs once the switch's last step has ended could undo what it did \
         before the switch goes on",
    ),
    (
        "SuccessExitStatus",
        "an exit status that counts as success would let a failed step go on with the switch",
    ),
    (
        "BindPaths",
        "the step would see other files mounted into its view, and act on those instead of the \
         machine's",
    ),
    (
        "BindReadOnlyPaths",
        "the step would see other files mounted into its view, and act on those instead of the \
         machine's",
    ),
    (
        "RootDirectory",
        "the step would run in another root, and act on that instead of the machine's",
    ),
    (
        "RootImage",
        "the step would run in another root, and act on that instead of the machine's",
    ),
];

/// The properties of [`SWITCH_STEP_UNIT`] that must have one value with every
/// drop-in loaded, as `systemctl show --value` prints it, each with what the
/// switch would do otherwise. The failure action is the session's ending
/// ([`nails_teardown::whole_root::session_end::SessionEnd::emergency_action`]),
/// which the tests pin to this one.
const SWITCH_STEP_VALUES: [(&str, &str, &str); 5] = [
    (
        "FailureAction",
        "poweroff-force",
        "a failed step would let the switch go on, or leave the machine stopped",
    ),
    (
        "SuccessAction",
        "soft-reboot-force",
        "the step's success would not take the switch on, or would take it elsewhere",
    ),
    (
        "Type",
        "oneshot",
        "PID 1 would not wait for the step to end before the switch goes on",
    ),
    (
        "RemainAfterExit",
        "no",
        "the service would stay active once the step ends, and its success would not take the \
         switch on",
    ),
    (
        "JobTimeoutAction",
        "none",
        "a job timeout of the step's own would act instead of the switch's power-off",
    ),
];

/// The job timeouts of [`SWITCH_STEP_UNIT`], each with the setting that sets
/// it. systemd has one action for both, `JobTimeoutAction=`.
const SWITCH_STEP_TIMEOUTS: [(&str, &str); 2] = [
    ("JobTimeoutUSec", "JobTimeoutSec="),
    ("JobRunningTimeoutUSec", "JobRunningTimeoutSec="),
];

/// Refuse the entry unless PID 1, with every drop-in loaded, starts the
/// switch's last step as NAILS installed it ([`transition::dropin_text`]):
///
/// - one start command, which runs the RAM copy `binary` (the program, which
///   an `@` prefix can set apart from the arguments) with the step's
///   argument, and does not ignore its failure. The entry's host reads it over
///   D-Bus, where each argument stays apart ([`GuardHost::unit_commands`]);
/// - no other command around it or after it, no exit status but 0 that counts
///   as success, and no other root or mounts in the step's view
///   ([`SWITCH_STEP_EMPTY`]);
/// - the power-off as its failure action, the switch as its success action,
///   a oneshot that does not stay active, and no action of its own at a job
///   timeout ([`SWITCH_STEP_VALUES`]);
/// - no job timeout of its own shorter than the switch's
///   ([`transition::SWITCH_TIMEOUT_UNIT`], [`check_switch_timeout`]), at which
///   the step's job would end before the switch's power-off.
///
/// A drop-in of the decoy's that sorts after NAILS's (`override.conf` from
/// `systemctl edit`) can change any of them, and the step would then no
/// longer run, or no longer fail closed. A PID 1 that cannot be asked
/// refuses it too.
pub fn check_switch_step(host: &(impl GuardHost + ?Sized), binary: &Path) -> Result<()> {
    let refuse = |reason: String| {
        Err(NailsError::PreFlightCheckFailed(vec![(
            "switch-step".to_string(),
            reason,
            Some(format!(
                "Remove the setting that changes how {SWITCH_STEP_UNIT} runs the switch's last \
                 step (`systemctl cat {SWITCH_STEP_UNIT}` shows every drop-in) and activate again"
            )),
        )]))
    };
    let path = binary.display().to_string();
    let ours = |c: &ExecCommand| {
        c.path == path && c.argv == [path.as_str(), transition::TRANSITION_ARG] && !c.ignores
    };
    let starts = match host.unit_commands(SWITCH_STEP_UNIT, "ExecStart") {
        Ok(starts) => starts,
        Err(NailsError::InvalidState(why)) => {
            return refuse(format!(
                "{SWITCH_STEP_UNIT}'s start command (ExecStart=) could not be read: {why}"
            ));
        }
        Err(other) => return Err(other),
    };
    match starts.as_slice() {
        [command] if ours(command) => {}
        _ => {
            return refuse(format!(
                "{SWITCH_STEP_UNIT} does not start the switch's last step as NAILS installed it \
                 (ExecStart: {}): the step would not run, or not fail closed",
                shown(&starts)
            ));
        }
    }
    for (property, why) in SWITCH_STEP_EMPTY {
        let value = host.unit_property(SWITCH_STEP_UNIT, property)?;
        if !value.trim().is_empty() {
            return refuse(format!(
                "{SWITCH_STEP_UNIT} has {property}={} with every drop-in loaded: {why}",
                value.trim()
            ));
        }
    }
    for (property, wanted, why) in SWITCH_STEP_VALUES {
        let value = host.unit_property(SWITCH_STEP_UNIT, property)?;
        if value.trim() != wanted {
            return refuse(format!(
                "{SWITCH_STEP_UNIT} has {property}={} with every drop-in loaded, where NAILS \
                 needs {wanted}: {why}",
                value.trim()
            ));
        }
    }
    let unit = transition::SWITCH_TIMEOUT_UNIT;
    let budget = host.job_timeout(unit)?;
    let budget = timespan_usec(budget.trim()).ok_or_else(|| {
        NailsError::InvalidState(format!(
            "systemctl show printed JobTimeoutUSec={} for {unit}, which reads as no span of time",
            budget.trim()
        ))
    })?;
    for (property, setting) in SWITCH_STEP_TIMEOUTS {
        let value = host.unit_property(SWITCH_STEP_UNIT, property)?;
        let value = value.trim();
        if value == "infinity" || timespan_usec(value).is_some_and(|usec| usec >= budget) {
            continue;
        }
        return refuse(format!(
            "{SWITCH_STEP_UNIT} has {property}={value} with every drop-in loaded ({setting}), \
             shorter than the job timeout of {unit} or no span of time: the step's job would \
             end before the switch's power-off"
        ));
    }
    Ok(())
}

/// Refuse the way back unless the guards the entry checked in the decoy's
/// PID 1 hold in the hidden session's: `blk-availability.service` runs no
/// stop command ([`stop_guards`]), and a switch that hangs until its job
/// timeout powers the machine off ([`switch_timeout`]). A PID 1 that cannot
/// be asked refuses it too. The refusal names the two other ways to end the
/// session ([`way_back_fix`]), after the one command that makes the guard
/// hold where the session has one ([`Unheld::in_session`]).
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
    let (check, reason, in_session) = match unheld {
        Ok(None) => return Ok(()),
        Ok(Some(unheld)) => (unheld.check, unheld.reason, unheld.in_session),
        Err((check, error)) => (
            check,
            format!(
                "the hidden session's PID 1 could not be asked whether its guards hold: {error}"
            ),
            None,
        ),
    };
    Err(NailsError::PreFlightCheckFailed(vec![(
        check.to_string(),
        reason,
        Some(way_back_fix(in_session.as_deref())),
    )]))
}

/// The fix of a refused way back: the one command that makes the guard hold
/// (`in_session`), where the session has one, then the two other ways to end
/// the session, `deactivate --poweroff`, whose power-off goes through no
/// soft-reboot, and `emergency`, which does not ask PID 1 about the guards.
fn way_back_fix(in_session: Option<&str>) -> String {
    use nails_base::next_step::{NextStep, sudo_line};
    let endings = format!(
        "the session with `{}`, which powers off, or with `{}`",
        sudo_line(NextStep::DeactivatePoweroff),
        sudo_line(NextStep::Emergency)
    );
    match in_session {
        Some(change) => format!("{change}, or end {endings}"),
        None => format!("End {endings}"),
    }
}

#[cfg(test)]
#[path = "guards_tests.rs"]
mod tests;
