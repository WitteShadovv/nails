// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the runtime guards' checks, on a PID 1 that answers what a
//! test gives it: nothing here reaches a service manager.

use super::*;
use std::path::Path;

/// The guard of `soft-reboot.target`, as the refusals name it.
const TIMEOUT_GUARD: &str = "/run/systemd/system/soft-reboot.target.d/zz-overlay-runtime.conf";

/// A PID 1 that holds every guard, but for what a test sets: the answers as
/// `systemctl show --value` prints them, and a property it cannot be asked
/// about (`unreadable`).
struct Pid1 {
    stop: &'static str,
    action: &'static str,
    watchdogs: &'static str,
    timeout: &'static str,
    dropins: String,
    unreadable: Option<&'static str>,
}

impl Default for Pid1 {
    fn default() -> Self {
        Self {
            stop: "\n",
            action: "poweroff-force\n",
            watchdogs: "yes\n",
            timeout: "30min\n",
            dropins: String::new(),
            unreadable: None,
        }
    }
}

impl Pid1 {
    fn answer(&self, property: &str, unit: &str, value: &str) -> Result<String> {
        if self.unreadable == Some(property) {
            return Err(NailsError::InvalidState(format!(
                "systemctl show {unit} failed"
            )));
        }
        Ok(value.to_string())
    }
}

impl GuardHost for Pid1 {
    fn unit_stop_commands(&self, unit: &str) -> Result<String> {
        assert!(
            !unit.ends_with("-.service"),
            "asked about the prefix {unit}"
        );
        // Only blk-availability's guard has a unit of its own to ask about.
        let stop = if unit == "blk-availability.service" {
            self.stop
        } else {
            "{ path=/bin/true }"
        };
        self.answer("ExecStop", unit, stop)
    }
    fn job_timeout_action(&self, unit: &str) -> Result<String> {
        assert_eq!(unit, "soft-reboot.target");
        self.answer("JobTimeoutAction", unit, self.action)
    }
    fn job_timeout(&self, unit: &str) -> Result<String> {
        assert_eq!(unit, "soft-reboot.target");
        self.answer("JobTimeoutUSec", unit, self.timeout)
    }
    fn service_watchdogs(&self) -> Result<String> {
        self.answer(
            "ServiceWatchdogs",
            "--property=ServiceWatchdogs",
            self.watchdogs,
        )
    }
    fn unit_dropins(&self, unit: &str) -> Result<String> {
        assert_eq!(unit, "soft-reboot.target");
        self.answer("DropInPaths", unit, &self.dropins)
    }
}

/// The one refusal `error` carries: its check, its reason and its fix.
fn refusal(error: &NailsError) -> (String, String, String) {
    let NailsError::PreFlightCheckFailed(failures) = error else {
        panic!("not a refusal: {error}")
    };
    assert_eq!(failures.len(), 1, "{error}");
    let (check, reason, fix) = &failures[0];
    (
        check.clone(),
        reason.clone(),
        fix.clone().unwrap_or_default(),
    )
}

#[test]
fn a_prefix_guard_is_not_asked_about_by_name() {
    assert!(check_stop_guards(&Pid1::default()).is_ok());
}

#[test]
fn a_stop_command_left_after_the_guard_refuses_the_entry() {
    let pid1 = Pid1 {
        stop: "{ path=/usr/sbin/blkdeactivate ; argv[]=/usr/sbin/blkdeactivate -u ; }\n",
        ..Pid1::default()
    };
    let (check, reason, fix) = refusal(&check_stop_guards(&pid1).unwrap_err());
    assert_eq!(check, "stop-guard");
    assert!(
        reason.starts_with(
            "blk-availability.service would still run a stop command during the switch ({ \
             path=/usr/sbin/blkdeactivate"
        ),
        "{reason}"
    );
    assert!(
        reason.contains(
            "/run/systemd/system/blk-availability.service.d/zz-overlay-runtime.conf is not \
             loaded, or a drop-in that sorts after it sets ExecStop= again"
        ),
        "{reason}"
    );
    assert_eq!(
        fix,
        "Remove the ExecStop= from that drop-in (`systemctl cat blk-availability.service` shows \
         where it is) and activate again"
    );
}

/// The entry goes on only when the switch powers off by force at its job
/// timeout with every drop-in loaded: any other action refuses it and names
/// the guard, a plain `poweroff` (which systemd skips during a switch) and
/// the forced or immediate actions that are no switch included.
#[test]
fn a_switch_that_would_not_power_off_at_its_timeout_refuses_the_entry() {
    assert!(check_switch_timeout(&Pid1::default()).is_ok());
    for action in [
        "soft-reboot-force",
        "poweroff",
        "none",
        "reboot-force",
        "poweroff-immediate",
        "",
    ] {
        let pid1 = Pid1 {
            action,
            ..Pid1::default()
        };
        let (check, reason, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
        assert_eq!(check, "switch-timeout");
        // It says what PID 1 reports and which drop-in sets the guard's
        // action, and gives the forced switch only as what the unit's own
        // action would do: the others do not switch by force.
        assert!(
            reason.starts_with(&format!(
                "soft-reboot.target has JobTimeoutAction={action} with every drop-in loaded, \
                 not the poweroff-force that {TIMEOUT_GUARD} sets: that drop-in is not loaded, \
                 or one that sorts after it sets the action again."
            )),
            "{reason}"
        );
        assert!(
            reason.ends_with(
                "With soft-reboot-force, the unit's own action, a switch that hung until the \
                 job timeout would go on by force without its last step, which keeps the \
                 hidden session's systemd off the decoy's disks"
            ),
            "{reason}"
        );
        assert_eq!(
            fix,
            "Remove the JobTimeoutAction= from that drop-in (`systemctl cat soft-reboot.target` \
             shows where it is) and activate again"
        );
    }
}

/// With service watchdogs off PID 1 takes no action at a job timeout, the
/// guard's included: the entry is refused. After the entry's reload only the
/// kernel command line, or with systemd 257 and older the `SystemdOptions`
/// EFI variable, can have turned them off, and the fix names both.
#[test]
fn service_watchdogs_turned_off_refuse_the_entry() {
    let pid1 = Pid1 {
        watchdogs: "no\n",
        ..Pid1::default()
    };
    let (check, reason, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
    assert_eq!(check, "switch-timeout");
    assert_eq!(
        reason,
        format!(
            "PID 1 has service watchdogs turned off (ServiceWatchdogs=no), and then takes no \
             action at a job timeout: a switch that hung until soft-reboot.target's job timeout \
             would not power off as {TIMEOUT_GUARD} sets, and would stay where it stopped, the \
             hidden volume's key in RAM, until the machine is powered off by hand"
        )
    );
    assert_eq!(
        fix,
        "Remove `systemd.service_watchdogs=` from the kernel command line, and with systemd 257 \
         or older from the SystemdOptions EFI variable (`bootctl systemd-efi-options`): every \
         reload of PID 1, the one activation makes included, sets service watchdogs to what \
         those say, so `systemctl service-watchdogs yes` does not last. Then boot again and \
         activate again"
    );
    // The entry's refusal has nothing for a session to change.
    let unheld = switch_timeout(&pid1, Direction::Enter).unwrap().unwrap();
    assert_eq!(unheld.in_session, None);
}

/// A switch with no job timeout never reaches the guard's power-off: the
/// entry is refused, and the fix names where the timeout went. Any timeout
/// at all lets it go on, a shorter or longer one than the unit's own too.
#[test]
fn a_switch_without_a_job_timeout_refuses_the_entry() {
    let pid1 = Pid1 {
        timeout: "infinity\n",
        ..Pid1::default()
    };
    let (check, reason, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
    assert_eq!(check, "switch-timeout");
    assert_eq!(
        reason,
        format!(
            "soft-reboot.target has no job timeout with every drop-in loaded \
             (JobTimeoutUSec=infinity): a switch that hung would never reach the timeout at \
             which {TIMEOUT_GUARD} powers the machine off, and would stay where it stopped, the \
             hidden volume's key in RAM, until the machine is powered off by hand"
        )
    );
    assert_eq!(
        fix,
        "Remove the JobTimeoutSec= that turns the timeout off (`systemctl cat \
         soft-reboot.target` shows the drop-in or unit file that has it) and activate again"
    );
    for timeout in [
        "1min\n",
        "30min",
        "2h 30min",
        "1us",
        "1min 30s",
        "1.500000s",
        "1y 2month 3w 4d 5h 6min 7s 8ms 9us",
    ] {
        let pid1 = Pid1 {
            timeout,
            ..Pid1::default()
        };
        assert!(check_switch_timeout(&pid1).is_ok(), "{timeout}");
        assert!(check_way_back(&pid1).is_ok(), "{timeout}");
    }
}

/// A timeout that reads as no span of time, as systemd prints one, is no
/// answer to go on with: the entry and the way back both refuse, as for an
/// answer that cannot be read at all.
#[test]
fn a_timeout_that_reads_as_no_span_of_time_refuses_both_ways() {
    for timeout in [
        "forever",
        "30",
        "1 min",
        "-1",
        "30min!",
        "1.s",
        ".5s",
        "1min  30s",
        "1fortnight",
    ] {
        let pid1 = Pid1 {
            timeout,
            ..Pid1::default()
        };
        let error = check_switch_timeout(&pid1).unwrap_err();
        assert_eq!(
            error.to_string(),
            NailsError::InvalidState(format!(
                "systemctl show printed JobTimeoutUSec={timeout} for soft-reboot.target, which \
                 reads as no span of time"
            ))
            .to_string()
        );
        let (check, reason, _) = refusal(&check_way_back(&pid1).unwrap_err());
        assert_eq!(check, "switch-timeout", "{timeout}");
        assert!(
            reason.ends_with(&format!(
                "could not be asked whether its guards hold: systemctl show printed \
                 JobTimeoutUSec={timeout} for soft-reboot.target, which reads as no span of time"
            )),
            "{reason}"
        );
    }
}

/// What systemd's `format_timespan()` prints reads as a span of time: `0`, or
/// numbers with their units set apart by single spaces, a fraction only
/// before a unit.
#[test]
fn a_span_of_time_reads_as_systemd_prints_one() {
    for text in ["0", "1us", "90s", "1.5s", "1min 30s", "2month 1w", "3y"] {
        assert!(is_timespan(text), "{text}");
    }
    for text in [
        "", "infinity", "s", "1", "1 s", "1s ", " 1s", "1,5s", "1.5", "1.s", "1sec", "1S", "1m",
        "1min30s",
    ] {
        assert!(!is_timespan(text), "{text:?}");
    }
}

/// A `systemctl` that cannot be asked, or an answer the check cannot read,
/// refuses the entry as well.
#[test]
fn an_answer_that_cannot_be_read_refuses_the_entry() {
    for property in ["JobTimeoutAction", "ServiceWatchdogs", "JobTimeoutUSec"] {
        let pid1 = Pid1 {
            unreadable: Some(property),
            ..Pid1::default()
        };
        let error = check_switch_timeout(&pid1).unwrap_err();
        assert!(error.to_string().contains("failed"), "{property}: {error}");
    }
    let pid1 = Pid1 {
        unreadable: Some("ExecStop"),
        ..Pid1::default()
    };
    assert!(
        check_stop_guards(&pid1)
            .unwrap_err()
            .to_string()
            .contains("systemctl show blk-availability.service failed")
    );
    for (watchdogs, timeout, said) in [
        ("", "30min", "ServiceWatchdogs=, neither yes nor no"),
        (
            "maybe",
            "30min",
            "ServiceWatchdogs=maybe, neither yes nor no",
        ),
        ("yes", "\n", "no JobTimeoutUSec for soft-reboot.target"),
    ] {
        let pid1 = Pid1 {
            watchdogs,
            timeout,
            ..Pid1::default()
        };
        let error = check_switch_timeout(&pid1).unwrap_err();
        assert!(
            matches!(&error, NailsError::InvalidState(message) if message.contains(said)),
            "{error}"
        );
    }
}

/// Write `text` as `name` in `dir`, and return its path.
fn dropin(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
}

/// The entry's fix names the drop-in whose `JobTimeoutSec=` or
/// `JobTimeoutAction=` holds, the last of those PID 1 applies that sets it in
/// `[Unit]`; a comment, another section, the guard itself and a drop-in it
/// cannot read count for nothing. Without one it says where to look.
#[test]
fn the_entrys_fix_names_the_drop_in_that_undoes_the_timeout_guard() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let earlier = dropin(dir, "50-short.conf", "[Unit]\nJobTimeoutSec=60s\n");
    let later = dropin(
        dir,
        "90-none.conf",
        "[Unit]\n# JobTimeoutSec=1h\nDescription=x\nJobTimeoutSec = infinity\n",
    );
    let service = dropin(dir, "95-service.conf", "[Service]\nJobTimeoutSec=5s\n");
    let missing = dir.join("99-missing.conf").display().to_string();
    let pid1 = Pid1 {
        timeout: "infinity\n",
        dropins: format!("{earlier} {later} {TIMEOUT_GUARD} {service} {missing}"),
        ..Pid1::default()
    };
    let (_, _, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
    assert_eq!(
        fix,
        format!(
            "Remove the JobTimeoutSec= that turns the timeout off from {later} and activate again"
        )
    );

    let action = dropin(dir, "zzz-action.conf", "[Unit]\nJobTimeoutAction=none\n");
    let pid1 = Pid1 {
        action: "none\n",
        dropins: format!("{earlier} {TIMEOUT_GUARD} {action}"),
        ..Pid1::default()
    };
    let (_, _, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
    assert_eq!(
        fix,
        format!("Remove the JobTimeoutAction= from {action} and activate again")
    );

    // None of them sets the timeout: the unit file may.
    let pid1 = Pid1 {
        timeout: "infinity\n",
        dropins: format!("{service} {missing}"),
        ..Pid1::default()
    };
    let (_, _, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
    assert!(
        fix.contains("`systemctl cat soft-reboot.target` shows the drop-in"),
        "{fix}"
    );
    // Nor is a drop-in PID 1 cannot name a reason to refuse less.
    let pid1 = Pid1 {
        timeout: "infinity\n",
        unreadable: Some("DropInPaths"),
        ..Pid1::default()
    };
    let (check, _, fix) = refusal(&check_switch_timeout(&pid1).unwrap_err());
    assert_eq!(check, "switch-timeout");
    assert!(fix.contains("`systemctl cat soft-reboot.target`"), "{fix}");
}

#[test]
fn a_setting_counts_only_on_a_line_of_its_own_in_the_unit_section() {
    for (text, sets) in [
        ("[Unit]\nJobTimeoutSec=infinity\n", true),
        ("[Unit]\n  JobTimeoutSec =0\n", true),
        (
            "[Unit]\nDescription=a\n\n[Install]\nJobTimeoutSec=0\n",
            false,
        ),
        ("[Unit]\n#JobTimeoutSec=0\n;JobTimeoutSec=0\n", false),
        ("JobTimeoutSec=0\n", false),
        ("[Unit]\nJobTimeoutSecX=0\nJobTimeoutAction=none\n", false),
        ("[Service]\nExecStop=\n[Unit]\nJobTimeoutSec=1\n", true),
    ] {
        assert_eq!(
            sets_in_unit_section(text, "JobTimeoutSec"),
            sets,
            "{text:?}"
        );
    }
}

/// What a refused way back names first where the session turned service
/// watchdogs off.
const WATCHDOGS_BACK_ON: &str = concat!(
    "Turn service watchdogs back on with `sudo systemctl service-watchdogs yes` ",
    "and deactivate again"
);

/// The way back asks the hidden session's PID 1 the same: it goes on only
/// when both guards hold, and its refusal says what a forced way back would
/// leave and names the two other ways to end the session, never a fix to
/// activate with. Only service watchdogs turned off are something the
/// session can change itself, which the fix then names first: nothing
/// reloads PID 1 before the way back, so `systemctl service-watchdogs yes`
/// lasts until it goes.
#[test]
fn the_way_back_is_refused_unless_both_guards_hold() {
    assert!(check_way_back(&Pid1::default()).is_ok());
    let unheld = [
        (
            Pid1 {
                stop: "{ path=/usr/sbin/blkdeactivate ; }\n",
                ..Pid1::default()
            },
            "stop-guard",
            "blk-availability.service would still run a stop command",
            None,
        ),
        (
            Pid1 {
                action: "soft-reboot-force\n",
                ..Pid1::default()
            },
            "switch-timeout",
            "would go on by force without its last step, and the decoy would start with the \
             hidden session's files in /run",
            None,
        ),
        (
            Pid1 {
                watchdogs: "no\n",
                ..Pid1::default()
            },
            "switch-timeout",
            "ServiceWatchdogs=no",
            Some(WATCHDOGS_BACK_ON),
        ),
        (
            Pid1 {
                timeout: "infinity\n",
                ..Pid1::default()
            },
            "switch-timeout",
            "JobTimeoutUSec=infinity",
            None,
        ),
        (
            Pid1 {
                unreadable: Some("ExecStop"),
                ..Pid1::default()
            },
            "stop-guard",
            "the hidden session's PID 1 could not be asked whether its guards hold: systemctl \
             show blk-availability.service failed",
            None,
        ),
        (
            Pid1 {
                unreadable: Some("ServiceWatchdogs"),
                ..Pid1::default()
            },
            "switch-timeout",
            "could not be asked whether its guards hold",
            None,
        ),
    ];
    for (pid1, check, said, in_session) in unheld {
        let error = check_way_back(&pid1).unwrap_err();
        let (named, reason, fix) = refusal(&error);
        assert_eq!(named, check, "{error}");
        assert!(reason.contains(said), "{reason}");
        assert!(!fix.contains(" and activate again"), "{fix}");
        assert_eq!(fix, way_back_fix(in_session), "{error}");
    }
}

/// The two other ways to end the session, as the running binary's lines,
/// after what the session can change itself where there is such a thing.
#[test]
fn a_refused_way_back_names_the_power_off_and_the_emergency() {
    use nails_base::next_step::{NextStep, sudo_line};
    let poweroff = sudo_line(NextStep::DeactivatePoweroff);
    let emergency = sudo_line(NextStep::Emergency);
    assert_eq!(
        way_back_fix(None),
        format!("End the session with `{poweroff}`, which powers off, or with `{emergency}`")
    );
    assert_eq!(
        way_back_fix(Some(WATCHDOGS_BACK_ON)),
        format!(
            "{WATCHDOGS_BACK_ON}, or end the session with `{poweroff}`, which powers off, or \
             with `{emergency}`"
        )
    );
}
