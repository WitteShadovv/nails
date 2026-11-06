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
/// guard's included: the entry is refused, and the fix turns them on.
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
        "Turn them on with `sudo systemctl service-watchdogs yes` and activate again"
    );
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
    for timeout in ["1min", "30min", "2h 30min", "1us"] {
        let pid1 = Pid1 {
            timeout,
            ..Pid1::default()
        };
        assert!(check_switch_timeout(&pid1).is_ok(), "{timeout}");
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
