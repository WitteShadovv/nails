// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ending the hidden session the orderly way (`nails deactivate`).
//!
//! A hidden session never goes back to the decoy's kernel: deactivation ends
//! it the way every hidden session ends ([`session_end`]), with a power-off.
//! Before it enqueues anything it refuses while a program blocks shutdown
//! ([`may_leave`]): the power-off would cut it short. Then it enqueues
//! `poweroff.target`: the orderly shutdown stops every hidden unit
//! (applications flush, the hidden journal reaches the upper), and
//! systemd-shutdown unmounts every filesystem, removes the device-mapper
//! devices and powers off.
//!
//! The way back to the decoy this module once prepared (the decoy root at
//! `/run/nextroot`, the backend marked for deferred removal, the plan armed for
//! a second soft-reboot) is gone; the [`RealTargetHost`] still asks logind for
//! the entry's soft-reboot.
//!
//! [`session_end`]: nails_teardown::whole_root::session_end::session_end

use super::guards::{self, GuardHost};
use crate::error::{NailsError, Result};
use nails_teardown::whole_root::plan::{PLAN_NAME, Plan, RUNTIME_DIR};
use nails_teardown::whole_root::session_end::session_end;
use nails_teardown::whole_root::{logind, tools};
use std::path::{Path, PathBuf};

/// Enqueues a systemd target: tests replace it. It asks PID 1 whether the
/// guards the way back checks hold as a [`GuardHost`].
pub trait TargetHost: GuardHost {
    /// Enqueue `target`. An error means it is known not to have been taken:
    /// nothing is left that would start it later.
    fn start_target(&self, target: &str) -> Result<()>;
    /// Refuse to end the session while a program blocks shutdown outright:
    /// it is in the middle of something the switch would cut short.
    fn may_switch(&self) -> Result<()> {
        Ok(())
    }
}

/// The real host, through the plan's `systemctl` and the system's `busctl`.
#[derive(Debug, Clone)]
pub struct RealTargetHost {
    systemctl: Option<PathBuf>,
    busctl: Option<PathBuf>,
    /// The session plan, which a soft-reboot waits on only while it is armed.
    plan: PathBuf,
    /// What kills the interactive shells around the soft-reboot: the entry's
    /// does, a deactivation's does not (its power-off stops them).
    kill_shells: Option<fn()>,
}

/// SIGKILL every interactive shell on the decoy, the newest first.
fn kill_decoy_shells() {
    nails_teardown::shells::kill_interactive_shells_newest_first();
}

impl RealTargetHost {
    /// The host for `plan` (its recorded `systemctl`, else the system's).
    pub fn for_plan(plan: Option<&Plan>) -> Self {
        Self {
            systemctl: tools::find(plan.and_then(|p| p.tools.systemctl.as_deref()), "systemctl"),
            busctl: tools::find(plan.and_then(|p| p.tools.busctl.as_deref()), logind::BUSCTL),
            plan: Path::new(RUNTIME_DIR).join(PLAN_NAME),
            kill_shells: None,
        }
    }

    /// The host of an entry, which kills the decoy's interactive shells
    /// around its soft-reboot. Stopping a login session sends its shells
    /// SIGHUP, on which bash writes its history (on the decoy: to the decoy
    /// disk), and the switch stops them the moment PID 1 holds its job. So
    /// the shells die right before logind is asked, then again between two
    /// looks while logind holds the soft-reboot back (the desktop runs on
    /// meanwhile, and a shell opened then lives about a tenth of a second,
    /// too short to have anything to write), and once more when PID 1 holds
    /// the job. Each time they die the newest first: a dying shell hangs up
    /// what its session started, such as a desktop started from a console
    /// login and the shells in its terminal windows, and those are gone by
    /// then.
    pub fn killing_shells(mut self) -> Self {
        self.kill_shells = Some(kill_decoy_shells);
        self
    }

    /// The soft-reboot of the entry, through logind as
    /// `systemctl soft-reboot` does ([`logind::request_soft_reboot`]): the
    /// programs waiting for its shutdown signal end on it first. `Ok` once
    /// PID 1 holds the job. While it waits, an activation stays the plan's
    /// owner, so `status` reports the entry under way and `recover` leaves it
    /// alone; once the plan is no longer armed (an emergency on the decoy took
    /// the entry down), the wait is called off.
    fn soft_reboot(&self, systemctl: &Path) -> Result<()> {
        let kill_shells = || {
            if let Some(kill) = self.kill_shells {
                kill();
            }
        };
        kill_shells();
        let mut wanted = || match Plan::load(&self.plan) {
            Ok(plan) if plan.armed.is_some() => {
                kill_shells();
                logind::Wanted::Yes
            }
            _ => logind::Wanted::No("the switch was called off".to_string()),
        };
        match logind::request_soft_reboot(
            systemctl,
            self.busctl.as_deref(),
            logind::Waits::SWITCH,
            &mut wanted,
        ) {
            logind::Request::Queued => {
                kill_shells();
                Ok(())
            }
            logind::Request::Refused(why) | logind::Request::Held(why) => Err(
                NailsError::InvalidState(format!("the soft-reboot was not started: {why}")),
            ),
        }
    }
}

/// PID 1, asked with the plan's `systemctl`, as the switch is enqueued: in
/// the hidden session the hidden session's own.
impl GuardHost for RealTargetHost {
    fn unit_stop_commands(&self, unit: &str) -> Result<String> {
        guards::show_property(self.systemctl.as_deref(), Some(unit), "ExecStop")
    }

    fn job_timeout_action(&self, unit: &str) -> Result<String> {
        guards::show_property(self.systemctl.as_deref(), Some(unit), "JobTimeoutAction")
    }

    fn job_timeout(&self, unit: &str) -> Result<String> {
        guards::show_property(self.systemctl.as_deref(), Some(unit), "JobTimeoutUSec")
    }

    fn service_watchdogs(&self) -> Result<String> {
        guards::show_property(self.systemctl.as_deref(), None, "ServiceWatchdogs")
    }

    fn selinux_context(&self, unit: &str) -> Result<String> {
        guards::show_property(self.systemctl.as_deref(), Some(unit), "SELinuxContext")
    }
}

impl TargetHost for RealTargetHost {
    fn may_switch(&self) -> Result<()> {
        let blocked = logind::blocking(self.busctl.as_deref(), self.systemctl.as_deref());
        let why = blocked.refusal();
        match (blocked, why) {
            (logind::Blocking::By(_), Some(why)) => Err(NailsError::InvalidState(format!(
                "{why}: the switch would cut it short. Let it finish, then try again"
            ))),
            (logind::Blocking::Unknown, Some(why)) => Err(NailsError::InvalidState(format!(
                "{why}, and the switch would cut such a program short. Try again once logind \
                 answers"
            ))),
            _ => Ok(()),
        }
    }

    fn start_target(&self, target: &str) -> Result<()> {
        let systemctl = self
            .systemctl
            .as_deref()
            .ok_or_else(|| NailsError::InvalidState("systemctl not found".to_string()))?;
        if target == tools::SOFT_REBOOT_TARGET {
            return self.soft_reboot(systemctl);
        }
        // A power-off is enqueued with PID 1 directly. A call cut short (by
        // the very stop it enqueued, typically) counts as enqueued.
        match tools::start_target(systemctl, target) {
            tools::Outcome::Done | tools::Outcome::Unknown => Ok(()),
            tools::Outcome::Refused => Err(NailsError::InvalidState(format!(
                "systemctl could not enqueue {target}"
            ))),
        }
    }
}

/// Whether the session may end now: not while a program blocks shutdown
/// ([`TargetHost::may_switch`]), which the power-off would cut short.
pub fn may_leave(host: &dyn TargetHost) -> Result<()> {
    host.may_switch()
}

/// End the hidden session ([`session_end`]): refuse while a program blocks
/// shutdown, then enqueue the power-off with PID 1.
pub fn leave(host: &dyn TargetHost) -> Result<()> {
    may_leave(host)?;
    host.start_target(session_end().target())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::whole_root::plan::{PolicyMount, PolicyMountKind};

    fn plan() -> Plan {
        let text = r#"{"version":2,"hidden_root":"/mnt/data","upper":"/mnt/data/root/upper",
            "work":"/mnt/data/root/work","decoy_root":{"source":"/dev/vda2","fstype":"ext4"},
            "decoy":{"init":"/sbin/init"},"hidden":{"init":"/sbin/init"}}"#;
        let mut plan = Plan::from_json(text).unwrap();
        plan.policy_mounts = vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }];
        plan
    }

    /// A real host on a stand-in `systemctl` that records its calls in
    /// `calls` and answers `soft-reboot` with `soft_reboot` (shell code), and
    /// an armed plan.
    fn real_host(dir: &Path, soft_reboot: &str) -> RealTargetHost {
        let d = dir.display();
        let systemctl = dir.join("systemctl");
        nails_base::test_support::write_executable(
            &systemctl,
            format!(
                "#!/bin/sh\necho \"$*\" >> {d}/calls\n\
                 case \"$*\" in\n\
                 '--no-wall soft-reboot') {soft_reboot} ;;\n\
                 list-jobs*) [ -e {d}/job ] \
                 && echo '7 soft-reboot.target start waiting'; exit 0 ;;\n\
                 esac\nexit 0\n"
            ),
            0o755,
        );
        let plan_path = dir.join("plan.json");
        let mut armed = plan();
        armed.armed = Some(nails_teardown::whole_root::plan::Arm::now(
            nails_teardown::whole_root::plan::Direction::Leave,
        ));
        armed.write_atomic(&plan_path).unwrap();
        RealTargetHost {
            systemctl: Some(systemctl),
            busctl: None,
            plan: plan_path,
            kill_shells: None,
        }
    }

    fn calls(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.starts_with("list-jobs"))
            .map(str::to_string)
            .collect()
    }

    /// The real host asks logind for the soft-reboot, as `systemctl
    /// soft-reboot` does, and returns once PID 1 holds the job; a power-off
    /// it enqueues with PID 1 directly.
    #[test]
    fn the_real_host_soft_reboots_through_logind_and_powers_off_directly() {
        let dir = tempfile::tempdir().unwrap();
        let host = real_host(
            dir.path(),
            &format!("touch {}/job; exit 0", dir.path().display()),
        );
        host.start_target(tools::SOFT_REBOOT_TARGET).unwrap();
        host.start_target("poweroff.target").unwrap();
        assert_eq!(
            calls(dir.path()),
            [
                "--no-wall soft-reboot",
                "start --no-block --job-mode=replace-irreversibly -- poweroff.target",
            ]
        );
    }

    static KILLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn count_kill() {
        KILLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// The entry's host kills the decoy's interactive shells right before it
    /// asks logind, again between two looks while logind holds the
    /// soft-reboot back, and once more when PID 1 holds the job; the way
    /// back's host kills none.
    #[test]
    fn the_entry_kills_the_shells_until_pid_1_holds_the_job() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        let mut host = real_host(dir.path(), "exit 0");
        // PID 1 holds the job from the third look on.
        nails_base::test_support::write_executable(
            host.systemctl.as_deref().unwrap(),
            format!(
                "#!/bin/sh\necho \"$*\" >> {d}/calls\n\
                 case \"$*\" in\n\
                 list-jobs*) n=$(cat {d}/polls 2>/dev/null || echo 0)\n\
                 echo $((n + 1)) > {d}/polls\n\
                 [ \"$n\" -ge 2 ] && echo '7 soft-reboot.target start waiting'; exit 0 ;;\n\
                 esac\nexit 0\n"
            ),
            0o755,
        );
        assert!(RealTargetHost::for_plan(None).kill_shells.is_none());
        assert!(
            RealTargetHost::for_plan(None)
                .killing_shells()
                .kill_shells
                .is_some()
        );
        host.kill_shells = Some(count_kill);
        host.start_target(tools::SOFT_REBOOT_TARGET).unwrap();
        // Before, at the two looks without a job, and once it is there.
        assert_eq!(KILLS.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert_eq!(calls(dir.path()), ["--no-wall soft-reboot"]);
    }

    /// A soft-reboot logind refuses is an error that says why, and nothing is
    /// enqueued in its place.
    #[test]
    fn a_soft_reboot_logind_refuses_is_an_error_with_its_reason() {
        let dir = tempfile::tempdir().unwrap();
        let host = real_host(dir.path(), "echo 'Operation denied' >&2; exit 1");
        let error = host.start_target(tools::SOFT_REBOOT_TARGET).unwrap_err();
        assert_eq!(
            error.to_string(),
            NailsError::InvalidState(
                "the soft-reboot was not started: Operation denied".to_string()
            )
            .to_string()
        );
        assert_eq!(calls(dir.path()), ["--no-wall soft-reboot"]);
    }

    /// A program that blocks shutdown outright refuses the session's end
    /// before anything is enqueued.
    #[test]
    fn a_program_that_blocks_shutdown_refuses_the_session_s_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = real_host(dir.path(), "exit 0");
        let busctl = dir.path().join("busctl");
        nails_base::test_support::write_executable(
            &busctl,
            "#!/bin/sh\necho '{\"type\":\"a(ssssuu)\",\"data\":[[[\"shutdown\",\"apt\",\
             \"Installing\",\"block\",0,4242]]]}'\n",
            0o755,
        );
        host.busctl = Some(busctl);
        let error = leave(&host).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("apt blocks shutdown (Installing, PID 4242)"),
            "{error}"
        );
        assert!(calls(dir.path()).is_empty());
    }

    /// The real host asks PID 1 with its `systemctl` for the guarded units'
    /// loaded properties and for PID 1's own, and cannot ask without one,
    /// which refuses the return.
    #[test]
    fn the_real_host_asks_pid_1_about_the_guards_with_its_systemctl() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().display();
        let host = real_host(dir.path(), "exit 0");
        nails_base::test_support::write_executable(
            host.systemctl.as_deref().unwrap(),
            format!(
                "#!/bin/sh\necho \"$*\" >> {d}/calls\n\
                 case \"$*\" in\n\
                 'show --property=JobTimeoutAction --value soft-reboot.target') \
                 echo poweroff-force ;;\n\
                 'show --property=JobTimeoutUSec --value soft-reboot.target') echo 30min ;;\n\
                 'show --property=ServiceWatchdogs --value') echo yes ;;\n\
                 esac\nexit 0\n"
            ),
            0o755,
        );
        guards::check_way_back(&host).unwrap();
        assert_eq!(
            calls(dir.path()),
            [
                "show --property=ExecStop --value blk-availability.service",
                "show --property=JobTimeoutAction --value soft-reboot.target",
                "show --property=ServiceWatchdogs --value",
                "show --property=JobTimeoutUSec --value soft-reboot.target",
            ]
        );
        let without = RealTargetHost {
            systemctl: None,
            ..host
        };
        let error = guards::check_way_back(&without).unwrap_err();
        let NailsError::PreFlightCheckFailed(failures) = &error else {
            panic!("{error}")
        };
        assert_eq!(failures[0].0, "stop-guard");
        assert!(failures[0].1.contains("systemctl not found"), "{error}");
    }

    /// A host whose PID 1 reports `unheld`, a (property, value), in place of
    /// what its guard sets, and holds every other guard; it records the
    /// targets it is asked to start, and starts none, a power-off least of
    /// all.
    #[derive(Default)]
    struct Guarded {
        unheld: Option<(&'static str, &'static str)>,
        started: std::cell::RefCell<Vec<String>>,
    }

    impl Guarded {
        fn answer(&self, property: &str, held: &str) -> Result<String> {
            Ok(match self.unheld {
                Some((unheld, value)) if unheld == property => value,
                _ => held,
            }
            .to_string())
        }
    }

    impl GuardHost for Guarded {
        fn unit_stop_commands(&self, _: &str) -> Result<String> {
            self.answer("ExecStop", "")
        }
        fn job_timeout_action(&self, _: &str) -> Result<String> {
            self.answer("JobTimeoutAction", "poweroff-force")
        }
        fn job_timeout(&self, _: &str) -> Result<String> {
            self.answer("JobTimeoutUSec", "30min")
        }
        fn service_watchdogs(&self) -> Result<String> {
            self.answer("ServiceWatchdogs", "yes")
        }
    }

    impl TargetHost for Guarded {
        fn start_target(&self, target: &str) -> Result<()> {
            self.started.borrow_mut().push(target.to_string());
            Ok(())
        }
    }

    /// Deactivation ends the session in a power-off and prepares nothing
    /// else: it asks none of the guards a switch needs, as no switch comes,
    /// and enqueues `poweroff.target` alone.
    #[test]
    fn deactivation_ends_the_session_in_a_power_off_whatever_the_guards_say() {
        for unheld in [
            None,
            Some(("JobTimeoutAction", "soft-reboot-force")),
            Some(("ServiceWatchdogs", "no")),
        ] {
            let host = Guarded {
                unheld,
                ..Guarded::default()
            };
            assert!(may_leave(&host).is_ok());
            leave(&host).unwrap();
            assert_eq!(*host.started.borrow(), ["poweroff.target"], "{unheld:?}");
        }
    }
}
