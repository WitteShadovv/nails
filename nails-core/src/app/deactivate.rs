// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `deactivate` operation: end the hidden session and return to the decoy
//! (or power off).
//!
//! The way back prepares the decoy root at `/run/nextroot`, marks the hidden
//! backend for closing, records the state inactive and enqueues the soft-reboot.
//! A front end confirms with the operator and shows a person the result before
//! the switch (the soft-reboot stops its terminal), so the operation is split:
//! [`prepare`] builds the manager and refuses, before anything is asked, outside
//! a hidden session and in a hidden root whose session plan cannot be read,
//! where the way back is unknown; [`ReadyDeactivation::warnings`] names what
//! the return will not put back, for the front end to show before it asks; and
//! [`ReadyDeactivation::leave`] commits the way back once the front end has
//! confirmed, taken the state lock and, for a person, printed. A
//! machine-readable result waits for the commit, so it reports the outcome.

use std::path::Path;

use nails_teardown::whole_root::plan::Plan;

use crate::session::{LeaveReport, LeaveTo, RealTargetHost, SessionView};
use crate::{NailsError, NailsManager, RealFilesystem, RuntimeEnv};

/// The result of preparing a deactivation.
pub enum Prepared {
    /// Not in a hidden session, so there is nothing to deactivate.
    NotHidden,
    /// In the hidden root, but its session plan in `/run` cannot be read, so
    /// the way back is unknown: refused before anything is asked or done.
    /// Carries why the plan cannot be read. Only a power-off ends such a
    /// session: a plain emergency finds no plan either, and does nothing.
    WayBackUnknown(String),
    /// In a hidden session: ready to confirm, lock and leave.
    Ready(Box<ReadyDeactivation>),
}

/// A deactivation whose preconditions hold, ready to commit.
pub struct ReadyDeactivation {
    manager: NailsManager<RealFilesystem>,
    /// The session plan the probe read, which the way back returns with.
    plan: Box<Plan>,
}

impl ReadyDeactivation {
    /// The hidden volume root, for taking the state lock.
    pub fn hidden_root(&self) -> &Path {
        &self.manager.config().hidden_volume_root
    }

    /// The state file path, for taking the state lock.
    pub fn state_path(&self) -> &Path {
        &self.manager.config().state_file_path
    }

    /// What the return to the decoy will not put back, as far as the hidden
    /// session can tell before the switch, one sentence each, for the front
    /// end to show before it asks: its last step, which cannot report, finds
    /// no `ip` to delete the session's links and set the MAC addresses back
    /// with. None for a power-off, after which the decoy starts afresh.
    pub fn warnings(&self, to: LeaveTo) -> Vec<String> {
        way_back_warnings(
            to,
            &self.plan,
            crate::session::leave::way_back_finds(&self.plan, "ip"),
        )
    }

    /// Commit the way back: enqueue the soft-reboot (or the power-off). A
    /// caller that shows a person the result prints it first, because this
    /// stops the terminal; a machine-readable result waits for the outcome.
    pub fn leave(mut self, to: LeaveTo) -> Result<LeaveReport, NailsError> {
        let view = self.manager.session_view();
        let host = RealTargetHost::for_plan(match &view {
            SessionView::Hidden(plan) => Some(&**plan),
            _ => None,
        });
        self.manager.leave_session(to, &host)
    }
}

/// Prepare a deactivation: load the configuration (never refusing, since a
/// broken config must not block the way back), build the manager and check that
/// a hidden session with a way back is running.
pub fn prepare(env: &RuntimeEnv, config_override: Option<&Path>) -> Prepared {
    let config = super::config::load_config_or_defaults(config_override).into_config();
    let state_path = config.state_file_path.clone();
    let manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    let view = manager.session_view();
    prepared(manager, view)
}

/// What a deactivation can do where the probe found the machine (`view`):
/// only the hidden root with its plan has a way back to take.
fn prepared(manager: NailsManager<RealFilesystem>, view: SessionView) -> Prepared {
    match view {
        SessionView::Hidden(plan) => Prepared::Ready(Box::new(ReadyDeactivation { manager, plan })),
        SessionView::HiddenWithoutPlan(why) => Prepared::WayBackUnknown(why),
        SessionView::Entering(_) | SessionView::Interrupted { .. } | SessionView::Decoy => {
            Prepared::NotHidden
        }
    }
}

/// The warnings for leaving `to` with `plan`, given whether the last step of
/// the way back finds `ip`.
fn way_back_warnings(to: LeaveTo, plan: &Plan, finds_ip: bool) -> Vec<String> {
    use crate::next_step::{NextStep, sudo_line};
    if to == LeaveTo::Poweroff || finds_ip {
        return Vec::new();
    }
    let place = if plan.decoy.system.is_some() {
        "in the decoy's NixOS system or the hidden session's system directories"
    } else {
        "in the hidden session's system directories"
    };
    vec![format!(
        "The return finds no `ip` (iproute2) {place}, so the links the session made and the \
         MAC addresses it changed stay on the decoy until power-off. `{}` leaves none of them.",
        sudo_line(NextStep::DeactivatePoweroff)
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, NailsManager, RealFilesystem, RuntimeEnv};

    /// A manager whose hidden volume and state file are under `dir`.
    fn manager_at(dir: &Path) -> NailsManager<RealFilesystem> {
        let hidden = dir.to_path_buf();
        let config = Config {
            hidden_volume_root: hidden.clone(),
            state_file_path: hidden.join("state.json"),
            log_path: hidden.join("logs"),
            ..Config::test_default()
        };
        let state_path = config.state_file_path.clone();
        NailsManager::new(RealFilesystem, config, state_path)
    }

    /// A [`ReadyDeactivation`] whose hidden volume and state file are under
    /// `dir`. The live probe still reads the real machine, which is never a
    /// hidden NAILS overlay root during the tests, so its view is the decoy.
    fn ready_at(dir: &Path) -> ReadyDeactivation {
        ReadyDeactivation {
            manager: manager_at(dir),
            plan: plan(),
        }
    }

    /// A session plan for the probe's view of the hidden root.
    fn plan() -> Box<nails_teardown::whole_root::plan::Plan> {
        use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
        let json = serde_json::json!({
            "version": PLAN_VERSION,
            "hidden_root": "/mnt/data",
            "upper": "/mnt/data/root/upper",
            "work": "/mnt/data/root/work",
            "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
            "decoy": {"init": "/sbin/init"},
            "hidden": {"init": "/sbin/init"},
        });
        Box::new(Plan::from_json(&json.to_string()).expect("a minimal plan"))
    }

    #[test]
    fn leaving_outside_a_hidden_session_refuses_instead_of_reporting_success() {
        // `leave` commits the real way back. Off the hidden root the live
        // view is the decoy, so it must surface the refusal rather than
        // quietly return an empty success report.
        let dir = tempfile::tempdir().unwrap();
        let err = ready_at(dir.path()).leave(LeaveTo::Decoy).unwrap_err();
        assert!(
            matches!(&err, NailsError::InvalidState(msg) if msg.contains("not in a hidden session")),
            "expected a refusal, got {err:?}"
        );
    }

    #[test]
    fn preparing_off_the_hidden_root_reports_not_hidden() {
        // On a machine that is not in a hidden session, prepare must refuse
        // the way back (NotHidden), never hand back a Ready deactivation.
        let env = RuntimeEnv::default();
        assert!(
            matches!(prepare(&env, None), Prepared::NotHidden),
            "a non-hidden machine must prepare NotHidden"
        );
    }

    /// A hidden root whose plan cannot be read has no way back: it is refused
    /// with the probe's reason before anything is asked, never handed out as
    /// a deactivation that confirms, prints and only then fails.
    #[test]
    fn a_hidden_root_without_its_plan_is_refused_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let why = "no session plan in /run (upper /mnt/data/root/upper)";
        match prepared(
            manager_at(dir.path()),
            SessionView::HiddenWithoutPlan(why.to_string()),
        ) {
            Prepared::WayBackUnknown(reason) => assert_eq!(reason, why),
            Prepared::NotHidden => panic!("refused as not hidden"),
            Prepared::Ready(_) => panic!("handed out a deactivation without a way back"),
        }
    }

    /// Only the hidden root with its plan is ready to leave; the decoy, an
    /// entry under way and an interrupted one have no session to end.
    #[test]
    fn only_the_hidden_root_with_its_plan_is_ready_to_leave() {
        let dir = tempfile::tempdir().unwrap();
        let ready = |view| matches!(prepared(manager_at(dir.path()), view), Prepared::Ready(_));
        let not_hidden =
            |view| matches!(prepared(manager_at(dir.path()), view), Prepared::NotHidden);
        assert!(ready(SessionView::Hidden(plan())));
        assert!(not_hidden(SessionView::Decoy));
        assert!(not_hidden(SessionView::Entering(plan())));
        assert!(not_hidden(SessionView::Interrupted {
            plan: Some(plan()),
            nextroot_mounted: true,
        }));
    }

    /// A return whose last step finds no `ip` is announced before the switch,
    /// with the power-off that leaves nothing behind; a power-off, or a return
    /// that finds it, has nothing to announce.
    #[test]
    fn a_return_that_finds_no_ip_is_announced_before_the_switch() {
        use crate::next_step::{NextStep, sudo_line};
        let fhs = plan();
        assert_eq!(
            way_back_warnings(LeaveTo::Decoy, &fhs, false),
            [format!(
                "The return finds no `ip` (iproute2) in the hidden session's system \
                 directories, so the links the session made and the MAC addresses it changed \
                 stay on the decoy until power-off. `{}` leaves none of them.",
                sudo_line(NextStep::DeactivatePoweroff)
            )]
        );
        assert!(way_back_warnings(LeaveTo::Decoy, &fhs, true).is_empty());
        assert!(way_back_warnings(LeaveTo::Poweroff, &fhs, false).is_empty());

        let mut nixos = plan();
        nixos.decoy.system = Some("/nix/store/aaa-nixos-system-decoy".into());
        let warnings = way_back_warnings(LeaveTo::Decoy, &nixos, false);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("in the decoy's NixOS system or the hidden session's"),
            "{warnings:?}"
        );
    }

    /// The prepared deactivation asks the real lookup: a return to a decoy
    /// system that holds `ip` warns of nothing, and a power-off never does.
    #[test]
    fn the_warnings_follow_where_the_return_finds_ip() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("decoy-system");
        std::fs::create_dir_all(system.join("sw/bin")).unwrap();
        std::fs::write(system.join("sw/bin/ip"), "").unwrap();
        let mut ready = ready_at(dir.path());
        ready.plan.decoy.system = Some(system);
        assert!(ready.warnings(LeaveTo::Decoy).is_empty());
        assert!(ready.warnings(LeaveTo::Poweroff).is_empty());
    }
}
