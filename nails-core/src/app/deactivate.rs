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
//! the return will not put back, for the front end to show before it asks;
//! [`ReadyDeactivation::lock`] takes the exclusive state lock once the front
//! end has confirmed; and [`LockedDeactivation::leave`], on the only handle
//! that leaves, commits the way back once the front end has, for a person,
//! printed. A machine-readable result waits for the commit, so it reports the
//! outcome.

use std::path::{Path, PathBuf};

use nails_teardown::whole_root::plan::Plan;

use super::lock::LockError;
use crate::hidden_root::Allow;
use crate::session::leave::NetworkTool;
use crate::session::{LeaveReport, LeaveTo, RealTargetHost, SessionView};
use crate::{NailsError, NailsManager, RealFilesystem, RuntimeEnv, StateLock};

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

/// A deactivation whose preconditions hold, ready to lock. It cannot leave:
/// only the [`LockedDeactivation`] its [`lock`](Self::lock) step hands out
/// can.
///
/// ```compile_fail
/// fn leave_unlocked(ready: nails_core::app::deactivate::ReadyDeactivation) {
///     let _ = ready.leave(nails_core::session::LeaveTo::Decoy);
/// }
/// ```
///
/// ```
/// fn leave_locked(locked: &mut nails_core::app::deactivate::LockedDeactivation) {
///     let _ = locked.leave(nails_core::session::LeaveTo::Decoy);
/// }
/// ```
pub struct ReadyDeactivation {
    manager: NailsManager<RealFilesystem>,
    /// The session plan the probe read, which the way back returns with.
    plan: Box<Plan>,
    /// The root the way back's last step runs in (`/`, but in tests), where
    /// [`warnings`](Self::warnings) looks for the tools that step runs.
    root: PathBuf,
}

impl ReadyDeactivation {
    /// The hidden volume root, which the state lock is taken on.
    fn hidden_root(&self) -> &Path {
        &self.manager.config().hidden_volume_root
    }

    /// The state file path, beside which the state lock lies.
    fn state_path(&self) -> &Path {
        &self.manager.config().state_file_path
    }

    /// What the return to the decoy will not put back, as far as the hidden
    /// session can tell before the switch, one sentence each, for the front
    /// end to show before it asks: its last step, which cannot report, finds
    /// no `ip` to delete the session's virtual links and policy-routing rules
    /// and set the MAC addresses back with, no `nft` to delete the session's
    /// nftables tables with, or, where a link is a Wi-Fi interface, no `iw` to
    /// delete the Wi-Fi interfaces the session added on the decoy's radios
    /// with ([`way_back_lacks`](crate::session::leave::way_back_lacks)). None
    /// for a power-off, after which the decoy starts afresh.
    pub fn warnings(&self, to: LeaveTo) -> Vec<String> {
        way_back_warnings(
            to,
            &self.plan,
            &crate::session::leave::way_back_lacks(&self.root, self.plan.decoy.system.as_deref()),
        )
    }

    /// Take the exclusive state lock on the hidden volume. Hands out the only
    /// handle that leaves, which holds the lock until it is dropped.
    pub fn lock(self) -> Result<LockedDeactivation, LockError> {
        self.lock_with(super::lock::acquire_mutating)
    }

    /// [`lock`](Self::lock), taking the lock with `acquire`.
    fn lock_with(
        self,
        acquire: impl FnOnce(&Path, Allow, &Path) -> Result<StateLock, LockError>,
    ) -> Result<LockedDeactivation, LockError> {
        let lock = acquire(self.hidden_root(), Allow::Nothing, self.state_path())?;
        Ok(LockedDeactivation {
            ready: self,
            _lock: lock,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ReadyDeactivation {
    /// A deactivation of the hidden session `plan` describes, for tests of a
    /// front end: its hidden volume and state file where `config` names them,
    /// and the way back's last step running in the tree at `root` instead of
    /// `/`. Outside tests only [`prepare`] hands one out, and only in a hidden
    /// root with its plan. The lock step is the real one, and the handle it
    /// hands out leaves only from a hidden root the live probe finds.
    pub fn for_test(config: crate::Config, plan: Plan, root: &Path) -> Self {
        let state_path = config.state_file_path.clone();
        Self {
            manager: NailsManager::new(RealFilesystem, config, state_path),
            plan: Box::new(plan),
            root: root.to_path_buf(),
        }
    }
}

/// A deactivation that holds the exclusive state lock: the only handle that
/// leaves. The lock is released when it is dropped.
pub struct LockedDeactivation {
    ready: ReadyDeactivation,
    /// Held for its `Drop`, which releases the lock.
    _lock: StateLock,
}

impl LockedDeactivation {
    /// Commit the way back: enqueue the soft-reboot (or the power-off). A
    /// caller that shows a person the result prints it first, because this
    /// stops the terminal; a machine-readable result waits for the outcome.
    pub fn leave(&mut self, to: LeaveTo) -> Result<LeaveReport, NailsError> {
        let manager = &mut self.ready.manager;
        let view = manager.session_view();
        let host = RealTargetHost::for_plan(match &view {
            SessionView::Hidden(plan) => Some(&**plan),
            _ => None,
        });
        manager.leave_session(to, &host)
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
        SessionView::Hidden(plan) => Prepared::Ready(Box::new(ReadyDeactivation {
            manager,
            plan,
            root: PathBuf::from("/"),
        })),
        SessionView::HiddenWithoutPlan(why) => Prepared::WayBackUnknown(why),
        SessionView::Entering(_) | SessionView::Interrupted { .. } | SessionView::Decoy => {
            Prepared::NotHidden
        }
    }
}

/// The warnings for leaving `to` with `plan`, one for each network tool the
/// last step of the way back `lacks`.
fn way_back_warnings(to: LeaveTo, plan: &Plan, lacks: &[NetworkTool]) -> Vec<String> {
    use crate::next_step::{NextStep, sudo_line};
    if to == LeaveTo::Poweroff {
        return Vec::new();
    }
    let place = if plan.decoy.system.is_some() {
        "in the decoy's NixOS system or the hidden session's system directories"
    } else {
        "in the hidden session's system directories"
    };
    let poweroff = sudo_line(NextStep::DeactivatePoweroff);
    lacks
        .iter()
        .map(|tool| {
            let (tool, stays) = match tool {
                NetworkTool::Ip => (
                    "`ip` (iproute2)",
                    "the virtual links the session made, the MAC addresses it changed and the \
                     policy-routing rules it added stay on the decoy until power-off",
                ),
                NetworkTool::Nft => (
                    "`nft` (nftables)",
                    "the nftables tables the session added stay on the decoy until power-off (a \
                     VPN app's table that blocks all traffic outside its tunnel keeps the decoy \
                     offline)",
                ),
                NetworkTool::Iw => (
                    "`iw`",
                    "the Wi-Fi interfaces the session added on the decoy's radios (monitor or \
                     access point interfaces) stay on the decoy until power-off",
                ),
            };
            format!(
                "The return finds no {tool} {place}, so {stays}. `{poweroff}` leaves none of \
                 them."
            )
        })
        .collect()
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

    /// A [`ReadyDeactivation`] whose hidden volume, state file and root of the
    /// way back's last step are under `dir`. The live probe still reads the
    /// real machine, which is never a hidden NAILS overlay root during the
    /// tests, so its view is the decoy.
    fn ready_at(dir: &Path) -> ReadyDeactivation {
        ReadyDeactivation {
            manager: manager_at(dir),
            plan: plan(),
            root: dir.to_path_buf(),
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

    /// The locked handle of `ready`, taking the lock beside its state file
    /// without the attach gate (the scratch directory is no mount point).
    fn locked(ready: ReadyDeactivation) -> LockedDeactivation {
        ready
            .lock_with(crate::app::lock::acquire_unattached)
            .unwrap_or_else(|error| panic!("the lock step refused: {error:?}"))
    }

    #[test]
    fn leaving_outside_a_hidden_session_refuses_instead_of_reporting_success() {
        // `leave` commits the real way back. Off the hidden root the live
        // view is the decoy, so it must surface the refusal rather than
        // quietly return an empty success report.
        let dir = tempfile::tempdir().unwrap();
        let err = locked(ready_at(dir.path()))
            .leave(LeaveTo::Decoy)
            .unwrap_err();
        assert!(
            matches!(&err, NailsError::InvalidState(msg) if msg.contains("not in a hidden session")),
            "expected a refusal, got {err:?}"
        );
    }

    /// The handle that leaves holds the state lock for as long as it lives,
    /// and the real lock step runs the attach gate first.
    #[test]
    fn the_lock_step_holds_the_lock_for_the_handle_that_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let locked = locked(ready_at(dir.path()));
        assert!(crate::StateLock::try_acquire(dir.path()).is_err());
        drop(locked);
        assert!(crate::StateLock::try_acquire(dir.path()).is_ok());
        assert!(matches!(
            ready_at(dir.path()).lock(),
            Err(LockError::Refused(_))
        ));
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

    /// Each network tool a return's last step finds no copy of is announced
    /// before the switch, in the order the tools are named, with what stays
    /// on the decoy without it and the power-off that leaves nothing behind;
    /// a power-off, or a return that finds them all, has nothing to announce.
    #[test]
    fn each_network_tool_a_return_lacks_is_announced_before_the_switch() {
        use crate::next_step::{NextStep, sudo_line};
        let poweroff = sudo_line(NextStep::DeactivatePoweroff);
        let fhs = plan();
        assert_eq!(
            way_back_warnings(LeaveTo::Decoy, &fhs, &NetworkTool::ALL),
            [
                format!(
                    "The return finds no `ip` (iproute2) in the hidden session's system \
                     directories, so the virtual links the session made, the MAC addresses it \
                     changed and the policy-routing rules it added stay on the decoy until \
                     power-off. `{poweroff}` leaves none of them."
                ),
                format!(
                    "The return finds no `nft` (nftables) in the hidden session's system \
                     directories, so the nftables tables the session added stay on the decoy \
                     until power-off (a VPN app's table that blocks all traffic outside its \
                     tunnel keeps the decoy offline). `{poweroff}` leaves none of them."
                ),
                format!(
                    "The return finds no `iw` in the hidden session's system directories, so the \
                     Wi-Fi interfaces the session added on the decoy's radios (monitor or access \
                     point interfaces) stay on the decoy until power-off. `{poweroff}` leaves \
                     none of them."
                ),
            ]
        );
        assert!(way_back_warnings(LeaveTo::Decoy, &fhs, &[]).is_empty());
        assert!(way_back_warnings(LeaveTo::Poweroff, &fhs, &NetworkTool::ALL).is_empty());

        let mut nixos = plan();
        nixos.decoy.system = Some("/nix/store/aaa-nixos-system-decoy".into());
        let warnings = way_back_warnings(LeaveTo::Decoy, &nixos, &[NetworkTool::Nft]);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with(
                "The return finds no `nft` (nftables) in the decoy's NixOS system or the hidden \
                 session's system directories, so"
            ),
            "{warnings:?}"
        );
    }

    /// Put an empty file at `path` below `root`.
    fn put(root: &Path, path: &str) {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "").unwrap();
    }

    /// List a Wi-Fi interface of radio `phy0` below the tree's
    /// `/sys/class/net`, as the kernel lists one.
    fn put_wifi_link(root: &Path) {
        let link = root.join("sys/class/net/wlan0");
        std::fs::create_dir_all(link.join("device")).unwrap();
        std::fs::write(link.join("ifindex"), "3\n").unwrap();
        std::os::unix::fs::symlink("../../ieee80211/phy0", link.join("phy80211")).unwrap();
    }

    /// The prepared deactivation looks for the network tools where the
    /// return's last step will, in the root that step runs in: in the hidden
    /// root's system directories, and on NixOS first in the decoy's system
    /// that step repoints `/run/current-system` to, never in the hidden system
    /// the link names until then; `iw` only where a link is a Wi-Fi interface.
    /// Each it finds no copy of is warned of; once it finds them all, or for a
    /// power-off, nothing is.
    #[test]
    fn the_warnings_follow_where_the_return_looks_for_its_network_tools() {
        use NetworkTool::{Ip, Iw, Nft};
        let fhs = tempfile::tempdir().unwrap();
        let ready = ready_at(fhs.path());
        let warned = |lacks: &[NetworkTool]| way_back_warnings(LeaveTo::Decoy, &ready.plan, lacks);
        assert_eq!(ready.warnings(LeaveTo::Decoy), warned(&[Ip, Nft]));
        assert!(ready.warnings(LeaveTo::Poweroff).is_empty());
        put(fhs.path(), "usr/bin/ip");
        assert_eq!(ready.warnings(LeaveTo::Decoy), warned(&[Nft]));
        put(fhs.path(), "usr/sbin/nft");
        assert!(ready.warnings(LeaveTo::Decoy).is_empty());
        put_wifi_link(fhs.path());
        assert_eq!(ready.warnings(LeaveTo::Decoy), warned(&[Iw]));
        put(fhs.path(), "sbin/iw");
        assert!(ready.warnings(LeaveTo::Decoy).is_empty());

        let nixos = tempfile::tempdir().unwrap();
        let mut ready = ready_at(nixos.path());
        ready.plan.decoy.system = Some("/nix/store/aaa-nixos-system-decoy".into());
        put_wifi_link(nixos.path());
        for tool in ["ip", "nft", "iw"] {
            put(nixos.path(), &format!("run/current-system/sw/bin/{tool}"));
        }
        let warned = way_back_warnings(LeaveTo::Decoy, &ready.plan, &NetworkTool::ALL);
        assert_eq!(warned.len(), 3, "{warned:?}");
        assert_eq!(ready.warnings(LeaveTo::Decoy), warned);
        for tool in ["ip", "nft", "iw"] {
            put(
                nixos.path(),
                &format!("nix/store/aaa-nixos-system-decoy/sw/bin/{tool}"),
            );
        }
        assert!(ready.warnings(LeaveTo::Decoy).is_empty());
        assert!(ready.warnings(LeaveTo::Poweroff).is_empty());
    }
}
