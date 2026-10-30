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
//! where the way back is unknown; [`ReadyDeactivation::foresee`] tells what
//! the return is bound to leave, which makes it power off instead, and
//! [`ReadyDeactivation::warnings`] names what the return will not put back,
//! for the front end to show before it asks;
//! [`ReadyDeactivation::lock`] takes the exclusive state lock once the front
//! end has confirmed; and [`LockedDeactivation::leave`], on the only handle
//! that leaves, commits the way back once the front end has, for a person,
//! printed. A machine-readable result waits for the commit, so it reports the
//! outcome.

use std::path::{Path, PathBuf};

use nails_teardown::whole_root::fresh_pids;
use nails_teardown::whole_root::network::Foreseen;
use nails_teardown::whole_root::plan::Plan;

use super::lock::LockError;
use crate::hidden_root::Allow;
use crate::session::leave::NetworkTool;
use crate::session::{LeaveReport, LeaveTo, RealTargetHost, SessionView, TargetHost};
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
    /// Where that step sets the process-number counter, which
    /// [`warnings`](Self::warnings) checks it can.
    pid_places: fresh_pids::Places,
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

    /// What the return to the decoy is bound to leave of the links and MAC
    /// addresses as they are now, which makes its last step power off instead
    /// ([`way_back_foresees`](crate::session::leave::way_back_foresees)).
    /// Nothing for a power-off.
    pub fn foresee(&self, to: LeaveTo) -> Foreseen {
        if to == LeaveTo::Poweroff {
            return Foreseen::default();
        }
        crate::session::leave::way_back_foresees(&self.root, self.plan.decoy.system.as_deref())
    }

    /// What the return to the decoy will not put back, as far as the hidden
    /// session can tell before the switch, one sentence each, for the front
    /// end to show before it asks: what it is bound to leave (`foreseen`,
    /// from [`foresee`](Self::foresee)), which makes it power off instead;
    /// then that its last step, which cannot report, finds no `ip` to delete
    /// the session's virtual links and policy-routing rules and set the MAC
    /// addresses back with, no `nft` to delete the session's nftables tables
    /// with, or, where a link is a Wi-Fi interface, no `iw` to delete the
    /// Wi-Fi interfaces the session added on the decoy's radios with
    /// ([`way_back_lacks`](crate::session::leave::way_back_lacks)); or that
    /// it cannot number the decoy's units from where the decoy's own boot
    /// numbered them ([`fresh_pids::way_back_can_lower`]), or finds no getty
    /// or logind to measure where by ([`fresh_pids::counter`]). None for a
    /// power-off, after which the decoy starts afresh.
    pub fn warnings(&self, to: LeaveTo, foreseen: &Foreseen) -> Vec<String> {
        let mut warnings = way_back_warnings(
            to,
            &self.plan,
            &crate::session::leave::way_back_lacks(&self.root, self.plan.decoy.system.as_deref()),
            foreseen,
        );
        warnings.extend(pid_warning(
            to,
            fresh_pids::way_back_can_lower(&self.plan.pids, &self.pid_places),
            fresh_pids::counter(&self.plan.pids, &self.root.join("proc")).is_some(),
        ));
        warnings
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
    /// `/`, where it also sets the process-number counter. Outside tests only
    /// [`prepare`] hands one out, and only in a hidden
    /// root with its plan. The lock step is the real one, and the handle it
    /// hands out leaves only from a hidden root the live probe finds.
    pub fn for_test(config: crate::Config, plan: Plan, root: &Path) -> Self {
        let state_path = config.state_file_path.clone();
        Self {
            manager: NailsManager::new(RealFilesystem, config, state_path),
            plan: Box::new(plan),
            root: root.to_path_buf(),
            pid_places: fresh_pids::Places::under(root),
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
    /// Whether the way back may start now: not while a program blocks
    /// shutdown, or while logind does not answer whether one does
    /// ([`TargetHost::may_switch`]). [`leave`](Self::leave) asks again
    /// itself; a caller that shows a person what comes asks first, so that a
    /// refusal comes before it.
    pub fn may_leave(&self) -> Result<(), NailsError> {
        let view = self.ready.manager.session_view();
        RealTargetHost::for_plan(match &view {
            SessionView::Hidden(plan) => Some(&**plan),
            _ => None,
        })
        .may_switch()
    }

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
            pid_places: fresh_pids::Places::system(),
        })),
        SessionView::HiddenWithoutPlan(why) => Prepared::WayBackUnknown(why),
        SessionView::Entering(_) | SessionView::Interrupted { .. } | SessionView::Decoy => {
            Prepared::NotHidden
        }
    }
}

/// Why the way back is bound to power off instead of returning, for a person
/// to read before the switch ([`power_off_reason`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerOffReason {
    /// What the way back cannot undo, as the start of a sentence: "The way
    /// back cannot delete tunl0, which the kernel keeps".
    pub what: String,
    /// Whether it powers off whatever happens before it runs: a link the
    /// kernel keeps never goes, where the session's own stop may still take
    /// another link down or set an address back.
    pub certain: bool,
}

impl PowerOffReason {
    /// "unless that changes before it runs, " where the power-off is not
    /// [`certain`](Self::certain), for the clause before the power-off.
    pub fn unless(&self) -> &'static str {
        if self.certain {
            ""
        } else {
            "unless that changes before it runs, "
        }
    }
}

/// Why the way back is bound to power off, from what it is bound to leave
/// (`foreseen`); `None` when nothing there makes it.
pub fn power_off_reason(foreseen: &Foreseen) -> Option<PowerOffReason> {
    let mut clauses = Vec::new();
    if !foreseen.kernel_kept.is_empty() {
        clauses.push(format!(
            "cannot delete {}, which the kernel keeps",
            joined(&foreseen.kernel_kept)
        ));
    }
    let mut with_ip = Vec::new();
    if !foreseen.links_without_ip.is_empty() {
        with_ip.push(format!("delete {}", joined(&foreseen.links_without_ip)));
    }
    match foreseen.addresses_without_ip.as_slice() {
        [] => {}
        [one] => with_ip.push(format!("set the MAC address of {one} back")),
        many => with_ip.push(format!("set the MAC addresses of {} back", joined(many))),
    }
    let mut missing = Vec::new();
    if !with_ip.is_empty() {
        missing.push(format!("no `ip` to {} with", with_ip.join(" or ")));
    }
    if !foreseen.wifi_without_iw.is_empty() {
        missing.push(format!(
            "no `iw` to delete {} with",
            joined(&foreseen.wifi_without_iw)
        ));
    }
    if !missing.is_empty() {
        clauses.push(format!("finds {}", missing.join(" and ")));
    }
    if clauses.is_empty() {
        return None;
    }
    Some(PowerOffReason {
        what: format!("The way back {}", clauses.join(", and ")),
        certain: !foreseen.kernel_kept.is_empty(),
    })
}

/// `names` in a sentence: `a`, `a and b`, or `a, b and c`.
fn joined(names: &[String]) -> String {
    match names.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// The warnings for leaving `to` with `plan`: why the way back is bound to
/// power off (`foreseen`), then one for each network tool its last step
/// `lacks`.
fn way_back_warnings(
    to: LeaveTo,
    plan: &Plan,
    lacks: &[NetworkTool],
    foreseen: &Foreseen,
) -> Vec<String> {
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
    let bound = power_off_reason(foreseen).map(|reason| {
        format!(
            "{}, so {}the machine powers off instead of returning to the decoy. `{poweroff}` \
             powers off at once.",
            reason.what,
            reason.unless()
        )
    });
    bound
        .into_iter()
        .chain(lacks.iter().map(|tool| {
            let (tool, stays) = match tool {
                NetworkTool::Ip => (
                    "`ip` (iproute2)",
                    "the policy-routing rules the session added stay on the decoy until \
                     power-off, and a virtual link it made or a MAC address it changed makes the \
                     machine power off instead of returning",
                ),
                NetworkTool::Nft => (
                    "`nft` (nftables)",
                    "the nftables tables the session added stay on the decoy until power-off (a \
                     VPN app's table that blocks all traffic outside its tunnel keeps the decoy \
                     offline)",
                ),
                NetworkTool::Iw => (
                    "`iw`",
                    "a Wi-Fi interface the session added on one of the decoy's radios (a \
                     monitor or access point interface, or the one iwd makes in place of the \
                     decoy's, as it does by default when it starts) makes the machine power off \
                     instead of returning",
                ),
            };
            format!(
                "The return finds no {tool} {place}, so {stays}. `{poweroff}` leaves none of \
                 them."
            )
        }))
        .collect()
}

/// The warning for leaving `to` when the last step of the way back cannot
/// set the process-number counter back (`lowers` false), or has no getty or
/// logind to measure by (`measured` false) and can only set it to just below
/// the lowest number the decoy's own userspace held at entry.
fn pid_warning(to: LeaveTo, lowers: bool, measured: bool) -> Option<String> {
    use crate::next_step::{NextStep, sudo_line};
    if to == LeaveTo::Poweroff || (lowers && measured) {
        return None;
    }
    let poweroff = sudo_line(NextStep::DeactivatePoweroff);
    Some(if lowers {
        format!(
            "The return finds no getty or logind to measure the decoy's process numbers by, so \
             it numbers the decoy's processes from just below the lowest number its own \
             userspace held when the session began, and where the decoy keeps classic wtmp, its \
             getty and login records can carry process numbers that a fresh boot would not give \
             them. `{poweroff}` leaves none of them."
        )
    } else {
        format!(
            "The return cannot number the decoy's processes from where its own boot numbered \
             them, so where the decoy keeps classic wtmp, its getty and login records carry \
             process numbers that continue from this boot. `{poweroff}` leaves none of them."
        )
    })
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
    /// way back's last step are under `dir`. Its handle still leaves from what
    /// the live probe sees of the machine, so the test that leaves with it
    /// gives it a `/run` of its own.
    fn ready_at(dir: &Path) -> ReadyDeactivation {
        let mut plan = plan();
        plan.pids = nails_teardown::test_support::stage_pid_measure(dir);
        ReadyDeactivation {
            manager: manager_at(dir),
            plan,
            root: dir.to_path_buf(),
            pid_places: fresh_pids::Places::under(dir),
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

    /// Nothing the way back is bound to leave.
    fn none() -> Foreseen {
        Foreseen::default()
    }

    /// A way back bound to leave the link the kernel keeps once a session
    /// loads `ipip`.
    fn kept() -> Foreseen {
        Foreseen {
            kernel_kept: vec!["tunl0".to_string()],
            ..Foreseen::default()
        }
    }

    /// The locked handle of `ready`, taking the lock beside its state file
    /// without the attach gate (the scratch directory is no mount point).
    fn locked(ready: ReadyDeactivation) -> LockedDeactivation {
        ready
            .lock_with(crate::app::lock::acquire_unattached)
            .unwrap_or_else(|error| panic!("the lock step refused: {error:?}"))
    }

    /// `leave` commits the real way back, from what the live probe sees. On
    /// the plain decoy it must surface the refusal rather than quietly return
    /// an empty success report. The test runs in a PID, user and mount
    /// namespace of its own with a fresh `/run`: the probe finds no session
    /// plan there, whatever the host runs, and neither `systemctl` nor
    /// `busctl` finds the host's service manager or logind, whose sockets are
    /// in the host's `/run`.
    #[test]
    fn leaving_outside_a_hidden_session_refuses_instead_of_reporting_success() {
        let _ = crate::test_support::Rerun::new(crate::test_path!(
            leaving_outside_a_hidden_session_refuses_instead_of_reporting_success
        ))
        .in_pid_ns()
        .run(|| {
            nix::mount::mount(
                Some("tmpfs"),
                "/run",
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                Some("mode=0755"),
            )
            .expect("a fresh /run");
            let dir = tempfile::tempdir().unwrap();
            let err = locked(ready_at(dir.path()))
                .leave(LeaveTo::Decoy)
                .unwrap_err();
            assert!(
                matches!(&err, NailsError::InvalidState(msg) if msg.contains("not in a hidden session")),
                "expected a refusal, got {err:?}"
            );
        });
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
            way_back_warnings(LeaveTo::Decoy, &fhs, &NetworkTool::ALL, &none()),
            [
                format!(
                    "The return finds no `ip` (iproute2) in the hidden session's system \
                     directories, so the policy-routing rules the session added stay on the \
                     decoy until power-off, and a virtual link it made or a MAC address it \
                     changed makes the machine power off instead of returning. `{poweroff}` \
                     leaves none of them."
                ),
                format!(
                    "The return finds no `nft` (nftables) in the hidden session's system \
                     directories, so the nftables tables the session added stay on the decoy \
                     until power-off (a VPN app's table that blocks all traffic outside its \
                     tunnel keeps the decoy offline). `{poweroff}` leaves none of them."
                ),
                format!(
                    "The return finds no `iw` in the hidden session's system directories, so a \
                     Wi-Fi interface the session added on one of the decoy's radios (a monitor \
                     or access point interface, or the one iwd makes in place of the decoy's, as \
                     it does by default when it starts) makes the machine power off instead of \
                     returning. `{poweroff}` leaves none of them."
                ),
            ]
        );
        assert!(way_back_warnings(LeaveTo::Decoy, &fhs, &[], &none()).is_empty());
        assert!(way_back_warnings(LeaveTo::Poweroff, &fhs, &NetworkTool::ALL, &kept()).is_empty());

        let mut nixos = plan();
        nixos.decoy.system = Some("/nix/store/aaa-nixos-system-decoy".into());
        let warnings = way_back_warnings(LeaveTo::Decoy, &nixos, &[NetworkTool::Nft], &none());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].starts_with(
                "The return finds no `nft` (nftables) in the decoy's NixOS system or the hidden \
                 session's system directories, so"
            ),
            "{warnings:?}"
        );
    }

    /// What the way back is bound to leave comes first, as one sentence that
    /// says why the machine powers off instead of returning, and whether
    /// anything before the way back runs can still change it: a link the
    /// kernel keeps never goes, a link or address it finds no tool for may.
    #[test]
    fn a_way_back_bound_to_power_off_says_so_first() {
        use crate::next_step::{NextStep, sudo_line};
        let poweroff = sudo_line(NextStep::DeactivatePoweroff);
        let fhs = plan();
        let warnings = way_back_warnings(LeaveTo::Decoy, &fhs, &[NetworkTool::Iw], &kept());
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert_eq!(
            warnings[0],
            format!(
                "The way back cannot delete tunl0, which the kernel keeps, so the machine powers \
                 off instead of returning to the decoy. `{poweroff}` powers off at once."
            )
        );
        assert!(
            warnings[1].starts_with("The return finds no `iw`"),
            "{warnings:?}"
        );
        let without_iw = Foreseen {
            wifi_without_iw: vec!["wlan1".to_string()],
            ..Foreseen::default()
        };
        assert_eq!(
            way_back_warnings(LeaveTo::Decoy, &fhs, &[], &without_iw),
            [format!(
                "The way back finds no `iw` to delete wlan1 with, so unless that changes before \
                 it runs, the machine powers off instead of returning to the decoy. `{poweroff}` \
                 powers off at once."
            )]
        );
    }

    /// The reason names each thing the way back cannot undo, the links the
    /// kernel keeps first, then by the tool it finds none of; it is certain
    /// only with a link the kernel keeps.
    #[test]
    fn the_reason_names_what_the_way_back_cannot_undo() {
        assert_eq!(power_off_reason(&none()), None);
        let reason = power_off_reason(&kept()).unwrap();
        assert_eq!(
            reason.what,
            "The way back cannot delete tunl0, which the kernel keeps"
        );
        assert!(reason.certain);
        assert_eq!(reason.unless(), "");
        let names = |names: &[&str]| names.iter().map(ToString::to_string).collect::<Vec<_>>();
        let all = Foreseen {
            kernel_kept: names(&["tunl0", "sit0"]),
            links_without_ip: names(&["wg0"]),
            addresses_without_ip: names(&["eth0", "eth1"]),
            wifi_without_iw: names(&["wlan1", "wlan2", "mon0"]),
        };
        assert_eq!(
            power_off_reason(&all).unwrap().what,
            "The way back cannot delete tunl0 and sit0, which the kernel keeps, and finds no `ip` \
             to delete wg0 or set the MAC addresses of eth0 and eth1 back with and no `iw` to \
             delete wlan1, wlan2 and mon0 with"
        );
        let address = Foreseen {
            addresses_without_ip: names(&["eth0"]),
            ..Foreseen::default()
        };
        let reason = power_off_reason(&address).unwrap();
        assert_eq!(
            reason.what,
            "The way back finds no `ip` to set the MAC address of eth0 back with"
        );
        assert!(!reason.certain);
        assert_eq!(reason.unless(), "unless that changes before it runs, ");
    }

    /// A power-off is bound to leave nothing: the decoy starts afresh.
    #[test]
    fn a_power_off_foresees_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready_at(dir.path());
        assert_eq!(ready.foresee(LeaveTo::Poweroff), none());
        // Without the record entry takes, a return is bound to leave nothing
        // either: the way back then leaves the links alone.
        assert_eq!(ready.foresee(LeaveTo::Decoy), none());
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
        let warned =
            |lacks: &[NetworkTool]| way_back_warnings(LeaveTo::Decoy, &ready.plan, lacks, &none());
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), warned(&[Ip, Nft]));
        assert!(ready.warnings(LeaveTo::Poweroff, &none()).is_empty());
        put(fhs.path(), "usr/bin/ip");
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), warned(&[Nft]));
        put(fhs.path(), "usr/sbin/nft");
        assert!(ready.warnings(LeaveTo::Decoy, &none()).is_empty());
        put_wifi_link(fhs.path());
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), warned(&[Iw]));
        put(fhs.path(), "sbin/iw");
        assert!(ready.warnings(LeaveTo::Decoy, &none()).is_empty());

        let nixos = tempfile::tempdir().unwrap();
        let mut ready = ready_at(nixos.path());
        ready.plan.decoy.system = Some("/nix/store/aaa-nixos-system-decoy".into());
        put_wifi_link(nixos.path());
        for tool in ["ip", "nft", "iw"] {
            put(nixos.path(), &format!("run/current-system/sw/bin/{tool}"));
        }
        let warned = way_back_warnings(LeaveTo::Decoy, &ready.plan, &NetworkTool::ALL, &none());
        assert_eq!(warned.len(), 3, "{warned:?}");
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), warned);
        for tool in ["ip", "nft", "iw"] {
            put(
                nixos.path(),
                &format!("nix/store/aaa-nixos-system-decoy/sw/bin/{tool}"),
            );
        }
        assert!(ready.warnings(LeaveTo::Decoy, &none()).is_empty());
        assert!(ready.warnings(LeaveTo::Poweroff, &none()).is_empty());
    }

    /// The return warns when its last step will not be able to number the
    /// decoy's processes from where its own boot did: no floor in the plan, or
    /// a counter it cannot write. Never for a power-off.
    #[test]
    fn the_return_warns_when_it_cannot_set_the_process_numbers_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut ready = ready_at(dir.path());
        for tool in ["usr/bin/ip", "usr/sbin/nft"] {
            put(dir.path(), tool);
        }
        assert!(ready.warnings(LeaveTo::Decoy, &none()).is_empty());
        let warning = pid_warning(LeaveTo::Decoy, false, true).unwrap();
        assert!(warning.contains("continue from this boot"), "{warning}");
        let expected = vec![warning];
        ready.plan.pids.floor = None;
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), expected);
        ready.plan.pids.floor = Some(388);
        std::fs::remove_file(dir.path().join("proc/sys/kernel/ns_last_pid")).unwrap();
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), expected);
        assert!(ready.warnings(LeaveTo::Poweroff, &none()).is_empty());
        assert_eq!(pid_warning(LeaveTo::Poweroff, false, false), None);
        assert_eq!(pid_warning(LeaveTo::Decoy, true, true), None);
        assert_eq!(
            pid_warning(LeaveTo::Decoy, false, false),
            expected.first().cloned()
        );
    }

    /// The return warns, too, when its last step can set the counter but
    /// finds no getty or logind that both the decoy's start and the hidden
    /// start ran to measure where to by, so it can only set it to just below
    /// the floor. Never for a power-off.
    #[test]
    fn the_return_warns_when_it_has_nothing_to_measure_the_process_numbers_by() {
        let dir = tempfile::tempdir().unwrap();
        let ready = ready_at(dir.path());
        for tool in ["usr/bin/ip", "usr/sbin/nft"] {
            put(dir.path(), tool);
        }
        let warning = pid_warning(LeaveTo::Decoy, true, false).unwrap();
        assert!(warning.contains("no getty or logind"), "{warning}");
        let expected = vec![warning];
        // The hidden start's getty is gone.
        std::fs::remove_dir_all(dir.path().join("proc/9150")).unwrap();
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), expected);
        assert!(ready.warnings(LeaveTo::Poweroff, &none()).is_empty());
        // The decoy had none to anchor on.
        let mut ready = ready_at(dir.path());
        ready.plan.pids.anchors.clear();
        assert_eq!(ready.warnings(LeaveTo::Decoy, &none()), expected);
        assert_eq!(pid_warning(LeaveTo::Poweroff, true, false), None);
    }
}
