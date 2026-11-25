// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `deactivate` operation: end the hidden session.
//!
//! A hidden session never goes back to the decoy's kernel: deactivation ends
//! it the way every hidden session ends, with a power-off
//! ([`session_end`](nails_teardown::whole_root::session_end::session_end)). It
//! records the state inactive and enqueues `poweroff.target`. A front end
//! confirms with the operator and shows a person the result before the
//! power-off stops its terminal, so the operation is split: [`prepare`]
//! builds the manager and refuses, before anything is asked, outside a hidden
//! session; [`ReadyDeactivation::lock`] takes the exclusive state lock once
//! the front end has confirmed; and [`LockedDeactivation::leave`], on the only
//! handle that leaves, commits the power-off once the front end has, for a
//! person, printed. A machine-readable result waits for the commit, so it
//! reports the outcome.

use std::path::Path;

use super::lock::LockError;
use crate::hidden_root::Allow;
use crate::session::{RealTargetHost, SessionView};
use crate::{NailsError, NailsManager, RealFilesystem, RuntimeEnv, StateLock};

/// What ends the session where `deactivate` takes no lock or records nothing
/// before the power-off, as a person reads it: the emergency, which needs
/// neither, so no failure there strands the session.
pub fn emergency_needs_no_lock() -> String {
    use crate::next_step::{NextStep, sudo_line};
    format!(
        "`{}` ends the session without the lock: it powers off at once",
        sudo_line(NextStep::Emergency)
    )
}

/// The result of preparing a deactivation.
pub enum Prepared {
    /// Not in a hidden session, so there is nothing to deactivate.
    NotHidden,
    /// In a hidden session: ready to confirm, lock and leave.
    Ready(Box<ReadyDeactivation>),
}

/// A deactivation whose preconditions hold, ready to lock. It cannot leave:
/// only the [`LockedDeactivation`] its [`lock`](Self::lock) step hands out
/// can.
///
/// ```compile_fail
/// fn leave_unlocked(ready: nails_core::app::deactivate::ReadyDeactivation) {
///     let _ = ready.leave();
/// }
/// ```
///
/// ```
/// fn leave_locked(locked: &mut nails_core::app::deactivate::LockedDeactivation) {
///     let _ = locked.leave();
/// }
/// ```
pub struct ReadyDeactivation {
    manager: NailsManager<RealFilesystem>,
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
    /// A deactivation with its hidden volume and state file where `config`
    /// names them, for tests of a front end. Outside tests only [`prepare`]
    /// hands one out, and only in a hidden root. The lock step is the real
    /// one, and the handle it hands out leaves only from a hidden root the
    /// live probe finds.
    pub fn for_test(config: crate::Config) -> Self {
        let state_path = config.state_file_path.clone();
        Self {
            manager: NailsManager::new(RealFilesystem, config, state_path),
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
    /// The host [`leave`](Self::leave) leaves with: PID 1 and logind, asked
    /// with the tools the session plan records, where it can be read.
    fn host(&self) -> RealTargetHost {
        let view = self.ready.manager.session_view();
        RealTargetHost::for_plan(match &view {
            SessionView::Hidden(plan) => Some(&**plan),
            _ => None,
        })
    }

    /// Whether the session may end now: not while a program blocks
    /// shutdown, or while logind does not answer whether one does
    /// ([`may_leave`](crate::session::leave::may_leave)). [`leave`](Self::leave)
    /// asks again itself; a caller that shows a person what comes asks first,
    /// so that a refusal comes before it.
    pub fn may_leave(&self) -> Result<(), NailsError> {
        crate::session::leave::may_leave(&self.host())
    }

    /// Commit the session's end: enqueue the power-off. A caller that shows
    /// a person the result prints it first, because this stops the terminal;
    /// a machine-readable result waits for the outcome.
    pub fn leave(&mut self) -> Result<(), NailsError> {
        let host = self.host();
        self.ready.manager.leave_session(&host)
    }
}

/// Prepare a deactivation: load the configuration (never refusing, since a
/// broken config must not block the end of the session), build the manager
/// and check that a hidden session is running.
pub fn prepare(env: &RuntimeEnv, config_override: Option<&Path>) -> Prepared {
    let config = super::config::load_config_or_defaults(config_override).into_config();
    let state_path = config.state_file_path.clone();
    let manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    let view = manager.session_view();
    prepared(manager, view)
}

/// What a deactivation can do where the probe found the machine (`view`):
/// only a hidden root has a session to end, with its plan or without (the
/// power-off needs none).
fn prepared(manager: NailsManager<RealFilesystem>, view: SessionView) -> Prepared {
    match view {
        SessionView::Hidden(_) | SessionView::HiddenWithoutPlan(_) => {
            Prepared::Ready(Box::new(ReadyDeactivation { manager }))
        }
        SessionView::Entering(_) | SessionView::Interrupted { .. } | SessionView::Decoy => {
            Prepared::NotHidden
        }
    }
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
    /// `dir`. Its handle still leaves from what the live probe sees of the
    /// machine, so the test that leaves with it gives it a `/run` of its own.
    fn ready_at(dir: &Path) -> ReadyDeactivation {
        ReadyDeactivation {
            manager: manager_at(dir),
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

    /// `leave` commits the real power-off, from what the live probe sees. On
    /// the plain decoy it must surface the refusal rather than quietly
    /// report a success. The test runs in a PID, user and mount namespace of
    /// its own with a fresh `/run`: the probe finds no hidden root there,
    /// whatever the host runs, and neither `systemctl` nor `busctl` finds the
    /// host's service manager or logind, whose sockets are in the host's
    /// `/run`.
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
            let err = locked(ready_at(dir.path())).leave().unwrap_err();
            assert!(
                matches!(&err, NailsError::InvalidState(msg) if msg.contains("not in a hidden session")),
                "expected a refusal, got {err:?}"
            );
        });
    }

    /// The locked handle asks logind whether a program blocks shutdown, and
    /// nothing about the guards a switch needs: none comes. The namespaces
    /// are those of the test above; stand-ins below its `/run` answer for a
    /// logind that lists an inhibitor or none, as a file there says, and a
    /// PID 1 whose service watchdogs are off. They only print: nothing is
    /// started.
    #[test]
    fn the_locked_handle_asks_logind_only() {
        let _ =
            crate::test_support::Rerun::new(crate::test_path!(the_locked_handle_asks_logind_only))
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
                    let bin = Path::new("/run/current-system/sw/bin");
                    std::fs::create_dir_all(bin).unwrap();
                    let inhibitors = Path::new("/run/inhibitors");
                    crate::test_support::write_executable(
                        &bin.join("busctl"),
                        format!(
                            "#!/bin/sh\nIFS= read -r line < {}\necho \"$line\"\n",
                            inhibitors.display()
                        ),
                        0o755,
                    );
                    crate::test_support::write_executable(
                        &bin.join("systemctl"),
                        "#!/bin/sh\ncase \"$*\" in\n\
                 'show --property=ServiceWatchdogs --value') echo no ;;\n\
                 esac\nexit 0\n",
                        0o755,
                    );
                    std::fs::write(inhibitors, "{\"type\":\"a(ssssuu)\",\"data\":[[]]}\n").unwrap();
                    let dir = tempfile::tempdir().unwrap();
                    let locked = locked(ready_at(dir.path()));
                    locked.may_leave().unwrap();

                    std::fs::write(
                        inhibitors,
                        "{\"type\":\"a(ssssuu)\",\"data\":[[[\"shutdown\",\"apt\",\"Installing\",\
                 \"block\",0,4242]]]}\n",
                    )
                    .unwrap();
                    let error = locked.may_leave().unwrap_err();
                    assert!(error.to_string().contains("apt blocks shutdown"), "{error}");
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
        // (NotHidden), never hand back a Ready deactivation.
        let env = RuntimeEnv::default();
        assert!(
            matches!(prepare(&env, None), Prepared::NotHidden),
            "a non-hidden machine must prepare NotHidden"
        );
    }

    /// A hidden root has a session to end, with its plan or without: the
    /// power-off needs none. The decoy, an entry under way and an
    /// interrupted one have no session to end.
    #[test]
    fn only_a_hidden_root_is_ready_to_leave_with_its_plan_or_without() {
        let dir = tempfile::tempdir().unwrap();
        let ready = |view| matches!(prepared(manager_at(dir.path()), view), Prepared::Ready(_));
        let not_hidden =
            |view| matches!(prepared(manager_at(dir.path()), view), Prepared::NotHidden);
        assert!(ready(SessionView::Hidden(plan())));
        assert!(ready(SessionView::HiddenWithoutPlan(
            "no session plan in /run".to_string()
        )));
        assert!(not_hidden(SessionView::Decoy));
        assert!(not_hidden(SessionView::Entering(plan())));
        assert!(not_hidden(SessionView::Interrupted {
            plan: Some(plan()),
            nextroot_mounted: true,
        }));
    }

    #[test]
    fn the_emergency_hint_promises_no_return() {
        let hint = emergency_needs_no_lock();
        assert!(hint.contains("powers off"), "{hint}");
        assert!(!hint.contains("return"), "{hint}");
    }
}
