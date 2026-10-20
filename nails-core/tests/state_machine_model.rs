// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Model-based test over the reconciliation of the recorded state and the live
//! session view.
//!
//! A soft-reboot keeps the boot ID, so the state file alone cannot tell the
//! decoy from the hidden root; the live mount table and the session plan can.
//! `nails status` reconciles the two: [`probe_with`] turns the live facts into
//! a [`SessionView`], [`StatusCommand::report`] folds that view together with
//! the recorded [`SystemState`] into a [`Posture`], and the activation gate
//! ([`judge_session`]) refuses to enter a second session on top of a live one.
//! That reconciliation is pure, and it is where the stale-`Active` class of bug
//! lives (a record left at `Active` by a power loss, read next to a plain
//! decoy).
//!
//! This drives it as a state machine: random `activate`/`deactivate`/
//! `emergency`/`recover`/crash sequences walk an abstract reference model, and
//! after every step the test materialises the concrete world the model
//! describes (a state file, a session plan and a mount table on disk) and
//! asserts that the real reconciliation of that world matches the model, and
//! that the activation gate accepts the step exactly on the plain decoy. The
//! reference model is the specification; a divergence is a reconciliation bug.

use chrono::{DateTime, Utc};
use nails_core::session::Paths;
use nails_core::session::checks::judge_session;
use nails_core::session::probe::probe_with;
use nails_core::{Config, Posture, RealFilesystem, StateFile, StatusCommand, SystemState};
use nails_teardown::mountinfo::{MountEntry, parse_mountinfo};
use nails_teardown::whole_root::plan::{
    Arm, DecoyRoot, Direction, Owner, PLAN_VERSION, Plan, PolicyMount, PolicyMountKind, RootSide,
    Tools, unix_now,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// --- The reference model -------------------------------------------------

/// Where the machine really is, which fixes the [`SessionView`] a probe of the
/// world yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spot {
    /// The plain decoy root.
    Decoy,
    /// On the decoy, an armed entry whose activation process is still alive.
    Entering,
    /// In the hidden root, with its plan readable.
    Hidden,
    /// In an overlay root on the hidden volume, but with no readable plan.
    HiddenNoPlan,
    /// On the decoy with the leftovers of an interrupted entry (a stale plan).
    Interrupted,
}

/// The recorded state, as the state file carries it. [`Corrupt`](Self::Corrupt)
/// stands for a file whose contents do not parse, which reads back as an
/// unknown state (a missing file is a clean `Inactive`, so it is not modelled
/// separately here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    Inactive,
    Active,
    Degraded,
    Corrupt,
}

/// The abstract state: where the machine is, and what the record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Model {
    spot: Spot,
    record: Record,
}

/// An operator action or a loss of power, the transitions the model walks.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// `nails activate`.
    Activate,
    /// `nails deactivate`.
    Deactivate,
    /// `nails emergency`.
    Emergency,
    /// `nails recover`.
    Recover,
    /// A power loss, a reset or an interrupted soft-reboot: the live world
    /// resets, the state file does not.
    Crash,
}

impl ReferenceStateMachine for Model {
    type State = Model;
    type Transition = Op;

    fn init_state() -> BoxedStrategy<Self::State> {
        // Every run begins on the decoy. The record varies, so a case can open
        // already holding a stale `Active` record or an unreadable one.
        prop_oneof![
            Just(Record::Inactive),
            Just(Record::Active),
            Just(Record::Degraded),
            Just(Record::Corrupt),
        ]
        .prop_map(|record| Model {
            spot: Spot::Decoy,
            record,
        })
        .boxed()
    }

    fn transitions(_state: &Self::State) -> BoxedStrategy<Self::Transition> {
        // Every action is offered from every state. An action the live facts
        // forbid is a no-op in the model, and the concrete test asserts that
        // the real gate refuses it; there are no pre-conditions to filter, so
        // proptest never rejects a generated transition.
        prop_oneof![
            Just(Op::Activate),
            Just(Op::Deactivate),
            Just(Op::Emergency),
            Just(Op::Recover),
            Just(Op::Crash),
        ]
        .boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            // Entry is allowed only from the plain decoy (the session-state
            // gate refuses every other view). It commits the record to
            // `Active` and soft-reboots into the hidden root.
            Op::Activate => {
                if state.spot == Spot::Decoy {
                    state.spot = Spot::Hidden;
                    state.record = Record::Active;
                }
            }
            // The way back acts only from the hidden root with a readable plan;
            // it writes the record inactive before it returns to the decoy.
            Op::Deactivate => {
                if state.spot == Spot::Hidden {
                    state.spot = Spot::Decoy;
                    state.record = Record::Inactive;
                }
            }
            // Emergency returns to the decoy from wherever the machine is and
            // resets the record.
            Op::Emergency => {
                state.spot = Spot::Decoy;
                state.record = Record::Inactive;
            }
            // Recover clears the leftovers of an interrupted entry, and clears a
            // stale `Active` record left on the decoy; it refuses while a
            // session or an entry is live.
            Op::Recover => match state.spot {
                Spot::Interrupted => {
                    state.spot = Spot::Decoy;
                    state.record = Record::Inactive;
                }
                Spot::Decoy if state.record == Record::Active => {
                    state.record = Record::Inactive;
                }
                _ => {}
            },
            // A crash drops the live session without touching the record: the
            // hidden root and a plan-less hidden root both fall back to the
            // decoy (so an `Active` record is now stale), and an entry under
            // way is left interrupted.
            Op::Crash => match state.spot {
                Spot::Hidden | Spot::HiddenNoPlan => state.spot = Spot::Decoy,
                Spot::Entering => state.spot = Spot::Interrupted,
                _ => {}
            },
        }
        state
    }
}

// --- The concrete world --------------------------------------------------

/// The reconciliation's own prediction for a model state: the live view, the
/// posture, whether the record reads as a stale active session, and whether the
/// activation gate accepts an entry here.
#[derive(Debug, PartialEq, Eq)]
struct Expected {
    view: &'static str,
    posture: Posture,
    stale_active_record: bool,
    gate_accepts: bool,
}

impl Model {
    /// What a correct reconciliation must say about this state.
    fn expected(&self) -> Expected {
        let on_decoy = self.spot == Spot::Decoy;
        let view = match self.spot {
            Spot::Decoy => "decoy",
            Spot::Entering => "entering",
            Spot::Hidden => "hidden",
            Spot::HiddenNoPlan => "hidden_without_plan",
            Spot::Interrupted => "interrupted",
        };
        let posture = match self.spot {
            Spot::Hidden => Posture::Active,
            Spot::Entering => Posture::Transitioning,
            Spot::HiddenNoPlan | Spot::Interrupted => Posture::Degraded,
            // On the decoy the record decides: an unreadable record is Unknown,
            // an active one is still a Decoy posture but flagged as stale.
            Spot::Decoy if self.record == Record::Corrupt => Posture::Unknown,
            Spot::Decoy => Posture::Decoy,
        };
        Expected {
            view,
            posture,
            // Only a loaded `Active` record next to a decoy posture is stale; a
            // corrupt file reads back as the default inactive state.
            stale_active_record: on_decoy && self.record == Record::Active,
            gate_accepts: on_decoy,
        }
    }
}

/// The concrete system under test: a temporary hidden volume the test
/// materialises a world into, and a `status` command reading it.
struct World {
    _dir: TempDir,
    hidden_root: PathBuf,
    paths: Paths,
    command: StatusCommand<RealFilesystem>,
}

/// A session plan for the hidden volume at `hidden_root`, without an entry
/// armed and without an owner: the shape `status` reads in the hidden root and
/// in an interrupted entry.
fn base_plan(hidden_root: &Path) -> Plan {
    let side = RootSide {
        init: PathBuf::from("/run/current-system/systemd/lib/systemd/systemd"),
        system: Some(PathBuf::from("/nix/store/bbb-nixos-system")),
    };
    Plan {
        version: PLAN_VERSION,
        hidden_root: hidden_root.to_path_buf(),
        hidden_dev: None,
        accepted_decoy_storage: None,
        upper: hidden_root.join("root/upper"),
        work: hidden_root.join("root/work"),
        owner: None,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".into(),
            data: None,
        },
        decoy: RootSide {
            system: Some(PathBuf::from("/nix/store/aaa-nixos-system")),
            ..side.clone()
        },
        hidden: side,
        policy_mounts: vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }],
        masks: vec!["dev-vda3.swap".into()],
        boot_masks: Vec::new(),
        session_units: Vec::new(),
        backend: Vec::new(),
        tools: Tools::default(),
        armed: None,
        entered_at: Some(1_700_000_000),
        run_noexec: false,
        carried: Vec::new(),
        decoy_mounts: Vec::new(),
        read_only_disks: false,
        failed_at_entry: Vec::new(),
        kernel_settings: Vec::new(),
    }
}

impl World {
    /// A fresh hidden volume in a temporary directory the world owns, with a
    /// `status` command reading its state file.
    fn new() -> Self {
        let dir = TempDir::new().expect("a temporary directory");
        let hidden_root = dir.path().join("data");
        std::fs::create_dir_all(&hidden_root).expect("create the hidden volume root");
        let paths = Paths {
            root: dir.path().join("root"),
            run: dir.path().join("run"),
        };
        let state_path = hidden_root.join("state.json");
        let config = Config {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: state_path.clone(),
            log_path: hidden_root.join("logs"),
            ..Config::test_default()
        };
        let command = StatusCommand::new(RealFilesystem, config, state_path);
        World {
            _dir: dir,
            hidden_root,
            paths,
            command,
        }
    }

    fn state_path(&self) -> PathBuf {
        self.hidden_root.join("state.json")
    }

    /// Write the state file the record describes. A corrupt record is a file
    /// that does not parse; the rest are written through the real save path, so
    /// they carry the integrity digest a clean load needs.
    fn write_record(&self, record: Record) {
        let path = self.state_path();
        match record {
            Record::Corrupt => {
                std::fs::write(&path, b"{ not a valid state file ").expect("write a corrupt file");
            }
            Record::Inactive | Record::Active | Record::Degraded => {
                let state = match record {
                    Record::Inactive => SystemState::Inactive,
                    Record::Active => SystemState::Active {
                        activated_at: fixed_time(),
                    },
                    Record::Degraded => SystemState::Degraded {
                        since: fixed_time(),
                        reason: "the way back did not finish".into(),
                    },
                    Record::Corrupt => unreachable!(),
                };
                let file = StateFile {
                    state,
                    ..StateFile::default()
                };
                file.save_with_custom_root(&path, &self.hidden_root)
                    .expect("save the state file onto the hidden volume");
            }
        }
    }

    /// Write or remove the session plan so a probe reads the spot's view.
    fn write_plan(&self, spot: Spot) {
        let plan_path = self.paths.plan();
        let runtime = plan_path.parent().expect("the plan has a parent directory");
        std::fs::create_dir_all(runtime).expect("create the runtime directory");
        match spot {
            // No readable plan on the plain decoy or a plan-less hidden root.
            Spot::Decoy | Spot::HiddenNoPlan => {
                let _ = std::fs::remove_file(&plan_path);
            }
            Spot::Hidden | Spot::Interrupted => {
                base_plan(&self.hidden_root)
                    .write_atomic(&plan_path)
                    .expect("write the plan");
            }
            // An entry under way: armed for Enter, owned by this live process,
            // so the probe sees the owner alive.
            Spot::Entering => {
                let mut plan = base_plan(&self.hidden_root);
                plan.armed = Some(Arm {
                    direction: Direction::Enter,
                    at: unix_now(),
                });
                let pid = std::process::id();
                let start_time = nails_teardown::proc::stat(pid)
                    .expect("this process has a /proc/self/stat")
                    .start_time;
                plan.owner = Some(Owner { pid, start_time });
                plan.write_atomic(&plan_path).expect("write the plan");
            }
        }
    }

    /// The mount table the spot presents: a plain ext4 root, or a root overlay
    /// whose upper is on the hidden volume.
    fn mount_table(&self, spot: Spot) -> Vec<MountEntry> {
        let table = match spot {
            Spot::Decoy | Spot::Entering | Spot::Interrupted => {
                "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n".to_string()
            }
            Spot::Hidden | Spot::HiddenNoPlan => {
                let upper = self.hidden_root.join("root/upper");
                let work = self.hidden_root.join("root/work");
                format!(
                    "1 0 0:40 / / rw - overlay overlay \
                     rw,lowerdir=/decoy,upperdir={},workdir={}\n\
                     2 1 253:0 / {} rw - ext4 /dev/mapper/data rw\n",
                    upper.display(),
                    work.display(),
                    self.hidden_root.display(),
                )
            }
        };
        parse_mountinfo(&table)
    }

    /// Materialise the world for `model` and assert the real reconciliation
    /// matches its own prediction.
    fn check(&self, model: Model) {
        self.write_record(model.record);
        self.write_plan(model.spot);
        let entries = self.mount_table(model.spot);

        // The live view the mount table and the plan reconcile to.
        let view = probe_with(&self.paths, &self.hidden_root, &entries);
        let report = self
            .command
            .report(&view, &entries, fixed_time())
            .expect("status builds a report");
        let expected = model.expected();

        assert_eq!(
            report.session, expected.view,
            "{model:?}: the live view the probe read"
        );
        assert_eq!(
            report.posture, expected.posture,
            "{model:?}: the reconciled posture"
        );

        // The stale-active reconciliation: a decoy posture next to a loaded
        // active record carries the "the record still holds an active session"
        // note and points at `recover`, and nothing else does.
        let names_stale_record = report
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("still holds an active session"));
        assert_eq!(
            names_stale_record, expected.stale_active_record,
            "{model:?}: the stale-active note (reason: {:?})",
            report.reason
        );
        if expected.stale_active_record {
            assert_eq!(
                report.remediation,
                Some("Run `nails recover` to reset the record"),
                "{model:?}: a stale record points at recover"
            );
        }

        // The activation gate: it accepts an entry only on the plain decoy, and
        // refuses every live-session view. This is the forbidden-transition
        // guard that keeps an `activate` from running on top of a session.
        assert_eq!(
            judge_session(&view).is_pass(),
            expected.gate_accepts,
            "{model:?}: the activation gate's verdict"
        );
    }
}

/// A fixed timestamp, so a report is deterministic (the posture never depends
/// on it, and the uptime is only read, not asserted).
fn fixed_time() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("a valid timestamp")
}

/// The system-under-test driver the `prop_state_machine!` macro runs.
struct Reconciliation;

impl StateMachineTest for Reconciliation {
    type SystemUnderTest = World;
    type Reference = Model;

    fn init_test(ref_state: &Model) -> Self::SystemUnderTest {
        let world = World::new();
        world.check(*ref_state);
        world
    }

    fn apply(
        state: Self::SystemUnderTest,
        ref_state: &Model,
        _transition: Op,
    ) -> Self::SystemUnderTest {
        state.check(*ref_state);
        state
    }
}

prop_state_machine! {
    #![proptest_config(ProptestConfig {
        // Each step writes a few small files and runs the reconciliation, so a
        // few dozen sequences of up to a couple of dozen steps covers the
        // reachable combinations without a slow suite.
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Random operator-and-crash sequences keep the real reconciliation in step
    /// with the reference model after every transition.
    #[test]
    fn reconciliation_tracks_the_model(sequential 1..24 => Reconciliation);
}

// --- Focused guards ------------------------------------------------------

/// Every non-decoy view is a seeded illegal activation: the gate must refuse
/// each one, and accept only the plain decoy. A regression that let the gate
/// pass on a live session (the class the stale-`Active` bug was) fails here.
#[test]
fn activation_is_refused_from_every_non_decoy_view() {
    let world = World::new();
    for spot in [
        Spot::Entering,
        Spot::Hidden,
        Spot::HiddenNoPlan,
        Spot::Interrupted,
    ] {
        world.write_record(Record::Inactive);
        world.write_plan(spot);
        let entries = world.mount_table(spot);
        let view = probe_with(&world.paths, &world.hidden_root, &entries);
        assert!(
            !judge_session(&view).is_pass(),
            "{spot:?}: the gate must refuse an entry on a live session"
        );
    }

    world.write_record(Record::Inactive);
    world.write_plan(Spot::Decoy);
    let entries = world.mount_table(Spot::Decoy);
    let view = probe_with(&world.paths, &world.hidden_root, &entries);
    assert!(
        judge_session(&view).is_pass(),
        "the gate must accept an entry on the plain decoy"
    );
}

/// The record materialised for each spot reads back as the view the model
/// names, so the proptest harness is asserting against the facts it means to.
#[test]
fn every_spot_materialises_its_view() {
    let world = World::new();
    for (spot, view) in [
        (Spot::Decoy, "decoy"),
        (Spot::Entering, "entering"),
        (Spot::Hidden, "hidden"),
        (Spot::HiddenNoPlan, "hidden_without_plan"),
        (Spot::Interrupted, "interrupted"),
    ] {
        world.write_record(Record::Inactive);
        world.write_plan(spot);
        let entries = world.mount_table(spot);
        let probed = probe_with(&world.paths, &world.hidden_root, &entries);
        let report = world
            .command
            .report(&probed, &entries, fixed_time())
            .expect("status builds a report");
        assert_eq!(report.session, view, "{spot:?}");
    }
}

/// A power loss in the hidden session leaves the record at `Active` while the
/// machine boots the plain decoy: status must report a decoy posture and name
/// the record as stale. This is the exact reconciliation the stale-`Active` bug
/// got wrong.
#[test]
fn a_crash_in_session_reads_as_a_stale_active_record() {
    let model = Model::apply(
        Model {
            spot: Spot::Decoy,
            record: Record::Inactive,
        },
        &Op::Activate,
    );
    assert_eq!(model.spot, Spot::Hidden);
    assert_eq!(model.record, Record::Active);
    let crashed = Model::apply(model, &Op::Crash);
    assert_eq!(crashed.spot, Spot::Decoy);
    assert_eq!(
        crashed.record,
        Record::Active,
        "the crash leaves the record"
    );

    let world = World::new();
    world.check(crashed);
}
