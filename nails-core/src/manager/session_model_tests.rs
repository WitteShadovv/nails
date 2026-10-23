// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Model-based test of the session flow: the operations an operator runs, and
//! the reconciliation `nails status` makes of the record and the live view.
//!
//! A soft-reboot keeps the boot ID, so the state file alone cannot tell the
//! decoy from the hidden root; the live mount table and the session plan can.
//! `status` reconciles the two: `probe_with` turns the live facts into a
//! [`SessionView`], [`StatusCommand::report`] folds that view together with the
//! recorded [`SystemState`] into a [`Posture`], and the activation gate
//! (`judge_session`) refuses to enter a second session on top of a live one.
//! That reconciliation is where the stale-`Active` class of bug lives: a record
//! left at `Active` by a power loss, read next to a plain decoy.
//!
//! The reference model below is the specification. A world is one of the five
//! places the machine can be (the plain decoy, an entry under way, the hidden
//! root with or without its plan, the leftovers of an interrupted entry) with
//! one of four records (inactive, active, degraded, unreadable). Every world is
//! checked on its own, every step is taken from every world, and random
//! sequences of steps walk the model from any world.
//!
//! The operator actions run the real code against a scratch machine, a scratch
//! `/run` and a fixed mount table (`Machine`):
//!
//! - `activate`: the refusal of an unreadable record, the no-op in the hidden
//!   root, the session-state gate, and the record the activation commits before
//!   its soft-reboot (`record_entry`);
//! - `deactivate --poweroff`: the way back (`leave_session_on`);
//! - `emergency --poweroff`: the emergency hot path, judging the plan without
//!   acting on the host, and the record it leaves (`record_inactive`);
//! - `recover`: `recover_session_on`.
//!
//! What a test cannot do for real, the world does as the machine would: the
//! entry's mounts (the world lays down the armed plan `entry::prepare` leaves),
//! the soft-reboot once the real trigger enqueued it, a power cycle, a killed
//! activation and a lost plan. After every step the test checks that the real
//! operation accepted or refused it as the model says, and that the real
//! reconciliation of the world it left matches the model: the view, the
//! posture, the reason and advice, how the record was read, and the gate. A
//! divergence is a bug in one or the other.

use super::*;
use crate::app::emergency::record_inactive;
use crate::session::checks::judge_session;
use crate::{Posture, RuntimeEnv, StatusCommand, StatusReport};
use nails_teardown::whole_root::emergency::{self, Finish};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use tempfile::TempDir;

// --- The reference model -------------------------------------------------

/// Where the machine is, which fixes the [`SessionView`] a probe reads.
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
    /// On the decoy with the leftovers of an interrupted entry: its plan.
    Interrupted,
}

impl Spot {
    const ALL: [Spot; 5] = [
        Spot::Decoy,
        Spot::Entering,
        Spot::Hidden,
        Spot::HiddenNoPlan,
        Spot::Interrupted,
    ];

    /// Whether a session plan is readable here: what the emergency hot path
    /// finds to act on.
    fn has_plan(self) -> bool {
        matches!(self, Spot::Entering | Spot::Hidden | Spot::Interrupted)
    }
}

/// The recorded state, as the state file carries it. [`Corrupt`](Self::Corrupt)
/// stands for a file whose contents do not parse, which reads back as an
/// unknown state (a missing file is a clean `Inactive`, so it is not modelled
/// separately).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    Inactive,
    Active,
    Degraded,
    Corrupt,
}

impl Record {
    const ALL: [Record; 4] = [
        Record::Inactive,
        Record::Active,
        Record::Degraded,
        Record::Corrupt,
    ];
}

/// The abstract state: where the machine is, and what the record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Model {
    spot: Spot,
    record: Record,
}

/// A step: an operator action, which runs the real code, or a machine event,
/// which the world applies as the machine would.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// `nails activate`, up to the soft-reboot it enqueues.
    Activate,
    /// `nails deactivate --poweroff`.
    Deactivate,
    /// `nails emergency --poweroff`.
    Emergency,
    /// `nails recover`.
    Recover,
    /// The soft-reboot an activation enqueued switches into the hidden root.
    Switch,
    /// systemd refuses the soft-reboot an activation enqueues.
    SwitchRefused,
    /// The activation is killed before its soft-reboot.
    Killed,
    /// The session plan in `/run` is lost while the hidden root runs.
    PlanLost,
    /// A power loss or a reset: the next boot is the plain decoy, and the
    /// state file keeps what it held.
    PowerLoss,
}

impl Op {
    const ALL: [Op; 9] = [
        Op::Activate,
        Op::Deactivate,
        Op::Emergency,
        Op::Recover,
        Op::Switch,
        Op::SwitchRefused,
        Op::Killed,
        Op::PlanLost,
        Op::PowerLoss,
    ];
}

impl ReferenceStateMachine for Model {
    type State = Model;
    type Transition = Op;

    fn init_state() -> BoxedStrategy<Self::State> {
        // A run starts in any world, so a case can open on a stale or an
        // unreadable record, an entry under way, an interrupted entry or a
        // hidden root without its plan.
        (
            prop::sample::select(Spot::ALL.to_vec()),
            prop::sample::select(Record::ALL.to_vec()),
        )
            .prop_map(|(spot, record)| Model { spot, record })
            .boxed()
    }

    fn transitions(_state: &Self::State) -> BoxedStrategy<Self::Transition> {
        // Every step is offered from every world. One the machine refuses, or
        // that cannot happen there, changes nothing in the model, and the real
        // operation must refuse it too; there are no pre-conditions to filter,
        // so proptest never rejects a generated transition.
        prop::sample::select(Op::ALL.to_vec()).boxed()
    }

    fn apply(mut state: Self::State, op: &Self::Transition) -> Self::State {
        match (*op, state.spot) {
            // Activation refuses an unreadable record and enters only from the
            // plain decoy. It commits the record to Active before the
            // soft-reboot, because the activating process dies in it.
            (Op::Activate, Spot::Decoy) if state.record != Record::Corrupt => {
                state.spot = Spot::Entering;
                state.record = Record::Active;
            }
            // The way back records the session inactive first, then powers
            // off; the next boot is the plain decoy. Without its plan, or
            // outside the hidden root, it refuses.
            (Op::Deactivate, Spot::Hidden) => {
                state.spot = Spot::Decoy;
                state.record = Record::Inactive;
            }
            // The emergency powers off from anywhere, and records the session
            // inactive only where it found a plan to act on.
            (Op::Emergency, spot) => {
                if spot.has_plan() {
                    state.record = Record::Inactive;
                }
                state.spot = Spot::Decoy;
            }
            // Recover resets a stale active record on the plain decoy and rolls
            // back an interrupted entry; it refuses while an entry or a session
            // is live.
            (Op::Recover, Spot::Decoy) if state.record == Record::Active => {
                state.record = Record::Inactive;
            }
            (Op::Recover, Spot::Interrupted) => {
                state.spot = Spot::Decoy;
                state.record = Record::Inactive;
            }
            (Op::Switch, Spot::Entering) => state.spot = Spot::Hidden,
            // A refused soft-reboot rolls the entry back and records the
            // session inactive.
            (Op::SwitchRefused, Spot::Entering) => {
                state.spot = Spot::Decoy;
                state.record = Record::Inactive;
            }
            (Op::Killed, Spot::Entering) => state.spot = Spot::Interrupted,
            (Op::PlanLost, Spot::Hidden) => state.spot = Spot::HiddenNoPlan,
            (Op::PowerLoss, _) => state.spot = Spot::Decoy,
            _ => {}
        }
        state
    }
}

/// The reconciliation's own prediction for a world.
#[derive(Debug, PartialEq, Eq)]
struct Expected {
    /// The live view `status` names.
    view: &'static str,
    /// The posture.
    posture: Posture,
    /// A part of the reason `status` gives, when it gives one.
    reason: Option<&'static str>,
    /// What the remediation points at, when there is one.
    advice: Option<&'static str>,
    /// How `status` read the record.
    state_source: &'static str,
    /// The recorded state `status` reports.
    recorded: &'static str,
    /// Whether the activation gate lets an entry in.
    gate_accepts: bool,
}

impl Model {
    /// Every world: each place with each record.
    fn all() -> impl Iterator<Item = Model> {
        Spot::ALL.into_iter().flat_map(|spot| {
            Record::ALL
                .into_iter()
                .map(move |record| Model { spot, record })
        })
    }

    /// Whether the real operation accepts `op` here: `Some` for an operator
    /// action, `None` for a machine event.
    fn accepts(self, op: Op) -> Option<bool> {
        match op {
            Op::Activate => Some(self.spot == Spot::Decoy && self.record != Record::Corrupt),
            Op::Deactivate => Some(self.spot == Spot::Hidden),
            Op::Emergency => Some(true),
            Op::Recover => Some(matches!(self.spot, Spot::Decoy | Spot::Interrupted)),
            Op::Switch | Op::SwitchRefused | Op::Killed | Op::PlanLost | Op::PowerLoss => None,
        }
    }

    /// What a correct reconciliation says about this world.
    fn expected(self) -> Expected {
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
            // On the decoy the record decides: an unreadable one is Unknown.
            Spot::Decoy if self.record == Record::Corrupt => Posture::Unknown,
            Spot::Decoy => Posture::Decoy,
        };
        let (reason, advice) = match self.spot {
            Spot::Interrupted => (Some("an interrupted activation left"), Some("recover")),
            Spot::HiddenNoPlan => (
                Some("in the hidden root without a way back"),
                Some("Power off"),
            ),
            // A loaded active record next to the plain decoy is stale: status
            // names it and points at recover, which resets it.
            Spot::Decoy if self.record == Record::Active => (
                Some("still holds an active session"),
                Some("to reset the record"),
            ),
            Spot::Decoy if self.record == Record::Corrupt => (None, Some("verify")),
            _ => (None, None),
        };
        Expected {
            view,
            posture,
            reason,
            advice,
            state_source: if self.record == Record::Corrupt {
                "corrupt"
            } else {
                "loaded"
            },
            // An unreadable record reads back as the inactive default.
            recorded: match self.record {
                Record::Active => "active",
                Record::Degraded => "degraded",
                Record::Inactive | Record::Corrupt => "inactive",
            },
            gate_accepts: self.spot == Spot::Decoy,
        }
    }
}

// --- The concrete world --------------------------------------------------

/// The system under test: a scratch machine whose hidden volume, `/run` and
/// mount table the steps change, with the model state it stands for.
struct World {
    _dir: TempDir,
    /// The scratch tree: the hidden volume, the machine and the config file.
    base: PathBuf,
    /// The hidden volume root.
    hidden: PathBuf,
    /// The scratch `/` and `/run`, and the mount table of the place.
    machine: Machine,
    /// A `nails.toml` naming the hidden volume, which the emergency reads.
    config_file: PathBuf,
    /// The model state the world stands for.
    model: Model,
}

impl World {
    /// A fresh machine laid out as `model` says.
    fn new(model: Model) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let base = dir.path().canonicalize().expect("a canonical directory");
        let hidden = base.join("hidden");
        std::fs::create_dir_all(&hidden).expect("create the hidden volume root");
        let config_file = base.join("nails.toml");
        std::fs::write(
            &config_file,
            format!(
                "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\n",
                hidden.display(),
                hidden.join("state.json").display(),
            ),
        )
        .expect("write the config file");
        let scratch = machine(&base, DECOY_TABLE);
        let mut world = World {
            _dir: dir,
            base,
            hidden,
            machine: scratch,
            config_file,
            model,
        };
        world.write_record(model.record);
        world.lay_out(model.spot);
        world
    }

    fn state_path(&self) -> PathBuf {
        self.hidden.join("state.json")
    }

    /// A manager on this machine's hidden volume, fresh for each operation as
    /// each command runs in a process of its own.
    fn manager(&self) -> NailsManager<RealFilesystem> {
        manager(&self.hidden)
    }

    /// Write the record: a corrupt one does not parse; the rest go through
    /// the real save path, with the integrity digest a clean load needs.
    fn write_record(&self, which: Record) {
        let state = match which {
            Record::Corrupt => {
                std::fs::write(self.state_path(), b"{ not a valid state file ")
                    .expect("write a corrupt record");
                return;
            }
            Record::Inactive => SystemState::Inactive,
            Record::Active => active(),
            Record::Degraded => SystemState::Degraded {
                since: Utc::now(),
                reason: "the way back did not finish".into(),
            },
        };
        record(&self.hidden, state);
    }

    /// The plan an entry under way leaves: armed for the entry and owned by a
    /// live process, this one.
    fn armed_plan(&self) -> Plan {
        let mut armed = plan(&self.hidden);
        let pid = std::process::id();
        let start_time = nails_teardown::proc::stat(pid)
            .expect("this process has a /proc/self/stat")
            .start_time;
        armed.owner = Some(Owner { pid, start_time });
        armed.armed = Some(Arm::now(Direction::Enter));
        armed
    }

    /// Lay the machine out as `spot` presents it: the plan in `/run`, and the
    /// mount table (the decoy's ext4 root, or a root overlay whose upper is on
    /// the hidden volume).
    fn lay_out(&mut self, spot: Spot) {
        match spot {
            Spot::Decoy | Spot::HiddenNoPlan => {
                let _ = std::fs::remove_dir_all(self.machine.paths.runtime());
            }
            Spot::Hidden | Spot::Interrupted => write_plan(&self.machine, &plan(&self.hidden)),
            Spot::Entering => write_plan(&self.machine, &self.armed_plan()),
        }
        let table = match spot {
            Spot::Decoy | Spot::Entering | Spot::Interrupted => DECOY_TABLE.to_string(),
            Spot::Hidden | Spot::HiddenNoPlan => hidden_table(&self.hidden.join("root/upper")),
        };
        self.machine.mounts = Some(parse_mountinfo(&table));
    }

    /// A power-off or a reset, and the next boot: `/run` starts empty and the
    /// root is the plain decoy again. The hidden volume keeps what was written.
    fn power_cycle(&mut self) {
        let _ = std::fs::remove_dir_all(&self.machine.paths.run);
        std::fs::create_dir_all(&self.machine.paths.run).expect("an empty /run");
        self.machine.mounts = Some(parse_mountinfo(DECOY_TABLE));
    }

    /// The live view the operations read: the real probe of the machine.
    fn view(&self) -> SessionView {
        self.manager().session_view_on(&self.machine)
    }

    /// What `status` reports about the machine now.
    fn status(&self) -> StatusReport {
        let manager = self.manager();
        let entries = self.machine.mounts().expect("the fixed mount table");
        StatusCommand::new(RealFilesystem, manager.config().clone(), self.state_path())
            .report(&self.view(), &entries, Utc::now())
            .expect("status builds a report")
    }

    /// Take `op` from the world's model state: run it, check that the real
    /// operation accepted or refused it as the model says and that the world
    /// it left reconciles to the model's next state, and return that state.
    fn step(&mut self, op: Op) -> Model {
        let before = self.model;
        let after = Model::apply(before, &op);
        let accepted = match op {
            Op::Activate => Some(self.activate()),
            Op::Deactivate => Some(self.deactivate()),
            Op::Emergency => Some(self.emergency(before)),
            Op::Recover => Some(self.recover()),
            Op::Switch => {
                self.switch(false);
                None
            }
            Op::SwitchRefused => {
                self.switch(true);
                None
            }
            Op::Killed => {
                self.kill_activation();
                None
            }
            Op::PlanLost => {
                self.lose_plan();
                None
            }
            Op::PowerLoss => {
                self.power_cycle();
                None
            }
        };
        let context = format!("{before:?}, then {op:?}");
        assert_eq!(
            accepted,
            before.accepts(op),
            "{context}: whether the operation ran"
        );
        self.check(after, &context);
        self.model = after;
        after
    }

    /// `nails activate`, up to the soft-reboot it enqueues. It refuses an
    /// unreadable record and changes nothing in the hidden root; elsewhere the
    /// session-state gate decides. An entry it lets in leaves an armed plan in
    /// `/run` (the world lays it down: the mounts `entry::prepare` makes need
    /// privileges) and commits the record to Active before the soft-reboot.
    /// Returns whether it entered.
    fn activate(&mut self) -> bool {
        let mut manager = self.manager();
        let (_, read) = manager
            .current_state_with_outcome()
            .expect("the record can be read");
        if read.is_unknown() {
            return false;
        }
        let view = self.view();
        if view.is_hidden() {
            let outcome = manager
                .enter_session_on(
                    &self.machine,
                    &EnterOptions::default(),
                    &FakeEntryHost::default(),
                )
                .expect("an entry in the hidden root is a no-op");
            assert!(
                matches!(outcome, EnterOutcome::AlreadyActive),
                "{outcome:?}"
            );
            return false;
        }
        if !judge_session(&view).is_pass() {
            return false;
        }
        let armed = self.armed_plan();
        write_plan(&self.machine, &armed);
        let prepared = entry::Entry {
            plan: armed,
            decisions: Vec::new(),
            warnings: Vec::new(),
        };
        manager
            .record_entry(&prepared, std::time::Duration::from_millis(1))
            .expect("the activation records the session");
        true
    }

    /// `nails deactivate --poweroff`: the real way back records the session
    /// inactive and enqueues the power-off, and the next boot is the plain
    /// decoy. (The way back to the decoy without a power-off mounts the decoy
    /// root, which needs privileges.) Returns whether it left.
    fn deactivate(&mut self) -> bool {
        let target = FakeTarget::default();
        let left = self
            .manager()
            .leave_session_on(&self.machine, LeaveTo::Poweroff, &target);
        if left.is_err() {
            assert!(
                target.started.borrow().is_empty(),
                "a refused way back enqueues nothing"
            );
            return false;
        }
        assert_eq!(*target.started.borrow(), ["poweroff.target"]);
        self.power_cycle();
        true
    }

    /// `nails emergency --poweroff`: the real hot path judges the plan it
    /// finds without acting on the host, the record is left as the command
    /// leaves it, and the power-off it enqueues ends in the next boot of the
    /// plain decoy. The hot path reads the live mount table to tell the hidden
    /// side from the decoy side, so here it runs on the decoy side; the record
    /// it leaves depends only on whether it found a plan.
    fn emergency(&mut self, before: Model) -> bool {
        let paths = &self.machine.paths;
        let host = emergency::Host {
            run: paths.run.clone(),
            nextroot: paths.nextroot(),
            runtime_dir: paths.runtime(),
            cgroup_root: self.base.join("cgroup"),
            protected_pids: Vec::new(),
            act: false,
        };
        let report = emergency::run(Plan::load(&paths.plan()).ok(), &host, Finish::Poweroff);
        assert_eq!(
            report.found_nothing(),
            !before.spot.has_plan(),
            "{before:?}: whether the hot path found a plan"
        );
        assert_eq!(report.dispatched, Some(Finish::Poweroff), "{before:?}");
        record_inactive(
            &RuntimeEnv::default(),
            &report,
            Some(self.config_file.as_path()),
        );
        self.power_cycle();
        true
    }

    /// `nails recover`. Returns whether it ran.
    fn recover(&mut self) -> bool {
        self.manager()
            .recover_session_on(&self.machine, &FakeEntryHost::default())
            .is_ok()
    }

    /// The soft-reboot of an entry under way: the real trigger enqueues it and
    /// the machine switches into the hidden root, or, `refused`, systemd
    /// refuses it and the trigger rolls the entry back.
    fn switch(&mut self, refused: bool) {
        if !matches!(self.view(), SessionView::Entering(_)) {
            return;
        }
        let target = FakeTarget {
            refuse: refused,
            ..FakeTarget::default()
        };
        let triggered =
            self.manager()
                .trigger_entry_on(&self.machine, &target, &FakeEntryHost::default());
        assert_eq!(*target.started.borrow(), ["soft-reboot.target"]);
        assert_eq!(triggered.is_err(), refused, "{triggered:?}");
        if !refused {
            self.lay_out(Spot::Hidden);
        }
    }

    /// The activation dies before its soft-reboot: its armed plan stays in
    /// `/run`, and the owner's pid now names another process.
    fn kill_activation(&mut self) {
        let SessionView::Entering(plan) = self.view() else {
            return;
        };
        let mut orphaned = *plan;
        if let Some(owner) = orphaned.owner.as_mut() {
            owner.start_time += 1;
        }
        write_plan(&self.machine, &orphaned);
    }

    /// The plan in `/run` is lost while the hidden root runs.
    fn lose_plan(&mut self) {
        if matches!(self.view(), SessionView::Hidden(_)) {
            std::fs::remove_file(self.machine.paths.plan()).expect("remove the plan");
        }
    }

    /// Assert that the real reconciliation of the machine matches `model`.
    fn check(&self, model: Model, context: &str) {
        let report = self.status();
        let expected = model.expected();
        assert_eq!(report.session, expected.view, "{context}: the live view");
        assert_eq!(report.posture, expected.posture, "{context}: the posture");
        assert_eq!(
            report.state_source, expected.state_source,
            "{context}: how the record was read"
        );
        assert_eq!(
            report.state.label(),
            expected.recorded,
            "{context}: the recorded state"
        );
        match expected.reason {
            Some(part) => assert!(
                report.reason.as_deref().is_some_and(|r| r.contains(part)),
                "{context}: the reason names {part:?}: {:?}",
                report.reason
            ),
            None => assert_eq!(report.reason, None, "{context}: no reason"),
        }
        match expected.advice {
            Some(part) => assert!(
                report
                    .remediation
                    .as_deref()
                    .is_some_and(|r| r.contains(part)),
                "{context}: the advice names {part:?}: {:?}",
                report.remediation
            ),
            None => assert_eq!(report.remediation, None, "{context}: no advice"),
        }
        assert_eq!(
            judge_session(&self.view()).is_pass(),
            expected.gate_accepts,
            "{context}: the activation gate"
        );
    }
}

/// The system-under-test driver the `prop_state_machine!` macro runs.
struct Walk;

impl StateMachineTest for Walk {
    type SystemUnderTest = World;
    type Reference = Model;

    fn init_test(ref_state: &Model) -> World {
        let world = World::new(*ref_state);
        world.check(*ref_state, &format!("{ref_state:?}"));
        world
    }

    fn apply(mut world: World, ref_state: &Model, op: Op) -> World {
        let after = world.step(op);
        assert_eq!(after, *ref_state, "the world follows the reference model");
        world
    }
}

prop_state_machine! {
    #![proptest_config(ProptestConfig {
        // Each step writes a few small files and runs a real operation and the
        // reconciliation, so a few dozen sequences of up to a couple of dozen
        // steps walk well past the single steps the exhaustive test takes.
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Random sequences of operator actions and machine events, from any
    /// world, keep the real operations and the reconciliation in step with the
    /// reference model after every step.
    #[test]
    fn random_walks_follow_the_model(sequential 1..24 => Walk);
}

// --- Exhaustive guards ---------------------------------------------------

/// Every world reconciles as the model says: each place with each record, the
/// view, the posture, the reason and advice `status` gives, how it read the
/// record, and whether the activation gate lets an entry in. A regression that
/// lets the gate pass on a live session (the class the stale-`Active` bug was)
/// fails here.
#[test]
fn every_world_reconciles_as_the_model_says() {
    for model in Model::all() {
        World::new(model).check(model, &format!("{model:?}"));
    }
}

/// Every step from every world: the real operation accepts or refuses it as
/// the model says, and the world it leaves reconciles to the model's next
/// state.
#[test]
fn every_step_from_every_world_follows_the_model() {
    for model in Model::all() {
        for op in Op::ALL {
            World::new(model).step(op);
        }
    }
}

/// A power loss in the hidden session leaves the record at `Active` while the
/// machine boots the plain decoy: status reports a decoy posture, names the
/// record as stale, and `recover` resets it. This is the exact reconciliation
/// the stale-`Active` bug got wrong.
#[test]
fn a_power_loss_in_session_reads_as_a_stale_record_until_recover() {
    let mut world = World::new(Model {
        spot: Spot::Decoy,
        record: Record::Inactive,
    });
    for (op, spot, record) in [
        (Op::Activate, Spot::Entering, Record::Active),
        (Op::Switch, Spot::Hidden, Record::Active),
        (Op::PowerLoss, Spot::Decoy, Record::Active),
        (Op::Recover, Spot::Decoy, Record::Inactive),
    ] {
        assert_eq!(world.step(op), Model { spot, record }, "{op:?}");
    }
}
