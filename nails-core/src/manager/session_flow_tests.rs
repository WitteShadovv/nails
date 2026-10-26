// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the whole-root session through the manager.
//!
//! Each test hands the flow a [`Machine`] of its own: a scratch `/` and `/run`
//! and a fixed mount table, so the live view (decoy, interrupted, entering,
//! hidden) is whatever the test lays out. The full entry runs in a private
//! user + mount namespace on scratch tmpfs. Kept in a sibling file so
//! `session_flow.rs` stays within the production line budget.

use super::*;
use crate::nixos::NixOSBuilder;
use crate::platform::FakePlatform;
use crate::test_support::{Rerun, ScratchTmpfs, write_executable};
use crate::{Config, PlatformState, RealFilesystem, StateFile};
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::plan::{
    Arm, DecoyRoot, Direction, Owner, PLAN_VERSION, Plan, RootSide, Tools,
};
use std::cell::{Cell, RefCell};
use std::path::Path;

// The model-based test of the session flow and its reconciliation, on the
// scratch machines and fakes below.
#[path = "session_model_tests.rs"]
mod model;

/// The plain decoy: `/` is the decoy's own ext4.
const DECOY_TABLE: &str = "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n";

/// Counts the reloads; nothing else is asked of it outside the namespace test.
#[derive(Default)]
struct FakeEntryHost {
    reloads: Cell<u32>,
    /// Request a cancel during the first reload, as a Ctrl+C would.
    cancel_at_reload: bool,
}

impl EntryHost for FakeEntryHost {
    fn daemon_reload(&self) -> Result<()> {
        if self.cancel_at_reload && self.reloads.get() == 0 {
            crate::cancel::testing::request();
        }
        self.reloads.set(self.reloads.get() + 1);
        Ok(())
    }
    fn build_hidden_system(&self, _: &NixOSBuilder, _: &Path, _: &Path) -> Result<PathBuf> {
        Err(NailsError::NixOSError("not in this test".into()))
    }
    fn keep_hidden_closure(
        &self,
        _: &Path,
        _: &Path,
        _: &Path,
    ) -> Result<crate::session::store::KeepReport> {
        Err(NailsError::NixOSError("not in this test".into()))
    }
    fn activate_hidden_system(&self, _: &Path, _: &Path) -> Result<()> {
        Ok(())
    }
    fn unit_stop_commands(&self, _: &str) -> Result<String> {
        Ok(String::new())
    }
}

/// Records the targets started; refuses them when `refuse` is set.
#[derive(Default)]
struct FakeTarget {
    started: RefCell<Vec<String>>,
    refuse: bool,
}

impl TargetHost for FakeTarget {
    fn start_target(&self, target: &str) -> Result<()> {
        self.started.borrow_mut().push(target.to_string());
        if self.refuse {
            return Err(NailsError::InvalidState(format!("{target} refused")));
        }
        Ok(())
    }
}

/// A manager whose hidden volume (and state file) is `hidden`.
fn manager(hidden: &Path) -> NailsManager<RealFilesystem> {
    let config = Config {
        hidden_volume_root: hidden.to_path_buf(),
        state_file_path: hidden.join("state.json"),
        log_path: hidden.join("logs"),
        ..Config::test_default()
    };
    NailsManager::new(RealFilesystem, config, hidden.join("state.json"))
}

/// A scratch `/` and `/run` below `dir`, seen through `table`.
fn machine(dir: &Path, table: &str) -> Machine {
    let paths = Paths {
        root: dir.join("root"),
        run: dir.join("run"),
    };
    std::fs::create_dir_all(&paths.root).unwrap();
    std::fs::create_dir_all(&paths.run).unwrap();
    Machine {
        paths,
        mounts: Some(parse_mountinfo(table)),
    }
}

/// The table of a hidden root whose upper is `upper`.
fn hidden_table(upper: &Path) -> String {
    format!(
        "1 0 0:40 / / rw - overlay overlay rw,lowerdir=/x,upperdir={},workdir=/w\n",
        upper.display()
    )
}

fn plan(hidden: &Path) -> Plan {
    let side = RootSide {
        init: PathBuf::from("/usr/lib/systemd/systemd"),
        system: None,
    };
    Plan {
        version: PLAN_VERSION,
        hidden_root: hidden.to_path_buf(),
        hidden_dev: None,
        accepted_decoy_storage: None,
        upper: hidden.join("root/upper"),
        work: hidden.join("root/work"),
        owner: None,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".into(),
            data: None,
        },
        decoy: side.clone(),
        hidden: side,
        policy_mounts: Vec::new(),
        masks: Vec::new(),
        boot_masks: Vec::new(),
        generator_masks: Vec::new(),
        session_units: Vec::new(),
        backend: Vec::new(),
        tools: Tools::default(),
        armed: None,
        entered_at: None,
        run_noexec: false,
        carried: Vec::new(),
        decoy_mounts: Vec::new(),
        read_only_disks: false,
        failed_at_entry: Vec::new(),
        kernel_settings: Vec::new(),
    }
}

fn write_plan(machine: &Machine, plan: &Plan) {
    std::fs::create_dir_all(machine.paths.runtime()).unwrap();
    plan.write_atomic(&machine.paths.plan()).unwrap();
}

fn record(hidden: &Path, state: SystemState) {
    StateFile {
        state,
        ..StateFile::default()
    }
    .save_with_custom_root(&hidden.join("state.json"), hidden)
    .unwrap();
}

fn recorded(hidden: &Path) -> StateFile {
    StateFile::load(&hidden.join("state.json")).unwrap()
}

fn active() -> SystemState {
    SystemState::Active {
        activated_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// recover
// ---------------------------------------------------------------------------

#[test]
fn recovering_the_plain_decoy_resets_an_active_record() {
    // A hard reset in the session leaves the record Active on the decoy.
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    record(&hidden, active());
    let mut m = manager(&hidden);
    let host = FakeEntryHost::default();

    let outcome = m
        .recover_session_on(&machine(dir.path(), DECOY_TABLE), &host)
        .unwrap();

    assert_eq!(outcome, SessionRecovery::Clean);
    assert_eq!(recorded(&hidden).state, SystemState::Inactive);
    assert_eq!(host.reloads.get(), 0, "nothing to reload on a clean decoy");
}

#[test]
fn recovering_the_plain_decoy_leaves_an_inactive_record_unwritten() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let mut m = manager(&hidden);

    let outcome = m
        .recover_session_on(&machine(dir.path(), DECOY_TABLE), &FakeEntryHost::default())
        .unwrap();

    assert_eq!(outcome, SessionRecovery::Clean);
    assert!(
        !hidden.join("state.json").exists(),
        "an inactive record needs no write"
    );
}

#[test]
fn an_interrupted_entry_is_rolled_back_and_the_record_reset() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    record(&hidden, active());
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut leftover = plan(&hidden);
    // A device that is not open is not reported.
    leftover.backend = vec!["nails-test-never-open".into()];
    write_plan(&machine, &leftover);
    std::fs::write(machine.paths.runtime().join("nails"), b"binary copy").unwrap();
    let mut m = manager(&hidden);
    let host = FakeEntryHost::default();

    let outcome = m.recover_session_on(&machine, &host).unwrap();

    assert_eq!(
        outcome,
        SessionRecovery::RolledBack {
            remaining: Vec::new(),
            backend: Vec::new(),
        }
    );
    assert!(
        !machine.paths.runtime().exists(),
        "the runtime directory with the plan and the binary copy is removed"
    );
    assert_eq!(host.reloads.get(), 1);
    assert_eq!(recorded(&hidden).state, SystemState::Inactive);
}

#[test]
fn recovery_refuses_while_an_activation_is_still_entering() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    // Armed just now by a live process: this test's own.
    let pid = std::process::id();
    let mut entering = plan(&hidden);
    entering.owner = Some(Owner {
        pid,
        start_time: nails_teardown::proc::stat(pid).unwrap().start_time,
    });
    entering.armed = Some(Arm::now(Direction::Enter));
    write_plan(&machine, &entering);
    let mut m = manager(&hidden);

    let error = m
        .recover_session_on(&machine, &FakeEntryHost::default())
        .unwrap_err();

    assert!(matches!(error, RecoverError::Entering), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("entering the hidden root right now"),
        "{error}"
    );
    assert!(
        machine.paths.plan().exists(),
        "the live activation's plan stays"
    );
}

#[test]
fn recovery_in_the_hidden_root_points_to_deactivate() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    let table = hidden_table(&hidden.join("root/upper"));
    let mut m = manager(&hidden);

    let error = m
        .recover_session_on(&machine(dir.path(), &table), &FakeEntryHost::default())
        .unwrap_err();

    assert!(matches!(error, RecoverError::HiddenSession), "{error:?}");
    let error = error.to_string();
    assert!(
        error.contains("sudo ") && error.contains("deactivate"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// leave
// ---------------------------------------------------------------------------

#[test]
fn leaving_is_refused_outside_the_hidden_session() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    let mut m = manager(&hidden);
    let target = FakeTarget::default();

    let error = m
        .leave_session_on(&machine(dir.path(), DECOY_TABLE), LeaveTo::Decoy, &target)
        .unwrap_err();

    assert!(
        error.to_string().contains("not in a hidden session"),
        "{error}"
    );
    assert!(target.started.borrow().is_empty());
}

#[test]
fn leaving_a_hidden_root_without_its_plan_asks_for_a_power_off() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    record(&hidden, active());
    let table = hidden_table(&hidden.join("root/upper"));
    let mut m = manager(&hidden);
    let target = FakeTarget::default();

    let error = m
        .leave_session_on(&machine(dir.path(), &table), LeaveTo::Decoy, &target)
        .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("the way back is unknown"), "{message}");
    assert!(message.contains("no session plan in /run"), "{message}");
    assert!(message.contains("Power the machine off"), "{message}");
    assert!(target.started.borrow().is_empty());
    assert!(
        recorded(&hidden).state.is_active(),
        "the record is untouched"
    );
}

#[test]
fn powering_off_from_the_hidden_root_records_inactive_first() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    record(&hidden, active());
    let session = plan(&hidden);
    let machine = machine(dir.path(), &hidden_table(&session.upper));
    write_plan(&machine, &session);
    let mut m = manager(&hidden);
    let target = FakeTarget::default();

    let report = m
        .leave_session_on(&machine, LeaveTo::Poweroff, &target)
        .unwrap();

    assert_eq!(report, crate::session::LeaveReport::default());
    assert_eq!(*target.started.borrow(), ["poweroff.target"]);
    assert_eq!(recorded(&hidden).state, SystemState::Inactive);
}

/// Keep a refused switch's record in `dir`, as the transition does.
fn refused_in(dir: &Path) {
    use nails_teardown::whole_root::switch_refusal::refusal_path;
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        refusal_path(dir),
        r#"{"reason":"failed init check","at":1}"#,
    )
    .unwrap();
}

/// Whether a refused switch's record is left in `dir`.
fn refusal_left(dir: &Path) -> bool {
    nails_teardown::whole_root::switch_refusal::refusal_path(dir).exists()
}

#[test]
fn leaving_forgets_the_last_refused_switch() {
    // A way back refused before kept its reason in the runtime directory; the
    // new one supersedes it, wherever a reason was kept.
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    record(&hidden, active());
    let session = plan(&hidden);
    let machine = machine(dir.path(), &hidden_table(&session.upper));
    write_plan(&machine, &session);
    refused_in(&machine.paths.runtime());
    refused_in(&hidden);
    let mut m = manager(&hidden);

    m.leave_session_on(&machine, LeaveTo::Poweroff, &FakeTarget::default())
        .unwrap();

    assert!(!refusal_left(&machine.paths.runtime()));
    assert!(!refusal_left(&hidden));
}

// ---------------------------------------------------------------------------
// trigger
// ---------------------------------------------------------------------------

#[test]
fn a_started_soft_reboot_leaves_the_prepared_entry_alone() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    let machine = machine(dir.path(), DECOY_TABLE);
    write_plan(&machine, &plan(&hidden));
    let mut m = manager(&hidden);
    let target = FakeTarget::default();
    let host = FakeEntryHost::default();

    let finishes = activation_finishes(|| {
        m.trigger_entry_on(&machine, &target, &host).unwrap();
    });

    assert_eq!(*target.started.borrow(), ["soft-reboot.target"]);
    assert!(machine.paths.plan().exists());
    assert_eq!(host.reloads.get(), 0);
    assert_eq!(
        finishes,
        vec![true],
        "the activation ends once its soft-reboot is enqueued"
    );
}

#[test]
fn a_refused_soft_reboot_rolls_the_entry_back_and_resets_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    record(&hidden, active());
    let machine = machine(dir.path(), DECOY_TABLE);
    write_plan(&machine, &plan(&hidden));
    let mut m = manager(&hidden);
    let target = FakeTarget {
        refuse: true,
        ..FakeTarget::default()
    };
    let host = FakeEntryHost::default();

    let mut result = None;
    let finishes = activation_finishes(|| {
        result = Some(m.trigger_entry_on(&machine, &target, &host));
    });
    let error = result.unwrap().unwrap_err();

    assert_eq!(
        error.to_string(),
        NailsError::InvalidState("soft-reboot.target refused".into()).to_string()
    );
    assert!(!machine.paths.runtime().exists());
    assert_eq!(host.reloads.get(), 1);
    assert_eq!(recorded(&hidden).state, SystemState::Inactive);
    assert_eq!(
        finishes,
        vec![false],
        "a soft-reboot PID 1 refused ends the activation as a failure"
    );
}

// ---------------------------------------------------------------------------
// enter
// ---------------------------------------------------------------------------

#[test]
fn entering_from_the_hidden_root_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    let session = plan(&hidden);
    let machine = machine(dir.path(), &hidden_table(&session.upper));
    write_plan(&machine, &session);
    let mut m = manager(&hidden);
    let host = FakeEntryHost::default();

    let outcome = m
        .enter_session_on(&machine, &EnterOptions::default(), &host)
        .unwrap();

    assert!(
        matches!(outcome, EnterOutcome::AlreadyActive),
        "{outcome:?}"
    );
    assert_eq!(host.reloads.get(), 0);
    assert!(!hidden.join("state.json").exists());
}

#[test]
fn an_unsupported_host_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut m = manager(&hidden);
    let mut profile = FakePlatform::fhs().host_profile();
    profile.kind = PlatformKind::Unsupported;
    profile.unsupported_reason = Some("an immutable image-based host".into());
    m.set_host_profile(profile);

    let error = m
        .enter_session_on(
            &machine,
            &EnterOptions::default(),
            &FakeEntryHost::default(),
        )
        .unwrap_err();

    assert!(
        matches!(&error, NailsError::UnsupportedPlatform { reason } if reason == "an immutable image-based host"),
        "{error:?}"
    );
    assert!(!machine.paths.runtime().exists());
}

#[test]
fn without_a_profile_the_host_is_nixos_when_it_has_a_current_system() {
    let dir = tempfile::tempdir().unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    let m = manager(&dir.path().join("hidden"));
    assert!(!m.require_supported_host(&machine).unwrap());
    std::os::unix::fs::symlink(
        "/nix/store/aaa-nixos-system",
        machine.paths.run.join("current-system"),
    )
    .unwrap();
    // `exists` follows the link; a dangling one is not a live generation.
    assert!(!m.require_supported_host(&machine).unwrap());
    std::fs::remove_file(machine.paths.run.join("current-system")).unwrap();
    std::fs::create_dir(machine.paths.run.join("current-system")).unwrap();
    assert!(m.require_supported_host(&machine).unwrap());
}

#[test]
fn a_detected_profile_decides_nixos_by_its_kind() {
    let dir = tempfile::tempdir().unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut m = manager(&dir.path().join("hidden"));
    m.set_host_profile(FakePlatform::nixos().host_profile());
    assert!(m.require_supported_host(&machine).unwrap());
    m.set_host_profile(FakePlatform::fhs().host_profile());
    assert!(!m.require_supported_host(&machine).unwrap());
}

/// What activation announces it will build is what the entry builds: a hidden
/// NixOS system only on NixOS, with a build target, without `--overlay-only`.
#[test]
fn a_hidden_system_is_built_only_on_nixos_with_a_target_and_without_overlay_only() {
    let dir = tempfile::tempdir().unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut m = manager(&dir.path().join("hidden"));
    let plain = EnterOptions::default();
    let overlay_only = EnterOptions {
        overlay_only: true,
        ..EnterOptions::default()
    };

    m.set_host_profile(FakePlatform::nixos().host_profile());
    assert!(
        !m.builds_hidden_system_on(&machine, &plain),
        "no build target"
    );
    m.set_nixos_builder(NixOSBuilder::new_legacy(PathBuf::from(
        "/etc/nixos/configuration.nix",
    )));
    assert!(m.builds_hidden_system_on(&machine, &plain));
    assert!(!m.builds_hidden_system_on(&machine, &overlay_only));

    m.set_host_profile(FakePlatform::fhs().host_profile());
    assert!(
        !m.builds_hidden_system_on(&machine, &plain),
        "Debian and Ubuntu build nothing"
    );
}

#[test]
fn a_ram_decoy_root_refuses_the_entry_before_anything_is_prepared() {
    // The way back mounts the decoy root again, so it must be a block device.
    let dir = tempfile::tempdir().unwrap();
    let machine = machine(dir.path(), "1 0 0:30 / / rw - tmpfs tmpfs rw\n");
    let mut m = manager(&dir.path().join("hidden"));
    m.set_host_profile(FakePlatform::fhs().host_profile());
    let options = EnterOptions::default();
    let host = FakeEntryHost::default();

    let error = m
        .enter_session_no_preflight_on(&machine, &options, &host)
        .unwrap_err();

    assert!(
        error.to_string().contains("is not on a block device"),
        "{error}"
    );
    assert!(!machine.paths.runtime().exists());
    assert_eq!(host.reloads.get(), 0);
}

#[test]
fn a_cancel_before_the_entry_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut m = manager(&hidden);
    m.set_host_profile(FakePlatform::fhs().host_profile());
    let options = EnterOptions::default();
    let host = FakeEntryHost::default();

    crate::cancel::testing::request();
    let result = m.enter_session_no_preflight_on(&machine, &options, &host);
    crate::cancel::testing::reset();

    assert!(matches!(result, Err(NailsError::Cancelled)), "{result:?}");
    assert!(!machine.paths.runtime().exists());
    assert_eq!(host.reloads.get(), 0);
    assert!(!hidden.join("state.json").exists());
}

#[test]
fn a_caller_s_cancel_token_before_the_entry_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden).unwrap();
    let machine = machine(dir.path(), DECOY_TABLE);
    let mut m = manager(&hidden);
    m.set_host_profile(FakePlatform::fhs().host_profile());
    let options = EnterOptions::default();
    let host = FakeEntryHost::default();

    // A caller — a window whose control pipe closed before the point of no
    // return — trips its token. The entry stops at a checkpoint and leaves the
    // decoy exactly as a SIGINT would, because the token feeds the same
    // checkpoint the signal flag does.
    let token = crate::cancel::CancelToken::new();
    let scope = token.install();
    token.cancel();
    let result = m.enter_session_no_preflight_on(&machine, &options, &host);
    drop(scope);

    assert!(matches!(result, Err(NailsError::Cancelled)), "{result:?}");
    assert!(!machine.paths.runtime().exists());
    assert_eq!(host.reloads.get(), 0);
    assert!(!hidden.join("state.json").exists());
}

#[test]
fn a_step_that_fails_while_a_cancel_is_pending_reports_the_cancel() {
    // A Ctrl+C from the terminal reaches the step's processes too.
    crate::cancel::testing::request();
    let result: Result<()> = cancellable(|| Err(NailsError::InvalidState("killed".into())));
    crate::cancel::testing::reset();
    assert!(matches!(result, Err(NailsError::Cancelled)), "{result:?}");
    assert_eq!(cancellable(|| Ok(7)).unwrap(), 7);
}

/// Run `body` with an event-collecting reporter installed on this thread and
/// return the `success` of each `finish` the session flow raised, in order.
/// The session flow alone calls `progress::finish`: at the end of an entry that
/// failed, and once the soft-reboot of a prepared one is enqueued or refused,
/// so this is precisely what a watching front end sees as the activation
/// ending.
fn activation_finishes(body: impl FnOnce()) -> Vec<bool> {
    let sink = crate::reporter::CollectingSink::new();
    {
        let reporter = crate::reporter::EventReporter::new(sink.clone());
        let _scope =
            crate::reporter::progress::install(crate::reporter::progress::shared(reporter));
        body();
    }
    sink.events()
        .into_iter()
        .filter_map(|event| match event {
            nails_api::Event::Finished { success } => Some(success),
            _ => None,
        })
        .collect()
}

#[test]
fn a_no_op_entry_in_the_hidden_root_raises_no_finish() {
    // Already in the hidden root: nothing was done, so a watcher must not be
    // told the activation finished.
    let dir = tempfile::tempdir().unwrap();
    let hidden = dir.path().join("hidden");
    let session = plan(&hidden);
    let machine = machine(dir.path(), &hidden_table(&session.upper));
    write_plan(&machine, &session);
    let mut m = manager(&hidden);
    let host = FakeEntryHost::default();

    let mut outcome = None;
    let finishes = activation_finishes(|| {
        outcome = Some(
            m.enter_session_on(&machine, &EnterOptions::default(), &host)
                .unwrap(),
        );
    });

    assert!(
        matches!(outcome, Some(EnterOutcome::AlreadyActive)),
        "{outcome:?}"
    );
    assert!(
        finishes.is_empty(),
        "a no-op entry raises no finish, got {finishes:?}"
    );
}

#[test]
fn a_refused_entry_raises_exactly_one_failed_finish() {
    // A real activation that fails did do work, so it ends with one finish, and
    // that finish reports the failure.
    let dir = tempfile::tempdir().unwrap();
    let machine = machine(dir.path(), "1 0 0:30 / / rw - tmpfs tmpfs rw\n");
    let mut m = manager(&dir.path().join("hidden"));
    m.set_host_profile(FakePlatform::fhs().host_profile());
    let options = EnterOptions::default();
    let host = FakeEntryHost::default();

    let mut result = None;
    let finishes = activation_finishes(|| {
        result = Some(m.enter_session_no_preflight_on(&machine, &options, &host));
    });

    assert!(
        matches!(result, Some(Err(_))),
        "the RAM decoy root is refused: {result:?}"
    );
    assert_eq!(
        finishes,
        vec![false],
        "a failed activation raises one finish that reports the failure"
    );
}

// ---------------------------------------------------------------------------
// record
// ---------------------------------------------------------------------------

fn entry_with(hidden_system: Option<&str>, decoy_system: Option<&str>) -> entry::Entry {
    let mut plan = plan(Path::new("/mnt/data"));
    plan.hidden.system = hidden_system.map(PathBuf::from);
    plan.decoy.system = decoy_system.map(PathBuf::from);
    entry::Entry {
        plan,
        decisions: Vec::new(),
        warnings: Vec::new(),
    }
}

#[test]
fn a_recorded_nixos_entry_keeps_both_generations_and_its_timing() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = manager(dir.path());
    let entry = entry_with(
        Some("/nix/store/bbb-nixos-system"),
        Some("/nix/store/aaa-nixos-system"),
    );

    m.record_entry(&entry, std::time::Duration::from_millis(1234))
        .unwrap();

    let state = recorded(dir.path());
    assert!(state.state.is_active(), "{:?}", state.state);
    assert_eq!(
        state.platform,
        Some(PlatformState::NixOs {
            generation: Some("/nix/store/bbb-nixos-system".into()),
            last_switch_warning: None,
        })
    );
    assert_eq!(
        state.decoy_system.as_deref(),
        Some("/nix/store/aaa-nixos-system")
    );
    assert_eq!(state.last_activation.unwrap().duration_ms, 1234);
}

#[test]
fn a_recorded_fhs_entry_marks_the_debian_family() {
    let dir = tempfile::tempdir().unwrap();
    let mut m = manager(dir.path());

    m.record_entry(&entry_with(None, None), std::time::Duration::ZERO)
        .unwrap();

    let state = recorded(dir.path());
    assert!(state.state.is_active());
    assert_eq!(
        state.platform,
        Some(PlatformState::DebianFamily { family: None })
    );
    assert_eq!(state.decoy_system, None);
}

#[test]
fn an_overlay_only_entry_on_nixos_records_no_platform() {
    // The decoy's own NixOS system, no hidden build: nothing hidden to name.
    let dir = tempfile::tempdir().unwrap();
    let mut m = manager(dir.path());
    m.seed_cached_state(StateFile {
        platform: Some(PlatformState::DebianFamily { family: None }),
        ..StateFile::default()
    });

    m.record_entry(
        &entry_with(None, Some("/nix/store/aaa-nixos-system")),
        std::time::Duration::ZERO,
    )
    .unwrap();

    let state = recorded(dir.path());
    assert!(state.state.is_active());
    assert_eq!(state.platform, None);
    assert_eq!(
        state.decoy_system.as_deref(),
        Some("/nix/store/aaa-nixos-system")
    );
}

// ---------------------------------------------------------------------------
// the whole entry, against a real kernel
// ---------------------------------------------------------------------------

/// A minimal FHS decoy root: an os-release, an init, the soft-reboot units
/// and an fstab.
fn fhs_decoy() -> ScratchTmpfs {
    let decoy = ScratchTmpfs::new("");
    for dir in ["etc", "usr/lib/systemd/system", "run", "home"] {
        decoy.mkdir(dir);
    }
    for unit in ["soft-reboot.target", "systemd-soft-reboot.service"] {
        std::fs::write(decoy.path().join("usr/lib/systemd/system").join(unit), "").unwrap();
    }
    std::fs::write(decoy.path().join("etc/os-release"), "ID=debian\n").unwrap();
    std::fs::write(
        decoy.path().join("etc/fstab"),
        "/dev/vda2 / ext4 defaults 0 1\n",
    )
    .unwrap();
    write_executable(
        &decoy.path().join("usr/lib/systemd/systemd"),
        "#!/bin/sh\n",
        0o755,
    );
    decoy
}

#[test]
fn an_fhs_entry_is_prepared_recorded_active_and_rolled_back_when_the_reboot_is_refused() {
    let _ = Rerun::new(crate::test_path!(
        an_fhs_entry_is_prepared_recorded_active_and_rolled_back_when_the_reboot_is_refused
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = fhs_decoy();
        let hidden = ScratchTmpfs::new("");
        let run = ScratchTmpfs::new("");
        let machine = Machine {
            paths: Paths {
                root: decoy.path().to_path_buf(),
                run: run.path().to_path_buf(),
            },
            mounts: Some(parse_mountinfo(DECOY_TABLE)),
        };
        let mut m = manager(hidden.path());
        m.set_host_profile(FakePlatform::fhs().host_profile());
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        let host = FakeEntryHost::default();
        // The last switch was refused, its reason kept on the hidden volume and
        // (a way back) in the runtime directory.
        refused_in(hidden.path());
        refused_in(&machine.paths.runtime());

        let mut outcome = None;
        let finishes = activation_finishes(|| {
            outcome = Some(
                m.enter_session_no_preflight_on(&machine, &options, &host)
                    .unwrap(),
            );
        });

        let Some(EnterOutcome::Prepared { entry, elapsed }) = outcome else {
            panic!("expected a prepared entry, got {outcome:?}");
        };
        // Prepared is not the end: the soft-reboot is still to be enqueued.
        assert!(finishes.is_empty(), "{finishes:?}");
        // The new switch supersedes the refused one.
        assert!(!refusal_left(hidden.path()));
        assert!(!refusal_left(&machine.paths.runtime()));
        // The plan is armed for the entry, read from the given mount table,
        // and written where the soft-reboot will find it.
        assert_eq!(entry.plan.decoy_root.source, Path::new("/dev/vda2"));
        assert_eq!(
            entry.plan.armed.map(|arm| arm.direction),
            Some(Direction::Enter)
        );
        assert_eq!(entry.plan.hidden_root, hidden.path());
        assert!(machine.paths.plan().is_file());
        assert!(
            machine
                .paths
                .nextroot()
                .join("usr/lib/systemd/systemd")
                .is_file()
        );
        assert!(host.reloads.get() >= 1, "the drop-in is loaded");
        // The record says Active before the soft-reboot kills this process.
        let state = recorded(hidden.path());
        assert!(state.state.is_active(), "{:?}", state.state);
        assert_eq!(
            state.platform,
            Some(PlatformState::DebianFamily { family: None })
        );
        // `activate` prints the outcome's time and `status` the recorded one:
        // one measurement.
        assert_eq!(
            state.last_activation.map(|last| last.duration_ms),
            Some(u64::try_from(elapsed.as_millis()).unwrap())
        );

        let target = FakeTarget {
            refuse: true,
            ..FakeTarget::default()
        };
        let finishes = activation_finishes(|| {
            assert!(m.trigger_entry_on(&machine, &target, &host).is_err());
        });
        assert_eq!(finishes, vec![false]);

        // Nothing of the entry is left, and the record is back to inactive.
        let mounts = read_mountinfo().unwrap();
        assert!(
            mounts
                .iter()
                .all(|e| !e.mount_point.starts_with(machine.paths.nextroot())),
            "the next root is detached"
        );
        assert!(!machine.paths.runtime().exists());
        assert_eq!(recorded(hidden.path()).state, SystemState::Inactive);
    });
}

#[test]
fn a_cancel_during_the_entry_rolls_it_back_and_records_nothing() {
    let _ = Rerun::new(crate::test_path!(
        a_cancel_during_the_entry_rolls_it_back_and_records_nothing
    ))
    .in_user_mount_ns()
    .run(|| {
        let decoy = fhs_decoy();
        let hidden = ScratchTmpfs::new("");
        let run = ScratchTmpfs::new("");
        let machine = Machine {
            paths: Paths {
                root: decoy.path().to_path_buf(),
                run: run.path().to_path_buf(),
            },
            mounts: Some(parse_mountinfo(DECOY_TABLE)),
        };
        let mut m = manager(hidden.path());
        m.set_host_profile(FakePlatform::fhs().host_profile());
        let options = EnterOptions {
            binary: PathBuf::from("/proc/self/exe"),
            ..EnterOptions::default()
        };
        // The signal arrives while the service manager loads the drop-in.
        let host = FakeEntryHost {
            cancel_at_reload: true,
            ..FakeEntryHost::default()
        };

        let result = m.enter_session_no_preflight_on(&machine, &options, &host);
        crate::cancel::testing::reset();

        assert!(matches!(result, Err(NailsError::Cancelled)), "{result:?}");
        let mounts = read_mountinfo().unwrap();
        assert!(
            mounts
                .iter()
                .all(|e| !e.mount_point.starts_with(machine.paths.nextroot())),
            "the next root is detached"
        );
        assert!(!machine.paths.runtime().exists());
        assert!(
            !run.path()
                .join(nails_teardown::whole_root::transition::DROPIN_DIR)
                .exists()
        );
        assert_eq!(host.reloads.get(), 2, "one loads the drop-in, one drops it");
        assert!(!hidden.path().join("state.json").exists());
    });
}

#[test]
fn the_plan_records_only_what_the_override_alone_accepted() {
    use crate::filesystem::MockFilesystem;
    use crate::hidden_root::Allow;
    use std::path::Path;

    // A folder of the decoy's /srv bound at /mnt/data.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:2 / /srv rw - ext4 /dev/vda2 rw\n\
         3 1 8:2 /x /mnt/data rw - ext4 /dev/vda2 rw\n",
    );
    let bind = Path::new("/mnt/data");
    assert_eq!(
        accepted_decoy_storage(&fs, bind, Allow::DecoyStorage)
            .unwrap()
            .as_deref(),
        Some("/mnt/data is not a volume of its own: it is a bind mount of a folder of /srv")
    );
    // Without the override the bind is refused, which the entry never
    // reaches; nothing is recorded either way.
    assert_eq!(
        accepted_decoy_storage(&fs, bind, Allow::Nothing).unwrap(),
        None
    );
    // A folder is refused with the override too.
    fs.mock_set_path_exists("/srv/x", true);
    assert_eq!(
        accepted_decoy_storage(&fs, Path::new("/srv/x"), Allow::DecoyStorage).unwrap(),
        None
    );

    // A volume of its own needs no override.
    let volume = Path::new("/mnt/data");
    let mounted = MockFilesystem::new();
    mounted.mock_set_path_exists("/mnt/data", true);
    mounted.mock_set_mounted(volume, true);
    assert_eq!(
        accepted_decoy_storage(&mounted, volume, Allow::DecoyStorage).unwrap(),
        None
    );
}
