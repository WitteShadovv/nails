// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The transition step against real directory trees: a `/run` and a next
//! root, all in a temporary directory. Only the mount table is given (a
//! `/run/nextroot` entry), so nothing here needs privileges; the mounts
//! themselves are exercised by the kernel tests in `nails-core`.
//!
//! No test here powers anything off: every step gets a `systemctl` that only
//! logs its arguments ([`fake_systemctl`]) and a kernel power-off that
//! refuses and counts the calls ([`refused_power_off`]), so a step that ends
//! the session returns [`Outcome::Ended`].

use super::run as run_step;
use super::*;
use crate::mountinfo::parse_mountinfo;
use crate::test_support::write_executable;
use crate::whole_root::plan::{Arm, sample};
use crate::whole_root::program_label;
use crate::whole_root::runtime_units::RuntimeUnit;
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

// The step's check of its own domain, where the plan records a label.
#[path = "transition_domain_tests.rs"]
mod domain;

thread_local! {
    /// How often this test thread's steps asked the kernel to power off.
    static KERNEL_ASKED: Cell<u32> = const { Cell::new(0) };
}

/// The kernel's power-off in every test: it refuses, so no test powers its
/// host off, whatever the code under test decides, and counts the calls of
/// this thread ([`kernel_asked`]).
fn refused_power_off() -> bool {
    KERNEL_ASKED.with(|asked| asked.set(asked.get() + 1));
    false
}

/// How often this thread's steps asked the kernel to power off so far.
fn kernel_asked() -> u32 {
    KERNEL_ASKED.with(Cell::get)
}

/// A detach that finds nothing mounted, as the real one does below the
/// world's next root, which the live mount table never names.
fn detached(_: &Path) -> Vec<PathBuf> {
    Vec::new()
}

/// A detach that leaves a mount at the next root.
fn stuck(_: &Path) -> Vec<PathBuf> {
    vec![PathBuf::from("/run/nextroot")]
}

struct World {
    dir: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let world = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir_all(world.run().join("udev/data")).unwrap();
        fs::create_dir_all(world.run().join("systemd/journal")).unwrap();
        fs::create_dir_all(world.run().join("mount")).unwrap();
        fs::write(world.run().join("mount/utab"), "ID=1 decoy\n").unwrap();
        fs::write(world.run().join("decoy-state"), "keep").unwrap();
        symlink(
            "/nix/store/aaa-nixos-system",
            world.run().join("current-system"),
        )
        .unwrap();
        fs::create_dir_all(world.runtime()).unwrap();
        fs::create_dir_all(world.nextroot().join("etc")).unwrap();
        fs::write(world.nextroot().join("etc/os-release"), "ID=nixos\n").unwrap();
        world
    }
    fn run(&self) -> PathBuf {
        self.dir.path().join("run")
    }
    fn runtime(&self) -> PathBuf {
        self.run().join("overlay-runtime")
    }
    fn nextroot(&self) -> PathBuf {
        self.dir.path().join("nextroot")
    }
    fn init_in_nextroot(&self, init: &Path) {
        let path = self.nextroot().join(init.strip_prefix("/").unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_executable(&path, "", 0o755);
    }
    fn env(&self, mounted: bool, now: u64) -> Env {
        let table = if mounted {
            format!(
                "40 1 0:40 / {} rw - overlay overlay rw\n",
                self.nextroot().display()
            )
        } else {
            String::new()
        };
        Env {
            run: self.run(),
            nextroot: self.nextroot(),
            runtime_dir: self.runtime(),
            systemctl: Some(fake_systemctl(self.dir.path(), 0)),
            now,
            mounts: Some(parse_mountinfo(&table)),
            power_off: PowerOff {
                grace: std::time::Duration::ZERO,
                kernel: refused_power_off,
            },
            detach: detached,
            selinux: &crate::whole_root::selinux::KERNEL,
            start: crate::whole_root::program_label::Started::by_hand(),
            fence: None,
        }
    }
    fn write_plan(&self, plan: &Plan) {
        plan.write_atomic(&self.runtime().join(PLAN_NAME)).unwrap();
    }
    fn plan(&self) -> Plan {
        Plan::load(&self.runtime().join(PLAN_NAME)).unwrap()
    }
    fn current_system(&self) -> PathBuf {
        fs::read_link(self.run().join("current-system")).unwrap()
    }
}

/// A fake `systemctl` in `dir` that logs its arguments ([`systemctl_calls`])
/// and exits `code`.
fn fake_systemctl(dir: &Path, code: i32) -> PathBuf {
    let tool = dir.join("systemctl");
    write_executable(
        &tool,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\nexit {code}\n",
            dir.join("calls").display()
        ),
        0o755,
    );
    tool
}

/// What the `systemctl` of the world was asked, one call per line.
fn systemctl_calls(world: &World) -> String {
    fs::read_to_string(world.dir.path().join("calls")).unwrap_or_default()
}

/// Run the step of `env` in `world` and check that it ended the session the
/// way every hidden session ends: it asked PID 1 to power off at once, then
/// the kernel, and, as neither took it here, returned [`Outcome::Ended`],
/// whose exit code fails the service. Returns why.
fn ends(world: &World, env: &Env) -> String {
    let before = kernel_asked();
    let outcome = run(env);
    assert_eq!(kernel_asked(), before + 1, "{outcome:?}");
    assert!(
        systemctl_calls(world)
            .lines()
            .any(|call| call == "--force poweroff"),
        "{outcome:?}: {}",
        systemctl_calls(world)
    );
    assert_eq!(outcome.exit_code(), 1);
    let Outcome::Ended(why) = outcome else {
        panic!("expected the session's end, got {outcome:?}");
    };
    why
}

/// Run the step of `env` and check that it asked for no power-off.
fn goes_on(world: &World, env: &Env) -> Outcome {
    let before = kernel_asked();
    let outcome = run(env);
    assert_eq!(kernel_asked(), before, "{outcome:?}");
    assert!(
        !systemctl_calls(world).contains("poweroff"),
        "{outcome:?}: {}",
        systemctl_calls(world)
    );
    assert_eq!(outcome.exit_code(), 0);
    outcome
}

fn armed(direction: Direction) -> Plan {
    let mut plan = sample();
    plan.armed = Some(Arm {
        direction,
        at: 1_000,
    });
    plan.session_units = vec![RuntimeUnit {
        name: "overlay-runtime-monitor.service".to_string(),
        content: "[Service]\nExecStart=/run/overlay-runtime/control watch\n".to_string(),
        wanted_by: vec!["multi-user.target".to_string()],
    }];
    plan
}

/// A plan the entry has recorded: the hidden session's, armed for nothing.
fn in_session() -> Plan {
    let mut plan = armed(Direction::Enter);
    plan.armed = None;
    plan.entered_at = Some(900);
    plan
}

/// An entry ready to go in `world`: the plan armed for it and the hidden
/// init in the next root.
fn ready_entry(world: &World) -> Plan {
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    plan
}

/// On the decoy side without a plan NAILS staged nothing to judge. Where the
/// mount table cannot be read the step cannot tell the decoy from a hidden
/// root whose plan is gone, and ends the session.
#[test]
fn without_a_plan_nothing_happens_on_the_decoy_side() {
    for mounted in [true, false] {
        let world = World::new();
        assert_eq!(
            goes_on(&world, &world.env(mounted, 1_000)),
            Outcome::NothingToDo
        );
        let world = World::new();
        let mut env = world.env(mounted, 1_000);
        env.mounts = None;
        assert_eq!(ends(&world, &env), "the mount table cannot be read");
    }
}

/// The mount table of a hidden root: `/` is the root overlay.
fn with_a_root_overlay(env: &mut Env) {
    env.mounts.as_mut().unwrap().insert(
        0,
        parse_mountinfo(
            "1 0 0:30 / / rw - overlay overlay rw,lowerdir=/a,upperdir=/mnt/data/root/upper,workdir=/w\n",
        )
        .remove(0),
    );
}

/// In a hidden session every soft-reboot ends in a power-off, whatever
/// /run/nextroot is: PID 1 switches into any OS tree there (a mount, a link
/// to the decoy root, a plain directory), and a restart of the hidden
/// userspace is no ending either. A hidden root whose plan is gone is told by
/// its root overlay.
#[test]
fn every_soft_reboot_in_a_hidden_session_ends_it() {
    for mounted in [true, false] {
        let world = World::new();
        world.write_plan(&in_session());
        let why = ends(&world, &world.env(mounted, 1_000));
        assert!(
            why.starts_with("a soft-reboot in the hidden session"),
            "{why}"
        );
        assert!(
            world.runtime().join(PLAN_NAME).exists(),
            "nothing is cleaned up"
        );

        let world = World::new();
        let mut env = world.env(mounted, 1_000);
        with_a_root_overlay(&mut env);
        let why = ends(&world, &env);
        assert!(
            why.starts_with("a soft-reboot in the hidden session"),
            "{why}"
        );
    }
    // A link to the decoy root at /run/nextroot, which no mount table names.
    let world = World::new();
    world.write_plan(&in_session());
    let decoy = world.dir.path().join("decoy-root");
    fs::create_dir_all(decoy.join("etc")).unwrap();
    fs::write(decoy.join("etc/os-release"), "ID=debian\n").unwrap();
    fs::remove_dir_all(world.nextroot()).unwrap();
    symlink(&decoy, world.nextroot()).unwrap();
    let why = ends(&world, &world.env(false, 1_000));
    assert!(
        why.starts_with("a soft-reboot in the hidden session"),
        "{why}"
    );
}

/// A plan armed for nothing and no next root on the decoy side: a plain
/// soft-reboot of the decoy.
#[test]
fn a_plan_armed_for_nothing_without_a_next_root_lets_a_plain_soft_reboot_go_on() {
    let world = World::new();
    let mut plan = armed(Direction::Enter);
    plan.armed = None;
    world.write_plan(&plan);
    assert_eq!(
        goes_on(&world, &world.env(false, 1_000)),
        Outcome::NothingToDo
    );
    assert!(world.runtime().join(PLAN_NAME).exists());
}

#[test]
fn entering_repoints_current_system_masks_decoy_units_and_records_the_entry() {
    let world = World::new();
    ready_entry(&world);

    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);

    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/bbb-nixos-system")
    );
    let units = world.run().join("systemd/system");
    assert_eq!(
        fs::read_link(units.join("dev-vda3.swap")).unwrap(),
        Path::new("/dev/null")
    );
    assert!(
        units
            .join("multi-user.target.wants/overlay-runtime-monitor.service")
            .exists()
    );
    let after = world.plan();
    assert_eq!(after.armed, None);
    assert_eq!(after.entered_at, Some(1_010));
    // Nothing of the way back: no record of the decoy's /run records, no
    // journald work, no process-number counter.
    assert!(!world.runtime().join(plan::RECORDS_NAME).exists());
    assert_eq!(systemctl_calls(&world), "");
    assert_eq!(after.pids, Default::default());
}

#[test]
fn entering_keeps_only_the_utab_lines_of_mounts_the_switch_carries() {
    // The decoy's initrd wrote lines for the decoy's root and store, which the
    // switch leaves behind; the kernel then hands their IDs to the next mounts
    // made (here ID 62 to the hidden volume). Joined to that mount, the root's
    // x-initrd.mount would hide it from the shutdown order. A line without an
    // ID joins whatever is mounted at its target later with its source and
    // root, as the next userspace mounts /run/wrappers.
    let world = World::new();
    ready_entry(&world);
    let utab = world.run().join("mount/utab");
    fs::write(
        &utab,
        "ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n\
         ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n\
         ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=X-kept\n\
         SRC=/dev/vda TARGET=/ OPTS=x-initrd.mount\n\
         SRC=wrappers TARGET=/run/wrappers ROOT=/ OPTS=x-initrd.mount\n\
         SRC=/dev/mapper/data TARGET=/mnt/data ROOT=/ OPTS=X-kept\n",
    )
    .unwrap();
    let mut env = world.env(true, 1_010);
    let next = world.nextroot();
    env.mounts
        .as_mut()
        .unwrap()
        .extend(parse_mountinfo(&format!(
            "62 1 8:0 / / rw - ext4 /dev/vda rw\n\
             85 62 0:50 / /nix/store rw - overlay overlay rw\n\
             70 62 0:51 / /run/wrappers rw - tmpfs wrappers rw\n\
             63 40 254:0 / {}/mnt/data rw - ext4 /dev/mapper/data rw\n",
            next.display()
        )));

    assert_eq!(goes_on(&world, &env), Outcome::Entered);
    assert_eq!(
        fs::read_to_string(&utab).unwrap(),
        "ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=X-kept\n\
         SRC=/dev/mapper/data TARGET=/mnt/data ROOT=/ OPTS=X-kept\n"
    );
}

/// A plan that exists but cannot be read is no plain soft-reboot: the step
/// cannot tell what it would let PID 1 switch into.
#[test]
fn a_plan_that_cannot_be_read_ends_the_session() {
    for (text, what) in [
        ("{not json", "session plan corrupt"),
        (r#"{"version":999}"#, "format version 999"),
    ] {
        let world = World::new();
        fs::write(world.runtime().join(PLAN_NAME), text).unwrap();
        let why = ends(&world, &world.env(true, 1_000));
        assert!(why.starts_with("the session plan cannot be read"), "{why}");
        assert!(why.contains(what), "{why}");
    }
    // A plan path that is no file.
    let world = World::new();
    fs::create_dir(world.runtime().join(PLAN_NAME)).unwrap();
    let why = ends(&world, &world.env(false, 1_000));
    assert!(why.starts_with("the session plan cannot be read"), "{why}");
}

/// Without the mount table the step cannot tell whether PID 1 would switch
/// into `/run/nextroot`.
#[test]
fn a_mount_table_that_cannot_be_read_ends_the_session() {
    for plan in [armed(Direction::Enter), in_session()] {
        let world = World::new();
        world.write_plan(&plan);
        let mut env = world.env(true, 1_000);
        env.mounts = None;
        assert_eq!(ends(&world, &env), "the mount table cannot be read");
    }
}

/// Nothing of this build arms the way back, and a plan armed for it ends the
/// session: a hidden session never goes back to the decoy's kernel. PID 1
/// stays in the hidden root, with its system, and the reason is kept in the
/// runtime directory.
#[test]
fn a_plan_armed_for_the_way_back_ends_the_session() {
    for mounted in [true, false] {
        let world = World::new();
        repoint_current_system(&world.run(), Path::new("/nix/store/bbb-nixos-system")).unwrap();
        let mut plan = armed(Direction::Leave);
        plan.entered_at = Some(900);
        world.init_in_nextroot(&plan.decoy.init);
        world.write_plan(&plan);

        let why = ends(&world, &world.env(mounted, 1_000));

        assert!(why.contains("never goes back"), "{why}");
        let kept = switch_refusal::read(&world.runtime()).expect("the reason is kept in /run");
        assert_eq!(kept.reason, why);
        assert_eq!(
            world.current_system(),
            Path::new("/nix/store/bbb-nixos-system"),
            "the session's system stays"
        );
        assert!(world.run().join("decoy-state").exists(), "no scrub ran");
    }
}

/// An entry armed with nothing at `/run/nextroot` would start the decoy's
/// userspace again: it powers off instead.
#[test]
fn an_entry_armed_without_a_next_root_ends_the_session() {
    let world = World::new();
    ready_entry(&world);
    let why = ends(&world, &world.env(false, 1_000));
    assert_eq!(
        why,
        "the entry is armed, but nothing is mounted at /run/nextroot"
    );
}

/// An arming that expired is no arming, and no leftover either: the switch
/// was under way. Mounted or not, it powers off.
#[test]
fn an_arming_that_expired_ends_the_session() {
    let late = 1_001 + crate::whole_root::plan::ARM_VALIDITY_SECS;
    for mounted in [true, false] {
        let world = World::new();
        ready_entry(&world);
        let why = ends(&world, &world.env(mounted, late));
        assert_eq!(why, "the arming of the switch expired");
    }
}

#[test]
fn an_entry_whose_init_does_not_resolve_ends_the_session_instead_of_freezing_pid1() {
    let world = World::new();
    install_dropin(&world.run(), Path::new("/run/overlay-runtime/control")).unwrap();
    world.write_plan(&armed(Direction::Enter));

    let why = ends(&world, &world.env(true, 1_000));

    assert!(why.contains("does not resolve"), "{why}");
    // The repoint is undone, and nothing of the entry's masks was written.
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system")
    );
    assert!(!world.run().join("systemd/system/dev-vda3.swap").exists());
}

/// On a NixOS decoy the step's `systemctl` is reached through
/// /run/current-system, which the entry repoints to the hidden toplevel, a
/// path in the next root's store that leads nowhere on this side. A part that
/// fails after the repoint undoes it first, so PID 1 is asked for the
/// orderly power-off before the kernel.
#[test]
fn a_part_that_fails_after_the_repoint_asks_pid_1_first() {
    let world = World::new();
    let decoy_system = world.dir.path().join("decoy-system");
    let bin = decoy_system.join("sw/bin");
    fs::create_dir_all(&bin).unwrap();
    write_executable(
        &bin.join("systemctl"),
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\nexit 0\n",
            world.dir.path().join("calls").display()
        ),
        0o755,
    );
    fs::remove_file(world.run().join("current-system")).unwrap();
    symlink(&decoy_system, world.run().join("current-system")).unwrap();
    fs::create_dir_all(world.run().join("systemd")).unwrap();
    fs::write(world.run().join("systemd/system"), "not a directory").unwrap();
    let mut plan = armed(Direction::Enter);
    plan.decoy.system = Some(decoy_system.clone());
    plan.hidden.system = Some(world.dir.path().join("hidden-system-not-on-this-side"));
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    let mut env = world.env(true, 1_010);
    env.systemctl = Some(world.run().join("current-system/sw/bin/systemctl"));

    let why = ends(&world, &env);

    assert!(why.starts_with("could not mask decoy units"), "{why}");
    assert_eq!(world.current_system(), decoy_system);
}

/// A `current-system` that cannot be repointed ends the session.
#[test]
fn an_entry_that_cannot_repoint_current_system_ends_the_session() {
    let world = World::new();
    ready_entry(&world);
    fs::remove_file(world.run().join("current-system")).unwrap();
    fs::create_dir_all(world.run().join("current-system/keep")).unwrap();

    let why = ends(&world, &world.env(true, 1_000));

    assert!(why.starts_with("could not repoint current-system"), "{why}");
}

/// The mount table as the transition finds it: the decoy root, the next root
/// (`env`'s, made canonical) and in it the hidden volume's bind at
/// `/mnt/data`, on device 254:0. The shutdown has already unmounted the volume
/// at its own path. Returns the bind's directory.
fn with_the_volume_s_bind(world: &World, env: &mut Env) -> PathBuf {
    let next = fs::canonicalize(world.nextroot()).unwrap();
    let volume = next.join("mnt/data");
    fs::create_dir_all(&volume).unwrap();
    env.mounts = Some(parse_mountinfo(&format!(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         40 1 0:40 / {} rw - overlay overlay rw\n\
         63 40 254:0 / {} rw - ext4 /dev/mapper/data rw\n",
        next.display(),
        volume.display()
    )));
    env.nextroot = next;
    volume
}

/// A plan armed for `direction` on the hidden volume of device 254:0.
fn armed_on_the_volume(direction: Direction) -> Plan {
    let mut plan = armed(direction);
    plan.hidden_dev = Some("254:0".to_string());
    plan
}

/// A refused entry keeps why on the hidden volume before it powers off, so
/// `status` can say it once the volume is open again.
#[test]
fn a_refused_entry_keeps_its_reason_on_the_hidden_volume_and_powers_off() {
    let world = World::new();
    world.write_plan(&armed_on_the_volume(Direction::Enter));
    let mut env = world.env(true, 1_000);
    let volume = with_the_volume_s_bind(&world, &mut env);

    // The hidden init is not in the next root: the check refuses the switch.
    let why = ends(&world, &env);

    assert!(why.contains("does not resolve"), "{why}");
    assert_eq!(
        switch_refusal::read(&volume),
        Some(switch_refusal::SwitchRefusal {
            reason: why,
            at: 1_000
        }),
        "the reason is on the hidden volume"
    );
}

/// A unit mask that cannot be written ends the session: through a unit
/// directory that is a link elsewhere, the mask would not reach the hidden
/// systemd.
#[test]
fn an_entry_whose_masks_cannot_be_written_ends_the_session() {
    let world = World::new();
    fs::create_dir_all(world.run().join("systemd")).unwrap();
    fs::write(world.run().join("systemd/system"), "not a directory").unwrap();
    ready_entry(&world);

    let why = ends(&world, &world.env(true, 1_010));

    assert!(why.starts_with("could not mask decoy units"), "{why}");
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system"),
        "the repoint is undone before the power-off returns"
    );
}

/// The generator every entry masks.
const GPT_AUTO: &str = "systemd-gpt-auto-generator";

/// The generator masks are written at the switch, where they rank above every
/// other generator directory.
#[test]
fn the_generator_masks_are_written_at_the_switch() {
    let world = World::new();
    let generators = world.run().join(runtime_units::GENERATOR_DIR);
    let mut plan = armed(Direction::Enter);
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);
    assert_eq!(
        fs::read_link(generators.join(GPT_AUTO)).unwrap(),
        Path::new("/dev/null")
    );
}

/// A generator mask that cannot be written ends the session, as a unit mask
/// does: through a generator directory that is a link into another
/// directory, the mask would not be where PID 1 looks first.
#[test]
fn an_entry_whose_generator_masks_cannot_be_written_ends_the_session() {
    let world = World::new();
    let elsewhere = world.run().join("udev/elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(world.run().join("systemd")).unwrap();
    symlink(&elsewhere, world.run().join(runtime_units::GENERATOR_DIR)).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);

    let why = ends(&world, &world.env(true, 1_010));

    assert!(why.starts_with("could not mask generators"), "{why}");
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
}

/// An entry of the decoy at a generator mask's path that does not mask the
/// generator ends the session: PID 1 would skip this directory and run the
/// generator from the next one. The entry stays as the decoy left it.
#[test]
fn an_entry_whose_generator_path_holds_no_mask_ends_the_session() {
    let world = World::new();
    let taken = world
        .run()
        .join(runtime_units::GENERATOR_DIR)
        .join(GPT_AUTO);
    fs::create_dir_all(&taken).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);

    let why = ends(&world, &world.env(true, 1_010));

    assert!(why.starts_with("could not mask generators"), "{why}");
    assert!(taken.is_dir(), "the decoy's entry stays");
}

/// The skips of a disk local-fs.target requires, with its fsck, of an
/// automount, and of a disk that is gone by the switch.
fn skips(world: &World) -> Vec<crate::whole_root::plan::Skip> {
    use crate::whole_root::plan::Skip;
    let disk = world.dir.path().join("disk");
    fs::write(&disk, "").unwrap();
    vec![
        Skip {
            units: vec!["srv-data.mount".to_string()],
            pulled: vec!["systemd-fsck@dev-vdb1.service".to_string()],
            device: Some(disk),
        },
        Skip {
            units: vec!["boot.automount".to_string()],
            pulled: Vec::new(),
            device: None,
        },
        Skip {
            units: vec!["srv-gone.mount".to_string()],
            pulled: vec!["systemd-fsck@dev-vdc1.service".to_string()],
            device: Some(world.dir.path().join("gone")),
        },
    ]
}

/// The units a boot target requires are skipped at the switch, those they
/// pull in with them, and the units of a disk gone by then masked instead.
#[test]
fn the_skips_are_written_at_the_switch() {
    use crate::whole_root::skips::{SKIP_DROPIN_NAME, SKIP_TEXT, dropin_dir};
    let world = World::new();
    let mut plan = armed(Direction::Enter);
    plan.skips = skips(&world);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);

    let r = world.run();
    for unit in [
        "srv-data.mount",
        "systemd-fsck@dev-vdb1.service",
        "boot.automount",
    ] {
        let dropin = r.join(dropin_dir(unit)).join(SKIP_DROPIN_NAME);
        assert_eq!(fs::read_to_string(&dropin).unwrap(), SKIP_TEXT, "{unit}");
    }
    let gone = r.join("systemd/system/srv-gone.mount");
    assert_eq!(fs::read_link(&gone).unwrap(), Path::new("/dev/null"));
    assert!(!r.join(dropin_dir("srv-gone.mount")).exists());
    assert!(!r.join(dropin_dir("systemd-fsck@dev-vdc1.service")).exists());
}

/// A skip that cannot be written ends the session, as a mask does.
#[test]
fn an_entry_whose_skips_cannot_be_written_ends_the_session() {
    use crate::whole_root::skips::dropin_dir;
    let world = World::new();
    let elsewhere = world.run().join("udev/elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(world.run().join("systemd/system")).unwrap();
    symlink(&elsewhere, world.run().join(dropin_dir("boot.automount"))).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.skips = skips(&world);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);

    let why = ends(&world, &world.env(true, 1_010));

    assert!(why.starts_with("could not skip decoy units"), "{why}");
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
}

/// Without its own units (the watcher, the sleep guard) the hidden session
/// would run unwatched: an entry that cannot install them ends the session.
#[test]
fn an_entry_whose_session_units_cannot_be_installed_ends_the_session() {
    let world = World::new();
    fs::create_dir_all(world.run().join("systemd/system")).unwrap();
    fs::write(
        world.run().join("systemd/system/multi-user.target.wants"),
        "not a directory",
    )
    .unwrap();
    ready_entry(&world);

    let why = ends(&world, &world.env(true, 1_010));

    assert!(
        why.starts_with("could not install the session's units"),
        "{why}"
    );
}

#[test]
fn the_read_only_rule_is_installed_at_the_entry_where_it_is_opted_in() {
    let world = World::new();
    let rule = world
        .run()
        .join(disk_guard::RULE_DIR)
        .join(disk_guard::RULE_NAME);
    let mut plan = armed(Direction::Enter);
    plan.read_only_disks = true;
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);

    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);
    let text = fs::read_to_string(&rule).unwrap();
    let copy = world.runtime().join(BINARY_NAME);
    assert!(
        text.contains(&format!(
            "RUN+=\"{} guard-device $devnode\"",
            copy.display()
        )),
        "{text}"
    );
}

/// The opted-in read-only rule for unused disks is part of the session's
/// safety: an entry that cannot install it ends the session.
#[test]
fn an_entry_whose_opted_in_read_only_rule_cannot_be_installed_ends_the_session() {
    let world = World::new();
    fs::write(world.run().join("udev/rules.d"), "not a directory").unwrap();
    let mut plan = armed(Direction::Enter);
    plan.read_only_disks = true;
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);

    let why = ends(&world, &world.env(true, 1_010));

    assert!(
        why.starts_with("could not install the read-only rule for unused disks"),
        "{why}"
    );
}

#[test]
fn without_the_opt_in_no_rule_is_installed() {
    let world = World::new();
    ready_entry(&world);
    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);
    assert!(!world.run().join(disk_guard::RULE_DIR).exists());
}

/// The masks of the units the hidden root does not need are best effort: a
/// mask that cannot be written leaves the entry as it is.
#[test]
fn the_boot_loader_masks_are_best_effort() {
    let world = World::new();
    let taken = world
        .run()
        .join(runtime_units::RUNTIME_CONTROL_DIR)
        .join("systemd-boot-random-seed.service");
    fs::create_dir_all(taken.join("held")).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);
    assert!(taken.is_dir(), "the mask could not be written");

    let world = World::new();
    let mut plan = armed(Direction::Enter);
    plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);
    let mask = world
        .run()
        .join(runtime_units::RUNTIME_CONTROL_DIR)
        .join("systemd-boot-random-seed.service");
    assert_eq!(fs::read_link(&mask).unwrap(), Path::new("/dev/null"));
}

/// The plan records the entry; a plan that cannot be written would leave it
/// armed for the entry inside the hidden session, so the entry ends the
/// session instead.
#[test]
fn an_entry_that_cannot_record_itself_ends_the_session() {
    if rustix::process::geteuid().is_root() {
        // Root writes into a directory without write permission.
        return;
    }
    let world = World::new();
    ready_entry(&world);
    let env = world.env(true, 1_010);
    let runtime = world.runtime();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o555)).unwrap();

    let before = kernel_asked();
    let outcome = run(&env);

    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(kernel_asked(), before + 1);
    let Outcome::Ended(why) = outcome else {
        panic!("expected the session's end, got {outcome:?}");
    };
    assert!(why.starts_with("could not record the entry"), "{why}");
    assert!(systemctl_calls(&world).contains("--force poweroff"));
}

/// The leftover guard: an activation died after building the tree, and a
/// later plain reboot became a soft-reboot. Nothing of a hidden session ran
/// in this boot, and the tree goes with the runtime pieces: PID 1 starts the
/// decoy's userspace again in place.
#[test]
fn a_populated_nextroot_that_is_not_armed_is_never_entered() {
    let world = World::new();
    install_dropin(&world.run(), Path::new("/run/overlay-runtime/control")).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.armed = None;
    world.write_plan(&plan);

    let outcome = goes_on(&world, &world.env(true, 1_000));

    assert!(matches!(outcome, Outcome::Disarmed(_)), "{outcome:?}");
    assert!(!world.runtime().exists());
    assert!(!world.run().join(DROPIN_DIR).exists());
    assert!(
        !world
            .run()
            .join(stop_guard_dir(SWITCH_TIMEOUT_UNIT))
            .exists()
    );
}

/// A next root that stays mounted after the detach would be entered: the
/// step ends the session instead.
#[test]
fn a_next_root_that_stays_mounted_after_the_detach_ends_the_session() {
    let mut leftover = armed(Direction::Enter);
    leftover.armed = None;
    let world = World::new();
    world.write_plan(&leftover);
    let mut env = world.env(true, 1_000);
    env.detach = stuck;
    let why = ends(&world, &env);
    assert_eq!(
        why,
        "not armed for this transition, and /run/nextroot stays mounted after the detach"
    );
}

/// A runtime directory the cleanup of a leftover tree cannot remove leaves
/// the plan for the next boot step: the step ends the session instead.
#[test]
fn a_leftover_whose_runtime_directory_stays_ends_the_session() {
    if rustix::process::geteuid().is_root() {
        // Root removes entries of a directory without write permission.
        return;
    }
    let mut leftover = armed(Direction::Enter);
    leftover.armed = None;
    let world = World::new();
    world.write_plan(&leftover);
    let env = world.env(true, 1_000);
    let run = world.run();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o555)).unwrap();

    let before = kernel_asked();
    let outcome = run_step(&env);

    fs::set_permissions(&run, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(kernel_asked(), before + 1);
    assert_eq!(
        outcome,
        Outcome::Ended(
            "not armed for this transition, and the runtime directory could not be removed"
                .to_string()
        )
    );
}

/// A leftover whose `/run` was `noexec` before the activation, which cannot
/// be made `noexec` again (here a directory that is no mount point, as no
/// test may remount the real `/run`), ends the session: the decoy's start
/// would run with an executable `/run`.
#[test]
fn a_leftover_whose_run_cannot_be_made_noexec_again_ends_the_session() {
    let mut leftover = armed(Direction::Enter);
    leftover.armed = None;
    leftover.run_noexec = true;
    let world = World::new();
    world.write_plan(&leftover);
    let why = ends(&world, &world.env(true, 1_000));
    assert!(
        why.starts_with("not armed for this transition, and /run could not be made noexec again"),
        "{why}"
    );
}

#[test]
fn a_reboot_that_meets_an_unarmed_tree_records_nothing_on_the_volume() {
    let world = World::new();
    let mut plan = armed_on_the_volume(Direction::Enter);
    plan.armed = None;
    world.write_plan(&plan);
    let mut env = world.env(true, 1_000);
    let volume = with_the_volume_s_bind(&world, &mut env);

    assert!(matches!(goes_on(&world, &env), Outcome::Disarmed(_)));

    assert!(!switch_refusal::refusal_path(&volume).exists());
}

/// A file that stands for the kernel's module loader path: the decoy's
/// value recorded, then the session's written over it.
fn repointed_modprobe(world: &World) -> Vec<kernel_helpers::KernelSetting> {
    let modprobe = world.dir.path().join("modprobe");
    fs::write(&modprobe, "/nix/store/decoy-kmod/bin/modprobe\n").unwrap();
    let recorded = kernel_helpers::read(&[modprobe.to_str().unwrap()]);
    fs::write(&modprobe, "/nix/store/hidden-kmod/bin/modprobe\n").unwrap();
    recorded
}

/// A reboot met a next root the activation left unarmed: the decoy gets back
/// its kernel paths and loses the session's masks of every kind, and a mask
/// the decoy had before stays.
#[test]
fn a_disarmed_next_root_gives_the_decoy_back_its_kernel_paths_and_units() {
    let world = World::new();
    let control = world.run().join(runtime_units::RUNTIME_CONTROL_DIR);
    fs::create_dir_all(&control).unwrap();
    symlink("/dev/null", control.join("grub-common.service")).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.armed = None;
    plan.boot_masks = vec![
        "systemd-boot-random-seed.service".to_string(),
        "grub-common.service".to_string(),
    ];
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    plan.kernel_settings = repointed_modprobe(&world);
    world.write_plan(&plan);
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&world.run()).to_text(),
    )
    .unwrap();
    let mut masks = runtime_units::mask_units(&world.run(), &plan.masks).unwrap();
    masks.extend(runtime_units::mask_units_best_effort(
        &world.run(),
        &plan.boot_masks[..1],
    ));
    masks.extend(runtime_units::mask_generators(&world.run(), &plan.generator_masks).unwrap());

    assert!(matches!(
        goes_on(&world, &world.env(true, 1_000)),
        Outcome::Disarmed(_)
    ));

    assert_eq!(
        fs::read_to_string(world.dir.path().join("modprobe")).unwrap(),
        "/nix/store/decoy-kmod/bin/modprobe"
    );
    for mask in masks {
        assert!(fs::symlink_metadata(&mask).is_err(), "{mask:?} stays");
    }
    assert_eq!(
        fs::read_link(control.join("grub-common.service")).unwrap(),
        Path::new("/dev/null"),
        "the decoy's own mask stays"
    );
}

#[test]
fn the_dropin_runs_the_ram_copy_with_its_output_discarded_and_fails_closed() {
    let text = dropin_text(Path::new("/run/overlay-runtime/control"));
    assert!(text.contains("\nExecStart=/run/overlay-runtime/control transition\n"));
    assert!(
        !text.contains("ExecStart=-"),
        "a failure must not be ignored"
    );
    assert!(text.starts_with("[Unit]\nFailureAction=poweroff-force\n[Service]\n"));
    assert!(text.contains("StandardOutput=null"));
    assert!(text.contains("StandardError=null"));
    assert!(text.contains("Type=oneshot"));
    assert!(!text.to_lowercase().contains("nails"));
    assert!(!DROPIN_NAME.contains("nails"));
}

#[test]
fn only_the_session_s_end_fails_the_service() {
    assert_eq!(Outcome::NothingToDo.exit_code(), 0);
    assert_eq!(Outcome::Entered.exit_code(), 0);
    assert_eq!(Outcome::Disarmed("x".to_string()).exit_code(), 0);
    assert_eq!(Outcome::Ended("x".to_string()).exit_code(), 1);
}

#[test]
fn the_stop_guards_clear_blkdeactivate_for_the_switches_and_go_with_the_dropin() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    // blkdeactivate -u would unmount the hidden volume below /run/nextroot on
    // the way in. Debian's and Ubuntu's copy of the unit has its stop as its
    // only command: the guard gives it a start that does nothing, or systemd
    // would refuse to load it.
    let guard = run
        .join(stop_guard_dir("blk-availability.service"))
        .join(STOP_GUARD_NAME);
    assert_eq!(
        fs::read_to_string(&guard).unwrap(),
        "[Service]\nExecStop=\nExecStart=-/usr/bin/true\n"
    );
    for text in [STOP_GUARD_TEXT, STOP_GUARD_WITH_START_TEXT] {
        assert!(text.lines().all(|l| !l.to_lowercase().contains("nails")));
    }
    assert!(!STOP_GUARD_NAME.contains("nails"));
    // Later than what `systemctl edit` and NixOS write, so neither undoes it.
    for other in ["override.conf", "overrides.conf", "99-local.conf"] {
        assert!(STOP_GUARD_NAME > other, "{other} sorts after the guard");
    }

    // NixOS's static addresses: one prefix drop-in covers every interface.
    let addresses = run
        .join(stop_guard_dir("network-addresses-.service"))
        .join(STOP_GUARD_NAME);
    assert_eq!(
        fs::read_to_string(&addresses).unwrap(),
        "[Service]\nExecStop=\n"
    );
    assert_eq!(
        stop_guard_dir("network-addresses-.service"),
        Path::new("systemd/system/network-addresses-.service.d")
    );
    assert!(is_unit_prefix("network-addresses-.service"));
    assert!(!is_unit_prefix("blk-availability.service"));

    // Ubuntu 26.04's bus outlives a shutdown; the guard stops it with the root.
    for unit in ["dbus.service", "dbus.socket"] {
        let bus = run.join(stop_guard_dir(unit)).join(STOP_GUARD_NAME);
        assert_eq!(
            fs::read_to_string(&bus).unwrap(),
            "[Unit]\nConflicts=shutdown.target\nBefore=shutdown.target\n",
            "{unit}"
        );
    }
    assert_eq!(runtime_guards().count(), 5);

    remove_dropin(run, &Snapshot::default());
    for unit in ["dbus.service", "dbus.socket", "soft-reboot.target"] {
        assert!(!run.join(stop_guard_dir(unit)).exists(), "{unit}");
    }
    assert!(
        !run.join(stop_guard_dir("network-addresses-.service"))
            .exists()
    );
    assert!(
        !run.join(stop_guard_dir("blk-availability.service"))
            .exists()
    );
    assert!(!run.join(DROPIN_DIR).exists());
}

/// The timeout guard: a switch that hangs until `soft-reboot.target`'s job
/// timeout powers off, by force, as a plain `poweroff` is skipped while
/// `shutdown.target` is active or queued. The timeout stays the unit's own,
/// and the guard goes with the other drop-ins.
#[test]
fn the_timeout_guard_powers_off_a_switch_that_hangs_and_goes_with_the_dropin() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    let guard = run.join("systemd/system/soft-reboot.target.d/zz-overlay-runtime.conf");
    assert_eq!(
        fs::read_to_string(&guard).unwrap(),
        "[Unit]\nJobTimeoutAction=poweroff-force\n"
    );
    assert_eq!(SWITCH_TIMEOUT_ACTION, session_end().emergency_action());
    assert!(
        SWITCH_TIMEOUT_TEXT
            .lines()
            .any(|line| line == format!("JobTimeoutAction={SWITCH_TIMEOUT_ACTION}"))
    );
    assert!(!SWITCH_TIMEOUT_TEXT.contains("JobTimeoutSec"));
    assert!(!SWITCH_TIMEOUT_TEXT.to_lowercase().contains("nails"));
    assert!(
        runtime_guards()
            .any(|(unit, text)| unit == SWITCH_TIMEOUT_UNIT && text == SWITCH_TIMEOUT_TEXT)
    );

    assert!(remove_dropin(run, &Snapshot::default()));
    assert!(!guard.exists());
    assert!(!run.join(stop_guard_dir(SWITCH_TIMEOUT_UNIT)).exists());
}

/// The timeout guard stays for the whole session: the switch into it keeps
/// it for the hidden PID 1, and a soft-reboot in the session ends it with
/// the guard still in place.
#[test]
fn the_timeout_guard_stays_for_the_whole_session() {
    let world = World::new();
    let r = world.run();
    let guard = r
        .join(stop_guard_dir(SWITCH_TIMEOUT_UNIT))
        .join(STOP_GUARD_NAME);
    install_dropin(&r, Path::new("/run/overlay-runtime/control")).unwrap();
    ready_entry(&world);
    assert_eq!(goes_on(&world, &world.env(true, 1_010)), Outcome::Entered);
    assert!(guard.exists(), "the hidden PID 1 loads it");

    ends(&world, &world.env(true, 1_015));
    assert!(guard.exists());
}

#[test]
fn the_dropins_are_readable_by_all_so_pid1_never_names_them_in_the_kernel_log() {
    // PID 1 warns about a configuration file that is not readable by all, or
    // that is executable or writable by all, and names it; at the start of
    // the other root no journald runs yet, so the warning reaches dmesg.
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let dropin = install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    let guards =
        runtime_guards().map(|(unit, _)| run.join(stop_guard_dir(unit)).join(STOP_GUARD_NAME));
    for file in guards.chain(std::iter::once(dropin)) {
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode & 0o044, 0o044, "{}: {mode:o}", file.display());
        assert_eq!(mode & 0o113, 0, "{}: {mode:o}", file.display());
    }
}

#[test]
fn a_rollback_removes_the_guards_and_only_the_directories_it_made() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let decoy_dir = run.join(stop_guard_dir("dbus.service"));
    fs::create_dir_all(&decoy_dir).unwrap();
    fs::write(decoy_dir.join("10-local.conf"), "[Unit]\n").unwrap();
    let kept = Snapshot::take(run);
    install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    remove_dropin(run, &kept);
    assert!(decoy_dir.is_dir());
    assert!(!decoy_dir.join(STOP_GUARD_NAME).exists());
    assert_eq!(
        fs::read_to_string(decoy_dir.join("10-local.conf")).unwrap(),
        "[Unit]\n"
    );
    assert!(!run.join(stop_guard_dir("dbus.socket")).exists());
    assert!(!run.join(DROPIN_DIR).exists());
}

/// The carried filesystems' mount units get one drop-in for their prefix,
/// readable by all, that drops PID 1's info lines about them; a name that is
/// no prefix of mount units is refused, so nothing else is quieted.
#[test]
fn the_carried_mount_units_are_quieted_by_their_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let file = install_quiet_mounts(run, "mnt-data-root-decoy-.mount").unwrap();
    assert_eq!(
        file,
        run.join("systemd/system/mnt-data-root-decoy-.mount.d")
            .join(STOP_GUARD_NAME)
    );
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "[Mount]\nLogLevelMax=notice\n"
    );
    let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o644, "{mode:o}");
    for name in [
        "mnt-data-root-decoy.mount",
        "-.mount",
        "mnt-data-root-decoy-.service",
        "../escape-.mount",
        "",
    ] {
        assert!(install_quiet_mounts(run, name).is_err(), "{name}");
    }
    assert_eq!(
        fs::read_dir(run.join("systemd/system")).unwrap().count(),
        1,
        "only the prefix's directory"
    );
}

/// Every removal of the drop-ins removes the quieting one too, whichever
/// prefix the entry quieted, and its directory unless the decoy had it; a
/// file of the same name with other content is the decoy's and stays.
#[test]
fn the_quieting_dropin_goes_with_the_other_dropins() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let decoy_dir = run.join(stop_guard_dir("srv-x-.mount"));
    fs::create_dir_all(&decoy_dir).unwrap();
    let kept = Snapshot::take(run);
    install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    install_quiet_mounts(run, "mnt-data-root-decoy-.mount").unwrap();
    install_quiet_mounts(run, "srv-x-.mount").unwrap();
    let theirs = run.join(stop_guard_dir("home-.mount"));
    fs::create_dir_all(&theirs).unwrap();
    fs::write(theirs.join(STOP_GUARD_NAME), "[Mount]\nLogLevelMax=debug\n").unwrap();

    assert!(remove_dropin(run, &kept));

    assert!(
        !run.join(stop_guard_dir("mnt-data-root-decoy-.mount"))
            .exists()
    );
    assert!(decoy_dir.is_dir(), "the decoy's directory stays");
    assert!(!decoy_dir.join(STOP_GUARD_NAME).exists());
    assert_eq!(
        fs::read_to_string(theirs.join(STOP_GUARD_NAME)).unwrap(),
        "[Mount]\nLogLevelMax=debug\n"
    );
}

/// A fence kernel that does nothing but count its attaches, or fails them.
#[derive(Debug)]
struct StubFence {
    fail: bool,
    attached: std::sync::atomic::AtomicUsize,
}

impl crate::whole_root::fence::FenceKernel for StubFence {
    fn sync(&self) {}
    fn swaps(&self) -> Vec<crate::whole_root::fence::Swap> {
        Vec::new()
    }
    fn reconfigure(
        &self,
        _: &crate::whole_root::fence::Superblock,
        _: &Path,
    ) -> std::io::Result<()> {
        Ok(())
    }
    fn superblock_read_only(&self, _: &crate::whole_root::fence::Superblock) -> Option<bool> {
        Some(true)
    }
    fn device_read_only(&self, _: &crate::whole_root::fence::Device) -> bool {
        false
    }
    fn set_read_only(&self, _: &crate::whole_root::fence::Device) -> std::io::Result<()> {
        Ok(())
    }
    fn discard_max(&self, _: &Path) -> std::io::Result<u64> {
        Ok(0)
    }
    fn discard_off(&self, _: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn attach(
        &self,
        _: &crate::whole_root::fence::Rules,
    ) -> std::io::Result<crate::whole_root::fence::Program> {
        if self.fail {
            return Err(std::io::Error::other("no program"));
        }
        self.attached
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::whole_root::fence::Program {
            id: 1,
            tag: "00".into(),
        })
    }
    fn crash_log_backend(&self) -> Option<String> {
        None
    }
    fn efi_crash_log_stoppable(&self) -> bool {
        true
    }
    fn stop_efi_crash_log(&self) -> std::io::Result<()> {
        Ok(())
    }
    fn dm_targets(&self, _: disk_guard::DevNum) -> std::io::Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn probe(&self, _: &crate::whole_root::fence::Rules) -> std::io::Result<()> {
        Ok(())
    }
}

static FENCE_UP: StubFence = StubFence {
    fail: false,
    attached: std::sync::atomic::AtomicUsize::new(0),
};
static FENCE_REFUSED: StubFence = StubFence {
    fail: true,
    attached: std::sync::atomic::AtomicUsize::new(0),
};
static LEFTOVERS_ENDED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn count_leftovers(_: Option<&Path>) -> Vec<u32> {
    LEFTOVERS_ENDED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Vec::new()
}

/// `env` with a fence through `kernel` over an empty sysfs in `world`.
fn with_fence(world: &World, env: &mut Env, kernel: &'static StubFence) {
    let sys = world.dir.path().join("sys");
    fs::create_dir_all(&sys).unwrap();
    env.fence = Some(FencePlaces {
        sys: disk_guard::Sysfs { root: sys },
        kernel,
        leftovers: count_leftovers,
    });
}

/// An entry ready to go with the fence's record of one decoy disk.
fn fenced_entry(world: &World) -> Plan {
    let mut plan = armed(Direction::Enter);
    plan.fence = Some(crate::whole_root::fence::FenceSpec {
        disks: vec![disk_guard::DevNum { major: 8, minor: 0 }],
        ..Default::default()
    });
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    plan
}

#[test]
fn the_entry_ends_the_leftovers_and_puts_the_fence_up() {
    let world = World::new();
    fenced_entry(&world);
    let mut env = world.env(true, 1_010);
    with_fence(&world, &mut env, &FENCE_UP);
    let ended = LEFTOVERS_ENDED.load(std::sync::atomic::Ordering::SeqCst);
    let attached = FENCE_UP.attached.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(goes_on(&world, &env), Outcome::Entered);
    assert!(LEFTOVERS_ENDED.load(std::sync::atomic::Ordering::SeqCst) > ended);
    assert_eq!(
        FENCE_UP.attached.load(std::sync::atomic::Ordering::SeqCst),
        attached + 1
    );
    assert_eq!(world.plan().entered_at, Some(1_010));
}

#[test]
fn a_fence_that_does_not_go_up_ends_the_session_instead_of_entering() {
    let world = World::new();
    fenced_entry(&world);
    let mut env = world.env(true, 1_010);
    with_fence(&world, &mut env, &FENCE_REFUSED);
    let why = ends(&world, &env);
    assert!(why.contains("could not be made read-only"), "{why}");
    assert_eq!(world.plan().entered_at, None);
}

#[test]
fn an_entry_without_the_fence_s_record_ends_the_session() {
    let world = World::new();
    ready_entry(&world);
    let mut env = world.env(true, 1_010);
    with_fence(&world, &mut env, &FENCE_UP);
    let why = ends(&world, &env);
    assert!(why.contains("recorded no decoy disk"), "{why}");
}
