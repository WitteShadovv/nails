// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The transition step against real directory trees: a `/run`, a next root and
//! a kernel log, all in a temporary directory. Only the mount table is given
//! (a `/run/nextroot` entry), so nothing here needs privileges; the mounts
//! themselves are exercised by the kernel tests in `nails-core`.

use super::*;
use crate::mountinfo::parse_mountinfo;
use crate::test_support::write_executable;
use crate::whole_root::plan::{Arm, sample};
use crate::whole_root::runtime_units::RuntimeUnit;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

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
    fn kmsg(&self) -> PathBuf {
        self.dir.path().join("kmsg")
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
            kmsg: self.kmsg(),
            systemctl: None,
            now,
            mounts: parse_mountinfo(&table),
            network: self.network(),
            network_tools: Some(network::NetTools::default()),
            power_off: PowerOff {
                grace: std::time::Duration::ZERO,
                kernel: refused_power_off,
            },
        }
    }
    /// Where the way back reads and writes the network state: a fake
    /// `/sys/class/net`, hostname and network settings below the world, and
    /// the per-link runtime state below its `/run`.
    fn network(&self) -> network::Places {
        network::Places {
            run: self.run(),
            sys_class_net: self.dir.path().join("sys/class/net"),
            proc_hostname: self.dir.path().join("proc/sys/kernel/hostname"),
            proc_sys: self.dir.path().join("proc/sys"),
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

#[test]
fn without_a_plan_or_a_mounted_nextroot_nothing_happens() {
    let world = World::new();
    assert_eq!(run(&world.env(true, 1_000)), Outcome::NothingToDo);
    world.write_plan(&armed(Direction::Enter));
    assert_eq!(run(&world.env(false, 1_000)), Outcome::NothingToDo);
    assert!(world.runtime().join(PLAN_NAME).exists());
}

#[test]
fn entering_repoints_current_system_masks_decoy_units_and_records_the_entry() {
    let world = World::new();
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);

    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);

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
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
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
    env.mounts.extend(parse_mountinfo(&format!(
        "62 1 8:0 / / rw - ext4 /dev/vda rw\n\
         85 62 0:50 / /nix/store rw - overlay overlay rw\n\
         70 62 0:51 / /run/wrappers rw - tmpfs wrappers rw\n\
         63 40 254:0 / {}/mnt/data rw - ext4 /dev/mapper/data rw\n",
        next.display()
    )));

    assert_eq!(run(&env), Outcome::Entered);
    assert_eq!(
        fs::read_to_string(&utab).unwrap(),
        "ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=X-kept\n\
         SRC=/dev/mapper/data TARGET=/mnt/data ROOT=/ OPTS=X-kept\n"
    );
}

#[test]
fn an_entry_whose_init_does_not_resolve_is_disarmed_instead_of_freezing_pid1() {
    let world = World::new();
    install_dropin(&world.run(), Path::new("/run/overlay-runtime/control")).unwrap();
    world.write_plan(&armed(Direction::Enter));

    assert!(matches!(
        run(&world.env(true, 1_000)),
        Outcome::Disarmed(why) if why.contains("does not resolve")
    ));
    // The repoint is undone and nothing of the failed activation is left.
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system")
    );
    assert!(!world.runtime().exists());
    assert!(!world.run().join(DROPIN_DIR).exists());
    assert!(
        !world
            .run()
            .join(stop_guard_dir("blk-availability.service"))
            .exists()
    );
    assert!(!world.run().join("systemd/system/dev-vda3.swap").exists());
}

#[test]
fn a_populated_nextroot_that_is_not_armed_is_never_entered() {
    // The leftover guard: an activation died after building the tree, and a
    // later plain reboot became a soft-reboot.
    let world = World::new();
    let mut plan = armed(Direction::Enter);
    plan.armed = None;
    world.write_plan(&plan);
    assert!(matches!(run(&world.env(true, 1_000)), Outcome::Disarmed(_)));
    assert!(!world.runtime().exists());

    // An arming that expired is no arming.
    let world = World::new();
    world.write_plan(&armed(Direction::Enter));
    let late = 1_001 + crate::whole_root::plan::ARM_VALIDITY_SECS;
    assert!(matches!(run(&world.env(true, late)), Outcome::Disarmed(_)));
}

#[test]
fn an_unarmed_nextroot_in_the_hidden_session_keeps_the_plan() {
    let world = World::new();
    let mut plan = armed(Direction::Leave);
    plan.armed = None;
    plan.entered_at = Some(900);
    world.write_plan(&plan);
    assert!(matches!(run(&world.env(true, 1_000)), Outcome::Disarmed(_)));
    assert!(world.runtime().join(PLAN_NAME).exists());
    assert_eq!(switch_refusal::read(&world.runtime()), None);
}

/// The mount table as the transition finds it: the decoy root, the next root
/// (`env`'s, made canonical) and in it the hidden volume's bind at
/// `/mnt/data`, on device 254:0. The shutdown has already unmounted the volume
/// at its own path. Returns the bind's directory.
fn with_the_volume_s_bind(world: &World, env: &mut Env) -> PathBuf {
    let next = fs::canonicalize(world.nextroot()).unwrap();
    let volume = next.join("mnt/data");
    fs::create_dir_all(&volume).unwrap();
    env.mounts = parse_mountinfo(&format!(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         40 1 0:40 / {} rw - overlay overlay rw\n\
         63 40 254:0 / {} rw - ext4 /dev/mapper/data rw\n",
        next.display(),
        volume.display()
    ));
    env.nextroot = next;
    volume
}

/// A plan armed for `direction` on the hidden volume of device 254:0.
fn armed_on_the_volume(direction: Direction) -> Plan {
    let mut plan = armed(direction);
    plan.hidden_dev = Some("254:0".to_string());
    plan
}

#[test]
fn a_refused_entry_keeps_its_reason_on_the_hidden_volume_through_the_next_root() {
    let world = World::new();
    world.write_plan(&armed_on_the_volume(Direction::Enter));
    let mut env = world.env(true, 1_000);
    let volume = with_the_volume_s_bind(&world, &mut env);

    // The hidden init is not in the next root: the check refuses the switch.
    let outcome = run(&env);

    let Outcome::Disarmed(why) = outcome else {
        panic!("expected a refused switch, got {outcome:?}");
    };
    assert!(why.contains("does not resolve"), "{why}");
    assert_eq!(
        switch_refusal::read(&volume),
        Some(switch_refusal::SwitchRefusal {
            reason: why,
            at: 1_000
        }),
        "the reason is on the hidden volume"
    );
    assert!(!world.runtime().exists(), "nothing of the entry is left");
}

#[test]
fn a_reboot_that_meets_an_unarmed_tree_records_nothing_on_the_volume() {
    let world = World::new();
    let mut plan = armed_on_the_volume(Direction::Enter);
    plan.armed = None;
    world.write_plan(&plan);
    let mut env = world.env(true, 1_000);
    let volume = with_the_volume_s_bind(&world, &mut env);

    assert!(matches!(run(&env), Outcome::Disarmed(_)));

    assert!(!switch_refusal::refusal_path(&volume).exists());
}

#[test]
fn a_refused_way_back_keeps_its_reason_in_the_runtime_directory() {
    // In the hidden session the next root is the decoy's: whatever is mounted
    // there, the reason never goes into it. PID 1 stays in the hidden root,
    // and `/run` with it.
    let world = World::new();
    repoint_current_system(&world.run(), Path::new("/nix/store/bbb-nixos-system")).unwrap();
    let mut plan = armed_on_the_volume(Direction::Leave);
    plan.entered_at = Some(900);
    world.write_plan(&plan);
    let mut env = world.env(true, 1_000);
    let in_next_root = with_the_volume_s_bind(&world, &mut env);

    // The decoy's init is not in the next root: the check refuses the way back.
    let outcome = run(&env);

    let Outcome::Disarmed(why) = outcome else {
        panic!("expected a refused switch, got {outcome:?}");
    };
    assert!(why.contains("does not resolve"), "{why}");
    let kept = switch_refusal::read(&world.runtime()).expect("the reason is kept in /run");
    assert_eq!((kept.reason.as_str(), kept.at), (why.as_str(), 1_000));
    assert!(!switch_refusal::refusal_path(&in_next_root).exists());
    // The session goes on, on its own system, with its plan for a later way
    // back.
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/bbb-nixos-system")
    );
    assert!(world.runtime().join(PLAN_NAME).exists());
}

#[test]
fn leaving_scrubs_run_restores_the_decoy_and_writes_the_cursor_last() {
    let world = World::new();
    let r = world.run();
    // In the decoy, just before entering: the snapshot and the utab copy.
    let snapshot = Snapshot::take(&r);
    fs::write(world.runtime().join(SNAPSHOT_NAME), snapshot.to_text()).unwrap();
    // The decoy's copy: a line for the mount that is the next root now (ID 40
    // in the world's mount table), and one for a decoy mount the entry's
    // switch left behind, whose ID the kernel may have handed on since.
    fs::write(
        world.runtime().join(UTAB_NAME),
        "ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount\n\
         ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n",
    )
    .unwrap();
    // The hidden session.
    repoint_current_system(&r, Path::new("/nix/store/bbb-nixos-system")).unwrap();
    fs::write(r.join("hidden-probe"), "x").unwrap();
    fs::write(r.join("mount/utab"), "ID=1 decoy\nID=77 /mnt/hidden-only\n").unwrap();
    install_dropin(&r, Path::new("/run/overlay-runtime/control")).unwrap();
    fs::write(world.kmsg(), "6,500,1,-;hidden record\n6,501,2,-;later\n").unwrap();
    let mut plan = armed(Direction::Leave);
    plan.entered_at = Some(900);
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);

    // A hidden unit not ordered before the shutdown is still stopping when
    // the transition runs, logs to the kernel once more on its way out and
    // unmounts, so libmount writes its copy of utab: the cursor and the
    // decoy's utab must come after it.
    let late = world.dir.path().join("late-stopped");
    let calls = world.dir.path().join("reset-failed-calls");
    plan.failed_at_entry = vec!["decoy-before.service".to_string()];
    world.write_plan(&plan);
    let systemctl = world.dir.path().join("systemctl");
    write_executable(
        &systemctl,
        format!(
            "#!/bin/sh\nif [ \"$1\" = reset-failed ]; then echo \"$@\" >> {calls}; exit 0; fi\n\
             if [ \"$1\" = list-units ]; then\n\
               echo 'overlay-runtime-monitor.service loaded failed failed watcher'\n\
               echo 'nscd.service loaded failed failed Name Service Cache Daemon'\n\
               echo 'decoy-before.service loaded failed failed failed before the session'\n\
               exit 0\n\
             fi\n\
             echo '7 soft-reboot.target start waiting'\n\
             if [ ! -e {late} ]; then\n\
               echo '12 late.service stop running'\n\
               printf '6,502,3,-;late hidden record\\n' >> {kmsg}\n\
               printf 'ID=77 /mnt/hidden-only\\n' > {utab}\n\
               : > {late}\n\
             fi\n",
            late = late.display(),
            kmsg = world.kmsg().display(),
            utab = r.join("mount/utab").display(),
            calls = calls.display()
        ),
        0o755,
    );
    let mut env = world.env(true, 1_000);
    env.systemctl = Some(systemctl);

    let outcome = run(&env);
    assert!(
        matches!(outcome, Outcome::Returned { failed: 0, .. }),
        "{outcome:?}"
    );

    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system")
    );
    assert!(!r.join("hidden-probe").exists());
    assert!(
        !world.runtime().exists(),
        "the runtime directory is scrubbed"
    );
    assert!(!r.join(DROPIN_DIR).exists(), "the drop-in is scrubbed");
    assert!(
        !r.join(stop_guard_dir("blk-availability.service")).exists(),
        "the stop guard is scrubbed, so the decoy's own shutdown is unchanged"
    );
    assert!(
        !r.join(stop_guard_dir("network-addresses-.service"))
            .exists(),
        "the address guard is scrubbed too"
    );
    assert_eq!(
        fs::read_to_string(r.join("mount/utab")).unwrap(),
        "ID=40 SRC=overlay TARGET=/ ROOT=/ OPTS=x-initrd.mount\n",
        "the hidden session's line and the stale decoy line are gone"
    );
    assert_eq!(fs::read_to_string(r.join("decoy-state")).unwrap(), "keep");
    let cursor = fs::read(r.join(run_scrub::KERNEL_SEQNUM)).unwrap();
    assert_eq!(u64::from_ne_bytes(cursor.try_into().unwrap()), 503);
    // An emergency's SIGKILL left units failed (the session's own, a decoy
    // unit caught stopping); the decoy must not inherit that record, but keeps
    // the failure it had before the session.
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "reset-failed overlay-runtime-monitor.service nscd.service\n"
    );
}

#[test]
fn leaving_gives_the_decoys_utab_lines_back_to_its_restored_mounts() {
    // The decoy's initrd lines name its root and store by the IDs they had at
    // entry. The way back mounts the decoy root and binds the store it carried
    // again, under new IDs (the hidden volume has the root's old one now): the
    // lines follow their mounts there, so the decoy keeps them as initrd
    // mounts. The tmpfs the session did not carry gets no line.
    let world = World::new();
    fs::write(
        world.runtime().join(UTAB_NAME),
        "ID=62 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n\
         ID=68 SRC=tmpfs TARGET=/sysroot/nix/.rw-store ROOT=/ OPTS=x-initrd.mount\n\
         ID=85 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n",
    )
    .unwrap();
    fs::write(
        world.runtime().join(UTAB_MOUNTS_NAME),
        "62 1 253:0 / / rw - ext4 /dev/vda rw\n\
         68 62 0:31 / /nix/.rw-store rw - tmpfs tmpfs rw\n\
         85 62 0:32 / /nix/store ro - overlay overlay rw\n",
    )
    .unwrap();
    fs::write(world.run().join("mount/utab"), "ID=112 hidden\n").unwrap();
    let mut plan = armed(Direction::Leave);
    plan.entered_at = Some(900);
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let mut env = world.env(true, 1_000);
    let next = world.nextroot();
    env.mounts = parse_mountinfo(&format!(
        "140 1 0:50 / / rw - overlay overlay rw\n\
         62 140 254:0 / /mnt/data rw - ext4 /dev/mapper/data rw\n\
         150 140 253:0 / {next} rw - ext4 /dev/vda rw\n\
         152 150 0:32 / {next}/nix/store ro - overlay overlay rw\n",
        next = next.display()
    ));

    assert!(matches!(run(&env), Outcome::Returned { .. }));
    assert_eq!(
        fs::read_to_string(world.run().join("mount/utab")).unwrap(),
        "ID=150 SRC=/dev/vda TARGET=/sysroot ROOT=/ OPTS=x-initrd.mount\n\
         ID=152 SRC=overlay TARGET=/sysroot/nix/store ROOT=/ OPTS=x-initrd.mount\n"
    );
}

#[test]
fn the_dropin_runs_the_ram_copy_with_its_output_discarded() {
    let text = dropin_text(Path::new("/run/overlay-runtime/control"));
    assert!(text.contains("ExecStart=-/run/overlay-runtime/control transition\n"));
    assert!(text.contains("StandardOutput=null"));
    assert!(text.contains("StandardError=null"));
    assert!(text.contains("Type=oneshot"));
    assert!(!text.to_lowercase().contains("nails"));
    assert!(!DROPIN_NAME.contains("nails"));
}

#[test]
fn the_stop_guards_clear_blkdeactivate_for_the_switches_and_go_with_the_dropin() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    // blkdeactivate -u would unmount the hidden volume below /run/nextroot on
    // the way in, and a LUKS or LVM decoy root below it on the way back.
    // Debian's and Ubuntu's copy of the unit has its stop as its only
    // command: the guard gives it a start that does nothing, or systemd would
    // refuse to load it.
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
    assert_eq!(runtime_guards().count(), 4);

    remove_dropin(run, &Snapshot::default());
    for unit in ["dbus.service", "dbus.socket"] {
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
fn a_dropin_directory_the_decoy_had_keeps_its_own_files_and_loses_the_guard() {
    let world = World::new();
    let r = world.run();
    let decoy_dir = r.join(stop_guard_dir("blk-availability.service"));
    fs::create_dir_all(&decoy_dir).unwrap();
    fs::write(decoy_dir.join("10-local.conf"), "[Unit]\n").unwrap();
    let empty_dir = r.join(stop_guard_dir("dbus.service"));
    fs::create_dir_all(&empty_dir).unwrap();
    // The entry: the snapshot first, then the drop-ins.
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&r).to_text(),
    )
    .unwrap();
    install_dropin(&r, Path::new("/run/overlay-runtime/control")).unwrap();
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);

    let mut plan = world.plan();
    plan.armed = Some(Arm {
        direction: Direction::Leave,
        at: 1_020,
    });
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let outcome = run(&world.env(true, 1_030));
    assert!(
        matches!(outcome, Outcome::Returned { failed: 0, .. }),
        "{outcome:?}"
    );

    assert!(!decoy_dir.join(STOP_GUARD_NAME).exists(), "the guard goes");
    assert_eq!(
        fs::read_to_string(decoy_dir.join("10-local.conf")).unwrap(),
        "[Unit]\n"
    );
    assert!(fs::read_dir(&empty_dir).unwrap().next().is_none());
    for unit in ["dbus.socket", "network-addresses-.service"] {
        assert!(!r.join(stop_guard_dir(unit)).exists(), "{unit}");
    }
    assert!(!r.join(DROPIN_DIR).exists());
}

#[test]
fn a_rollback_removes_the_guards_and_only_the_directories_it_made() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let decoy_dir = run.join(stop_guard_dir("dbus.service"));
    fs::create_dir_all(&decoy_dir).unwrap();
    let kept = Snapshot::take(run);
    install_dropin(run, Path::new("/run/overlay-runtime/control")).unwrap();
    remove_dropin(run, &kept);
    assert!(decoy_dir.is_dir());
    assert!(!decoy_dir.join(STOP_GUARD_NAME).exists());
    assert!(!run.join(stop_guard_dir("dbus.socket")).exists());
    assert!(!run.join(DROPIN_DIR).exists());
}

#[test]
fn a_decoy_service_s_pid_file_the_hidden_session_wrote_again_goes_on_the_way_back() {
    // The decoy's avahi wrote its PID file and removed it when the switch
    // stopped it; the hidden avahi wrote it again and was killed by an
    // emergency, so nothing removed it. The decoy's avahi must not find it.
    let world = World::new();
    let r = world.run();
    fs::create_dir_all(r.join("avahi-daemon")).unwrap();
    fs::write(r.join("avahi-daemon/pid"), "100\n").unwrap();
    // At activation, with the decoy's services still running.
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&r).to_text(),
    )
    .unwrap();
    // The decoy's own shutdown, then the switch.
    fs::remove_file(r.join("avahi-daemon/pid")).unwrap();
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
    // The hidden session, ended by a kill.
    fs::write(r.join("avahi-daemon/pid"), "200\n").unwrap();

    let mut plan = world.plan();
    plan.armed = Some(Arm {
        direction: Direction::Leave,
        at: 1_020,
    });
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let outcome = run(&world.env(true, 1_030));
    assert!(
        matches!(outcome, Outcome::Returned { failed: 0, .. }),
        "{outcome:?}"
    );

    assert!(!r.join("avahi-daemon/pid").exists());
    assert!(
        r.join("avahi-daemon").is_dir(),
        "kept through the decoy's shutdown"
    );
    assert_eq!(fs::read_to_string(r.join("decoy-state")).unwrap(), "keep");
}

#[test]
fn the_decoy_s_name_server_records_are_put_back_on_the_way_back() {
    let world = World::new();
    let r = world.run();
    let key = r.join("resolvconf/keys/NetworkManager");
    fs::create_dir_all(key.parent().unwrap()).unwrap();
    fs::write(&key, "nameserver 10.0.2.3\n").unwrap();
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&r).to_text(),
    )
    .unwrap();
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
    // The hidden NetworkManager rewrites its record and leaves it at its stop.
    fs::write(&key, "search hidden.example\nnameserver 10.213.77.53\n").unwrap();

    let mut plan = world.plan();
    plan.armed = Some(Arm {
        direction: Direction::Leave,
        at: 1_020,
    });
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let outcome = run(&world.env(true, 1_030));
    assert!(
        matches!(outcome, Outcome::Returned { failed: 0, .. }),
        "{outcome:?}"
    );
    assert_eq!(fs::read_to_string(&key).unwrap(), "nameserver 10.0.2.3\n");
}

#[test]
fn the_boot_loader_masks_are_written_where_they_outrank_etc_and_go_with_the_session() {
    let world = World::new();
    let mut plan = armed(Direction::Enter);
    plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&world.run()).to_text(),
    )
    .unwrap();
    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
    let mask = world
        .run()
        .join(runtime_units::RUNTIME_CONTROL_DIR)
        .join("systemd-boot-random-seed.service");
    assert_eq!(fs::read_link(&mask).unwrap(), Path::new("/dev/null"));

    let mut plan = world.plan();
    plan.armed = Some(Arm {
        direction: Direction::Leave,
        at: 1_020,
    });
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    assert!(matches!(
        run(&world.env(true, 1_030)),
        Outcome::Returned { .. }
    ));
    assert!(
        fs::symlink_metadata(&mask).is_err(),
        "the decoy runs the unit again"
    );
}

/// A switch that fails after the entry transition leaves the decoy running
/// with the session's masks in `/run`. Removing them on the decoy side (a
/// rollback, `nails recover`, an emergency there) takes only what the entry
/// wrote: a mask the decoy had before stays.
#[test]
fn the_masks_of_an_entry_whose_switch_failed_go_and_the_decoy_s_own_stay() {
    let world = World::new();
    let control = world.run().join(runtime_units::RUNTIME_CONTROL_DIR);
    fs::create_dir_all(&control).unwrap();
    symlink("/dev/null", control.join("grub-common.service")).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.boot_masks = vec![
        "systemd-boot-random-seed.service".to_string(),
        "grub-common.service".to_string(),
    ];
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    let kept = Snapshot::take(&world.run());
    fs::write(world.runtime().join(SNAPSHOT_NAME), kept.to_text()).unwrap();
    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
    let swap = world.run().join("systemd/system/dev-vda3.swap");
    let seed = control.join("systemd-boot-random-seed.service");
    let generators = world.run().join(runtime_units::GENERATOR_DIR);
    assert!(fs::symlink_metadata(&swap).is_ok() && fs::symlink_metadata(&seed).is_ok());
    assert!(fs::symlink_metadata(generators.join(GPT_AUTO)).is_ok());

    // The switch failed: the decoy userspace runs again over the same /run.
    let plan = world.plan();
    runtime_units::remove_masks(
        &world.run(),
        &plan.masks,
        &plan.boot_masks,
        &plan.generator_masks,
        &kept,
    );
    assert!(
        fs::symlink_metadata(&swap).is_err(),
        "the decoy swap is masked"
    );
    assert!(
        fs::symlink_metadata(&seed).is_err(),
        "the seed unit is masked"
    );
    assert!(!generators.exists(), "the decoy's generators are masked");
    assert_eq!(
        fs::read_link(control.join("grub-common.service")).unwrap(),
        Path::new("/dev/null"),
        "the decoy's own mask stays"
    );
}

/// The generator every entry masks.
const GPT_AUTO: &str = "systemd-gpt-auto-generator";

/// The generator masks are written at the switch, where they rank above every
/// other generator directory, and go with the session's `/run` on the way
/// back: the whole directory when the decoy had none, and only the session's
/// mask when the decoy keeps one of its own.
#[test]
fn the_generator_masks_are_written_at_the_switch_and_go_with_the_session() {
    for decoy_has_generators in [false, true] {
        let world = World::new();
        let generators = world.run().join(runtime_units::GENERATOR_DIR);
        if decoy_has_generators {
            fs::create_dir_all(&generators).unwrap();
            symlink("/dev/null", generators.join("zram-generator")).unwrap();
        }
        let mut plan = armed(Direction::Enter);
        plan.generator_masks = vec![GPT_AUTO.to_string()];
        world.init_in_nextroot(&plan.hidden.init);
        world.write_plan(&plan);
        fs::write(
            world.runtime().join(SNAPSHOT_NAME),
            Snapshot::take(&world.run()).to_text(),
        )
        .unwrap();
        assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
        let mask = generators.join(GPT_AUTO);
        assert_eq!(fs::read_link(&mask).unwrap(), Path::new("/dev/null"));

        let mut plan = world.plan();
        plan.armed = Some(Arm {
            direction: Direction::Leave,
            at: 1_020,
        });
        world.init_in_nextroot(&plan.decoy.init);
        world.write_plan(&plan);
        let outcome = run(&world.env(true, 1_030));
        assert!(
            matches!(outcome, Outcome::Returned { failed: 0, .. }),
            "{outcome:?}"
        );
        assert!(
            fs::symlink_metadata(&mask).is_err(),
            "the decoy runs the generator again"
        );
        if decoy_has_generators {
            assert_eq!(
                fs::read_link(generators.join("zram-generator")).unwrap(),
                Path::new("/dev/null"),
                "the decoy's own mask stays"
            );
        } else {
            assert!(!generators.exists());
        }
    }
}

/// A generator mask that cannot be written refuses the switch, as a unit mask
/// does: through a generator directory that is a link into a directory the
/// scrub never enters, the mask would outlive the session on the decoy.
#[test]
fn an_entry_whose_generator_masks_cannot_be_written_is_refused() {
    let world = World::new();
    let elsewhere = world.run().join("udev/elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(world.run().join("systemd")).unwrap();
    symlink(&elsewhere, world.run().join(runtime_units::GENERATOR_DIR)).unwrap();
    let mut plan = armed(Direction::Enter);
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&world.run()).to_text(),
    )
    .unwrap();

    let outcome = run(&world.env(true, 1_010));
    assert!(
        matches!(&outcome, Outcome::Disarmed(why) if why.starts_with("could not mask generators")),
        "{outcome:?}"
    );
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    assert!(
        fs::symlink_metadata(world.run().join("systemd/system/dev-vda3.swap")).is_err(),
        "the decoy units are unmasked again"
    );
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system")
    );
}

/// An entry of the decoy at a generator mask's path that does not mask the
/// generator refuses the switch: PID 1 would skip this directory and run the
/// generator from the next one. The entry stays as the decoy left it.
#[test]
fn an_entry_whose_generator_path_holds_no_mask_is_refused() {
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
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&world.run()).to_text(),
    )
    .unwrap();

    let outcome = run(&world.env(true, 1_010));
    assert!(
        matches!(&outcome, Outcome::Disarmed(why) if why.starts_with("could not mask generators")),
        "{outcome:?}"
    );
    assert!(taken.is_dir(), "the decoy's entry stays");
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system")
    );
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

fn modprobe_now(world: &World) -> String {
    fs::read_to_string(world.dir.path().join("modprobe")).unwrap()
}

/// The entry's snapshot of `/run`, then the masks the entry transition
/// writes: the decoy units in the runtime unit directory, the units the hidden
/// root does not need in the control directory, the generators in the
/// generator directory.
fn masked_after_snapshot(world: &World, plan: &Plan) -> Vec<PathBuf> {
    fs::write(
        world.runtime().join(SNAPSHOT_NAME),
        Snapshot::take(&world.run()).to_text(),
    )
    .unwrap();
    let mut masks = runtime_units::mask_units(&world.run(), &plan.masks).unwrap();
    masks.extend(runtime_units::mask_units_best_effort(
        &world.run(),
        &plan.boot_masks,
    ));
    masks.extend(runtime_units::mask_generators(&world.run(), &plan.generator_masks).unwrap());
    assert_eq!(
        masks.len(),
        plan.masks.len() + plan.boot_masks.len() + plan.generator_masks.len()
    );
    masks
}

/// A reboot met a next root the activation left unarmed, after an entry
/// transition whose switch failed: the decoy gets back its kernel paths and
/// loses the session's masks of every kind.
#[test]
fn a_disarmed_next_root_gives_the_decoy_back_its_kernel_paths_and_units() {
    let world = World::new();
    let mut plan = armed(Direction::Enter);
    plan.armed = None;
    plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    plan.kernel_settings = repointed_modprobe(&world);
    world.write_plan(&plan);
    let masks = masked_after_snapshot(&world, &plan);

    assert!(matches!(run(&world.env(true, 1_000)), Outcome::Disarmed(_)));

    assert_eq!(modprobe_now(&world), "/nix/store/decoy-kmod/bin/modprobe");
    for mask in masks {
        assert!(fs::symlink_metadata(&mask).is_err(), "{mask:?} stays");
    }
}

#[test]
fn the_way_back_gives_the_decoy_back_its_kernel_paths_and_units() {
    let world = World::new();
    let mut plan = armed(Direction::Leave);
    plan.entered_at = Some(900);
    plan.boot_masks = vec!["systemd-boot-random-seed.service".to_string()];
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    plan.kernel_settings = repointed_modprobe(&world);
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let masks = masked_after_snapshot(&world, &plan);

    let outcome = run(&world.env(true, 1_000));
    assert!(matches!(outcome, Outcome::Returned { .. }), "{outcome:?}");

    assert_eq!(modprobe_now(&world), "/nix/store/decoy-kmod/bin/modprobe");
    for mask in masks {
        assert!(fs::symlink_metadata(&mask).is_err(), "{mask:?} stays");
    }
}

/// A way back whose snapshot of `/run` is gone still removes the session's
/// masks of every kind. The scrub then keeps whatever it cannot judge, the
/// masks among it, and the decoy would start with its units and generators
/// masked.
#[test]
fn a_way_back_without_its_snapshot_still_removes_the_masks() {
    let world = World::new();
    let mut plan = armed(Direction::Leave);
    plan.entered_at = Some(900);
    plan.boot_masks = vec!["systemd-remount-fs.service".to_string()];
    plan.generator_masks = vec![GPT_AUTO.to_string()];
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let masks = masked_after_snapshot(&world, &plan);
    // Something in the hidden session deleted the snapshot.
    fs::remove_file(world.runtime().join(SNAPSHOT_NAME)).unwrap();

    let outcome = run(&world.env(true, 1_000));
    assert!(matches!(outcome, Outcome::Returned { .. }), "{outcome:?}");

    for mask in masks {
        assert!(fs::symlink_metadata(&mask).is_err(), "{mask:?} stays");
    }
    assert_eq!(
        fs::read_to_string(world.run().join("decoy-state")).unwrap(),
        "keep",
        "the decoy's own state stays"
    );
}

#[test]
fn the_read_only_rule_lives_from_the_entry_to_the_way_back_only() {
    let world = World::new();
    let rule = world
        .run()
        .join(disk_guard::RULE_DIR)
        .join(disk_guard::RULE_NAME);
    let mut plan = armed(Direction::Enter);
    plan.read_only_disks = true;
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    let snapshot = Snapshot::take(&world.run());
    fs::write(world.runtime().join(SNAPSHOT_NAME), snapshot.to_text()).unwrap();

    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
    let text = fs::read_to_string(&rule).unwrap();
    let copy = world.runtime().join(BINARY_NAME);
    assert!(
        text.contains(&format!(
            "RUN+=\"{} guard-device $devnode\"",
            copy.display()
        )),
        "{text}"
    );

    let mut plan = world.plan();
    plan.armed = Some(Arm {
        direction: Direction::Leave,
        at: 1_020,
    });
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    let outcome = run(&world.env(true, 1_030));
    assert!(matches!(outcome, Outcome::Returned { .. }), "{outcome:?}");
    assert!(!rule.exists(), "the decoy's udevd must never load the rule");
    assert!(world.run().join("udev/data").is_dir());
}

#[test]
fn without_the_opt_in_no_rule_is_installed() {
    let world = World::new();
    let plan = armed(Direction::Enter);
    world.init_in_nextroot(&plan.hidden.init);
    world.write_plan(&plan);
    assert_eq!(run(&world.env(true, 1_010)), Outcome::Entered);
    assert!(!world.run().join(disk_guard::RULE_DIR).exists());
}

/// A fake `systemctl` in `dir` that logs its arguments and exits `code`.
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

/// The way back asks PID 1 to power off at once and, should it still run
/// after the grace, asks the kernel.
#[test]
fn powering_off_instead_asks_pid_1_and_then_the_kernel() {
    let dir = tempfile::tempdir().unwrap();
    let systemctl = fake_systemctl(dir.path(), 0);
    let kernel = std::cell::Cell::new(false);

    let taken = power_off_instead(Some(&systemctl), std::time::Duration::ZERO, || {
        kernel.set(true);
        false
    });

    assert!(taken);
    assert!(
        kernel.get(),
        "the kernel is asked when this process still runs"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("calls")).unwrap(),
        "--force poweroff\n"
    );
}

/// When PID 1 refuses, or there is no `systemctl`, the kernel is asked at once.
#[test]
fn powering_off_instead_asks_the_kernel_when_pid_1_cannot_be_asked() {
    let dir = tempfile::tempdir().unwrap();
    let refusing = fake_systemctl(dir.path(), 1);
    for systemctl in [Some(refusing.as_path()), None] {
        let kernel = std::cell::Cell::new(false);
        let taken = power_off_instead(systemctl, std::time::Duration::from_secs(3600), || {
            kernel.set(true);
            false
        });
        assert!(!taken, "{systemctl:?}");
        assert!(kernel.get(), "{systemctl:?}");
    }
}

/// The kernel's power-off in every test: it refuses, so no test powers its
/// host off, whatever the code under test decides.
fn refused_power_off() -> bool {
    false
}

/// Add link `name` with interface index `index` to the fake `/sys/class/net`
/// at `sys_class_net`, virtual as the kernel lists a link it made (no
/// `device` entry).
fn add_virtual_link(sys_class_net: &Path, name: &str, index: u32) {
    let dir = sys_class_net.join(name);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
}

/// A way back armed in `world`, with the record entry took of the network
/// state the world's fake kernel has now (its loopback link and a hostname)
/// and a `systemctl` that logs each call ([`systemctl_calls`]).
fn way_back_with_a_network_record(world: &World) -> Env {
    let mut env = world.env(true, 1_000);
    fs::create_dir_all(env.network.proc_hostname.parent().unwrap()).unwrap();
    fs::write(&env.network.proc_hostname, "decoy-host\n").unwrap();
    add_virtual_link(&env.network.sys_class_net, "lo", 1);
    let record = network::NetworkRecord::capture(&env.network, &network::NetTools::default());
    fs::write(world.runtime().join(network::RECORD_NAME), record.encode()).unwrap();
    let mut plan = armed(Direction::Leave);
    plan.entered_at = Some(900);
    world.init_in_nextroot(&plan.decoy.init);
    world.write_plan(&plan);
    env.systemctl = Some(fake_systemctl(world.dir.path(), 0));
    env
}

/// What the `systemctl` of [`way_back_with_a_network_record`] was asked, one
/// call per line.
fn systemctl_calls(world: &World) -> String {
    fs::read_to_string(world.dir.path().join("calls")).unwrap_or_default()
}

/// A way back that cannot undo what the session did to the network state
/// powers off instead of returning: the link the session made is still there
/// (this way back finds no `ip` to delete it with), so it asks PID 1 to power
/// off at once.
#[test]
fn a_way_back_that_cannot_put_the_network_state_back_powers_off() {
    let world = World::new();
    let env = way_back_with_a_network_record(&world);
    add_virtual_link(&env.network.sys_class_net, "wg0", 9);

    let outcome = run(&env);

    let calls = systemctl_calls(&world);
    assert!(
        calls.lines().any(|call| call == "--force poweroff"),
        "{calls}"
    );
    // The stand-in kernel refused, so the way back returned after all, with
    // the link that stayed.
    let Outcome::Returned { network, .. } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(network.links, ["wg0"]);
}

/// A way back that puts the network state back returns and never asks for a
/// power-off: here its `ip` deletes the link the session made.
#[test]
fn a_way_back_that_puts_the_network_state_back_returns_without_a_power_off() {
    let world = World::new();
    let mut env = way_back_with_a_network_record(&world);
    let sys = env.network.sys_class_net.clone();
    add_virtual_link(&sys, "wg0", 9);
    // Deletes the link from the fake sysfs, as the kernel does.
    let ip = world.dir.path().join("ip");
    write_executable(
        &ip,
        format!(
            "#!/bin/sh\nif [ \"$1 $2\" = 'link delete' ]; then rm -r '{}'/\"$4\"; fi\n",
            sys.display()
        ),
        0o755,
    );
    env.network_tools = Some(network::NetTools {
        ip: Some(ip),
        ..network::NetTools::default()
    });

    let outcome = run(&env);

    assert!(!sys.join("wg0").exists(), "the way back deleted the link");
    let calls = systemctl_calls(&world);
    assert!(!calls.contains("poweroff"), "{calls}");
    assert!(matches!(outcome, Outcome::Returned { .. }), "{outcome:?}");
}
