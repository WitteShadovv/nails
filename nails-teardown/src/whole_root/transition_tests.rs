// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The transition step against real directory trees: a `/run`, a next root and
//! a kernel log, all in a temporary directory. Only the mount table is given
//! (a `/run/nextroot` entry), so nothing here needs privileges; the mounts
//! themselves are exercised by the kernel tests in `nails-core`.

use super::*;
use crate::mountinfo::parse_mountinfo;
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
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
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
}

#[test]
fn leaving_scrubs_run_restores_the_decoy_and_writes_the_cursor_last() {
    let world = World::new();
    let r = world.run();
    // In the decoy, just before entering: the snapshot and the utab copy.
    let snapshot = Snapshot::take(&r);
    fs::write(world.runtime().join(SNAPSHOT_NAME), snapshot.to_text()).unwrap();
    fs::write(world.runtime().join(UTAB_NAME), "ID=1 decoy\n").unwrap();
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
    // the transition runs, and logs to the kernel once more on its way out:
    // the cursor must be taken after it, so the decoy journald skips it.
    let late = world.dir.path().join("late-stopped");
    let calls = world.dir.path().join("reset-failed-calls");
    plan.session_units = vec![RuntimeUnit {
        name: "overlay-runtime-monitor.service".to_string(),
        content: String::new(),
        wanted_by: Vec::new(),
    }];
    world.write_plan(&plan);
    let systemctl = world.dir.path().join("systemctl");
    fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\nif [ \"$1\" = reset-failed ]; then echo \"$@\" >> {calls}; exit 0; fi\n\
             echo '7 soft-reboot.target start waiting'\n\
             if [ ! -e {late} ]; then\n\
               echo '12 late.service stop running'\n\
               printf '6,502,3,-;late hidden record\\n' >> {kmsg}\n\
               : > {late}\n\
             fi\n",
            late = late.display(),
            kmsg = world.kmsg().display(),
            calls = calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
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
        "ID=1 decoy\n"
    );
    assert_eq!(fs::read_to_string(r.join("decoy-state")).unwrap(), "keep");
    let cursor = fs::read(r.join(run_scrub::KERNEL_SEQNUM)).unwrap();
    assert_eq!(u64::from_ne_bytes(cursor.try_into().unwrap()), 503);
    // An emergency's SIGKILL left the session's own units failed; the decoy
    // must not inherit that record.
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "reset-failed overlay-runtime-monitor.service\n"
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
    let guard = run
        .join(stop_guard_dir("blk-availability.service"))
        .join(STOP_GUARD_NAME);
    assert_eq!(
        fs::read_to_string(&guard).unwrap(),
        "[Service]\nExecStop=\n"
    );
    assert!(
        STOP_GUARD_TEXT
            .lines()
            .all(|l| !l.to_lowercase().contains("nails"))
    );
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

    remove_dropin(run);
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
