// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The exec prefix through the whole entry, against real mounts: on a host
//! that may run SELinux the entry records `/usr/bin/env` in the plan, writes
//! the transition step's drop-in with it, and the transition installs the
//! hidden session's units with it; a decoy root without it refuses the entry
//! before anything is written, and a next root in which the hidden sessions'
//! upper replaced it refuses it once the next root is built, which is then
//! undone; neither check reads the program, so its access time stays. Without
//! a prefix a decoy root that has no `/usr/bin/env` at all is entered as
//! before.

use super::{FakeHost, World};
use nails_core::Config;
use nails_core::NailsError;
use nails_core::session::entry;
use nails_core::session::exec_prefix::{CHECK, ExecPrefix};
use nails_core::session::labels::Reason;
use nails_core::session::layout::{Layout, Paths};
use nails_core::session::units::session_units;
use nails_core::test_path;
use nails_core::test_support::{Rerun, write_executable};
use nails_teardown::mountinfo::read_mountinfo;
use nails_teardown::whole_root::exec_prefix::TRAMPOLINE;
use nails_teardown::whole_root::plan::{Plan, unix_now};
use nails_teardown::whole_root::transition::{self, DROPIN_DIR, DROPIN_NAME, Env, Outcome};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where SELinux runs.
const SELINUX: ExecPrefix = ExecPrefix::Trampoline(Reason::SelinuxRunning);

/// Give the decoy root of `world` a `/usr/bin/env`, and wait long enough
/// that a read of it would move its access time.
fn decoy_env(world: &World) -> PathBuf {
    let env = world.decoy.path().join("usr/bin/env");
    std::fs::create_dir_all(env.parent().unwrap()).unwrap();
    write_executable(&env, "#!/bin/sh\n", 0o755);
    std::thread::sleep(Duration::from_millis(20));
    env
}

/// The access time of `path` itself.
fn atime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.atime(), meta.atime_nsec())
}

/// Whether anything is mounted at or below the next root of `paths`.
fn next_root_mounted(paths: &Paths) -> bool {
    read_mountinfo()
        .unwrap()
        .iter()
        .any(|e| e.mount_point.starts_with(paths.nextroot()))
}

/// The refusal under the exec prefix's name, and its reason.
fn refused(error: NailsError) -> String {
    let NailsError::PreFlightCheckFailed(failures) = &error else {
        panic!("expected the exec-prefix refusal, got {error:?}");
    };
    assert_eq!(failures[0].0, CHECK, "{error}");
    failures[0].1.clone()
}

#[test]
fn an_entry_through_env_records_it_and_every_step_starts_through_it() {
    let _ = Rerun::new(test_path!(
        an_entry_through_env_records_it_and_every_step_starts_through_it
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let env = decoy_env(&world);
        let before = atime(&env);
        let paths = world.paths();
        let program = Path::new(TRAMPOLINE);
        let units = session_units(&Config::test_default(), Some(program));
        let inputs = entry::EntryInputs {
            exec_prefix: SELINUX,
            session_units: units.clone(),
            ..world.inputs()
        };

        let entry = entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");

        assert_eq!(entry.plan.exec_prefix.as_deref(), Some(program));
        assert_eq!(
            Plan::load(&paths.plan()).unwrap().exec_prefix.as_deref(),
            Some(program),
            "the plan the way back reads"
        );
        assert_eq!(
            std::fs::read_to_string(world.run.path().join(DROPIN_DIR).join(DROPIN_NAME)).unwrap(),
            transition::dropin_text(Path::new("/run/overlay-runtime/control"), Some(program))
        );
        // The checks in the decoy root and the next root read nothing.
        assert_eq!(atime(&env), before, "/usr/bin/env was read");

        // The switch installs the hidden session's units as the plan has
        // them, each starting the copy through the program.
        let env_of_switch = Env {
            run: paths.run.clone(),
            nextroot: paths.nextroot(),
            runtime_dir: paths.runtime(),
            kmsg: paths.run.join("no-kmsg"),
            systemctl: None,
            pid_places: None,
            now: unix_now(),
            mounts: read_mountinfo().unwrap(),
            network: nails_teardown::whole_root::network::Places::system(&paths.run),
            network_tools: None,
            power_off: transition::PowerOff {
                grace: Duration::ZERO,
                kernel: || false,
            },
        };
        assert_eq!(transition::run(&env_of_switch), Outcome::Entered);
        assert!(!units.is_empty());
        for unit in &units {
            let installed =
                std::fs::read_to_string(world.run.path().join("systemd/system").join(&unit.name))
                    .unwrap();
            assert_eq!(installed, unit.content);
            assert!(
                installed.contains("\nExecStart=/usr/bin/env /run/overlay-runtime/control "),
                "{installed}"
            );
        }
        entry::rollback(&paths);
    });
}

#[test]
fn a_decoy_without_env_is_refused_before_anything_is_written() {
    let _ = Rerun::new(test_path!(
        a_decoy_without_env_is_refused_before_anything_is_written
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let paths = world.paths();
        let host = FakeHost::default();
        let inputs = entry::EntryInputs {
            exec_prefix: SELINUX,
            ..world.inputs()
        };

        let error = entry::prepare(&paths, &inputs, &host).unwrap_err();

        assert!(
            refused(error).contains("in the decoy root /usr/bin/env does not exist"),
            "the reason names the decoy root"
        );
        assert!(!paths.runtime().exists(), "no runtime directory");
        assert!(!world.run.path().join(DROPIN_DIR).exists(), "no drop-in");
        assert_eq!(host.reloads.get(), 0);
        assert!(!next_root_mounted(&paths));
        assert!(!Layout::new(world.hidden.path()).upper().exists());
    });
}

#[test]
fn a_next_root_whose_upper_replaced_env_is_refused_and_undone() {
    // A hidden session put a directory where the decoy has the program: the
    // next root shows the upper's, so neither the hidden session's units nor
    // the way back's step could start through it.
    let _ = Rerun::new(test_path!(
        a_next_root_whose_upper_replaced_env_is_refused_and_undone
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        let env = decoy_env(&world);
        let before = atime(&env);
        let paths = world.paths();
        let upper = Layout::new(world.hidden.path()).upper();
        std::fs::create_dir_all(upper.join("usr/bin/env")).unwrap();
        let host = FakeHost::default();
        let inputs = entry::EntryInputs {
            exec_prefix: SELINUX,
            ..world.inputs()
        };

        let error = entry::prepare(&paths, &inputs, &host).unwrap_err();

        assert!(
            refused(error).contains("in the hidden root /usr/bin/env is not an executable file"),
            "the reason names the hidden root"
        );
        assert!(!next_root_mounted(&paths), "the next root is detached");
        assert!(!paths.runtime().exists());
        assert!(!world.run.path().join(DROPIN_DIR).exists());
        assert_eq!(host.reloads.get(), 2, "one loads the drop-in, one drops it");
        assert_eq!(atime(&env), before, "/usr/bin/env was read");
    });
}

#[test]
fn without_a_prefix_a_decoy_without_env_is_entered_as_before() {
    let _ = Rerun::new(test_path!(
        without_a_prefix_a_decoy_without_env_is_entered_as_before
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        assert!(!world.decoy.path().join("usr/bin/env").exists());
        let paths = world.paths();
        let inputs = entry::EntryInputs {
            exec_prefix: ExecPrefix::Direct,
            ..world.inputs()
        };

        let entry = entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");

        assert_eq!(entry.plan.exec_prefix, None);
        assert!(!entry.plan.to_json().contains("exec_prefix"));
        assert_eq!(
            std::fs::read_to_string(world.run.path().join(DROPIN_DIR).join(DROPIN_NAME)).unwrap(),
            transition::dropin_text(Path::new("/run/overlay-runtime/control"), None)
        );
        entry::rollback(&paths);
    });
}
