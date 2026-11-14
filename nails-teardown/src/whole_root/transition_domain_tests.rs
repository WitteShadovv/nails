// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The step's check of its own domain, where the plan records an SELinux
//! label for the RAM copy of the binary: it runs against the world of the
//! transition's tests, with a stand-in for the kernel's SELinux and a start
//! again that fails.

use super::*;
use crate::test_support::FakeSelinux;

const INIT: &str = "system_u:system_r:init_t:s0";

thread_local! {
    /// The copies the steps of this test thread started themselves again
    /// from.
    static STARTED_AGAIN_FROM: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// A start again that fails, once it noted the copy it was to start from.
fn refused_start_again(copy: &Path) -> io::Error {
    STARTED_AGAIN_FROM.with(|from| from.borrow_mut().push(copy.to_path_buf()));
    io::Error::from_raw_os_error(libc::EACCES)
}

/// The copies this thread's steps started themselves again from so far.
fn started_again_from() -> Vec<PathBuf> {
    STARTED_AGAIN_FROM.with(|from| from.borrow().clone())
}

/// A step PID 1 started from the drop-in, not again.
const BY_PID1: Started = Started {
    by_pid1: true,
    again: false,
    start_again: refused_start_again,
};

/// A stand-in for a loaded targeted policy under which the step runs in PID
/// 1's own domain, as from a copy that took the label of the files in `/run`
/// again, or under an `SELinuxContext=` of the switch's unit.
fn in_init() -> &'static FakeSelinux {
    FakeSelinux {
        current: INIT.to_string(),
        ..FakeSelinux::targeted()
    }
    .leak()
}

/// The step of a switch armed for `direction` in `world`, whose plan records
/// the program's label when `labelled`, with its copy in the runtime
/// directory, the next root's init in place and a `systemctl` that logs each
/// call ([`systemctl_calls`]), started as `start` under `selinux`.
fn armed_step(
    world: &World,
    direction: Direction,
    labelled: bool,
    start: Started,
    selinux: &'static FakeSelinux,
) -> Env {
    let mut plan = armed(direction);
    plan.program_label = labelled.then(|| program_label::PROGRAM_LABEL.to_string());
    if direction == Direction::Leave {
        plan.entered_at = Some(900);
        repoint_current_system(&world.run(), Path::new("/nix/store/bbb-nixos-system")).unwrap();
        world.init_in_nextroot(&plan.decoy.init);
    } else {
        world.init_in_nextroot(&plan.hidden.init);
    }
    world.write_plan(&plan);
    fs::write(world.runtime().join(BINARY_NAME), b"\x7fELF").unwrap();
    STARTED_AGAIN_FROM.with(|from| from.borrow_mut().clear());
    Env {
        systemctl: Some(fake_systemctl(world.dir.path(), 0)),
        selinux,
        start,
        ..world.env(true, 1_000)
    }
}

/// Where the plan records the program's label, an armed step PID 1 started
/// outside the program's domain gives its copy the label again and starts
/// itself again from it, in both directions, before it does anything of the
/// switch.
#[test]
fn an_armed_step_outside_the_program_s_domain_labels_its_copy_and_starts_again() {
    for direction in [Direction::Enter, Direction::Leave] {
        let world = World::new();
        let selinux = in_init();
        let env = armed_step(&world, direction, true, BY_PID1, selinux);

        let outcome = run(&env);

        assert_eq!(
            selinux.labels_written(),
            [b"system_u:object_r:bin_t:s0\0".to_vec()],
            "{direction:?}"
        );
        assert_eq!(
            started_again_from(),
            [world.runtime().join(BINARY_NAME)],
            "{direction:?}"
        );
        // That start failed here, so the step refused the switch.
        let Outcome::Disarmed(why) = outcome else {
            panic!("expected a refused switch, got {outcome:?}");
        };
        assert_eq!(
            why,
            "the last step before the switch does not run in unconfined_service_t: it could \
             not start itself again from its RAM copy: Permission denied (os error 13)"
        );
    }
}

/// A step still outside the program's domain once it started itself again
/// does nothing of the switch. It refuses the entry, so nothing of it is
/// left; on the way back it asks for the power-off first, and only where
/// neither PID 1 nor the kernel took it (the stand-ins here) does it refuse
/// the way back, which leaves the hidden session as it was, with its plan and
/// the reason in the runtime directory.
#[test]
fn a_step_still_outside_the_domain_refuses_the_entry_and_powers_off_on_the_way_back() {
    let again = Started {
        again: true,
        ..BY_PID1
    };
    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Enter, true, again, selinux);

    let outcome = run(&env);

    let Outcome::Disarmed(why) = outcome else {
        panic!("expected a refused entry, got {outcome:?}");
    };
    assert_eq!(
        why,
        "the last step before the switch does not run in unconfined_service_t: it runs in \
         system_u:system_r:init_t:s0, though it started itself again from its RAM copy with \
         the label"
    );
    assert!(selinux.labels_written().is_empty());
    assert!(started_again_from().is_empty());
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/aaa-nixos-system")
    );
    assert!(!world.run().join("systemd/system/dev-vda3.swap").exists());
    assert!(!world.runtime().exists(), "nothing of the entry is left");
    assert!(!systemctl_calls(&world).contains("poweroff"));

    let world = World::new();
    let env = armed_step(&world, Direction::Leave, true, again, in_init());

    let outcome = run(&env);

    assert_eq!(systemctl_calls(&world), "--force poweroff\n");
    let Outcome::Disarmed(why) = outcome else {
        panic!("expected a refused way back, got {outcome:?}");
    };
    assert!(why.contains("though it started itself again"), "{why}");
    let kept = switch_refusal::read(&world.runtime()).expect("the reason is kept in /run");
    assert_eq!(kept.reason, why);
    assert_eq!(
        world.current_system(),
        Path::new("/nix/store/bbb-nixos-system"),
        "the session's system stays"
    );
    assert_eq!(
        world.plan().armed.map(|arm| arm.direction),
        Some(Direction::Leave)
    );
    assert!(world.run().join("decoy-state").exists(), "no scrub ran");
}

/// The step goes on with the switch where it runs in the program's domain,
/// which it asks only whether a policy is loaded and the context it runs in;
/// and where the plan records no label, where PID 1 did not start it, or
/// where the switch is not armed, it asks nothing at all.
#[test]
fn a_step_in_the_domain_unlabelled_by_hand_or_unarmed_asks_no_more() {
    let world = World::new();
    let selinux = FakeSelinux::targeted().leak();
    let env = armed_step(&world, Direction::Enter, true, BY_PID1, selinux);
    assert_eq!(run(&env), Outcome::Entered);
    assert_eq!(selinux.questions(), ["pid1", "current"]);

    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Leave, false, BY_PID1, selinux);
    assert!(matches!(run(&env), Outcome::Returned { .. }));
    assert!(selinux.questions().is_empty(), "no label in the plan");

    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Enter, true, Started::by_hand(), selinux);
    assert_eq!(run(&env), Outcome::Entered);
    assert!(selinux.questions().is_empty(), "not started by PID 1");

    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Leave, true, BY_PID1, selinux);
    let mut plan = world.plan();
    plan.armed = None;
    world.write_plan(&plan);
    assert!(matches!(
        run(&env),
        Outcome::Disarmed(why) if why == "not armed for this transition"
    ));
    assert!(selinux.questions().is_empty(), "not armed");
    assert!(selinux.labels_written().is_empty());
    assert!(started_again_from().is_empty());
}
