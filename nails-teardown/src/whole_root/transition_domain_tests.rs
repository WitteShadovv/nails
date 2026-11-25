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
/// directory, the next root's init in place and the world's `systemctl`,
/// which logs each call ([`systemctl_calls`]), started as `start` under
/// `selinux`.
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
        selinux,
        start,
        fence: None,
        ..world.env(true, 1_000)
    }
}

/// Where the plan records the program's label, an armed entry PID 1 started
/// outside the program's domain gives its copy the label again and starts
/// itself again from it, before it does anything of the switch.
#[test]
fn an_armed_entry_outside_the_program_s_domain_labels_its_copy_and_starts_again() {
    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Enter, true, BY_PID1, selinux);

    // That start failed here, so the step ended the session.
    let why = ends(&world, &env);

    assert_eq!(
        selinux.labels_written(),
        [b"system_u:object_r:bin_t:s0\0".to_vec()]
    );
    assert_eq!(started_again_from(), [world.runtime().join(BINARY_NAME)]);
    assert_eq!(
        why,
        "the last step before the switch does not run in unconfined_service_t: it could \
         not start itself again from its RAM copy: Permission denied (os error 13)"
    );
}

/// An entry still outside the program's domain once it started itself again
/// does nothing of the switch and ends the session: it neither labels the
/// copy again nor starts again, and writes none of the entry's masks.
#[test]
fn an_entry_still_outside_the_domain_ends_the_session() {
    let again = Started {
        again: true,
        ..BY_PID1
    };
    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Enter, true, again, selinux);

    let why = ends(&world, &env);

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
}

/// A plan armed for the way back ends the session before the step asks its
/// domain anything: there is nothing it may do there.
#[test]
fn a_way_back_ends_the_session_without_asking_the_domain() {
    let world = World::new();
    let selinux = in_init();
    let env = armed_step(&world, Direction::Leave, true, BY_PID1, selinux);

    let why = ends(&world, &env);

    assert!(why.contains("never goes back"), "{why}");
    assert!(selinux.questions().is_empty());
    assert!(started_again_from().is_empty());
}

/// The step goes on with the entry where it runs in the program's domain,
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
    let env = armed_step(&world, Direction::Enter, false, BY_PID1, selinux);
    assert_eq!(run(&env), Outcome::Entered);
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
    // In the hidden session an unarmed soft-reboot ends the session before
    // the domain is asked.
    let why = ends(&world, &env);
    assert!(
        why.starts_with("a soft-reboot in the hidden session"),
        "{why}"
    );
    assert!(selinux.questions().is_empty(), "not armed");
    assert!(selinux.labels_written().is_empty());
    assert!(started_again_from().is_empty());
}
