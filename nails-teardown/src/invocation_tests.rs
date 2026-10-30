// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The invocation rule on process trees written out by hand: the desktops,
//! windows, terminals and wrappers an emergency runs from, and which of their
//! processes it spares. `nails-core/tests/whole_root_kernel/spare.rs` builds
//! such trees with real processes.

use super::{Invocation, Node, Stat};
use std::collections::HashMap;

/// The terminal a desktop's terminal emulator holds (`/dev/pts/0`).
const PTS0: i32 = 0x8800;
/// The pseudo-terminal `sudo` opens for its command (`/dev/pts/1`).
const PTS1: i32 = 0x8801;
/// The first virtual console (`/dev/tty1`).
const TTY1: i32 = 0x0401;
/// No controlling terminal.
const NO_TTY: i32 = 0;

/// A process tree by pid, with PID 1 in `init.scope`.
struct Tree(HashMap<u32, Node>);

impl Tree {
    fn new() -> Self {
        let mut tree = Self(HashMap::new());
        tree.add(1, 0, 1, 1, NO_TTY, "/init.scope");
        tree
    }

    /// Add `pid`, a child of `ppid` in process group `pgid` and session `sid`,
    /// with controlling terminal `tty`, in `cgroup`.
    fn add(
        &mut self,
        pid: u32,
        ppid: u32,
        pgid: u32,
        sid: u32,
        tty: i32,
        cgroup: &str,
    ) -> &mut Self {
        let stat = Stat {
            state: 'S',
            ppid,
            pgid,
            sid,
            tty,
            flags: 0,
            start_time: u64::from(pid),
        };
        self.0.insert(
            pid,
            Node {
                stat,
                cgroup: Some(cgroup.to_string()),
                interactive_shell: false,
            },
        );
        self
    }

    /// Mark `pid` as an interactive shell.
    fn shell(&mut self, pid: u32) -> &mut Self {
        self.0
            .get_mut(&pid)
            .expect("a process of the tree")
            .interactive_shell = true;
        self
    }

    fn invocation(&self, own: u32) -> Invocation {
        Invocation::walk(own, |pid| self.0.get(&pid).cloned())
    }

    /// The processes the invocation of `own` spares, in order.
    fn spared(&self, own: u32) -> Vec<u32> {
        let invocation = self.invocation(own);
        let mut spared: Vec<u32> = self
            .0
            .iter()
            .filter(|(pid, node)| invocation.contains(**pid, Some(&node.stat)))
            .map(|(pid, _)| *pid)
            .collect();
        spared.sort_unstable();
        spared
    }
}

const SHELL_UNIT: &str =
    "/user.slice/user-1000.slice/user@1000.service/session.slice/shell.service";
const USER_MANAGER: &str = "/user.slice/user-1000.slice/user@1000.service/init.scope";
const WINDOW_SCOPE: &str =
    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-window.scope";
const BROWSER_SCOPE: &str =
    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-browser.scope";
const TERMINAL_SCOPE: &str =
    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-terminal.scope";
const LOGIN: &str = "/user.slice/user-1000.slice/session-2.scope";

/// A desktop shell as GNOME Shell and niri run it: a unit of the user's
/// service manager (50) whose main process (100) leads its session and group,
/// with Xwayland (110) and a browser (120) started as its direct children in
/// both, the browser in a scope of its own.
fn desktop() -> Tree {
    let mut tree = Tree::new();
    tree.add(50, 1, 50, 50, NO_TTY, USER_MANAGER)
        .add(100, 50, 100, 100, NO_TTY, SHELL_UNIT)
        .add(110, 100, 100, 100, NO_TTY, SHELL_UNIT)
        .add(120, 100, 100, 100, NO_TTY, BROWSER_SCOPE);
    tree
}

#[test]
fn a_window_s_helper_spares_itself_alone() {
    let mut tree = desktop();
    // The window from its menu entry, and the helper pkexec runs in its place.
    tree.add(200, 100, 100, 100, NO_TTY, WINDOW_SCOPE).add(
        210,
        200,
        100,
        100,
        NO_TTY,
        WINDOW_SCOPE,
    );
    let invocation = tree.invocation(210);
    assert_eq!(invocation.chain, [210]);
    assert_eq!(invocation.ancestry, [210, 200, 100, 50, 1]);
    assert_eq!(tree.spared(210), [210]);
}

#[test]
fn a_window_in_the_desktop_s_own_cgroup_spares_its_helper_alone() {
    // A session manager (90) leading the session, a panel (100) in its group,
    // and everything in the login's scope: no scope of its own for anything.
    let mut tree = Tree::new();
    tree.add(80, 1, 80, 80, NO_TTY, LOGIN)
        .add(90, 80, 90, 90, NO_TTY, LOGIN)
        .add(100, 90, 90, 90, NO_TTY, LOGIN)
        .add(120, 100, 90, 90, NO_TTY, LOGIN)
        .add(200, 100, 90, 90, NO_TTY, LOGIN)
        .add(210, 200, 90, 90, NO_TTY, LOGIN);
    assert_eq!(tree.invocation(210).chain, [210]);
    assert_eq!(tree.spared(210), [210]);
}

#[test]
fn a_desktop_started_from_a_terminal_still_spares_its_window_s_helper_alone() {
    // A desktop started as a job (100) of a login shell (60) on a terminal:
    // its window and the helper have the terminal too, in the desktop's group.
    let mut tree = Tree::new();
    tree.add(60, 1, 60, 60, PTS0, LOGIN)
        .shell(60)
        .add(100, 60, 100, 60, PTS0, LOGIN)
        .add(120, 100, 100, 60, PTS0, LOGIN)
        .add(200, 100, 100, 60, PTS0, LOGIN)
        .add(210, 200, 100, 60, PTS0, LOGIN);
    assert_eq!(tree.invocation(210).chain, [210]);
    assert_eq!(tree.spared(210), [210]);
}

#[test]
fn a_window_that_leads_a_session_of_its_own_spares_its_helper_alone() {
    // A window started as a unit of the user's service manager, as Plasma
    // starts menu entries.
    let mut tree = desktop();
    let unit = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-window@1.service";
    tree.add(200, 50, 200, 200, NO_TTY, unit)
        .add(210, 200, 200, 200, NO_TTY, unit);
    assert_eq!(tree.invocation(210).chain, [210]);
    assert_eq!(tree.spared(210), [210]);
}

/// A terminal emulator (300) the desktop started in a scope of its own, its
/// interactive shell (310) leading the terminal's session, a background job of
/// that shell (320), and the job `sudo nails emergency | less`: `sudo` (400)
/// leads it, `less` (410) is in its group, `sudo`'s monitor (500) leads a
/// session on `sudo`'s pseudo-terminal, nails (600) leads a group in it.
fn terminal() -> Tree {
    let mut tree = desktop();
    tree.add(300, 100, 100, 100, NO_TTY, TERMINAL_SCOPE)
        .add(310, 300, 310, 310, PTS0, TERMINAL_SCOPE)
        .shell(310)
        .add(320, 310, 320, 310, PTS0, TERMINAL_SCOPE)
        .add(400, 310, 400, 310, PTS0, TERMINAL_SCOPE)
        .add(410, 310, 400, 310, PTS0, TERMINAL_SCOPE)
        .add(500, 400, 500, 500, PTS1, TERMINAL_SCOPE)
        .add(600, 500, 600, 500, PTS1, TERMINAL_SCOPE);
    tree
}

#[test]
fn a_command_typed_into_a_terminal_spares_sudo_its_monitor_and_their_job() {
    let tree = terminal();
    let invocation = tree.invocation(600);
    assert_eq!(invocation.chain, [600, 500, 400]);
    // Not the shell, its other job, the terminal, the desktop shell, Xwayland,
    // the browser or the user's service manager. The kill spares `less` with
    // `sudo`'s job, though the shell kill before it has ended a `less` in the
    // foreground.
    assert_eq!(tree.spared(600), [400, 410, 500, 600]);
}

#[test]
fn a_command_read_after_its_shell_died_keeps_no_monitor_without_sudo() {
    // The shell's death takes the terminal from its session, `sudo` and `less`
    // included, and leaves `sudo` to PID 1: read then, the walk ends at
    // `sudo`, not at a shell, and nails is alone.
    let mut tree = terminal();
    tree.0.remove(&310);
    tree.add(400, 1, 400, 310, NO_TTY, TERMINAL_SCOPE).add(
        410,
        1,
        400,
        310,
        NO_TTY,
        TERMINAL_SCOPE,
    );
    assert_eq!(tree.invocation(600).chain, [600]);
    assert_eq!(tree.spared(600), [600]);
}

#[test]
fn the_job_of_a_command_typed_into_a_root_shell_is_spared() {
    // `nails emergency | base64`: nails (400) leads the job, base64 (410) is
    // in its group.
    let mut tree = desktop();
    tree.add(300, 100, 100, 100, NO_TTY, TERMINAL_SCOPE)
        .add(310, 300, 310, 310, PTS0, TERMINAL_SCOPE)
        .shell(310)
        .add(400, 310, 400, 310, PTS0, TERMINAL_SCOPE)
        .add(410, 310, 400, 310, PTS0, TERMINAL_SCOPE);
    assert_eq!(tree.invocation(400).chain, [400]);
    assert_eq!(tree.spared(400), [400, 410]);
}

#[test]
fn sudo_s_monitor_is_never_spared_without_sudo() {
    // A script (390) the shell runs as its job starts `sudo` (400) in its own
    // group: `sudo` leads none, so the walk ends at it, not at a shell.
    let mut tree = terminal();
    tree.add(390, 310, 390, 310, PTS0, TERMINAL_SCOPE)
        .add(400, 390, 390, 310, PTS0, TERMINAL_SCOPE)
        .add(410, 390, 390, 310, PTS0, TERMINAL_SCOPE);
    assert_eq!(tree.invocation(600).chain, [600]);
    assert_eq!(tree.spared(600), [600]);
}

#[test]
fn sudo_that_a_terminal_runs_directly_dies_with_the_terminal() {
    // A terminal (300) running `sudo nails emergency` itself, as a menu entry
    // that asks for a terminal does: `sudo` (400) leads the terminal's session,
    // and the walk ends at the terminal, which has none.
    let mut tree = desktop();
    tree.add(300, 100, 100, 100, NO_TTY, TERMINAL_SCOPE)
        .add(400, 300, 400, 400, PTS0, TERMINAL_SCOPE)
        .add(500, 400, 500, 500, PTS1, TERMINAL_SCOPE)
        .add(600, 500, 600, 500, PTS1, TERMINAL_SCOPE);
    assert_eq!(tree.invocation(600).chain, [600]);
    assert_eq!(tree.spared(600), [600]);
}

#[test]
fn a_unit_s_emergency_spares_its_own_session() {
    // The panic switch: the unit's main process (700) leads its session and
    // group; what it starts (710) stays in both.
    let mut tree = desktop();
    let unit = "/system.slice/panic.service";
    tree.add(700, 1, 700, 700, NO_TTY, unit)
        .add(710, 700, 700, 700, NO_TTY, unit);
    assert_eq!(tree.invocation(700).chain, [700]);
    assert_eq!(tree.spared(700), [700, 710]);
}

#[test]
fn a_terminal_session_leader_that_pid_1_started_is_not_kept() {
    // A program a getty runs on the virtual console (60) leads its session
    // there and starts nails (300) as a job of its own: the walk takes the
    // program but ends at PID 1, not at a shell.
    let mut tree = Tree::new();
    tree.add(60, 1, 60, 60, TTY1, LOGIN)
        .add(300, 60, 300, 60, TTY1, LOGIN)
        .add(310, 60, 60, 60, TTY1, LOGIN);
    let invocation = tree.invocation(300);
    assert_eq!(invocation.ancestry, [300, 60, 1]);
    assert_eq!(invocation.chain, [300]);
    assert_eq!(tree.spared(300), [300]);
}

#[test]
fn a_wrapper_that_keeps_nails_in_its_group_dies_in_the_kill() {
    // `timeout -k 5 60 nails emergency | base64` typed into the shell:
    // `timeout` (400) leads the job, nails (410) and base64 (420) are in its
    // group. `timeout` would kill nails 5 s after the shell kill.
    let mut tree = terminal();
    tree.0.retain(|pid, _| *pid < 400);
    tree.add(400, 310, 400, 310, PTS0, TERMINAL_SCOPE)
        .add(410, 400, 400, 310, PTS0, TERMINAL_SCOPE)
        .add(420, 310, 400, 310, PTS0, TERMINAL_SCOPE);
    assert_eq!(tree.invocation(410).chain, [410]);
    assert_eq!(tree.spared(410), [410]);
    // `sudo timeout ...`: `timeout` (610) is the command of `sudo`'s monitor,
    // nails is in its group.
    let mut tree = terminal();
    tree.add(610, 500, 610, 500, PTS1, TERMINAL_SCOPE).add(
        600,
        610,
        610,
        500,
        PTS1,
        TERMINAL_SCOPE,
    );
    assert_eq!(tree.invocation(600).chain, [600]);
    assert_eq!(tree.spared(600), [600]);
}

/// A window manager as `exec startx` runs it on the virtual console: `startx`
/// (60) in place of the login shell, `xinit` (100) in its group, the window
/// manager (200) in a group of its own (`xinit` gives its client one), and a
/// bar (220) the session script started in that group before it became the
/// window manager.
fn window_manager() -> Tree {
    let mut tree = Tree::new();
    tree.add(60, 1, 60, 60, TTY1, LOGIN)
        .add(100, 60, 60, 60, TTY1, LOGIN)
        .add(110, 100, 110, 110, NO_TTY, LOGIN)
        .add(200, 100, 200, 60, TTY1, LOGIN)
        .add(220, 200, 200, 60, TTY1, LOGIN);
    tree
}

#[test]
fn a_window_manager_s_own_child_spares_itself_alone() {
    // A key binding's command in a session of its own, as dwm, dwl and xmonad
    // start one, and the helper pkexec runs in its place (300).
    let mut tree = window_manager();
    tree.add(300, 200, 300, 300, NO_TTY, LOGIN);
    assert_eq!(tree.invocation(300).chain, [300]);
    assert_eq!(tree.spared(300), [300]);
    // Started in the window manager's own session and group instead.
    tree.add(300, 200, 200, 60, TTY1, LOGIN);
    assert_eq!(tree.invocation(300).chain, [300]);
    assert_eq!(tree.spared(300), [300]);
    // A desktop typed into the login shell (60), with its own child (300) in
    // its group.
    let mut tree = Tree::new();
    tree.add(60, 1, 60, 60, TTY1, LOGIN)
        .shell(60)
        .add(200, 60, 200, 60, TTY1, LOGIN)
        .add(220, 200, 200, 60, TTY1, LOGIN)
        .add(300, 200, 200, 60, TTY1, LOGIN);
    assert_eq!(tree.invocation(300).chain, [300]);
    assert_eq!(tree.spared(300), [300]);
}

#[test]
fn the_chain_ends_at_another_cgroup() {
    let mut tree = terminal();
    // `sudo`'s monitor started nails in a scope of its own: the walk ends at
    // the monitor, not at a shell.
    tree.add(600, 500, 600, 500, PTS1, "/system.slice/run-nails.scope");
    assert_eq!(tree.invocation(600).chain, [600]);
    // Without a cgroup of its own to compare, nothing joins.
    tree.0.get_mut(&600).unwrap().cgroup = None;
    assert_eq!(tree.invocation(600).chain, [600]);
}

#[test]
fn the_shell_that_typed_the_command_is_an_ancestor_but_not_spared() {
    let tree = terminal();
    let invocation = tree.invocation(600);
    let stat = |pid: u32| tree.0[&pid].stat;
    // The shell that typed the command is an ancestor, though not spared.
    assert!(invocation.ancestry.contains(&310));
    assert!(!invocation.contains(310, Some(&stat(310))));
    // The shell's other job is neither.
    assert!(!invocation.ancestry.contains(&320));
    assert!(!invocation.contains(320, Some(&stat(320))));
}

#[test]
fn a_parent_that_is_gone_or_its_own_ancestor_ends_the_walk() {
    let mut tree = Tree::new();
    tree.add(400, 300, 400, 300, PTS0, LOGIN);
    let invocation = tree.invocation(400);
    assert_eq!(invocation.ancestry, [400, 300]);
    assert_eq!(invocation.chain, [400]);

    let mut looped = Tree::new();
    looped
        .add(400, 410, 400, 400, PTS0, LOGIN)
        .add(410, 400, 410, 410, PTS0, LOGIN);
    let invocation = looped.invocation(400);
    assert_eq!(invocation.ancestry, [400, 410]);
    assert_eq!(invocation.chain, [400]);

    // A process that is gone itself is its own chain.
    assert_eq!(Tree::new().invocation(999).chain, [999]);
}
