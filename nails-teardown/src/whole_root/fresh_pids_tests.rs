// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::fs;
use std::os::unix::fs::symlink;

/// tty1's device number, as `/proc/<pid>/stat` gives it.
const TTY1: i32 = 0x0401;
/// ttyS0's.
const TTYS0: i32 = 0x0440;
/// When a fake process started unless a test says otherwise: a second into
/// the boot, in clock ticks.
const BOOT: u64 = TICKS_PER_SECOND;
/// The task flags of a userspace process (`PF_RANDOMIZE | PF_SUPERPRIV`).
const USER_FLAGS: u64 = 0x0040_0100;

/// `seconds` into the boot, in clock ticks.
fn at(seconds: u64) -> u64 {
    seconds * TICKS_PER_SECOND
}

/// The getty anchor on `tty` with number `pid`.
fn getty(tty: i32, pid: u32) -> Anchor {
    Anchor {
        comm: "agetty".to_string(),
        tty,
        pid,
    }
}

/// The logind anchor with number `pid`.
fn logind(pid: u32) -> Anchor {
    Anchor {
        comm: "systemd-logind".to_string(),
        tty: 0,
        pid,
    }
}

/// A fake procfs with PID 1 rooted in `decoy`, and another root beside it.
struct FakeProc {
    dir: tempfile::TempDir,
}

impl FakeProc {
    fn new() -> Self {
        let fake = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        for path in [fake.proc(), fake.root(), fake.other()] {
            fs::create_dir_all(path).unwrap();
        }
        fake
    }
    fn proc(&self) -> PathBuf {
        self.dir.path().join("proc")
    }
    fn root(&self) -> PathBuf {
        self.dir.path().join("decoy")
    }
    fn other(&self) -> PathBuf {
        self.dir.path().join("other")
    }
    /// A process `pid` named `comm` with `state`, the kernel's task `flags`
    /// and the controlling terminal `tty`, rooted in `root`, started at
    /// [`BOOT`].
    fn add(&self, pid: u32, comm: &str, state: char, flags: u64, tty: i32, root: &Path) {
        let fields =
            format!("{state} 1 {pid} {pid} {tty} -1 {flags} 0 0 0 0 0 0 0 0 20 0 1 0 {BOOT}");
        self.write(pid, comm, &fields, root);
    }
    /// The files of process `pid` named `comm`, with the `stat` fields after
    /// the name up to its start, rooted in `root`.
    fn write(&self, pid: u32, comm: &str, fields: &str, root: &Path) {
        let dir = self.proc().join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), format!("{pid} ({comm}) {fields} 0 0\n")).unwrap();
        fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
        symlink(root, dir.join("root")).unwrap();
    }
    fn user(&self, pid: u32, comm: &str, tty: i32) {
        self.user_at(pid, comm, tty, BOOT);
    }
    /// A userspace process rooted where PID 1 is, started `start` clock
    /// ticks into the boot.
    fn user_at(&self, pid: u32, comm: &str, tty: i32, start: u64) {
        let fields =
            format!("S 1 {pid} {pid} {tty} -1 {USER_FLAGS} 0 0 0 0 0 0 0 0 20 0 1 0 {start}");
        self.write(pid, comm, &fields, &self.root());
    }
    /// A fake procfs with PID 1 and the userspace processes `live`, each
    /// `(pid, comm, tty, start)`.
    fn with(live: &[(u32, &str, i32, u64)]) -> Self {
        let fake = Self::new();
        fake.add(1, "systemd", 'S', 0x100, 0, &fake.root());
        for &(pid, comm, tty, start) in live {
            fake.user_at(pid, comm, tty, start);
        }
        fake
    }
}

#[test]
fn the_floor_is_the_lowest_userspace_process_in_pid_1s_root() {
    let fake = FakeProc::new();
    assert_eq!(boot_floor(&fake.proc()), None, "no PID 1, no floor");
    fake.add(1, "systemd", 'S', 0x100, 0, &fake.root());
    assert_eq!(boot_floor(&fake.proc()), None, "PID 1 alone is no floor");
    assert!(record(&fake.proc()).is_empty());
    // A kernel thread, a process kept from the initrd or in a chroot, a
    // zombie and an entry without its stat say nothing about the boot.
    fake.add(2, "kthreadd", 'S', 0x0020_8040, 0, &fake.root());
    fake.add(150, "plymouthd", 'S', 0x100, 0, &fake.other());
    fake.add(160, "gone", 'Z', 0x100, 0, &fake.root());
    fs::create_dir_all(fake.proc().join("170")).unwrap();
    fs::create_dir_all(fake.proc().join("self")).unwrap();
    fake.user(412, "systemd-udevd", 0);
    fake.user(388, "systemd-journal", 0);
    assert_eq!(boot_floor(&fake.proc()), Some(388));
}

#[test]
fn the_entry_anchors_on_the_first_getty_and_logind_near_the_floor() {
    let fake = FakeProc::new();
    fake.add(1, "systemd", 'S', 0x100, 0, &fake.root());
    fake.user(388, "systemd-journal", 0);
    fake.user(590, "systemd-logind", 0);
    fake.user(612, "agetty", TTYS0);
    fake.user(600, "agetty", TTY1);
    let found = record(&fake.proc());
    assert_eq!(found.floor, Some(388));
    assert_eq!(
        found.anchors,
        [
            Anchor {
                comm: "agetty".to_string(),
                tty: TTY1,
                pid: 600,
            },
            Anchor {
                comm: "systemd-logind".to_string(),
                tty: 0,
                pid: 590,
            },
        ]
    );
    assert_eq!(found.way_back_counter(), Some(387));

    // A unit started again long after the boot is no anchor.
    let fake = FakeProc::new();
    fake.add(1, "systemd", 'S', 0x100, 0, &fake.root());
    fake.user(388, "systemd-journal", 0);
    fake.user(388 + ANCHOR_SPAN + 1, "systemd-logind", 0);
    assert!(record(&fake.proc()).anchors.is_empty());
}

#[test]
fn the_way_back_counter_is_measured_on_the_hidden_start() {
    // The decoy's getty had 600. The hidden start began at 9031 and gave its
    // getty on the same terminal 9150: 119 numbers. So the way back sets the
    // counter to 481, and the decoy's getty gets about 600 again.
    let mut record = Record {
        floor: Some(388),
        anchors: vec![
            Anchor {
                comm: "agetty".to_string(),
                tty: TTY1,
                pid: 600,
            },
            Anchor {
                comm: "systemd-logind".to_string(),
                tty: 0,
                pid: 590,
            },
        ],
        at_switch: Some(9031),
        counter: None,
    };
    let fake = FakeProc::new();
    fake.add(1, "systemd", 'S', 0x100, 0, &fake.root());
    assert_eq!(
        counter(&record, &fake.proc()),
        None,
        "nothing to measure by"
    );
    fake.user(9140, "systemd-logind", 0);
    assert_eq!(
        counter(&record, &fake.proc()),
        Some(590 - 109),
        "logind, no getty"
    );
    fake.user(9100, "agetty", TTYS0);
    assert_eq!(
        counter(&record, &fake.proc()),
        Some(481),
        "the serial getty is not tty1's"
    );
    fake.user(9150, "agetty", TTY1);
    assert_eq!(counter(&record, &fake.proc()), Some(481));
    fake.user(9149, "agetty", TTY1);
    assert_eq!(
        counter(&record, &fake.proc()),
        Some(482),
        "the lowest one counts"
    );

    // A start that used more than the span, or numbers below the switch, is
    // no measure; nor is anything without the switch's counter.
    record.at_switch = Some(9149 - START_SPAN - 1);
    record.anchors.truncate(1);
    assert_eq!(counter(&record, &fake.proc()), None);
    record.at_switch = Some(9200);
    assert_eq!(counter(&record, &fake.proc()), None);
    record.at_switch = None;
    assert_eq!(counter(&record, &fake.proc()), None);

    record.counter = Some(481);
    assert_eq!(record.way_back_counter(), Some(481));
}

#[test]
fn a_unit_started_again_after_the_boot_is_no_anchor() {
    // The getty of tty1 was started again after a logout, five minutes into
    // the boot, with a number after everything that ran before it: logind is
    // the anchor.
    let restarted = FakeProc::with(&[
        (388, "systemd-journal", 0, at(3)),
        (590, "systemd-logind", 0, at(5)),
        (1100, "agetty", TTY1, at(300)),
    ]);
    let found = record(&restarted.proc());
    assert_eq!(found.floor, Some(388));
    assert_eq!(found.anchors, [logind(590)]);

    // A getty the boot started is the anchor beside a later one with a lower
    // number, up to the end of the window after the floor's start; logind, a
    // tick later, is none.
    let late = at(3) + START_WINDOW;
    let fake = FakeProc::with(&[
        (388, "systemd-journal", 0, at(3)),
        (590, "systemd-logind", 0, late + 1),
        (600, "agetty", TTY1, at(300)),
        (612, "agetty", TTYS0, late),
    ]);
    assert_eq!(record(&fake.proc()).anchors, [getty(TTYS0, 612)]);
}

#[test]
fn a_hidden_copy_started_again_after_the_switch_is_no_measure() {
    // In the hidden session the getty of tty1 was started again after a
    // logout, five minutes after the switch at 9031: its number says how many
    // the session used, not its start. The measure goes by logind instead.
    let record = Record {
        floor: Some(388),
        anchors: vec![getty(TTY1, 600), logind(590)],
        at_switch: Some(9031),
        counter: None,
    };
    let restarted = FakeProc::with(&[
        (9040, "systemd-journal", 0, at(1000)),
        (9140, "systemd-logind", 0, at(1002)),
        (9450, "agetty", TTY1, at(1300)),
    ]);
    assert_eq!(counter(&record, &restarted.proc()), Some(590 - 109));

    // A copy the hidden start ran counts up to the end of the window after
    // the start of the first process above the switch, not a tick later.
    let window = at(1000) + START_WINDOW;
    let on_time = FakeProc::with(&[
        (9040, "systemd-journal", 0, at(1000)),
        (9150, "agetty", TTY1, window),
    ]);
    assert_eq!(counter(&record, &on_time.proc()), Some(600 - 119));
    let too_late = FakeProc::with(&[
        (9040, "systemd-journal", 0, at(1000)),
        (9150, "agetty", TTY1, window + 1),
    ]);
    assert_eq!(counter(&record, &too_late.proc()), None);
}

#[test]
fn a_measure_may_go_below_the_floor_but_not_to_nothing() {
    // A soft-reboot start runs its generators before the first process that
    // keeps running, so the floor of a decoy that came back from an earlier
    // session sits above where its start began, and a hidden start that used
    // 300 numbers up to its getty, where the decoy's used 212 from its floor
    // to its own, is the normal case: the counter goes below the floor.
    let mut record = Record {
        floor: Some(388),
        anchors: vec![getty(TTY1, 600), logind(590)],
        at_switch: Some(9031),
        counter: None,
    };
    let fake = FakeProc::with(&[
        (9040, "systemd-journal", 0, BOOT),
        (9140, "systemd-logind", 0, BOOT),
        (9331, "agetty", TTY1, BOOT),
    ]);
    assert_eq!(counter(&record, &fake.proc()), Some(300));
    // A measure that leaves nothing is none, and the next anchor is tried; one
    // that leaves 1 counts.
    record.anchors[0] = getty(TTY1, 300);
    assert_eq!(counter(&record, &fake.proc()), Some(590 - 109));
    record.anchors[0] = getty(TTY1, 301);
    assert_eq!(counter(&record, &fake.proc()), Some(1));
}

#[test]
fn an_anchor_may_sit_up_to_the_span_above_the_floor() {
    // A decoy whose userspace begins at 1500 anchors on its getty at 1600, and
    // on one exactly the span above, but not one further up.
    let fake = FakeProc::with(&[
        (1500, "systemd-journal", 0, BOOT),
        (1600, "agetty", TTY1, BOOT),
        (1500 + ANCHOR_SPAN, "systemd-logind", 0, BOOT),
    ]);
    assert_eq!(
        record(&fake.proc()).anchors,
        [getty(TTY1, 1600), logind(1500 + ANCHOR_SPAN)]
    );
}

#[test]
fn a_start_is_measured_up_to_the_span_and_only_above_the_switch() {
    // The decoy's getty had 6000, the hidden start began at 10000 and gave its
    // own the span's worth of numbers on: measured. One number more is not,
    // nor is a copy with the switch's own number.
    let mut record = Record {
        floor: Some(1000),
        anchors: vec![getty(TTY1, 6000)],
        at_switch: Some(10_000),
        counter: None,
    };
    let fake = FakeProc::with(&[(10_000 + START_SPAN, "agetty", TTY1, BOOT)]);
    assert_eq!(
        counter(&record, &fake.proc()),
        Some(6000 - START_SPAN),
        "the span used up"
    );
    record.at_switch = Some(10_000 - 1);
    assert_eq!(
        counter(&record, &fake.proc()),
        None,
        "one more than the span"
    );
    record.at_switch = Some(10_000 + START_SPAN);
    assert_eq!(counter(&record, &fake.proc()), None, "no number used");
}

/// [`Places`] under `dir`, with the counter at `now` (none when `None`) and
/// this process in PID 1's PID namespace when `same`.
fn places(dir: &Path, now: Option<&str>, same: bool) -> Places {
    let init = dir.join("init-ns");
    fs::write(&init, "").unwrap();
    let own = if same {
        init.clone()
    } else {
        let own = dir.join("own-ns");
        fs::write(&own, "").unwrap();
        own
    };
    let counter = dir.join("ns_last_pid");
    if let Some(now) = now {
        fs::write(&counter, now).unwrap();
    }
    Places {
        ns_last_pid: counter,
        own_namespace: own,
        init_namespace: init,
    }
}

fn floor(pid: u32) -> Record {
    Record {
        floor: Some(pid),
        ..Record::default()
    }
}

#[test]
fn the_counter_is_set_and_never_raised() {
    let dir = tempfile::tempdir().unwrap();
    let at = places(dir.path(), Some("1625\n"), true);
    assert_eq!(at.current(), Some(1625));
    assert_eq!(lower(Some(387), &at), Lowered::Set(387));
    assert_eq!(fs::read_to_string(&at.ns_last_pid).unwrap(), "387");
    assert_eq!(lower(Some(387), &at), Lowered::AlreadyLow);
    assert_eq!(lower(Some(900), &at), Lowered::AlreadyLow);
    assert_eq!(fs::read_to_string(&at.ns_last_pid).unwrap(), "387");
    assert_eq!(lower(None, &at), Lowered::NoRecord);
    assert_eq!(floor(1).way_back_counter(), Some(1));
    assert_eq!(Record::default().way_back_counter(), None);
}

#[test]
fn the_counter_is_left_alone_outside_pid_1s_namespace_or_when_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let other = places(dir.path(), Some("1625"), false);
    assert_eq!(other.current(), None);
    assert_eq!(lower(Some(387), &other), Lowered::OtherNamespace);
    assert_eq!(fs::read_to_string(&other.ns_last_pid).unwrap(), "1625");
    assert!(!way_back_can_lower(&floor(388), &other));

    let dir = tempfile::tempdir().unwrap();
    let missing = places(dir.path(), None, true);
    assert_eq!(lower(Some(387), &missing), Lowered::Failed);
    assert!(!missing.ns_last_pid.exists(), "nothing is created");
    assert!(!way_back_can_lower(&floor(388), &missing));

    let dir = tempfile::tempdir().unwrap();
    let garbled = places(dir.path(), Some("many"), true);
    assert_eq!(lower(Some(387), &garbled), Lowered::Failed);
}

#[test]
fn the_check_before_the_switch_puts_the_counter_back_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let at = places(dir.path(), Some("1625\n"), true);
    assert!(way_back_can_lower(&floor(388), &at));
    assert_eq!(fs::read_to_string(&at.ns_last_pid).unwrap(), "1625");
    assert!(!way_back_can_lower(&Record::default(), &at));
}

#[test]
fn the_record_round_trips_and_an_empty_one_is_left_out() {
    let record = Record {
        floor: Some(388),
        anchors: vec![Anchor {
            comm: "agetty".to_string(),
            tty: TTY1,
            pid: 600,
        }],
        at_switch: Some(9031),
        counter: Some(481),
    };
    let text = serde_json::to_string(&record).unwrap();
    assert_eq!(serde_json::from_str::<Record>(&text).unwrap(), record);
    assert_eq!(
        serde_json::from_str::<Record>("{}").unwrap(),
        Record::default()
    );
}
