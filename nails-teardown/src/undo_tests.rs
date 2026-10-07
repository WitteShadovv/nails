// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The executor against an in-memory mount table. The assertions are on the
//! table the undo leaves behind, not on which calls it made; the same logic is
//! proven on real mounts by the kernel tests in `nails-core`.

use super::*;
use crate::derive::{derive_plan, entry_kind};
use crate::mountinfo::{MountEntry, parse_mountinfo, top_mount_at};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io;

/// A mutable mount table. An unmount removes the visible entry at the target;
/// a target in `busy`, or one with mounts on it, refuses a normal unmount and
/// accepts only a lazy one, which takes its subtree with it.
struct Table {
    entries: RefCell<Vec<MountEntry>>,
    busy: BTreeSet<PathBuf>,
    guarded: RefCell<BTreeSet<PathBuf>>,
    hidden: PathBuf,
}

impl Table {
    fn new(table: &str) -> Self {
        Self {
            entries: RefCell::new(parse_mountinfo(table)),
            busy: BTreeSet::new(),
            guarded: RefCell::new(BTreeSet::new()),
            hidden: PathBuf::from("/mnt/hidden"),
        }
    }

    fn points(&self) -> Vec<String> {
        self.entries
            .borrow()
            .iter()
            .map(|e| format!("{} {}", e.mount_id, e.mount_point.display()))
            .collect()
    }
}

impl MountOps for Table {
    fn presence(
        &self,
        target: &Path,
        _kind: MountKind,
        recorded_id: Option<i32>,
    ) -> io::Result<Presence> {
        let entries = self.entries.borrow();
        let Some(top) = top_mount_at(&entries, target) else {
            return Ok(Presence::Absent);
        };
        let rt = NailsMounts::from_entries(&entries, Some(&self.hidden)).runtime_tmpfs;
        let owned = match recorded_id {
            Some(id) => top.mount_id == id,
            None => entry_kind(&entries, top, Some(&self.hidden), rt.as_deref()).is_some(),
        };
        Ok(if owned {
            Presence::Owned
        } else {
            Presence::Foreign
        })
    }

    fn nails_mounts(&self) -> io::Result<NailsMounts> {
        Ok(NailsMounts::from_entries(
            &self.entries.borrow(),
            Some(&self.hidden),
        ))
    }

    fn unmount(&self, target: &Path, _kind: MountKind, lazy: bool) -> io::Result<()> {
        let mut entries = self.entries.borrow_mut();
        let Some(id) = top_mount_at(&entries, target).map(|e| e.mount_id) else {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        // A mount with mounts on it, or one a process holds, is busy.
        let has_children = entries.iter().any(|e| e.parent_id == id);
        if (self.busy.contains(target) || has_children) && !lazy {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        // A lazy detach takes the whole subtree with it.
        let mut doomed = vec![id];
        if lazy {
            let mut grew = true;
            while grew {
                grew = false;
                for e in entries.iter() {
                    if doomed.contains(&e.parent_id) && !doomed.contains(&e.mount_id) {
                        doomed.push(e.mount_id);
                        grew = true;
                    }
                }
            }
        }
        entries.retain(|e| !doomed.contains(&e.mount_id));
        Ok(())
    }

    fn guard_present(&self, tree: &Path) -> io::Result<bool> {
        Ok(self.guarded.borrow().contains(tree))
    }

    fn remove_guard(&self, tree: &Path) -> io::Result<()> {
        self.guarded.borrow_mut().remove(tree);
        Ok(())
    }

    fn unmount_in_init_namespace(&self, _target: &Path) -> io::Result<bool> {
        Ok(false)
    }

    fn remove_dir(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}

const SESSION: &str = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
9 1 8:3 / /home rw - ext4 /dev/sdb1 rw
20 1 0:70 / /run/0123456789abcdef rw - tmpfs tmpfs rw,mode=700
21 20 0:61 / /run/0123456789abcdef/etc rw - overlay overlay rw,lowerdir=/etc,upperdir=/mnt/hidden/etc/upper,workdir=/mnt/hidden/etc/work
22 1 0:61 / /etc rw - overlay overlay rw,lowerdir=/etc,upperdir=/mnt/hidden/etc/upper,workdir=/mnt/hidden/etc/work
30 9 0:50 / /home rw - overlay overlay rw,lowerdir=/home,upperdir=/mnt/hidden/home/upper,workdir=/mnt/hidden/home/work
34 30 8:9 /persona/home /home/op rw - ext4 /dev/mapper/hidden rw
";

/// A plan holding only the runtime root, as every activation records first.
fn with_runtime_root() -> Plan {
    let mut plan = Plan::new(PathBuf::from("/mnt/hidden"));
    plan.push(Undo::Unmount {
        target: PathBuf::from("/run/0123456789abcdef"),
        kind: MountKind::RuntimeRoot,
        mount_id: Some(20),
    });
    plan
}

fn decoy_only() -> Vec<String> {
    vec!["1 /".to_string(), "9 /home".to_string()]
}

#[test]
fn a_derived_plan_takes_every_nails_mount_down_and_spares_the_decoy() {
    let table = Table::new(SESSION);
    let plan = derive_plan(&table.entries.borrow(), Path::new("/mnt/hidden"));
    let report = run_plan(&table, &plan, &[Phase::Main, Phase::Store], true);
    assert_eq!(table.points(), decoy_only(), "{report:#?}");
    assert!(report.failures().is_empty());
    assert!(remaining(&table, &plan).is_empty());
}

#[test]
fn running_a_plan_twice_never_touches_the_decoy_mount_left_at_a_target() {
    let table = Table::new(SESSION);
    let plan = derive_plan(&table.entries.borrow(), Path::new("/mnt/hidden"));
    run_plan(&table, &plan, &[Phase::Main], true);
    // The recorded mount ids are gone; the decoy /home partition is at /home now.
    let second = run_plan(&table, &plan, &[Phase::Main], true);
    assert_eq!(table.points(), decoy_only());
    assert!(
        second
            .actions
            .iter()
            .all(|a| !matches!(a.outcome, Outcome::Detached { .. })),
        "{second:#?}"
    );
}

#[test]
fn a_busy_mount_is_detached_lazily_and_reported_as_such() {
    let mut table = Table::new(SESSION);
    table.busy.insert(PathBuf::from("/home"));
    let plan = derive_plan(&table.entries.borrow(), Path::new("/mnt/hidden"));
    let report = run_plan(&table, &plan, &[Phase::Main], true);
    assert_eq!(table.points(), decoy_only());
    let detached = report.detached(&[MountKind::Overlay]);
    assert!(
        detached.contains(&(PathBuf::from("/home"), true)),
        "{detached:?}"
    );
    assert!(detached.contains(&(PathBuf::from("/etc"), false)));
}

#[test]
fn a_stale_plan_is_completed_by_the_reconcile() {
    let table = Table::new(SESSION);
    // A plan that only knows /etc: the persona bind, /home and the staging
    // mount come off through the reconcile, still before the runtime root.
    let mut plan = with_runtime_root();
    plan.push(Undo::Unmount {
        target: PathBuf::from("/etc"),
        kind: MountKind::Overlay,
        mount_id: Some(22),
    });
    let report = run_plan(&table, &plan, &[Phase::Main], true);
    assert_eq!(table.points(), decoy_only(), "{report:#?}");
    let order: Vec<_> = report.actions.iter().map(|a| a.target.clone()).collect();
    let persona = order
        .iter()
        .position(|p| p == Path::new("/home/op"))
        .unwrap();
    let home = order.iter().position(|p| p == Path::new("/home")).unwrap();
    assert!(persona < home, "{order:?}");
}

#[test]
fn a_hand_stacked_second_overlay_is_swept_too() {
    let table = Table::new(&format!(
        "{SESSION}50 30 0:90 / /home rw - overlay overlay rw,lowerdir=/home,upperdir=/mnt/hidden/extra/upper,workdir=/mnt/hidden/extra/work\n"
    ));
    let mut plan = with_runtime_root();
    plan.push(Undo::Unmount {
        target: PathBuf::from("/home"),
        kind: MountKind::Overlay,
        mount_id: Some(30),
    });
    run_plan(&table, &plan, &[Phase::Main], true);
    assert_eq!(
        table.points(),
        vec!["1 /".to_string(), "9 /home".to_string()]
    );
}

#[test]
fn phases_run_only_their_own_steps() {
    let table = Table::new(SESSION);
    table.guarded.borrow_mut().insert(PathBuf::from("/usr"));
    let mut plan = derive_plan(&table.entries.borrow(), Path::new("/mnt/hidden"));
    plan.push(Undo::RemoveReadOnlyGuard {
        tree: PathBuf::from("/usr"),
    });
    let report = run_plan(&table, &plan, &[Phase::Dependents], false);
    assert!(table.guarded.borrow().is_empty());
    assert_eq!(report.actions.len(), 1);
    // The overlays are still up for the main phase.
    assert!(table.points().contains(&"30 /home".to_string()));
}

#[test]
fn the_sweep_never_takes_down_a_foreign_mount_stacked_on_a_nails_overlay() {
    // A mount made after activation sits on top of the /home overlay: the
    // classifier lists /home, but the top mount there is not NAILS's.
    let table = Table::new(&format!(
        "{SESSION}60 30 0:99 / /home rw - tmpfs tmpfs rw\n"
    ));
    sweep(&table, 4);
    assert!(table.points().contains(&"60 /home".to_string()));
    let plan = derive_plan(&table.entries.borrow(), Path::new("/mnt/hidden"));
    assert!(remaining(&table, &plan).contains(&PathBuf::from("/home")));
}
