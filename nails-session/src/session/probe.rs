// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the machine is right now, from live facts only.
//!
//! A soft-reboot keeps the boot ID, so the state file cannot tell the decoy
//! from the hidden root. The live mount table and the session plan in `/run`
//! can: in the hidden root `/` is an overlay whose upper is the plan's; on the
//! decoy a populated `/run/nextroot` or a plan without a hidden root means an
//! entry is under way or was interrupted. A plan file that is there but
//! cannot be read, or is no plan this build reads, counts as one that was
//! left behind; one below a file is not there.

use super::layout::Paths;
use nails_teardown::mountinfo::{MountEntry, read_mountinfo, root_is_hidden_overlay};
use nails_teardown::whole_root::nextroot;
use nails_teardown::whole_root::plan::{Direction, Plan, PlanError, unix_now};
use nails_teardown::whole_root::ret;
use std::path::Path;

/// Where the machine is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionView {
    /// In the hidden root, with its plan.
    Hidden(Box<Plan>),
    /// In an overlay root whose upper is on `hidden_root`, but without a
    /// readable plan (the panic paths then have nothing to go back with).
    HiddenWithoutPlan(String),
    /// On the decoy, with an armed entry whose activation still runs.
    Entering(Box<Plan>),
    /// On the decoy with leftovers of an interrupted entry: a plan, a
    /// populated `/run/nextroot`, or both.
    Interrupted {
        /// The plan, when one is readable.
        plan: Option<Box<Plan>>,
        /// Whether `/run/nextroot` is populated.
        nextroot_mounted: bool,
    },
    /// On the plain decoy.
    Decoy,
}

impl SessionView {
    /// Whether this is the hidden root.
    pub fn is_hidden(&self) -> bool {
        matches!(
            self,
            SessionView::Hidden(_) | SessionView::HiddenWithoutPlan(_)
        )
    }
}

fn owner_alive(plan: &Plan) -> bool {
    plan.owner.is_some_and(|owner| {
        nails_teardown::proc::stat(owner.pid).is_some_and(|s| s.start_time == owner.start_time)
    })
}

/// Probe the machine under `paths`, for the hidden volume at `hidden_root`,
/// with a mount table that cannot be read taken for an empty one: for a
/// caller that refuses outside a hidden session, which that table shows as
/// none. The session-state check reads the table itself and refuses
/// without it.
pub fn probe(paths: &Paths, hidden_root: &Path) -> SessionView {
    let entries = read_mountinfo().unwrap_or_default();
    probe_with(paths, hidden_root, &entries)
}

/// [`probe`] on a given mount table.
pub fn probe_with(paths: &Paths, hidden_root: &Path, entries: &[MountEntry]) -> SessionView {
    let plan = Plan::load(&paths.plan());
    let nextroot_mounted = nextroot::is_mount_point(entries, &paths.nextroot());
    match plan {
        Ok(plan) if ret::in_hidden_root(entries, &plan) => SessionView::Hidden(Box::new(plan)),
        Ok(plan) if plan.armed_for(Direction::Enter, unix_now()) && owner_alive(&plan) => {
            SessionView::Entering(Box::new(plan))
        }
        Ok(plan) => SessionView::Interrupted {
            plan: Some(Box::new(plan)),
            nextroot_mounted,
        },
        Err(why) => {
            if let Some(upper) = root_is_hidden_overlay(entries, hidden_root) {
                let why = match why {
                    PlanError::Missing => "no session plan in /run".to_string(),
                    other => other.to_string(),
                };
                return SessionView::HiddenWithoutPlan(format!("{why} (upper {upper})"));
            }
            // A plan that is there, but cannot be read or is not one this
            // build reads, is a leftover of an entry as a plan read is. One
            // below a file (ENOTDIR) is not there: nothing can be below a
            // file, which no entry leaves, and which recover would not
            // remove.
            let there = match &why {
                PlanError::Missing => false,
                PlanError::Unreadable(error) => error.kind() != std::io::ErrorKind::NotADirectory,
                _ => true,
            };
            if nextroot_mounted || there {
                SessionView::Interrupted {
                    plan: None,
                    nextroot_mounted,
                }
            } else {
                SessionView::Decoy
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;

    fn paths(dir: &Path) -> Paths {
        Paths {
            root: dir.join("root"),
            run: dir.join("run"),
        }
    }

    #[test]
    fn a_plain_decoy_is_the_decoy() {
        let dir = tempfile::tempdir().unwrap();
        let decoy = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
        assert_eq!(
            probe_with(&paths(dir.path()), Path::new("/mnt/data"), &decoy),
            SessionView::Decoy
        );
    }

    #[test]
    fn a_hidden_overlay_root_without_a_plan_is_still_recognised() {
        let dir = tempfile::tempdir().unwrap();
        let hidden = parse_mountinfo(
            "1 0 0:40 / / rw - overlay overlay rw,lowerdir=/x,upperdir=/mnt/data/root/upper,workdir=/mnt/data/root/work\n",
        );
        let view = probe_with(&paths(dir.path()), Path::new("/mnt/data"), &hidden);
        assert!(view.is_hidden(), "{view:?}");
        assert!(matches!(view, SessionView::HiddenWithoutPlan(_)));
    }

    /// A plan file that is there but cannot be read, or is not a plan this
    /// build reads, is a leftover of an entry, as a plan that can be read
    /// is: an interrupted entry, which `recover` removes, where it read as no
    /// plan and the decoy passed as plain.
    #[test]
    fn a_plan_that_cannot_be_read_is_an_interrupted_entry() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let decoy = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
        std::fs::create_dir_all(p.plan().parent().unwrap()).unwrap();
        for text in ["not json", "{\"version\": 999}"] {
            std::fs::write(p.plan(), text).unwrap();
            assert_eq!(
                probe_with(&p, Path::new("/mnt/data"), &decoy),
                SessionView::Interrupted {
                    plan: None,
                    nextroot_mounted: false
                },
                "{text}"
            );
        }
        std::fs::remove_file(p.plan()).unwrap();
        // A directory where the plan would be cannot be read as one.
        std::fs::create_dir(p.plan()).unwrap();
        assert!(matches!(
            probe_with(&p, Path::new("/mnt/data"), &decoy),
            SessionView::Interrupted { plan: None, .. }
        ));
        std::fs::remove_dir(p.plan()).unwrap();
        assert_eq!(
            probe_with(&p, Path::new("/mnt/data"), &decoy),
            SessionView::Decoy
        );
    }

    /// A file where the runtime directory would be holds no plan: below a
    /// file nothing is there (ENOTDIR), which no entry leaves. It is the
    /// plain decoy, where it counted as an interrupted entry whose `recover`
    /// could not remove the file, and check sent the operator to it in a
    /// loop.
    #[test]
    fn a_plan_below_a_file_is_no_plan() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let decoy = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
        let runtime = p.plan().parent().unwrap().to_path_buf();
        std::fs::create_dir_all(runtime.parent().unwrap()).unwrap();
        std::fs::write(&runtime, "not a directory").unwrap();
        assert!(matches!(
            Plan::load(&p.plan()),
            Err(PlanError::Unreadable(error)) if error.kind() == std::io::ErrorKind::NotADirectory
        ));
        assert_eq!(
            probe_with(&p, Path::new("/mnt/data"), &decoy),
            SessionView::Decoy
        );
    }

    #[test]
    fn a_leftover_nextroot_or_plan_is_an_interrupted_entry() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let table = format!(
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 0:40 / {} rw - overlay overlay rw\n",
            p.nextroot().display()
        );
        let entries = parse_mountinfo(&table);
        assert_eq!(
            probe_with(&p, Path::new("/mnt/data"), &entries),
            SessionView::Interrupted {
                plan: None,
                nextroot_mounted: true
            }
        );
    }
}
