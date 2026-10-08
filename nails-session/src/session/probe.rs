// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the machine is right now, from live facts only.
//!
//! A soft-reboot keeps the boot ID, so the state file cannot tell the decoy
//! from the hidden root. The live mount table and the session plan in `/run`
//! can: in the hidden root `/` is an overlay whose upper is the plan's; on the
//! decoy a populated `/run/nextroot` or a plan without a hidden root means an
//! entry is under way or was interrupted.

use super::layout::Paths;
use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts, read_mountinfo, top_mount_at};
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

/// Whether `/` is an overlay whose upper lies under `hidden_root`.
pub fn root_is_hidden_overlay(entries: &[MountEntry], hidden_root: &Path) -> Option<String> {
    let root = top_mount_at(entries, Path::new("/"))?;
    if root.fstype != "overlay" {
        return None;
    }
    let upper = parse_overlay_opts(&root.super_opts).upperdir?;
    upper
        .starts_with(hidden_root)
        .then(|| upper.display().to_string())
}

fn owner_alive(plan: &Plan) -> bool {
    plan.owner.is_some_and(|owner| {
        nails_teardown::proc::stat(owner.pid).is_some_and(|s| s.start_time == owner.start_time)
    })
}

/// Probe the machine under `paths`, for the hidden volume at `hidden_root`.
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
            if nextroot_mounted {
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

    /// The mount table of a live hidden session, captured as root in the
    /// decoy-journal-leak VM test (fixture README): `/` is the overlay whose
    /// upper is on the hidden volume at `/mnt/data`.
    #[test]
    fn the_captured_hidden_session_has_a_hidden_overlay_root() {
        let Some(mountinfo) = crate::kernel_fixtures::vm("mountinfo-host.txt") else {
            return;
        };
        let entries = parse_mountinfo(&mountinfo);
        let upper = root_is_hidden_overlay(&entries, Path::new("/mnt/data"))
            .expect("the captured root is the hidden overlay");
        assert!(upper.starts_with("/mnt/data/"), "{upper}");
        assert_eq!(
            root_is_hidden_overlay(&entries, Path::new("/mnt/other")),
            None
        );
    }
}
