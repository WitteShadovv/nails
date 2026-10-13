// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Session leftovers on the decoy: what an entry or a hidden session puts in
//! `/run` and the return scrub (or `nails recover`) removes.

use super::*;
use crate::session::units::WATCH_UNIT;
use nails_teardown::mountinfo::{MountEntry, parse_mountinfo};
use nails_teardown::whole_root::nextroot::NEXTROOT;
use nails_teardown::whole_root::plan::{PLAN_NAME, Plan, RUNTIME_DIR};
use nails_teardown::whole_root::transition::{
    DROPIN_DIR, DROPIN_NAME, STOP_GUARD_NAME, runtime_guards, stop_guard_dir,
};

/// Where runtime unit files live.
const RUN_UNIT_DIR: &str = "/run/systemd/system";

/// Guidance for an interrupted entry's leftovers.
const RECOVER: &str = "Run 'nails recover' to remove the leftovers of the interrupted entry";

impl<F: Filesystem> Verifier<F> {
    /// The live mount table, read through the filesystem seam.
    fn mount_table(&self) -> Vec<MountEntry> {
        self.filesystem
            .read_file_content(Path::new(SELF_MOUNTINFO))
            .map(|text| parse_mountinfo(&text))
            .unwrap_or_default()
    }

    /// Whether this runs inside the hidden root: `/` is the overlay the session
    /// plan names, or (without a readable plan) an overlay whose upper lies on
    /// the configured hidden volume.
    pub(super) fn in_hidden_root(&self) -> bool {
        let entries = self.mount_table();
        let plan = self
            .filesystem
            .read_file_content(&Path::new(RUNTIME_DIR).join(PLAN_NAME))
            .ok()
            .and_then(|text| Plan::from_json(&text).ok());
        if plan.is_some_and(|plan| nails_teardown::whole_root::ret::in_hidden_root(&entries, &plan))
        {
            return true;
        }
        self.hidden_root().is_some_and(|root| {
            nails_teardown::mountinfo::root_is_hidden_overlay(&entries, root).is_some()
        })
    }

    /// Flag what a session leaves in `/run` when verify runs on the decoy: a
    /// populated `/run/nextroot`, the runtime directory and the plan in it, the
    /// transition drop-in on `systemd-soft-reboot.service`, and the session's
    /// own units or masks among the runtime unit files. Inside the hidden root
    /// all of these are expected, so it reports that as information instead.
    pub(crate) fn check_session_leftovers(&self) -> Result<Vec<Finding>> {
        if self.in_hidden_root() {
            return Ok(vec![Finding::new(
                Severity::Info,
                "session",
                "verify runs inside the hidden session; its runtime files in /run are \
                 expected and the return to the decoy removes them",
            )]);
        }
        let mut findings = Vec::new();
        let critical = |what: String| {
            Finding::new(Severity::Critical, "session", what).with_fix_guidance(RECOVER)
        };
        if nails_teardown::whole_root::nextroot::is_mount_point(
            &self.mount_table(),
            Path::new(NEXTROOT),
        ) {
            findings.push(critical(format!(
                "{NEXTROOT} is populated: a later soft-reboot would enter it"
            )));
        }
        findings.extend(self.leftover_hidden_overlays());
        let runtime = Path::new(RUNTIME_DIR);
        if self.filesystem.path_exists(&runtime.join(PLAN_NAME))? {
            findings.push(critical(format!(
                "a session plan is left at {}",
                runtime.join(PLAN_NAME).display()
            )));
        } else if self.filesystem.path_exists(runtime)? {
            findings.push(critical(format!(
                "the session runtime directory {RUNTIME_DIR} is left in RAM"
            )));
        }
        let dropin = Path::new("/run").join(DROPIN_DIR).join(DROPIN_NAME);
        if self.filesystem.path_exists(&dropin)? {
            findings.push(critical(format!(
                "the soft-reboot transition drop-in {} is left",
                dropin.display()
            )));
        }
        for (unit, _) in runtime_guards() {
            let guard = Path::new("/run")
                .join(stop_guard_dir(unit))
                .join(STOP_GUARD_NAME);
            if self.filesystem.path_exists(&guard)? {
                findings.push(critical(format!(
                    "the session's runtime guard {} is left: {unit} runs changed until \
                     the next boot",
                    guard.display()
                )));
            }
        }
        findings.extend(self.leftover_run_units()?);
        Ok(findings)
    }

    /// Overlays outside `/run/nextroot` whose upper lies on the hidden volume:
    /// on the decoy nothing may write into a hidden layer.
    fn leftover_hidden_overlays(&self) -> Vec<Finding> {
        let Some(hidden) = self.hidden_root() else {
            return Vec::new();
        };
        self.mount_table()
            .iter()
            .filter(|m| m.fstype == "overlay" && !m.mount_point.starts_with(NEXTROOT))
            .filter(|m| {
                nails_teardown::mountinfo::parse_overlay_opts(&m.super_opts)
                    .upperdir
                    .is_some_and(|upper| upper.starts_with(hidden))
            })
            .map(|m| {
                Finding::new(
                    Severity::Critical,
                    "mount",
                    format!(
                        "Leftover overlay at {}: its upper layer is on the hidden volume",
                        m.mount_point.display()
                    ),
                )
                .with_fix_guidance(
                    "Unmount it before anything writes through it; the decoy must not \
                     write into a hidden layer",
                )
            })
            .collect()
    }

    /// The session's units (by their names) and runtime masks (links to
    /// `/dev/null`) in `/run/systemd/system`. A mask may also be the
    /// administrator's own `systemctl mask --runtime`, so it only warns.
    fn leftover_run_units(&self) -> Result<Vec<Finding>> {
        let dir = Path::new(RUN_UNIT_DIR);
        if !self.filesystem.is_directory(dir)? {
            return Ok(Vec::new());
        }
        let session_units = [
            WATCH_UNIT.to_string(),
            format!("{}.service", crate::sleep_guard::SLEEP_GUARD_UNIT_NAME),
        ];
        let mut findings = Vec::new();
        for path in self.filesystem.list_directory(dir).unwrap_or_default() {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if session_units.iter().any(|unit| unit == name) {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "session",
                        format!("the hidden session's unit {} is left", path.display()),
                    )
                    .with_fix_guidance(RECOVER),
                );
            } else if self.filesystem.is_symlink(&path)?
                && self.filesystem.canonicalize(&path).ok().as_deref()
                    == Some(Path::new("/dev/null"))
            {
                findings.push(
                    Finding::new(
                        Severity::Warn,
                        "session",
                        format!("{name} is masked at runtime ({})", path.display()),
                    )
                    .with_fix_guidance(
                        "If you did not mask it yourself, a hidden session left the mask: \
                         remove the link and run 'systemctl daemon-reload'",
                    ),
                );
            }
        }
        Ok(findings)
    }
}
