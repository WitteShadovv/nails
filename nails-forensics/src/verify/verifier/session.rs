// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Session leftovers on the decoy: what an entry or a hidden session puts in
//! `/run` and the return scrub (or `nails recover`) removes. Also how a run
//! tells that it is inside the hidden session, where the live root is the
//! session's root overlay.

use super::*;
use crate::session::units::WATCH_UNIT;
use nails_teardown::mountinfo::{MountEntry, parse_mountinfo, parse_overlay_opts, top_mount_at};
use nails_teardown::whole_root::disk_guard::{RULE_DIR, RULE_NAME};
use nails_teardown::whole_root::nextroot::NEXTROOT;
use nails_teardown::whole_root::plan::{PLAN_NAME, Plan, RUNTIME_DIR};
use nails_teardown::whole_root::transition::{
    DROPIN_DIR, DROPIN_NAME, QUIET_MOUNTS_TEXT, STOP_GUARD_NAME, runtime_guards, stop_guard_dir,
};

/// Where runtime unit files live.
const RUN_UNIT_DIR: &str = "/run/systemd/system";

/// The runtime directory that outranks `/etc/systemd/system`, where the entry
/// masks the units the hidden root does not need (the boot-loader units among
/// them).
const RUN_CONTROL_DIR: &str = "/run/systemd/system.control";

/// The runtime generator directory, which outranks every other, where the
/// entry masks systemd's GPT auto-generator.
const RUN_GENERATOR_DIR: &str = "/run/systemd/system-generators";

/// Guidance for an interrupted entry's leftovers, naming the real binary path.
fn recover_fix() -> String {
    use nails_base::next_step::{NextStep, sudo_line};
    format!(
        "Run `{}` to remove the leftovers of the interrupted entry",
        sudo_line(NextStep::Recover)
    )
}

/// How to check the decoy itself from inside the hidden session, where the
/// hidden layer hides what lies beneath it. Names the real binary path.
pub(super) fn check_decoy_offline() -> String {
    use nails_base::next_step::{NextStep, sudo_line};
    format!(
        "run `{}` against a read-only mount of the decoy root",
        sudo_line(NextStep::VerifyOffline)
    )
}

/// The hidden session a run is inside, as far as verify needs to know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HiddenSession {
    /// The root overlay's upper directory, on the hidden volume. An entry of
    /// the live root is the session's own when the upper holds it, and comes
    /// from the decoy root beneath otherwise.
    upper: PathBuf,
    /// Whether the entry installed the udev rule that keeps the disks the
    /// session does not use read-only (`[session_mounts] read_only`).
    read_only_disks: bool,
}

impl HiddenSession {
    /// Whether `path` is one of the session's own runtime files: the runtime
    /// directory, and the read-only disks rule when the entry installed it.
    /// Leftovers of earlier builds at other runtime paths come from the
    /// decoy's `/run` and stay reported.
    pub(super) fn owns_runtime_path(&self, path: &Path) -> bool {
        path == Path::new(RUNTIME_DIR)
            || (self.read_only_disks && path == Path::new("/run").join(RULE_DIR).join(RULE_NAME))
    }

    /// Where the live root's `path` lies in the upper layer.
    pub(super) fn upper_path(&self, path: &Path) -> PathBuf {
        self.upper.join(path.strip_prefix("/").unwrap_or(path))
    }
}

impl<F: Filesystem> Verifier<F> {
    /// The live mount table, read through the filesystem seam.
    fn mount_table(&self) -> Vec<MountEntry> {
        self.filesystem
            .read_file_content(Path::new(SELF_MOUNTINFO))
            .map(|text| parse_mountinfo(&text))
            .unwrap_or_default()
    }

    /// The hidden session this run is inside, if any: `/` is an overlay whose
    /// upper is the one the session plan names or, without a readable plan,
    /// one that lies on the configured hidden volume.
    pub(super) fn hidden_session(&self) -> Option<HiddenSession> {
        let entries = self.mount_table();
        let upper = top_mount_at(&entries, Path::new("/"))
            .filter(|root| root.fstype == "overlay")
            .and_then(|root| parse_overlay_opts(&root.super_opts).upperdir)?;
        let plan = self
            .filesystem
            .read_file_content(&Path::new(RUNTIME_DIR).join(PLAN_NAME))
            .ok()
            .and_then(|text| Plan::from_json(&text).ok());
        let read_only_disks = match plan {
            Some(plan) if plan.upper == upper => plan.read_only_disks,
            _ if self
                .hidden_root()
                .is_some_and(|root| upper.starts_with(root)) =>
            {
                self.config
                    .as_ref()
                    .is_some_and(|config| config.session_mounts.read_only)
            }
            _ => return None,
        };
        Some(HiddenSession {
            upper,
            read_only_disks,
        })
    }

    /// Flag what a session leaves in `/run` when verify runs on the decoy: a
    /// populated `/run/nextroot`, the runtime directory and the plan in it, the
    /// transition drop-in on `systemd-soft-reboot.service`, the runtime guards
    /// (the one that quiets the carried filesystems' mount units among them),
    /// and the session's own units or masks among the runtime unit files and
    /// generators. Inside
    /// the hidden root all of these are expected, so it reports that as
    /// information instead.
    pub(super) fn check_session_leftovers(
        &self,
        session: Option<&HiddenSession>,
    ) -> Result<Vec<Finding>> {
        if session.is_some() {
            return Ok(vec![
                Finding::new(
                    Severity::Info,
                    "session",
                    "verify runs inside the hidden session: its runtime files in /run, the \
                     mounted hidden volume and the active state are expected, and the return \
                     to the decoy removes the runtime files",
                )
                .with_fix_guidance(format!(
                    "The session cannot see what its hidden layer covers on the decoy; to \
                     check the decoy itself, {}",
                    check_decoy_offline()
                )),
            ]);
        }
        let mut findings = Vec::new();
        let critical = |what: String| {
            Finding::new(Severity::Critical, "session", what).with_fix_guidance(recover_fix())
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

    /// The session's units (by their names) in `/run/systemd/system`, and
    /// runtime masks (links to `/dev/null`) there, in
    /// `/run/systemd/system.control`, where the entry masks the units the
    /// hidden root does not need, and in `/run/systemd/system-generators`,
    /// where it masks the GPT auto-generator. A mask may also be the
    /// administrator's own (`systemctl mask --runtime`, or a link of their
    /// own), so it only warns.
    fn leftover_run_units(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for dir in [RUN_UNIT_DIR, RUN_CONTROL_DIR, RUN_GENERATOR_DIR] {
            findings.extend(self.leftover_units_in(Path::new(dir))?);
        }
        Ok(findings)
    }

    /// Whether the drop-in directory `dir` holds the drop-in an entry writes
    /// to quiet the carried filesystems' mount units.
    fn quiets_mounts(&self, dir: &Path) -> bool {
        self.filesystem
            .read_file_content(&dir.join(STOP_GUARD_NAME))
            .is_ok_and(|text| text == QUIET_MOUNTS_TEXT)
    }

    fn leftover_units_in(&self, dir: &Path) -> Result<Vec<Finding>> {
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
                    .with_fix_guidance(recover_fix()),
                );
            } else if name.ends_with("-.mount.d") && self.quiets_mounts(&path) {
                findings.push(
                    Finding::new(
                        Severity::Critical,
                        "session",
                        format!(
                            "the session's runtime guard {} is left: the mount units it names \
                             report nothing until the next boot",
                            path.join(STOP_GUARD_NAME).display()
                        ),
                    )
                    .with_fix_guidance(recover_fix()),
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
