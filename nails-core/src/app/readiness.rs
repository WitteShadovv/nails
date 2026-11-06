// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `readiness` operation (the CLI's `check`): a check of whether
//! activation would run that leaves nothing behind.
//!
//! It builds the same pre-flight registry activation would run, runs it without
//! staging anything (its only writes are the probes on the hidden volume, which
//! remove what they write), and gathers the effective configuration, the
//! overlay targets, how the decoy filesystems would be handled, which NixOS
//! profile would be built and the decoy persona state the hidden session would
//! inherit. The whole picture is one [`ReadinessReport`] a front end renders;
//! `activate --dry-run` runs this same operation, so the two always agree.
//!
//! The operation is split like activation: [`prepare`] builds the manager and
//! asks the attach gate about the hidden root, and [`Readiness::run`] runs the
//! checks. A front end reports a refused root ([`Readiness::refusal`]) first,
//! before any check runs and also when the checks cannot be assembled.

use std::path::{Path, PathBuf};

use nails_api::{Allowable, ErrorBody};
use nails_teardown::mountinfo::MountEntry;
use serde::Serialize;

use crate::config::{PersonaConfig, PersonaMode};
use crate::hidden_root::{Allow, Assessment};
use crate::{
    CheckResult, Config, EntryStatus, Filesystem, HostTarget, NailsManager, PersonaInventory,
    PreflightOptions, RealFilesystem, Result, RuntimeEnv, TargetUser, collect_inherited_persona,
};

/// One pre-flight check result as it appears in the report.
#[derive(Debug, Serialize)]
pub struct CheckRow {
    /// The check's stable kebab-case identifier.
    pub name: String,
    /// `"pass"`, `"warn"`, `"fail"` or `"skipped"`.
    pub status: &'static str,
    /// The check's human-readable message.
    pub message: String,
    /// What to do about a failure, when the check says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// The override that accepts a failure for one run, when a CLI flag
    /// covers what the check refused, so a front end can offer it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowable: Option<Allowable>,
}

impl CheckRow {
    /// Build a row from a registry result.
    pub fn from_result(name: String, result: &CheckResult) -> Self {
        let (status, message, remediation) = match result {
            CheckResult::Pass(msg) => ("pass", msg.clone(), None),
            CheckResult::Warn(msg) => ("warn", msg.clone(), None),
            CheckResult::Fail {
                message,
                remediation,
                ..
            } => ("fail", message.clone(), remediation.clone()),
            CheckResult::Skipped(reason) => ("skipped", reason.clone(), None),
        };
        Self {
            name,
            status,
            message,
            remediation,
            allowable: result.allowable(),
        }
    }
}

/// Tally of the check outcomes.
#[derive(Debug, Serialize)]
pub struct CheckSummary {
    /// Checks that passed.
    pub passed: usize,
    /// Checks that warned.
    pub warnings: usize,
    /// Checks that failed.
    pub failed: usize,
    /// Checks skipped because a prerequisite (the hidden volume) was absent.
    #[serde(default)]
    pub skipped: usize,
}

/// The effective configuration the checks ran against.
#[derive(Debug, Serialize)]
pub struct ConfigSummary {
    /// The configuration file consulted, if any.
    pub config_file: Option<String>,
    /// Hidden volume root.
    pub hidden_volume_root: String,
    /// State file path.
    pub state_file: String,
    /// Log directory.
    pub log_path: String,
    /// Persona mode: `"shared-home"` or `"fresh-home"`.
    pub persona_mode: &'static str,
    /// Minimum free space required to activate, in MB.
    pub minimum_space_mb: u64,
}

/// Which NixOS profile activation would build and switch to.
#[derive(Debug, Serialize)]
pub struct ProfileSummary {
    /// `"overlay-only"`, `"flake"`, `"legacy"`, `"refused"` (the decoy's own
    /// flake, which activation does not build) or `"none"`.
    pub mode: &'static str,
    /// A human description of the selected target, if any.
    pub detail: Option<String>,
}

impl ProfileSummary {
    /// The line `check` prints for it.
    pub fn line(&self) -> &str {
        self.detail
            .as_deref()
            .unwrap_or("no hidden NixOS build target")
    }
}

/// One inherited decoy persona entry.
#[derive(Debug, Serialize)]
pub struct InheritedEntry {
    /// The entry's name (autostart stem, unit name, or operator login).
    pub name: String,
    /// Where it comes from (`"user-autostart"`, `"global-unit"`, `"linger"`, …).
    pub source: &'static str,
    /// The name is on the list of known trace writers (name-only heuristic).
    pub remote_linked: bool,
    /// Whether this entry can be masked with `[persona] mask_inherited`.
    pub maskable: bool,
    /// `"desktop"` for a component the installed desktop or distribution
    /// ships, `"added"` for anything added by the user or third-party software.
    pub origin: &'static str,
    /// What becomes of it: `"ignored"`, `"masked"` or `"review"`.
    pub status: &'static str,
}

/// A place the inventory could not read: what lies there may be inherited
/// too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotReadEntry {
    /// The path.
    pub path: String,
    /// Why it was not read, naming the path.
    pub reason: String,
    /// The automount point a lookup there would have mounted, where that is
    /// why it was not made; `null` for a lookup that failed.
    pub automount_point: Option<String>,
}

/// The decoy persona state the hidden session would inherit.
#[derive(Debug, Serialize)]
pub struct InheritedSummary {
    /// Whether the inventory could be collected (an operator was resolved).
    pub inspected: bool,
    /// Every inherited entry, grouped by source.
    pub entries: Vec<InheritedEntry>,
    /// The names tagged as remote-linked.
    pub remote_linked: Vec<String>,
    /// The `[persona] mask_inherited` names that match no inherited autostart
    /// entry or user unit; activation masks them anyway.
    pub unmatched_masks: Vec<String>,
    /// The places the inventory could not read, in the order it came to
    /// them: a lookup that failed, or one the automount guard did not make.
    pub not_read: Vec<NotReadEntry>,
}

impl InheritedSummary {
    /// The not-inspected summary used when no operator could be resolved.
    pub fn not_inspected() -> Self {
        Self {
            inspected: false,
            entries: Vec::new(),
            remote_linked: Vec::new(),
            unmatched_masks: Vec::new(),
            not_read: Vec::new(),
        }
    }

    /// The summary of an inventory that read nothing, since the mount table,
    /// which shows where a lookup would mount an automount point, cannot be
    /// read (`error`): the table is the one place listed as not read.
    pub fn without_mount_table(error: &str) -> Self {
        Self {
            inspected: true,
            not_read: vec![NotReadEntry {
                path: nails_teardown::mountinfo::SELF_MOUNTINFO.to_string(),
                reason: format!(
                    "NAILS cannot read the mount table ({error}), which shows where a lookup \
                     would mount an automount point, so it looks up nothing"
                ),
                automount_point: None,
            }],
            ..Self::not_inspected()
        }
    }

    /// Build the summary from a collected inventory, judged under `persona`.
    pub fn from_inventory(inventory: &PersonaInventory, persona: &PersonaConfig) -> Self {
        let entries = inventory
            .entries
            .iter()
            .map(|entry| InheritedEntry {
                name: entry.name.clone(),
                source: entry.source.as_str(),
                remote_linked: entry.remote_linked,
                maskable: entry.source.is_maskable(),
                origin: if entry.desktop { "desktop" } else { "added" },
                status: entry.status(persona).as_str(),
            })
            .collect();
        Self {
            inspected: true,
            entries,
            remote_linked: inventory.remote_linked_names(),
            unmatched_masks: inventory.unmatched_masks(persona),
            not_read: inventory
                .not_read
                .iter()
                .map(|not_read| NotReadEntry {
                    path: not_read.path.display().to_string(),
                    reason: not_read.reason.clone(),
                    automount_point: not_read
                        .automount_point
                        .as_ref()
                        .map(|point| point.display().to_string()),
                })
                .collect(),
        }
    }

    /// Add each lookup of `skipped` the guard did not make whose path is not
    /// listed as not read yet: the inventory names every place it could not
    /// read, so this only keeps a lookup a reader took for nothing from
    /// passing unseen.
    pub fn with_skipped(mut self, skipped: &[crate::filesystem::automount::Skipped]) -> Self {
        for skip in skipped {
            let path = skip.path.display().to_string();
            if self.not_read.iter().any(|not_read| not_read.path == path) {
                continue;
            }
            self.not_read.push(NotReadEntry {
                path,
                reason: skip.reason.sentence(&skip.path),
                automount_point: skip.reason.point().map(|point| point.display().to_string()),
            });
        }
        self
    }

    /// How many entries end in `status`.
    pub fn count(&self, status: EntryStatus) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.status == status.as_str())
            .count()
    }
}

/// The full readiness report.
#[derive(Debug, Serialize)]
pub struct ReadinessReport {
    /// True when no check failed.
    pub ready: bool,
    /// The pre-flight check results, in execution order.
    pub checks: Vec<CheckRow>,
    /// Tally of the outcomes.
    pub summary: CheckSummary,
    /// The effective configuration.
    pub config: ConfigSummary,
    /// What happens to each decoy filesystem in the hidden root.
    pub filesystems: Vec<String>,
    /// Which NixOS profile would be built.
    pub profile: ProfileSummary,
    /// Whether the detected host is NixOS. A rendering hint for the human
    /// report, which shows the NixOS-profile section only where it is
    /// meaningful; not serialized, since the JSON always carries `profile`.
    #[serde(skip)]
    pub nixos_host: bool,
    /// The decoy persona state the hidden session would inherit.
    pub inherited: InheritedSummary,
    /// Why the attach gate refused the hidden root, with its code
    /// (`not_separate_volume`, `root_covered` or `storage_unjudged`); the
    /// hidden-volume row reports the same failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<ErrorBody>,
}

impl ReadinessReport {
    /// Build the summary tally and `ready` flag from the rows.
    pub fn finalize(
        checks: Vec<CheckRow>,
        config: ConfigSummary,
        filesystems: Vec<String>,
        profile: ProfileSummary,
        inherited: InheritedSummary,
    ) -> Self {
        let mut summary = CheckSummary {
            passed: 0,
            warnings: 0,
            failed: 0,
            skipped: 0,
        };
        for row in &checks {
            match row.status {
                "pass" => summary.passed += 1,
                "warn" => summary.warnings += 1,
                "skipped" => summary.skipped += 1,
                _ => summary.failed += 1,
            }
        }
        Self {
            refusal: None,
            ready: summary.failed == 0,
            checks,
            summary,
            config,
            filesystems,
            profile,
            nixos_host: false,
            inherited,
        }
    }
}

/// A readiness check whose manager is built and whose hidden root the attach
/// gate has judged, ready to run the checks.
pub struct Readiness {
    manager: NailsManager<RealFilesystem>,
    env: RuntimeEnv,
    config_path: PathBuf,
    options: PreflightOptions,
    refusal: Option<ErrorBody>,
}

/// Prepare the readiness check for the resolved configuration and options:
/// build the manager with the NixOS target activation would pick and ask the
/// attach gate about the hidden root. Nothing runs or is written yet.
///
/// `config_path` is the configuration file that was consulted, named in the
/// report when it exists.
pub fn prepare(
    env: &RuntimeEnv,
    config_path: &Path,
    config: Config,
    options: &PreflightOptions,
) -> Readiness {
    let state_path = config.state_file_path.clone();
    let manager = super::engine::build_nixos_manager(config, state_path, options.overlay_only, env);
    let refusal = attach_refusal(
        manager.filesystem(),
        &manager.config().hidden_volume_root,
        options,
    );
    Readiness {
        manager,
        env: env.clone(),
        config_path: config_path.to_path_buf(),
        options: options.clone(),
        refusal,
    }
}

impl Readiness {
    /// Why the attach gate refused the hidden root, as `activate` would report
    /// it: what a front end says first, before the checks run and also when
    /// [`run`](Self::run) cannot assemble them. The report carries it too.
    pub fn refusal(&self) -> Option<&ErrorBody> {
        self.refusal.as_ref()
    }

    /// Assemble the same pre-flight registry activation would run (no staging
    /// happens here; see [`crate::build_registry`]), run it and gather the
    /// whole readiness picture. An error means the checks could not be
    /// assembled; everything else is reported in the result.
    pub fn run(self) -> Result<ReadinessReport> {
        let Self {
            manager,
            env,
            config_path,
            options,
            refusal,
        } = self;
        // Only a NixOS host carries a config layer; the rendered report shows
        // the NixOS-profile section on NixOS and hides it elsewhere.
        let nixos_host = manager
            .host_profile()
            .is_some_and(|profile| profile.has_config_layer());

        let registry = manager.preflight_registry(&options)?;
        // A caller watching the typed event stream (a window) sees each check
        // the moment it ends, as activation reports them; with no event
        // reporter installed this is the plain run.
        let (results, _) = registry.run_all_detailed_with(manager.filesystem(), |name, result| {
            crate::reporter::progress::check(
                name,
                crate::manager::preflight_runner::check_outcome(result),
                result.message(),
            );
        });
        let checks: Vec<CheckRow> = results
            .iter()
            .map(|(name, result)| CheckRow::from_result(name.clone(), result))
            .collect();

        let config = manager.config();
        let config_summary = ConfigSummary {
            config_file: config_path
                .exists()
                .then(|| config_path.display().to_string()),
            hidden_volume_root: config.hidden_volume_root.display().to_string(),
            state_file: config.state_file_path.display().to_string(),
            log_path: config.log_path.display().to_string(),
            persona_mode: config.persona.mode.as_str(),
            minimum_space_mb: config.minimum_space_mb,
        };

        let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap_or_default();
        let filesystems = decoy_filesystems(
            manager.filesystem(),
            &crate::filesystem::automount::Snapshot::read(manager.filesystem(), Path::new("/")),
            Path::new("/"),
            &mounts,
            &config.hidden_volume_root,
        );
        let profile = profile_summary(
            manager
                .discover_host_target(options.overlay_only)
                .unwrap_or(HostTarget::None),
        );
        let inherited = inherited_summary(config, manager.filesystem(), &env);

        let mut report =
            ReadinessReport::finalize(checks, config_summary, filesystems, profile, inherited);
        report.refusal = refusal;
        report.nixos_host = nixos_host;
        Ok(report)
    }
}

/// The attach gate's refusal of the hidden root, as `activate` would report it,
/// for the report's `refusal` (the gate only reads).
fn attach_refusal<F: Filesystem>(
    fs: &F,
    root: &Path,
    options: &PreflightOptions,
) -> Option<ErrorBody> {
    let allow = if options.allow_decoy_storage {
        Allow::DecoyStorage
    } else {
        Allow::Nothing
    };
    // The root is looked up through the automount guard, as the hidden-volume
    // row looks it up, so a root behind an automount point that nothing is
    // mounted on yet is refused naming the point, and not mounted.
    let guarded = crate::filesystem::automount::Guarded::new(
        fs.clone(),
        &crate::filesystem::automount::Snapshot::read(fs, Path::new("/")),
    );
    match crate::HiddenRoot::assess_allowing(&guarded, root, allow) {
        Ok(Assessment::Refused(refusal)) => {
            let exe = std::env::current_exe().ok();
            let body = super::refusal::refusal_body(&refusal, exe.as_deref());
            // `check` takes `--allow-decoy-storage`: the refusal it covers
            // names it, as the hidden-volume row does.
            Some(if Allow::DecoyStorage.covers(&refusal.kind) {
                body.accepted_by(Allowable::DecoyStorage)
            } else {
                body
            })
        }
        _ => None,
    }
}

/// What the fstab policy would do with each filesystem in the fstab of the
/// decoy root at `root` (`/`, but in tests), its mount points resolved in that
/// root as activation resolves them, given the decoy's mount table `mounts`,
/// and with the decoy's mount, swap and automount units outside its fstab. An
/// entry the policy leaves as it is, such as the root itself, is not listed.
///
/// Each lookup is asked of the automount guard by `snapshot` first, as the
/// `fstab-policy` row asks it: what lies behind an automount point that
/// nothing is mounted on yet is not looked up, and a line names it; without
/// the mount table nothing is looked up.
fn decoy_filesystems<F: Filesystem>(
    fs: &F,
    snapshot: &std::sync::Arc<crate::filesystem::automount::Snapshot>,
    root: &Path,
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Vec<String> {
    use crate::filesystem::automount::{Guarded, Lookup, unnamed};
    use crate::session::{checks, fstab, mount_units, policy};
    if let Some(error) = snapshot.unreadable() {
        return vec![format!(
            "NAILS cannot tell how each decoy filesystem would be handled: NAILS cannot read the \
             mount table ({error}), which shows where a lookup would mount an automount point, \
             so it looks up nothing"
        )];
    }
    let guarded = Guarded::new(fs.clone(), snapshot);
    let ask = |path: &Path, lookup: Lookup| guarded.ask(path, lookup);
    let guard = mount_units::Guard(&ask);
    let fstab = Path::new("/etc/fstab");
    let text = match guard.ask(root, fstab, Lookup::Enters { follow: true }) {
        Ok(_) => {
            nails_teardown::whole_root::nextroot::read_in_root(root, fstab).unwrap_or_default()
        }
        Err(_) => Vec::new(),
    };
    let entries = fstab::parse_in_root_guarded(&text, root, Some(guard));
    let mut decisions = policy::decide_all(&entries, mounts, hidden_root, &policy::device_present);
    let run = root.join("run");
    let dirs = mount_units::UnitDirs {
        root,
        run: &run,
        guard: Some(guard),
    };
    let native = checks::decoy_units(dirs, &decisions, mounts, hidden_root);
    decisions.extend(native);
    let mut lines: Vec<String> = decisions
        .iter()
        .filter(|d| !matches!(d, policy::Decision::Leave { .. }))
        .map(policy::Decision::describe)
        .collect();
    let named = lines.join("\n");
    lines.extend(unnamed(&named, &guarded.skipped()));
    lines
}

/// The NixOS profile summary for a build target.
pub fn profile_summary(target: HostTarget) -> ProfileSummary {
    match target {
        HostTarget::OverlayOnly => ProfileSummary {
            mode: "overlay-only",
            detail: Some(
                "overlay-only: no hidden NixOS system is built; the session runs the decoy's \
                 own system"
                    .into(),
            ),
        },
        HostTarget::ExplicitFlake(flake) => ProfileSummary {
            mode: "flake",
            detail: Some(format!("NixOS flake: {flake}")),
        },
        HostTarget::Flake(dir) => ProfileSummary {
            mode: "flake",
            detail: Some(format!("NixOS flake found at {}", dir.display())),
        },
        HostTarget::DecoyFlake { dir, .. } => ProfileSummary {
            mode: "refused",
            detail: Some(format!(
                "the decoy's own flake at {} is not built (see nixos-build-target)",
                dir.display()
            )),
        },
        HostTarget::Legacy(path) => ProfileSummary {
            mode: "legacy",
            detail: Some(format!("legacy build target: {}", path.display())),
        },
        HostTarget::None => ProfileSummary {
            mode: "none",
            detail: None,
        },
    }
}

/// Collect the decoy persona state the hidden session would inherit, judged
/// under the configured `[persona]` table.
///
/// The check runs non-interactively and often without privileges, so when the
/// target user cannot be resolved the inventory is reported as "not inspected"
/// rather than surfaced as an error. In fresh-home mode only system-level
/// inherited state is listed, matching what that mode actually carries over.
/// The decoy is read through the automount guard, as the
/// `inherited-autostart` row reads it; without the mount table nothing is
/// looked up.
fn inherited_summary<F: Filesystem>(config: &Config, fs: &F, env: &RuntimeEnv) -> InheritedSummary {
    use crate::filesystem::automount::{Guarded, Snapshot};
    let Ok(user) = TargetUser::resolve_with(env) else {
        return InheritedSummary::not_inspected();
    };

    let snapshot = Snapshot::read(fs, Path::new("/"));
    if let Some(error) = snapshot.unreadable() {
        return InheritedSummary::without_mount_table(error);
    }
    let guarded = Guarded::new(fs.clone(), &snapshot);
    let fresh_home = config.persona.mode == PersonaMode::FreshHome;
    let inventory = collect_inherited_persona(&guarded, user.home(), &user.name, fresh_home);
    InheritedSummary::from_inventory(&inventory, &config.persona).with_skipped(&guarded.skipped())
}

#[cfg(test)]
#[path = "readiness_tests.rs"]
mod tests;
