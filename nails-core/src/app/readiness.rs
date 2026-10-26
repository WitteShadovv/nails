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

use nails_api::ErrorBody;
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
            } => ("fail", message.clone(), remediation.clone()),
            CheckResult::Skipped(reason) => ("skipped", reason.clone(), None),
        };
        Self {
            name,
            status,
            message,
            remediation,
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
}

impl InheritedSummary {
    /// The not-inspected summary used when no operator could be resolved.
    pub fn not_inspected() -> Self {
        Self {
            inspected: false,
            entries: Vec::new(),
            remote_linked: Vec::new(),
            unmatched_masks: Vec::new(),
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
        }
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
        let (results, _) = registry.run_all_detailed(manager.filesystem());
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
        let filesystems = decoy_filesystems(Path::new("/"), &mounts, &config.hidden_volume_root);
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
    match crate::HiddenRoot::assess_allowing(fs, root, allow) {
        Ok(Assessment::Refused(refusal)) => {
            let exe = std::env::current_exe().ok();
            Some(super::refusal::refusal_body(&refusal, exe.as_deref()))
        }
        _ => None,
    }
}

/// What the fstab policy would do with each filesystem in the fstab of the
/// decoy root at `root` (`/`, but in tests), its mount points resolved in that
/// root as activation resolves them, given the decoy's mount table `mounts`.
/// An entry the policy leaves as it is, such as the root itself, is not
/// listed.
fn decoy_filesystems(root: &Path, mounts: &[MountEntry], hidden_root: &Path) -> Vec<String> {
    use crate::session::{fstab, policy};
    let text = nails_teardown::whole_root::nextroot::read_in_root(root, Path::new("/etc/fstab"))
        .unwrap_or_default();
    let entries = fstab::parse_in_root(&text, root);
    policy::decide_all(&entries, mounts, hidden_root)
        .iter()
        .filter(|d| !matches!(d, policy::Decision::Leave { .. }))
        .map(policy::Decision::describe)
        .collect()
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
fn inherited_summary<F: Filesystem>(config: &Config, fs: &F, env: &RuntimeEnv) -> InheritedSummary {
    let Ok(user) = TargetUser::resolve_with(env) else {
        return InheritedSummary::not_inspected();
    };

    let fresh_home = config.persona.mode == PersonaMode::FreshHome;
    let inventory = collect_inherited_persona(fs, user.home(), &user.name, fresh_home);
    InheritedSummary::from_inventory(&inventory, &config.persona)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::FakePlatform;
    use crate::{MockFilesystem, NailsManager};
    use std::path::PathBuf;

    fn rows() -> Vec<CheckRow> {
        vec![
            CheckRow::from_result("a".into(), &CheckResult::Pass("ok".into())),
            CheckRow::from_result("b".into(), &CheckResult::Warn("careful".into())),
        ]
    }

    fn report(rows: Vec<CheckRow>) -> ReadinessReport {
        ReadinessReport::finalize(
            rows,
            ConfigSummary {
                config_file: None,
                hidden_volume_root: "/mnt/data".into(),
                state_file: "/mnt/data/state.json".into(),
                log_path: "/mnt/data/logs".into(),
                persona_mode: "shared-home",
                minimum_space_mb: 500,
            },
            Vec::new(),
            ProfileSummary {
                mode: "none",
                detail: None,
            },
            InheritedSummary::not_inspected(),
        )
    }

    #[test]
    fn finalize_counts_outcomes_and_sets_ready() {
        let report = report(rows());
        assert!(report.ready);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(report.summary.failed, 0);
    }

    #[test]
    fn a_failing_check_marks_the_report_not_ready() {
        let mut rows = rows();
        rows.push(CheckRow::from_result(
            "c".into(),
            &CheckResult::Fail {
                message: "boom".into(),
                remediation: Some("fix it".into()),
            },
        ));
        let report = report(rows);
        assert!(!report.ready);
        assert_eq!(report.summary.failed, 1);
    }

    #[test]
    fn a_skipped_check_is_tallied_on_its_own() {
        let mut rows = rows();
        rows.push(CheckRow::from_result(
            "c".into(),
            &CheckResult::Skipped("no hidden volume".into()),
        ));
        let report = report(rows);
        assert!(report.ready);
        assert_eq!(report.summary.skipped, 1);
    }

    #[test]
    fn profile_summary_reports_each_target_kind() {
        assert_eq!(
            profile_summary(HostTarget::OverlayOnly).mode,
            "overlay-only"
        );
        assert_eq!(profile_summary(HostTarget::None).mode, "none");
        assert!(profile_summary(HostTarget::None).detail.is_none());

        let explicit = profile_summary(HostTarget::ExplicitFlake("/cfg#host".into()));
        assert_eq!(explicit.mode, "flake");
        assert!(explicit.detail.unwrap().contains("/cfg#host"));

        let flake = profile_summary(HostTarget::Flake(PathBuf::from("/mnt/vault/nixos")));
        assert_eq!(flake.mode, "flake");
        assert!(flake.detail.unwrap().contains("/mnt/vault/nixos"));

        let decoy = profile_summary(HostTarget::DecoyFlake {
            dir: PathBuf::from("/etc/nixos"),
            hidden_volume_root: PathBuf::from("/mnt/vault"),
        });
        assert_eq!(decoy.mode, "refused");
        let detail = decoy.detail.unwrap();
        assert!(detail.contains("/etc/nixos is not built"), "{detail}");
        assert!(detail.contains("nixos-build-target"), "{detail}");

        let legacy = profile_summary(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix")));
        assert_eq!(legacy.mode, "legacy");
        assert!(legacy.detail.unwrap().contains("/cfg/configuration.nix"));
    }

    fn manager_on(fake: FakePlatform, nixos_flake: Option<&str>) -> NailsManager<MockFilesystem> {
        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/vault"),
            nixos_flake: nixos_flake.map(str::to_string),
            ..Config::default()
        };
        let mut manager = NailsManager::new(
            MockFilesystem::new(),
            config,
            PathBuf::from("/mnt/vault/state.json"),
        );
        manager.set_fake_platform(fake);
        manager
    }

    /// The summary is derived from the manager's platform-driven discovery: the
    /// target the (fake) NixOS backend reports is what `check`/`--dry-run` shows.
    #[test]
    fn summary_follows_the_platform_discovery() {
        let manager = manager_on(
            FakePlatform::nixos()
                .with_build_target(HostTarget::Legacy(PathBuf::from("/cfg/configuration.nix"))),
            None,
        );
        assert_eq!(
            profile_summary(manager.discover_host_target(false).unwrap()).mode,
            "legacy"
        );

        let overlay_only = profile_summary(manager.discover_host_target(true).unwrap());
        assert_eq!(overlay_only.mode, "overlay-only");
        // 0.3 switches no system profile: overlay-only builds no hidden system.
        assert_eq!(
            overlay_only.line(),
            "overlay-only: no hidden NixOS system is built; the session runs the decoy's own system"
        );
    }

    /// A host without a config layer auto-discovers no profile switch, matching
    /// activation, which wires no builder there.
    #[test]
    fn summary_is_none_on_a_host_without_a_config_layer() {
        let manager = manager_on(FakePlatform::fhs(), None);
        let profile = profile_summary(manager.discover_host_target(false).unwrap());
        assert_eq!(profile.mode, "none");
        assert_eq!(profile.detail, None);
        assert_eq!(profile.line(), "no hidden NixOS build target");
    }

    /// An explicit flake is the operator's own choice and is reported on every
    /// host, exactly as before discovery moved behind the platform.
    #[test]
    fn summary_reports_an_explicit_flake_on_any_host() {
        let manager = manager_on(FakePlatform::fhs(), Some("/cfg#host"));
        let profile = profile_summary(manager.discover_host_target(false).unwrap());
        assert_eq!(profile.mode, "flake");
    }

    /// `decoy_filesystems` lists what the fstab policy does with each decoy
    /// filesystem, in the order activation puts them in place, and leaves out
    /// the entries the policy leaves as they are. Here the swap and the
    /// unmounted `/srv/archive` are masked, the ESP is bound read-only and the
    /// mounted `/srv/data` is overlaid, while the root, a tmpfs, a `noauto`
    /// entry and one inside the hidden volume are not listed. An empty list
    /// would make `check` say that only the root is overlaid.
    #[test]
    fn decoy_filesystems_list_each_decision_but_the_entries_left_as_they_are() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        std::fs::write(
            root.path().join("etc/fstab"),
            "/dev/vda2 / ext4 defaults 0 1\n\
             /dev/vda1 /boot vfat defaults 0 2\n\
             /dev/vda3 /srv/data ext4 defaults 0 2\n\
             /dev/vda4 /srv/archive ext4 defaults 0 2\n\
             /dev/vda5 /srv/spare ext4 noauto 0 2\n\
             /dev/vda6 /mnt/data/inner ext4 defaults 0 2\n\
             tmpfs /tmp tmpfs defaults 0 0\n\
             /dev/vda7 none swap sw 0 0\n",
        )
        .unwrap();
        let mounts = nails_teardown::mountinfo::parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
             2 1 8:1 / /boot rw - vfat /dev/vda1 rw\n\
             3 1 8:3 / /srv/data rw - ext4 /dev/vda3 rw\n",
        );

        let rows = decoy_filesystems(root.path(), &mounts, Path::new("/mnt/data"));
        // Each row is `<path>: <decision>`, a mask followed by its reason in
        // the policy's own words.
        let decisions: Vec<&str> = rows
            .iter()
            .map(|row| row.split(" (").next().unwrap_or(row))
            .collect();
        assert_eq!(
            decisions,
            [
                "/dev/vda7: masked",
                "/boot: read-only",
                "/srv/data: overlaid",
                "/srv/archive: masked",
            ],
            "{rows:?}"
        );
    }

    /// `count` tallies exactly the entries whose status matches the one asked
    /// for; the human `check` summary relies on it to report, for instance, how
    /// many inherited components are ignored.
    #[test]
    fn count_tallies_entries_by_matching_status() {
        // Two ignored, one for review, none masked.
        let statuses = [
            EntryStatus::Ignored,
            EntryStatus::Ignored,
            EntryStatus::Review,
        ];
        let entries: Vec<InheritedEntry> = statuses
            .into_iter()
            .enumerate()
            .map(|(i, status)| InheritedEntry {
                name: format!("entry-{i}"),
                source: "user-autostart",
                remote_linked: false,
                maskable: true,
                origin: "added",
                status: status.as_str(),
            })
            .collect();
        let summary = InheritedSummary {
            inspected: true,
            entries,
            remote_linked: Vec::new(),
            unmatched_masks: Vec::new(),
        };

        // The real matching count is returned (not a fixed 0 or 1), and it
        // counts the entries that match the status, not those that differ.
        assert_eq!(summary.count(EntryStatus::Ignored), 2);
        assert_eq!(summary.count(EntryStatus::Review), 1);
        assert_eq!(summary.count(EntryStatus::Masked), 0);
    }

    /// The attach gate's refusal is surfaced into the report's `refusal`: a root
    /// the gate rejects (here, one that does not exist) yields the gate's own
    /// error body, with its stable code and message, not `None`. Without
    /// `--allow-decoy-storage`, a `Missing` refusal is never downgraded.
    #[test]
    fn attach_refusal_surfaces_a_refused_root() {
        let fs = MockFilesystem::new();
        let options = PreflightOptions::default();
        assert!(!options.allow_decoy_storage);

        let body = attach_refusal(&fs, Path::new("/mnt/vault"), &options)
            .expect("the gate refuses a root that does not exist, so a body must be returned");
        assert_eq!(body.code, "not_separate_volume");
        assert!(
            body.message.contains("does not exist"),
            "message should name the missing-root reason: {}",
            body.message
        );
    }

    /// `prepare` asks the attach gate before anything runs, so a front end has
    /// the refusal to report first, and still has it when `run` then cannot
    /// assemble the checks.
    #[test]
    fn prepare_holds_the_refusal_before_any_check_runs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("not-mounted");
        let config = Config {
            hidden_volume_root: root.clone(),
            state_file_path: root.join("state.json"),
            log_path: root.join("logs"),
            ..Config::test_default()
        };
        let readiness = prepare(
            &RuntimeEnv::empty(),
            &dir.path().join("nails.toml"),
            config,
            &PreflightOptions::default(),
        );
        let refusal = readiness
            .refusal()
            .expect("a root that does not exist is refused");
        assert_eq!(refusal.code, "not_separate_volume");
    }

    /// `inherited_summary` honours the persona mode: in shared-home the decoy's
    /// enabled *user* units carry into the hidden session and are listed, while
    /// fresh-home replaces the home and drops them. The `mode == FreshHome` test
    /// is exactly what decides this, so flipping it empties the user-unit list.
    #[test]
    fn inherited_summary_lists_user_units_in_shared_home_mode() {
        // Resolve the same operator `inherited_summary` will, through the real
        // passwd database, by pointing resolution at uid 0 (root exists on every
        // host). The mock filesystem supplies the inherited state under its home.
        let env = RuntimeEnv::empty().with_target_uid("0");
        let user = TargetUser::resolve_with(&env)
            .expect("uid 0 resolves against the passwd database on any host");

        let fs = MockFilesystem::new();
        let user_dir = user.home().join(".config/systemd/user");
        let wants = user_dir.join("default.target.wants");
        fs.mock_set_directory_contents(&user_dir, vec![wants.clone()]);
        fs.mock_set_directory_contents(&wants, vec![wants.join("syncthing.service")]);

        let shared_home = Config {
            persona: PersonaConfig {
                mode: PersonaMode::SharedHome,
                ..PersonaConfig::default()
            },
            ..Config::default()
        };
        let summary = inherited_summary(&shared_home, &fs, &env);
        assert!(
            summary.inspected,
            "the operator resolved, so it is inspected"
        );
        let user_units: Vec<&str> = summary
            .entries
            .iter()
            .filter(|entry| entry.source == "user-unit")
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(
            user_units,
            vec!["syncthing.service"],
            "shared-home inherits the decoy's enabled user units"
        );
    }
}
