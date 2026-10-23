// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `readiness` operation (the CLI's `check`): a strictly read-only
//! check of whether activation would run.
//!
//! It builds the same pre-flight registry activation would run, runs it without
//! staging or mutating anything, and gathers the effective configuration, the
//! overlay targets, how the decoy filesystems would be handled, which NixOS
//! profile would be built and the decoy persona state the hidden session would
//! inherit. The whole picture is one [`ReadinessReport`] a front end renders;
//! `activate --dry-run` runs this same operation, so the two always agree.

use std::path::Path;

use nails_api::ErrorBody;
use serde::Serialize;

use crate::config::{PersonaConfig, PersonaMode};
use crate::hidden_root::{Allow, Assessment};
use crate::{
    CheckResult, Config, EntryStatus, Filesystem, HostTarget, PersonaInventory, PreflightOptions,
    Result, RuntimeEnv, TargetUser, collect_inherited_persona,
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

/// Run the readiness check for the resolved configuration and options.
///
/// Builds the manager with the NixOS target activation would pick, assembles the
/// same pre-flight registry (read-only to run; no staging happens here), runs it
/// and gathers the whole readiness picture. `config_path` is the configuration
/// file that was consulted, named in the report when it exists. An error means
/// the checks could not be assembled; everything else is reported in the result.
pub fn readiness(
    env: &RuntimeEnv,
    config_path: &Path,
    config: Config,
    options: &PreflightOptions,
) -> Result<ReadinessReport> {
    let overlay_only = options.overlay_only;
    let state_path = config.state_file_path.clone();
    let manager = super::engine::build_nixos_manager(config, state_path, overlay_only, env);
    // Only a NixOS host carries a config layer; the rendered report shows the
    // NixOS-profile section on NixOS and hides it elsewhere.
    let nixos_host = manager
        .host_profile()
        .is_some_and(|profile| profile.has_config_layer());

    let refusal = attach_refusal(
        manager.filesystem(),
        &manager.config().hidden_volume_root,
        options,
    );

    let registry = manager.preflight_registry(options)?;
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

    let filesystems = decoy_filesystems(&config.hidden_volume_root);
    let profile = profile_summary(
        manager
            .discover_host_target(overlay_only)
            .unwrap_or(HostTarget::None),
    );
    let inherited = inherited_summary(config, manager.filesystem(), env);

    let mut report =
        ReadinessReport::finalize(checks, config_summary, filesystems, profile, inherited);
    report.refusal = refusal;
    report.nixos_host = nixos_host;
    Ok(report)
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

/// What the fstab policy would do with each decoy filesystem.
fn decoy_filesystems(hidden_root: &Path) -> Vec<String> {
    use crate::session::{fstab, policy};
    let text =
        nails_teardown::whole_root::nextroot::read_in_root(Path::new("/"), Path::new("/etc/fstab"))
            .unwrap_or_default();
    let entries = fstab::parse_fstab(&String::from_utf8_lossy(&text));
    let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap_or_default();
    policy::decide_all(&entries, &mounts, hidden_root)
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
#[path = "readiness_tests.rs"]
mod tests;
