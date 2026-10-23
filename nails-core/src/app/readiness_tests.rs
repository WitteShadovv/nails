// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `readiness` operation (the CLI's `check`).

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

#[test]
fn decoy_filesystems_never_list_the_left_alone_entries() {
    for line in decoy_filesystems(Path::new("/mnt/data")) {
        assert!(!line.contains("left as is"), "{line}");
    }
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

/// Every line `decoy_filesystems` reports is a real, structured decision
/// description of the `"<path>: <verb>"` shape `Decision::describe` produces:
/// never an empty string and never a bare token. This holds for whatever the
/// host's fstab and mounts yield, so it pins the contract without depending on
/// a particular host layout.
#[test]
fn decoy_filesystems_lines_are_structured_descriptions() {
    for line in decoy_filesystems(Path::new("/mnt/data")) {
        assert!(!line.is_empty(), "a decision description is never empty");
        assert!(
            line.contains(": "),
            "every line is a `<path>: <verb>` describe() line, got {line:?}"
        );
    }
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
