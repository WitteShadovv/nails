// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the readiness report.

use super::*;
use crate::filesystem::automount::Snapshot;
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
        &CheckResult::fail_with("boom", "fix it"),
    ));
    let report = report(rows);
    assert!(!report.ready);
    assert_eq!(report.summary.failed, 1);
}

#[test]
fn a_row_names_the_override_only_where_a_flag_accepts_the_failure() {
    let accepted = CheckRow::from_result(
        "hidden-volume".into(),
        &CheckResult::fail_with("on the decoy's storage", "use a volume of its own")
            .accepted_by(Allowable::DecoyStorage),
    );
    assert_eq!(
        serde_json::to_value(&accepted).unwrap(),
        serde_json::json!({
            "name": "hidden-volume",
            "status": "fail",
            "message": "on the decoy's storage",
            "remediation": "use a volume of its own",
            "allowable": "decoy_storage",
        })
    );
    let refused = CheckRow::from_result("swap".into(), &CheckResult::fail("swap is on"));
    let json = serde_json::to_value(&refused).unwrap();
    assert!(json.get("allowable").is_none(), "{json}");
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
/// unmounted `/srv/archive` are masked, the ESP is bound read-only, the
/// mounted `/srv/data` is overlaid and the entry inside the hidden volume
/// is refused, while the root, a tmpfs and a `noauto` entry are not
/// listed. An empty list would make `check` say that only the root is
/// overlaid.
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

    let snapshot = Snapshot::read(&RealFilesystem, root.path());
    let rows = decoy_filesystems(
        &RealFilesystem,
        &snapshot,
        root.path(),
        &mounts,
        Path::new("/mnt/data"),
    );
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
            "/mnt/data/inner: refused",
        ],
        "{rows:?}"
    );
}

/// The listing asks the automount guard before each lookup, as the
/// fstab-policy row does: a unit directory behind an automount point that
/// nothing is mounted on yet is not listed, and the line names the point;
/// an `x-systemd.automount` mount point that is such a point keeps its path.
/// Without the mount table nothing is looked up.
#[test]
fn decoy_filesystems_make_no_lookup_behind_an_automount_point() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(
        root.join("etc/fstab"),
        "/dev/vda2 / ext4 defaults 0 1\n\
         /dev/vda1 /boot/efi vfat noauto,x-systemd.automount 0 2\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("usr/local/lib/systemd/system")).unwrap();
    std::fs::create_dir_all(root.join("srv/elsewhere")).unwrap();
    std::fs::create_dir_all(root.join("boot")).unwrap();
    // Looked up, the point would lead elsewhere: it is not.
    std::os::unix::fs::symlink("../srv/elsewhere", root.join("boot/efi")).unwrap();
    let point = |at: &str, id: u32| {
        format!(
            "{id} 1 0:{id} / {} rw,relatime - autofs systemd-1 rw,fd={id},pgrp=1,timeout=0,\
             minproto=5,maxproto=5,direct,pipe_ino={id}\n",
            root.join(at).display()
        )
    };
    let table = nails_teardown::mountinfo::parse_mountinfo(&format!(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n{}{}",
        point("usr/local", 40),
        point("boot/efi", 41)
    ));
    let snapshot = Snapshot::from_table(table);
    let mounts = nails_teardown::mountinfo::parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");

    let rows = decoy_filesystems(
        &RealFilesystem,
        &snapshot,
        &root,
        &mounts,
        Path::new("/mnt/data"),
    );
    let usr_local = root.join("usr/local");
    assert!(
        rows.iter().any(
            |row| row.starts_with("/usr/local/lib/systemd/system/: refused")
                && row.ends_with(&format!(
                    "the lookup would mount the automount point {})",
                    usr_local.display()
                ))
        ),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.starts_with("/boot/efi: ")),
        "{rows:?}"
    );
    assert!(
        rows.iter().all(|row| !row.contains("elsewhere")),
        "{rows:?}"
    );

    let unreadable = crate::MockFilesystem::new();
    unreadable.mock_set_mount_table_error("permission denied");
    let snapshot = Snapshot::read(&unreadable, Path::new("/"));
    let rows = decoy_filesystems(
        &unreadable,
        &snapshot,
        Path::new("/"),
        &mounts,
        Path::new("/mnt/data"),
    );
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(
        rows[0].starts_with("NAILS cannot tell how each decoy filesystem would be handled"),
        "{rows:?}"
    );
    assert!(unreadable.mock_lookups().is_empty());
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
        not_read: Vec::new(),
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
    // No flag makes a missing root, so the body names none.
    assert_eq!(body.allowable, None);
}

/// A root that cannot be looked up is a refusal `check` leads with, as
/// for a missing one, naming the error and no override.
#[test]
fn attach_refusal_surfaces_a_root_that_cannot_be_looked_up() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/vault", true);
    fs.mock_set_lookup_error("/mnt/vault", std::io::ErrorKind::PermissionDenied);
    let body = attach_refusal(&fs, Path::new("/mnt/vault"), &PreflightOptions::default())
        .expect("a root that cannot be looked up is refused");
    assert_eq!(body.code, "not_separate_volume");
    assert_eq!(
        body.message,
        "nothing shows that /mnt/vault is a volume of its own: it cannot be looked up (Mock: \
         the lookup fails here). Nothing was written.\nRun the command again with sudo."
    );
    assert_eq!(body.allowable, None);
}

/// A root behind an automount point that nothing is mounted on yet is
/// not looked up: `check` leads with the gate's refusal, which names the
/// point and how to mount it, and nothing at or below the point is
/// looked up.
#[test]
fn attach_refusal_makes_no_lookup_behind_an_automount_point() {
    use crate::preflight::checks::automount_fixture::{reached, with_automounts};
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/vault", true);
    with_automounts(&fs, &["/mnt"]);
    let body = attach_refusal(&fs, Path::new("/mnt/vault"), &PreflightOptions::default())
        .expect("a root the guard does not look up is refused");
    assert_eq!(body.code, "not_separate_volume");
    assert_eq!(
        body.message,
        "nothing shows that /mnt/vault is a volume of its own: it is not looked up, since the \
         lookup would mount the automount point /mnt. Nothing was written.\nMount /mnt (for \
         example `ls /mnt`), then run the command again."
    );
    assert!(!reached(&fs, "/mnt"), "{:?}", fs.mock_lookups());
}

/// A root on the decoy's storage is the refusal `check
/// --allow-decoy-storage` turns into a warning: the body names that
/// override, as the hidden-volume row does.
#[test]
fn attach_refusal_names_the_override_for_decoy_storage() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/data", true);
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         30 1 8:1 /srv/x /mnt/data rw - ext4 /dev/vda1 rw\n",
    );
    let body = attach_refusal(&fs, Path::new("/mnt/data"), &PreflightOptions::default())
        .expect("a bind of a folder of / is refused");
    assert_eq!(body.allowable, Some(Allowable::DecoyStorage));
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

/// The inherited list names each place it could not read, with the
/// automount point where the guard did not look it up, and looks
/// nothing up below that point; without the mount table it names the
/// table and looks up nothing.
#[test]
fn inherited_summary_lists_the_places_it_could_not_read() {
    use crate::preflight::checks::automount_fixture::{reached, with_automounts};
    let env = RuntimeEnv::empty().with_target_uid("0");
    let user = TargetUser::resolve_with(&env)
        .expect("uid 0 resolves against the passwd database on any host");
    let home = user.home().display().to_string();
    let fs = MockFilesystem::new();
    with_automounts(&fs, &[home.as_str()]);

    let summary = inherited_summary(&Config::default(), &fs, &env);
    assert!(summary.inspected);
    let autostart = format!("{home}/.config/autostart");
    let place = summary
        .not_read
        .iter()
        .find(|place| place.path == autostart)
        .unwrap_or_else(|| panic!("{:?}", summary.not_read));
    assert_eq!(
        place.reason,
        format!(
            "NAILS does not look up {autostart}, since the lookup would mount the \
             automount point {home}"
        )
    );
    assert_eq!(place.automount_point.as_deref(), Some(home.as_str()));
    assert!(!reached(&fs, &home), "{:?}", fs.mock_lookups());
    let json = serde_json::to_value(&summary).unwrap();
    assert_eq!(json["not_read"][0]["path"], autostart);
    assert_eq!(json["not_read"][0]["automount_point"], home);

    fs.mock_set_mount_table_error("permission denied");
    fs.mock_clear_lookups();
    let summary = inherited_summary(&Config::default(), &fs, &env);
    assert!(summary.inspected);
    assert_eq!(
        summary.not_read,
        [NotReadEntry {
            path: "/proc/self/mountinfo".to_string(),
            reason: "NAILS cannot read the mount table (/proc/self/mountinfo: permission \
                     denied), which shows where a lookup would mount an automount point, so \
                     it looks up nothing"
                .to_string(),
            automount_point: None,
        }]
    );
    assert!(fs.mock_lookups().is_empty(), "{:?}", fs.mock_lookups());
    let json = serde_json::to_value(&summary).unwrap();
    assert!(json["not_read"][0]["automount_point"].is_null(), "{json}");
}

/// A lookup the guard did not make that the inventory does not list is
/// listed too, once.
#[test]
fn a_skip_the_inventory_does_not_list_is_listed_once() {
    use crate::filesystem::automount::Skipped;
    use nails_base::error::Skip;
    let skip = |path: &str| Skipped {
        path: PathBuf::from(path),
        reason: Skip::Automount {
            point: PathBuf::from("/home/bob"),
        },
    };
    let summary =
        InheritedSummary::from_inventory(&PersonaInventory::default(), &PersonaConfig::default())
            .with_skipped(&[
                skip("/home/bob/.config"),
                skip("/home/bob/.config"),
                skip("/home/bob/.config/autostart"),
            ]);
    let paths: Vec<&str> = summary
        .not_read
        .iter()
        .map(|place| place.path.as_str())
        .collect();
    assert_eq!(paths, ["/home/bob/.config", "/home/bob/.config/autostart"]);
    assert_eq!(
        summary.not_read[0].automount_point.as_deref(),
        Some("/home/bob")
    );
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
