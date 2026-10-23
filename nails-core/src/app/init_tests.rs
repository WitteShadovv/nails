// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `init` operation: the setup plan, what obstructs it and
//! the layout it creates.

use super::*;
use crate::platform::FakePlatform;
use crate::{MockFilesystem, PathKind};
use tempfile::TempDir;

/// A mock whose `root` reads as a mounted, writable, symlink-capable volume
/// of its own, so the attach gate admits it and planning reaches the
/// preconditions. Mirrors the CLI suite's helper of the same name.
fn attached_mock(root: &Path) -> MockFilesystem {
    let fs = MockFilesystem::new();
    let root_str = root.to_str().unwrap();
    fs.mock_set_path_exists(root_str, true);
    fs.mock_set_path_type(root_str, PathKind::Dir);
    fs.mock_set_writable(root_str, true);
    fs.mock_set_supports_symlinks(root, true);
    // The default mock device id for an unmapped path differs from `/`'s, so
    // a mount here reads as a filesystem of its own and the gate admits it.
    fs.mock_set_mounted(root, true);
    fs
}

/// Options that bootstrap `root` from an explicit base hardware config, which
/// pins the NixOS layout without consulting the host detector.
fn options_from(root: &Path, hardware_config: &str) -> InitOptions {
    InitOptions {
        path: root.to_path_buf(),
        hardware_config: Some(PathBuf::from(hardware_config)),
        ..Default::default()
    }
}

#[test]
fn plan_validates_a_mounted_writable_symlink_capable_volume() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    let hardware = "/seed/hardware-configuration.nix";
    fs.mock_set_path_exists(hardware, true);
    fs.mock_set_readable(hardware, true);

    let plan = plan(&fs, &options_from(root, hardware)).expect(
        "a mounted, writable, symlink-capable volume with a readable base config validates",
    );

    // The explicit base config pins the NixOS layout, and nothing warns.
    assert!(matches!(plan.bootstrap, HardwareBootstrap::From(_)));
    assert!(plan.warnings.is_empty(), "{:?}", plan.warnings);
}

#[test]
fn plan_rejects_a_hardware_config_that_exists_but_is_unreadable() {
    let root = Path::new("/mnt/data");
    let fs = attached_mock(root);
    let hardware = "/seed/hardware-configuration.nix";
    // Present on disk, but not readable: planning must still refuse it, since
    // the layout cannot be seeded from a base config it cannot read.
    fs.mock_set_path_exists(hardware, true);
    fs.mock_set_readable(hardware, false);

    match plan(&fs, &options_from(root, hardware)) {
        Err(InitFailure::Preconditions(failures)) => assert!(
            failures
                .iter()
                .any(|reason| reason.contains("missing or unreadable")),
            "{failures:?}"
        ),
        other => panic!("expected a precondition failure, got {:?}", other.is_ok()),
    }
}

#[test]
fn layout_subdirs_adds_the_nixos_paths_only_when_requested() {
    // Overlay-only: exactly the platform-agnostic subdirectories, no more.
    assert_eq!(layout_subdirs(false), COMMON_SUBDIRS.to_vec());
    assert!(!layout_subdirs(false).contains(&"config/nixos"));

    // With the NixOS layout: the common subdirectories plus the NixOS ones.
    let expected: Vec<&str> = COMMON_SUBDIRS
        .iter()
        .chain(NIXOS_SUBDIRS)
        .copied()
        .collect();
    assert_eq!(layout_subdirs(true), expected);
    assert!(layout_subdirs(true).contains(&"config/nixos"));
}

#[test]
fn obstructions_are_empty_when_the_layout_is_clear() {
    let base = Path::new("/mnt/data");

    // A pristine volume has nothing in the way.
    let clear = MockFilesystem::new();
    assert!(obstructions(&clear, base, true).unwrap().is_empty());

    // Layout directories that already exist as proper directories are not
    // obstructions, so a re-run does not flag its own prior layout.
    let present = MockFilesystem::new();
    present.mock_set_path_type(base.join("logs").to_str().unwrap(), PathKind::Dir);
    present.mock_set_path_type(base.join("root").to_str().unwrap(), PathKind::Dir);
    assert!(obstructions(&present, base, false).unwrap().is_empty());

    // An already-present config file and state file of the right kind are
    // likewise fine (they are the markers a re-run expects to find).
    let files = MockFilesystem::new();
    files.mock_set_path_type(
        base.join("config").join(CONFIG_FILE_NAME).to_str().unwrap(),
        PathKind::File,
    );
    files.mock_set_path_type(base.join("state.json").to_str().unwrap(), PathKind::File);
    assert!(obstructions(&files, base, false).unwrap().is_empty());
}

#[test]
fn obstructions_flag_entries_of_the_wrong_kind() {
    let base = Path::new("/mnt/data");

    // A file where the layout needs a directory is reported, naming the path.
    let file_in_the_way = MockFilesystem::new();
    file_in_the_way.mock_set_path_type(base.join("logs").to_str().unwrap(), PathKind::File);
    let found = obstructions(&file_in_the_way, base, false).unwrap();
    assert!(
        found
            .iter()
            .any(|reason| reason.contains("/mnt/data/logs exists but is not a directory")),
        "{found:?}"
    );

    // A directory where the layout needs the state file is reported too.
    let dir_in_the_way = MockFilesystem::new();
    dir_in_the_way.mock_set_path_type(base.join("state.json").to_str().unwrap(), PathKind::Dir);
    let found = obstructions(&dir_in_the_way, base, false).unwrap();
    assert!(
        found
            .iter()
            .any(|reason| reason.contains("/mnt/data/state.json exists but is a directory")),
        "{found:?}"
    );
}

#[test]
fn platform_label_names_the_host_or_falls_back() {
    let mut profile = FakePlatform::fhs().host_profile();
    profile.id = Some("debian".to_string());
    assert_eq!(platform_label(&profile), "host 'debian'");

    profile.id = Some("ubuntu".to_string());
    assert_eq!(platform_label(&profile), "host 'ubuntu'");

    // Without an os-release ID the label falls back to a generic phrase.
    profile.id = None;
    assert_eq!(platform_label(&profile), "this host");
}

#[test]
fn apply_creates_the_layout_on_disk_and_writes_the_config() {
    // A real temp dir backs the state file and its lock (written through the
    // core's own atomic path); the mock backs the layout directory writes.
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();
    let fs = attached_mock(base);

    let overlay_plan = InitPlan {
        bootstrap: HardwareBootstrap::Skip(
            "overlay-only: skipping the hidden NixOS layout".to_string(),
        ),
        warnings: Vec::new(),
    };
    let report = apply(&fs, base, overlay_plan).expect("apply writes the layout");

    // Each common subdirectory is actually created (not merely reported) and
    // locked down to 0700.
    for rel in COMMON_SUBDIRS {
        let dir = base.join(rel);
        assert!(
            fs.path_exists(&dir).unwrap(),
            "{rel} must be created on the filesystem, not only reported"
        );
        assert_eq!(fs.mock_get_permissions(&dir), Some(0o700), "{rel} mode");
    }
    // The skip keeps every NixOS path off the volume.
    for rel in NIXOS_SUBDIRS {
        assert!(
            !fs.path_exists(&base.join(rel)).unwrap(),
            "{rel} must not be created when the NixOS layout is skipped"
        );
    }

    // The config template is written when none is present.
    let config_path = base.join("config").join(CONFIG_FILE_NAME);
    let expected = Config::init_template(base);
    assert_eq!(
        fs.get_written_content(&config_path).as_deref(),
        Some(expected.as_str()),
        "the init config template must be written when none exists"
    );

    // A fresh run reports everything as freshly created, and the skip is a note.
    assert!(
        report
            .items
            .iter()
            .all(|item| item.status == ItemStatus::Created),
        "{:?}",
        report.items
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("overlay-only")),
        "{:?}",
        report.notes
    );
}

#[test]
fn write_state_file_keeps_an_existing_regular_state_file() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();
    let state_path = base.join("state.json");
    std::fs::write(&state_path, "{}").unwrap();

    // An existing *regular* state file is left in place and reported present,
    // never mistaken for a wrong-kind entry that would abort init.
    let item = write_state_file(base).expect("an existing regular state.json is accepted");
    assert_eq!(item.status, ItemStatus::AlreadyPresent);
    assert_eq!(item.path, state_path.display().to_string());
}

#[test]
fn item_status_labels_are_the_exact_human_strings() {
    // The labels are a surfaced contract (shown to the operator and matched
    // against in reports), so both are pinned exactly, not merely non-empty.
    assert_eq!(ItemStatus::Created.label(), "created");
    assert_eq!(ItemStatus::AlreadyPresent.label(), "already present");
}

#[test]
fn next_steps_lists_the_three_activation_steps() {
    let steps = next_steps(Path::new("/mnt/data"));

    assert_eq!(steps.len(), 3, "{steps:?}");
    assert!(steps[0].contains("another machine"), "{steps:?}");
    assert!(steps[1].contains("sudo /mnt/data/nails check"), "{steps:?}");
    assert!(
        steps[2].contains("sudo /mnt/data/nails activate"),
        "{steps:?}"
    );
}
