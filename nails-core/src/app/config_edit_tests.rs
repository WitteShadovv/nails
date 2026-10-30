// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::*;

/// The gate of these tests: every path beneath `root` is admitted, on no
/// particular mount. The attach gate itself is tested below and in the kernel
/// tier.
#[derive(Clone)]
struct Beneath {
    root: PathBuf,
    in_session: bool,
}

impl Gate for Beneath {
    fn admit(&self, path: &Path) -> Result<Target, Failure> {
        let (dir, name) = beneath(&self.root, path)?;
        Ok(Target {
            root: self.root.clone(),
            dir,
            name,
            mount_id: None,
            in_session: self.in_session,
        })
    }
}

/// A volume with a `config/` directory, the file's path in it, and its gate.
fn volume() -> (tempfile::TempDir, PathBuf, Beneath) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("config")).unwrap();
    let config = root.join("config").join("nails.toml");
    let gate = Beneath {
        root,
        in_session: false,
    };
    (dir, config, gate)
}

fn key(name: &str) -> &'static Setting {
    setting(name).unwrap()
}

fn set(name: &str, value: Value) -> Edit {
    Edit::Set(key(name), value)
}

fn string(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn a_setting_is_written_with_the_files_comments_and_reported() {
    let (_dir, config, gate) = volume();
    let before = "# My settings.\n[persona]\nmode = \"shared-home\" # for now\n";
    std::fs::write(&config, before).unwrap();
    let applied = edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap();
    assert_eq!(
        read(&config),
        "# My settings.\n[persona]\nmode = \"fresh-home\" # for now\n"
    );
    assert!(applied.written);
    assert_eq!(
        serde_json::to_value(applied.data()).unwrap(),
        serde_json::json!({
            "path": config.display().to_string(),
            "written": true,
            "changes": [{ "key": "persona.mode", "before": "shared-home", "after": "fresh-home" }],
        })
    );
}

#[test]
fn every_kind_reaches_the_data_as_json() {
    let (_dir, config, gate) = volume();
    let applied = edit_with(
        &gate,
        Some(&config),
        &[
            set("minimum_space_mb", Value::Integer(2000)),
            set("show_opsec_reminders", Value::Bool(false)),
            set(
                "persona.mask_inherited",
                Value::Names(vec!["dropbox".into()]),
            ),
            Edit::Unset(key("nixos_flake")),
        ],
    )
    .unwrap();
    let data = serde_json::to_value(applied.data()).unwrap();
    assert_eq!(data["changes"][0]["after"], 2000);
    assert_eq!(data["changes"][1]["after"], false);
    assert_eq!(data["changes"][2]["after"], serde_json::json!(["dropbox"]));
    assert_eq!(
        data["changes"][3],
        serde_json::json!({ "key": "nixos_flake", "before": null, "after": null })
    );
    assert!(data["changes"][0]["before"].is_null());
}

#[test]
fn an_edit_that_changes_nothing_writes_nothing() {
    let (_dir, config, gate) = volume();
    std::fs::write(&config, "minimum_space_mb = 750\n").unwrap();
    let inode = std::fs::metadata(&config).unwrap().ino();
    let applied = edit_with(
        &gate,
        Some(&config),
        &[
            set("minimum_space_mb", Value::Integer(750)),
            Edit::Unset(key("nixos_flake")),
        ],
    )
    .unwrap();
    assert!(!applied.written);
    assert_eq!(std::fs::metadata(&config).unwrap().ino(), inode);

    // Nothing to remove from a file that is not there: none is created.
    std::fs::remove_file(&config).unwrap();
    let applied = edit_with(&gate, Some(&config), &[Edit::Unset(key("nixos_flake"))]).unwrap();
    assert!(!applied.written);
    assert!(!config.exists());
}

#[test]
fn a_missing_file_is_created_root_only_with_the_setting_alone() {
    let (_dir, config, gate) = volume();
    edit_with(
        &gate,
        Some(&config),
        &[set("sleep_policy.mode", string("block"))],
    )
    .unwrap();
    assert_eq!(read(&config), "[sleep_policy]\nmode = \"block\"\n");
    let mode = std::fs::metadata(&config).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o600);
}

#[test]
fn the_files_mode_and_owner_are_kept() {
    let (_dir, config, gate) = volume();
    std::fs::write(&config, "").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = std::fs::metadata(&config).unwrap();
    edit_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(1))],
    )
    .unwrap();
    let after = std::fs::metadata(&config).unwrap();
    assert_eq!(after.mode() & 0o7777, 0o640);
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
}

#[test]
fn a_value_the_loader_refuses_leaves_the_file_byte_for_byte() {
    let (_dir, config, gate) = volume();
    let before = "# keep\nminimum_space_mb = 750\n";
    std::fs::write(&config, before).unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("hidden_volume_root", string("/mnt/data,b"))],
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::Invalid(_)), "{failure:?}");
    assert_eq!(failure.exit_status(), ExitStatus::Config);
    assert_eq!(failure.code(), "config");
    assert!(
        failure.message().contains("must not contain ','"),
        "{}",
        failure.message()
    );
    assert!(failure.message().ends_with("Nothing was written."));
    assert_eq!(read(&config), before);

    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("state_file_path", string("/elsewhere/state.json"))],
    )
    .unwrap_err();
    assert!(
        failure
            .message()
            .contains("must lie inside the hidden volume root"),
        "{}",
        failure.message()
    );
    assert_eq!(read(&config), before);

    // A value of the wrong kind never reaches the file.
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("separate-user"))],
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::Usage(_)), "{failure:?}");
    assert_eq!(failure.exit_status(), ExitStatus::Usage);
    assert_eq!(read(&config), before);
}

#[test]
fn a_file_the_loader_refuses_is_named_in_its_words() {
    let (_dir, config, gate) = volume();
    std::fs::write(&config, "nixos_flak = \"/x#y\"\n").unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap_err();
    assert!(
        failure.message().contains("did you mean `nixos_flake`?"),
        "{}",
        failure.message()
    );
    assert_eq!(read(&config), "nixos_flak = \"/x#y\"\n");

    std::fs::write(&config, "minimum_space_mb = \n").unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::Invalid(_)), "{failure:?}");
    assert!(
        failure.message().contains("line 1, column"),
        "{}",
        failure.message()
    );

    std::fs::write(&config, [0xff, 0xfe]).unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap_err();
    assert!(
        failure.message().contains("not UTF-8"),
        "{}",
        failure.message()
    );

    std::fs::write(&config, "persona = 5\n").unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap_err();
    assert!(
        failure.message().contains("`persona` is an integer"),
        "{}",
        failure.message()
    );
}

#[test]
fn a_link_at_the_file_or_on_the_way_is_refused() {
    let (dir, config, gate) = volume();
    let outside = tempfile::tempdir().unwrap();
    let decoy = outside.path().join("nails.toml");
    std::fs::write(&decoy, "minimum_space_mb = 1\n").unwrap();
    std::os::unix::fs::symlink(&decoy, &config).unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(2))],
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::OffVolume(_)), "{failure:?}");
    assert_eq!(failure.code(), "config_off_volume");
    assert_eq!(failure.exit_status(), ExitStatus::PreflightRefused);
    assert_eq!(read(&decoy), "minimum_space_mb = 1\n");
    std::fs::remove_file(&config).unwrap();

    let linked = dir.path().join("linked");
    std::os::unix::fs::symlink(outside.path(), &linked).unwrap();
    let through = gate.root.join("linked").join("nails.toml");
    let failure = edit_with(
        &gate,
        Some(&through),
        &[set("minimum_space_mb", Value::Integer(2))],
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::OffVolume(_)), "{failure:?}");
    assert_eq!(read(&decoy), "minimum_space_mb = 1\n");

    let hard = config.with_file_name("other.toml");
    std::fs::write(&hard, "").unwrap();
    std::fs::hard_link(&hard, &config).unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(2))],
    )
    .unwrap_err();
    assert!(
        failure.message().contains("hard link"),
        "{}",
        failure.message()
    );
    assert_eq!(read(&hard), "");
}

#[test]
fn a_file_off_the_volume_is_refused_before_it_is_read() {
    let (_dir, _config, gate) = volume();
    let outside = tempfile::tempdir().unwrap();
    let elsewhere = outside.path().join("nails.toml");
    std::fs::write(&elsewhere, "minimum_space_mb = 1\n").unwrap();
    for path in [
        elsewhere.clone(),
        gate.root.join("config/../../escape.toml"),
        gate.root.clone(),
    ] {
        let failure = edit_with(
            &gate,
            Some(&path),
            &[set("minimum_space_mb", Value::Integer(2))],
        )
        .unwrap_err();
        assert!(
            matches!(failure, Failure::OffVolume(_)),
            "{path:?}: {failure:?}"
        );
        assert!(
            failure
                .message()
                .contains("is not on the volume nails runs from"),
            "{}",
            failure.message()
        );
    }
    assert_eq!(read(&elsewhere), "minimum_space_mb = 1\n");
}

#[test]
fn concurrent_edits_all_land() {
    let (_dir, config, gate) = volume();
    std::fs::write(&config, "# Shared by every writer.\n").unwrap();
    let edits = [
        set("minimum_space_mb", Value::Integer(1000)),
        set("rebuild_space_mb", Value::Integer(9000)),
        set("show_opsec_reminders", Value::Bool(false)),
        set("persona.mode", string("fresh-home")),
        set("backend_watch.enabled", Value::Bool(false)),
        set("backend_watch.debounce_secs", Value::Integer(40)),
        set("session_mounts.alert", Value::Bool(false)),
        set("sleep_policy.mode", string("teardown")),
    ];
    std::thread::scope(|scope| {
        for edit in &edits {
            let gate = gate.clone();
            let config = config.clone();
            scope.spawn(move || {
                for _ in 0..5 {
                    edit_with(&gate, Some(&config), std::slice::from_ref(edit)).unwrap();
                }
            });
        }
    });
    let text = read(&config);
    assert!(text.starts_with("# Shared by every writer.\n"), "{text}");
    let loaded = LoadedConfig::parse(&config, &text).unwrap().into_config();
    assert_eq!(loaded.minimum_space_mb, 1000);
    assert_eq!(loaded.rebuild_space_mb, 9000);
    assert!(!loaded.show_opsec_reminders);
    assert_eq!(loaded.persona.mode, crate::config::PersonaMode::FreshHome);
    assert!(!loaded.backend_watch.enabled);
    assert_eq!(loaded.backend_watch.debounce_secs, 40);
    assert!(!loaded.session_mounts.alert);
    assert_eq!(
        loaded.sleep_policy.mode,
        crate::config::SleepPolicyMode::Teardown
    );
    let names: Vec<String> = std::fs::read_dir(config.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec!["nails.toml".to_string()],
        "no file is left behind"
    );
}

#[test]
fn a_plan_is_applied_only_to_the_file_it_read() {
    let (_dir, config, gate) = volume();
    std::fs::write(&config, "minimum_space_mb = 750\n").unwrap();
    let plan = plan_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(2000))],
    )
    .unwrap();
    assert!(plan.writes());
    assert_eq!(plan.path(), config.as_path());
    assert_eq!(
        read(&config),
        "minimum_space_mb = 750\n",
        "a plan writes nothing"
    );

    std::fs::write(&config, "minimum_space_mb = 800\n").unwrap();
    let failure = apply_with(&gate, &plan).unwrap_err();
    assert!(matches!(failure, Failure::Stale(_)), "{failure:?}");
    assert_eq!(failure.code(), "plan_stale");
    assert_eq!(read(&config), "minimum_space_mb = 800\n");

    let plan = plan_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(2000))],
    )
    .unwrap();
    let applied = apply_with(&gate, &plan).unwrap();
    assert!(applied.written);
    assert_eq!(read(&config), "minimum_space_mb = 2000\n");
    assert_eq!(plan.change_data()[0].after, Some(serde_json::json!(2000)));

    // A plan for another volume is stale too.
    let other = Beneath {
        root: gate.root.join("config"),
        in_session: false,
    };
    assert!(matches!(apply_with(&other, &plan), Err(Failure::Stale(_))));
}

#[test]
fn a_hidden_session_keeps_its_root_and_state_file() {
    let (_dir, config, mut gate) = volume();
    gate.in_session = true;
    let root = gate.root.display().to_string();
    std::fs::write(
        &config,
        format!("hidden_volume_root = {root:?}\nstate_file_path = \"{root}/state.json\"\n"),
    )
    .unwrap();
    let moved = format!("{root}/elsewhere.json");
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("state_file_path", string(&moved))],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("state_file_path")),
        "{failure:?}"
    );
    assert_eq!(failure.exit_status(), ExitStatus::PreflightRefused);
    let parent = gate.root.parent().unwrap().display().to_string();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("hidden_volume_root", string(&parent))],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("hidden_volume_root")),
        "{failure:?}"
    );

    // The default the file falls back to is where the state is now.
    edit_with(&gate, Some(&config), &[Edit::Unset(key("state_file_path"))]).unwrap();
    edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap();
    assert!(!read(&config).contains("state_file_path"));

    // Outside a session the same change is the operator's to make.
    gate.in_session = false;
    edit_with(
        &gate,
        Some(&config),
        &[set("state_file_path", string(&moved))],
    )
    .unwrap();
}

#[test]
fn a_folder_that_is_no_volume_of_its_own_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("config")).unwrap();
    std::fs::write(root.join("state.json"), "{}").unwrap();
    let path = root.join("config/nails.toml");
    let failure = admit(&RealFilesystem, &root, &path).unwrap_err();
    let Failure::Refused(refusal) = &failure else {
        panic!("{failure:?}");
    };
    assert_eq!(refusal.code(), "not_separate_volume");
    assert_eq!(failure.exit_status(), ExitStatus::PreflightRefused);
    let body = failure.body(None);
    assert_eq!(body.code, "not_separate_volume");
    assert!(
        body.message.contains("Nothing was written."),
        "{}",
        body.message
    );
    assert!(!path.exists());
}

#[test]
fn every_failure_has_a_code_a_status_and_a_sentence() {
    let path = PathBuf::from("/mnt/data/config/nails.toml");
    let io = || {
        NailsError::io(
            &path,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        )
    };
    let cases = [
        (
            Failure::Usage("`x` takes y".into()),
            "usage",
            ExitStatus::Usage,
        ),
        (
            Failure::OffVolume("x".into()),
            "config_off_volume",
            ExitStatus::PreflightRefused,
        ),
        (
            Failure::NoLayout(PathBuf::from("/mnt/data")),
            "no_layout",
            ExitStatus::PreflightRefused,
        ),
        (
            Failure::SessionPaths("state_file_path"),
            "session_paths",
            ExitStatus::PreflightRefused,
        ),
        (Failure::Read(io()), "config", ExitStatus::Config),
        (
            Failure::Invalid(NailsError::ConfigError("bad".into())),
            "config",
            ExitStatus::Config,
        ),
        (
            Failure::Stale(path.clone()),
            "plan_stale",
            ExitStatus::Failed,
        ),
        (
            Failure::Busy(path.clone()),
            "config_busy",
            ExitStatus::Failed,
        ),
        (Failure::Write(io()), "write_failed", ExitStatus::Failed),
    ];
    for (failure, code, status) in cases {
        assert_eq!(failure.code(), code, "{failure:?}");
        assert_eq!(failure.exit_status(), status, "{failure:?}");
        let body = failure.body(None);
        assert_eq!(body.code, code);
        assert!(!body.message.is_empty());
    }
    assert!(Failure::Read(io()).error().is_some());
    assert!(Failure::Busy(path).error().is_none());
}

mod kernel_tests {
    use super::*;
    use crate::test_support::{Rerun, ScratchTmpfs};

    /// The engine's gate, for a volume at `root` rather than the test
    /// binary's directory.
    struct At(PathBuf);

    impl Gate for At {
        fn admit(&self, path: &Path) -> Result<Target, Failure> {
            admit(&RealFilesystem, &self.0, path)
        }
    }

    #[test]
    fn a_volume_of_its_own_takes_the_edit_and_nothing_mounted_inside_it_does() {
        let _ = Rerun::new(crate::test_path!(
            a_volume_of_its_own_takes_the_edit_and_nothing_mounted_inside_it_does
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            let root = volume.path().canonicalize().unwrap();
            let config = root.join("config/nails.toml");
            std::fs::create_dir(root.join("config")).unwrap();
            let gate = At(root.clone());
            let edit = [set("persona.mode", string("fresh-home"))];

            // No layout yet.
            let failure = edit_with(&gate, Some(&config), &edit).unwrap_err();
            assert!(matches!(failure, Failure::NoLayout(_)), "{failure:?}");
            assert!(!config.exists());

            std::fs::write(root.join("state.json"), "{}").unwrap();
            let target = gate.admit(&config).unwrap();
            assert!(target.mount_id.is_some());
            assert!(!target.in_session);
            edit_with(&gate, Some(&config), &edit).unwrap();
            assert_eq!(read(&config), "[persona]\nmode = \"fresh-home\"\n");

            // Another filesystem mounted over the directory is not the volume.
            let other = ScratchTmpfs::new("");
            std::fs::write(other.path().join("nails.toml"), "").unwrap();
            nix::mount::mount(
                Some(other.path()),
                &root.join("config"),
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind another tmpfs over config");
            let failure = edit_with(&gate, Some(&config), &edit).unwrap_err();
            assert!(matches!(failure, Failure::OffVolume(_)), "{failure:?}");
            assert_eq!(read(&other.path().join("nails.toml")), "");
            nix::mount::umount(&root.join("config")).unwrap();

            // A file on another volume is not this one's.
            let failure =
                edit_with(&gate, Some(&other.path().join("nails.toml")), &edit).unwrap_err();
            assert!(matches!(failure, Failure::OffVolume(_)), "{failure:?}");
        });
    }
}
