// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use nails_teardown::whole_root::plan::Plan as SessionPlan;

use super::*;
use crate::MockFilesystem;

/// The gate of these tests: every path beneath `root` is admitted, on no
/// particular mount, with the hidden session it is given. The attach gate
/// itself and the session it finds are tested below and in the kernel tier.
#[derive(Clone)]
struct Beneath {
    root: PathBuf,
    session: Option<Session>,
}

impl Gate for Beneath {
    fn admit(&self, path: &Path) -> Result<Target, Failure> {
        let (dir, name) = beneath(&self.root, path)?;
        Ok(Target {
            root: self.root.clone(),
            dir,
            name,
            mount_id: None,
            session: self.session.clone(),
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
        session: None,
    };
    (dir, config, gate)
}

/// `/` and `/run` of a machine in `dir`, with nothing in its `/run` yet.
fn machine(dir: &Path) -> Paths {
    let paths = Paths {
        root: dir.join("decoy"),
        run: dir.join("run"),
    };
    std::fs::create_dir_all(paths.runtime()).unwrap();
    paths
}

/// The plan an entry for the hidden volume at `root` writes into `paths`,
/// with `change` made to it first.
fn record_plan(paths: &Paths, root: &Path, change: impl FnOnce(&mut SessionPlan)) {
    let text = format!(
        "{{\"version\":{version},\"hidden_root\":\"{root}\",\"hidden_dev\":\"253:0\",\
         \"upper\":\"{root}/root/upper\",\"work\":\"{root}/root/work\",\
         \"decoy_root\":{{\"source\":\"/dev/vda1\",\"fstype\":\"ext4\"}},\
         \"decoy\":{{\"init\":\"/sbin/init\"}},\"hidden\":{{\"init\":\"/sbin/init\"}}}}",
        version = nails_teardown::whole_root::plan::PLAN_VERSION,
        root = root.display(),
    );
    let mut plan = SessionPlan::from_json(&text).unwrap();
    change(&mut plan);
    plan.write_atomic(&paths.plan()).unwrap();
}

/// The copy of the configuration an entry writes into `paths`.
fn record_settings(paths: &Paths, config: &Config) {
    std::fs::write(
        paths.runtime().join(CONFIG_COPY_NAME),
        toml::to_string(config).unwrap(),
    )
    .unwrap();
}

/// The settings an activation from the volume at `root` copies.
fn settings_of(root: &Path) -> Config {
    Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        ..Config::default()
    }
}

/// The decoy's mount table: `/` and nothing at `/run/nextroot`.
fn decoy_table() -> Vec<crate::filesystem::MountEntry> {
    crate::filesystem::parse_mountinfo("1 0 8:1 / / rw - ext4 /dev/vda1 rw\n")
}

/// Clears the cancel this thread asked for, however the test ends.
struct Cancel;

impl Cancel {
    fn request() -> Self {
        crate::cancel::testing::request();
        Self
    }
}

impl Drop for Cancel {
    fn drop(&mut self) {
        crate::cancel::testing::reset();
    }
}

/// The names in `dir`.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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
        session: None,
    };
    assert!(matches!(apply_with(&other, &plan), Err(Failure::Stale(_))));
}

/// A window holds back the keys of the wire crate's session list while a
/// session runs: they are exactly the keys this guard keeps, and another
/// key changes as before.
#[test]
fn the_keys_a_window_holds_back_in_a_session_are_the_ones_the_guard_keeps() {
    let (_dir, config, mut gate) = volume();
    let root = gate.root.display().to_string();
    gate.session = Some(Session {
        running: true,
        hidden_root: Some(gate.root.clone()),
        state_file: Some(gate.root.join("state.json")),
    });
    std::fs::write(
        &config,
        format!("hidden_volume_root = {root:?}\nstate_file_path = \"{root}/state.json\"\n"),
    )
    .unwrap();
    let moved = |key: &str| -> String {
        match key {
            "hidden_volume_root" => gate.root.parent().unwrap().display().to_string(),
            _ => format!("{root}/elsewhere"),
        }
    };
    let mut guarded = Vec::new();
    for setting in SETTINGS.iter().filter(|setting| setting.kind == Kind::Path) {
        let failure = edit_with(
            &gate,
            Some(&config),
            &[set(setting.key, string(&moved(setting.key)))],
        )
        .err();
        if let Some(Failure::SessionPaths(key)) = failure {
            assert_eq!(key, setting.key);
            guarded.push(key);
        }
    }
    assert_eq!(guarded, nails_api::settings::SESSION_KEYS);
}

#[test]
fn a_hidden_session_keeps_its_root_and_state_file() {
    let (_dir, config, mut gate) = volume();
    let root = gate.root.display().to_string();
    gate.session = Some(Session {
        running: true,
        hidden_root: Some(gate.root.clone()),
        state_file: Some(gate.root.join("state.json")),
    });
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
    assert!(
        failure
            .message()
            .contains("Make this change on another machine, with the hidden volume mounted there."),
        "{}",
        failure.message()
    );
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

    // The default the file falls back to is where the session keeps its state.
    let applied = edit_with(&gate, Some(&config), &[Edit::Unset(key("state_file_path"))]).unwrap();
    assert!(applied.in_session);
    edit_with(
        &gate,
        Some(&config),
        &[set("persona.mode", string("fresh-home"))],
    )
    .unwrap();
    assert!(!read(&config).contains("state_file_path"));

    // Outside a session the same change is the operator's to make.
    gate.session = None;
    let applied = edit_with(
        &gate,
        Some(&config),
        &[set("state_file_path", string(&moved))],
    )
    .unwrap();
    assert!(!applied.in_session);
}

/// An activation on the decoy records both paths before the switch. From then
/// on, while it is entering and once it was left behind, neither moves away
/// from them, and a file that moved them anyway can be put back.
#[test]
fn an_entry_on_the_decoy_keeps_the_paths_it_recorded_and_a_moved_file_can_be_put_back() {
    let (dir, config, mut gate) = volume();
    let paths = machine(dir.path());
    let root = gate.root.clone();
    let shown = root.display().to_string();
    record_settings(&paths, &settings_of(&root));
    let me = std::process::id();
    let start_time = nails_teardown::proc::stat(me).unwrap().start_time;
    record_plan(&paths, &root, |plan| {
        plan.owner = Some(nails_teardown::whole_root::plan::Owner {
            pid: me,
            start_time,
        });
        plan.armed = Some(nails_teardown::whole_root::plan::Arm::now(
            nails_teardown::whole_root::plan::Direction::Enter,
        ));
    });
    let view = crate::session::probe::probe_with(&paths, &root, &decoy_table());
    assert!(matches!(view, SessionView::Entering(_)), "{view:?}");
    gate.session = Session::of(&view, &paths);
    assert_eq!(
        gate.session,
        Some(Session {
            running: false,
            hidden_root: Some(root.clone()),
            state_file: Some(root.join("state.json")),
        })
    );

    // The file names the root: without it the default would be the test
    // binary's directory.
    let named = format!("hidden_volume_root = {shown:?}\n");
    std::fs::write(&config, &named).unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("hidden_volume_root", string(&format!("{shown}/x")))],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("hidden_volume_root")),
        "{failure:?}"
    );
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("state_file_path", string(&format!("{shown}/x.json")))],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("state_file_path")),
        "{failure:?}"
    );
    assert_eq!(read(&config), named);

    // A file moved anyway, by hand: another change leaves it as it is, and
    // setting the recorded root again puts the way back right.
    std::fs::write(&config, format!("hidden_volume_root = \"{shown}/x\"\n")).unwrap();
    edit_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(600))],
    )
    .unwrap();
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("hidden_volume_root", string(&format!("{shown}/y")))],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("hidden_volume_root")),
        "{failure:?}"
    );
    let applied = edit_with(
        &gate,
        Some(&config),
        &[set("hidden_volume_root", string(&shown))],
    )
    .unwrap();
    assert!(applied.written);
    assert!(!applied.in_session, "the entry has not switched yet");
    assert_eq!(
        read(&config),
        format!("hidden_volume_root = {shown:?}\nminimum_space_mb = 600\n")
    );

    // No owner and no arming: an interrupted entry, which `recover` reads
    // from the same places.
    record_plan(&paths, &root, |_| {});
    let view = crate::session::probe::probe_with(&paths, &root, &decoy_table());
    assert!(matches!(view, SessionView::Interrupted { .. }), "{view:?}");
    gate.session = Session::of(&view, &paths);
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set("state_file_path", string(&format!("{shown}/x.json")))],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("state_file_path")),
        "{failure:?}"
    );

    // With nothing in `/run` the machine is the plain decoy.
    std::fs::remove_file(paths.plan()).unwrap();
    std::fs::remove_file(paths.runtime().join(CONFIG_COPY_NAME)).unwrap();
    let view = crate::session::probe::probe_with(&paths, &root, &decoy_table());
    assert_eq!(view, SessionView::Decoy);
    assert_eq!(Session::of(&view, &paths), None);
}

/// The engine's own gate, on a machine whose `/` is the hidden overlay and
/// whose `/run` holds the session's plan, finds the session and keeps its
/// state file in place.
#[test]
fn the_engine_gate_finds_the_hidden_session_and_keeps_its_state_file() {
    struct Engine {
        fs: MockFilesystem,
        paths: Paths,
        root: PathBuf,
    }

    impl Gate for Engine {
        fn admit(&self, path: &Path) -> Result<Target, Failure> {
            admit(&self.fs, &self.paths, &self.root, path)
        }
    }

    let (dir, config, Beneath { root, .. }) = volume();
    let paths = machine(dir.path());
    std::fs::write(root.join("state.json"), "{}").unwrap();
    // The file names the root: without it the default would be the test
    // binary's directory, which the state file must lie in.
    let named = format!("hidden_volume_root = {:?}\n", root.display().to_string());
    std::fs::write(&config, format!("{named}minimum_space_mb = 750\n")).unwrap();
    record_plan(&paths, &root, |_| {});

    // The attach gate reads the mock. The file is read and written for real,
    // on the mount the mock gives the ID the kernel gives the volume's root.
    let id = rustix::fs::statx(
        rustix::fs::CWD,
        &root,
        rustix::fs::AtFlags::empty(),
        rustix::fs::StatxFlags::MNT_ID,
    )
    .unwrap()
    .stx_mnt_id;
    let overlay = if id == 7 { 8 } else { 7 };
    let shown = root.display().to_string();
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(&shown, true);
    fs.mock_set_path_exists(&format!("{shown}/state.json"), true);
    fs.mock_set_device_id(Path::new("/"), 1);
    fs.mock_set_device_id(&root, 42);
    fs.mock_set_mount_table(&format!(
        "{overlay} 0 0:30 / / rw - overlay overlay rw,lowerdir=/run/lower,\
         upperdir={shown}/root/upper,workdir={shown}/root/work\n\
         {id} {overlay} 253:0 / {shown} rw - ext4 /dev/mapper/data rw\n"
    ));
    let plan = nails_teardown::whole_root::plan::default_plan_path();
    fs.mock_set_file_content(
        plan.to_str().unwrap(),
        &std::fs::read_to_string(paths.plan()).unwrap(),
    );
    let gate = Engine { fs, paths, root };

    let target = gate.admit(&config).unwrap();
    assert_eq!(target.mount_id, Some(id));
    assert_eq!(
        target.session,
        Some(Session {
            running: true,
            hidden_root: Some(gate.root.clone()),
            state_file: None,
        })
    );
    let failure = edit_with(
        &gate,
        Some(&config),
        &[set(
            "state_file_path",
            string(&format!("{shown}/moved.json")),
        )],
    )
    .unwrap_err();
    assert!(
        matches!(failure, Failure::SessionPaths("state_file_path")),
        "{failure:?}"
    );
    assert_eq!(read(&config), format!("{named}minimum_space_mb = 750\n"));
    let applied = edit_with(
        &gate,
        Some(&config),
        &[set("minimum_space_mb", Value::Integer(800))],
    )
    .unwrap();
    assert!(applied.in_session);
    assert_eq!(read(&config), format!("{named}minimum_space_mb = 800\n"));
}

#[test]
fn a_cancel_stops_an_edit_before_the_file_is_replaced() {
    let (_dir, config, gate) = volume();
    std::fs::write(&config, "minimum_space_mb = 750\n").unwrap();
    let edits = [set("minimum_space_mb", Value::Integer(800))];
    let plan = plan_with(&gate, Some(&config), &edits).unwrap();
    {
        let _cancel = Cancel::request();
        for failure in [
            edit_with(&gate, Some(&config), &edits).unwrap_err(),
            apply_with(&gate, &plan).unwrap_err(),
        ] {
            assert!(matches!(failure, Failure::Cancelled), "{failure:?}");
            assert_eq!(failure.code(), "cancelled");
            assert_eq!(failure.exit_status(), ExitStatus::Cancelled);
            assert_eq!(failure.message(), crate::catalog::CANCEL_CONFIG.text);
        }
    }
    assert_eq!(read(&config), "minimum_space_mb = 750\n");
    assert_eq!(names(&gate.root.join("config")), vec!["nails.toml"]);
    apply_with(&gate, &plan).unwrap();
    assert_eq!(read(&config), "minimum_space_mb = 800\n");
}

#[test]
fn a_folder_that_is_no_volume_of_its_own_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("config")).unwrap();
    std::fs::write(root.join("state.json"), "{}").unwrap();
    let path = root.join("config/nails.toml");
    let failure = admit(&RealFilesystem, &machine(dir.path()), &root, &path).unwrap_err();
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
        (Failure::Cancelled, "cancelled", ExitStatus::Cancelled),
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
    /// binary's directory, on a machine with nothing in its `/run`.
    struct At(PathBuf, Paths);

    impl Gate for At {
        fn admit(&self, path: &Path) -> Result<Target, Failure> {
            admit(&RealFilesystem, &self.1, &self.0, path)
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
            let run = tempfile::tempdir().unwrap();
            let gate = At(root.clone(), machine(run.path()));
            let edit = [set("persona.mode", string("fresh-home"))];

            // No layout yet.
            let failure = edit_with(&gate, Some(&config), &edit).unwrap_err();
            assert!(matches!(failure, Failure::NoLayout(_)), "{failure:?}");
            assert!(!config.exists());

            std::fs::write(root.join("state.json"), "{}").unwrap();
            let target = gate.admit(&config).unwrap();
            assert!(target.mount_id.is_some());
            assert_eq!(target.session, None);
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
