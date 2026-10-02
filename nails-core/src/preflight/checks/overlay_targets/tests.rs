//! Tests for the overlay target safety floor.

use super::*;
use crate::config::{LOAD_BEARING_DIRECTORIES, OverlayConfig};
use crate::filesystem::MockFilesystem;

const MEDIA_ROOT: &str = "/media/veracrypt1";

fn root_dirs(fs: &MockFilesystem, dirs: &[&str]) {
    fs.mock_set_root_directories(dirs.iter().map(PathBuf::from).collect());
}

fn config_with_root(root: &str) -> Config {
    let root = PathBuf::from(root);
    Config {
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        hidden_volume_root: root,
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    }
}

fn explicit(config: Config, targets: &[&str]) -> Config {
    let root = config.hidden_volume_root.clone();
    let overlays = targets
        .iter()
        .map(|target| {
            let name = Path::new(target)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            OverlayConfig {
                upper: root.join(&name),
                work: root.join(".work").join(&name),
                name,
                lower: PathBuf::from(target),
                target: PathBuf::from(target),
            }
        })
        .collect();
    Config {
        overlay_mode: OverlayMode::Explicit,
        overlays,
        ..config
    }
}

fn run(config: Config, binary: Option<&str>, fs: &MockFilesystem) -> CheckResult {
    OverlayTargetsCheck::with_binary(config, binary.map(PathBuf::from))
        .run(fs)
        .expect("check runs")
}

#[test]
fn metadata() {
    let check = OverlayTargetsCheck::with_binary(Config::default(), None);
    assert_eq!(
        <OverlayTargetsCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "overlay-targets"
    );
    assert!(
        !<OverlayTargetsCheck as PreFlightCheck<MockFilesystem>>::description(&check).is_empty()
    );
}

#[test]
fn hidden_root_under_mnt_passes_in_auto_mode() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/etc", "/home", "/media", "/mnt", "/var"]);

    let result = run(config_with_root("/mnt/hv"), None, &fs);

    assert!(result.is_pass(), "{}", result.message());
    assert!(result.message().starts_with("4 overlay target(s)"));
}

#[test]
fn hidden_root_under_media_is_refused_in_auto_mode() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/etc", "/home", "/media", "/mnt"]);

    let result = run(config_with_root(MEDIA_ROOT), None, &fs);

    assert!(result.is_fail());
    assert_eq!(
        result.message(),
        "hidden root /media/veracrypt1 is under overlay target /media; mount it under \
         /mnt or /run/media, or add /media to overlay_exclusions"
    );
}

#[test]
fn excluding_media_keeps_a_hidden_root_there_visible() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/etc", "/home", "/media", "/mnt"]);
    let mut config = config_with_root(MEDIA_ROOT);
    config.overlay_exclusions = vec![PathBuf::from("/media")];

    let result = run(config, None, &fs);

    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn explicit_target_above_the_state_file_is_refused() {
    let fs = MockFilesystem::new();
    let mut config = explicit(config_with_root("/mnt/hv"), &["/home", "/mnt/hv/data"]);
    config.state_file_path = PathBuf::from("/mnt/hv/data/state.json");

    let result = run(config, None, &fs);

    assert!(result.is_fail());
    assert_eq!(
        result.message(),
        "state file /mnt/hv/data/state.json is under overlay target /mnt/hv/data; \
         set state_file_path outside it, or remove the /mnt/hv/data overlay"
    );
}

#[test]
fn explicit_target_equal_to_the_log_directory_is_refused() {
    let fs = MockFilesystem::new();
    let config = explicit(config_with_root("/mnt/hv"), &["/mnt/hv/logs"]);

    let result = run(config, None, &fs);

    assert!(result.is_fail());
    assert!(
        result
            .message()
            .starts_with("log directory /mnt/hv/logs is under overlay target /mnt/hv/logs"),
        "{}",
        result.message()
    );
}

#[test]
fn symlinked_hidden_root_is_caught_after_resolution() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/etc", "/home", "/media", "/mnt"]);
    fs.create_symlink(Path::new(MEDIA_ROOT), Path::new("/mnt/hv"))
        .unwrap();

    let result = run(config_with_root("/mnt/hv"), None, &fs);

    assert!(result.is_fail());
    assert!(
        result.message().starts_with(
            "hidden root /mnt/hv (resolves to /media/veracrypt1) is under overlay target /media;"
        ),
        "{}",
        result.message()
    );
}

#[test]
fn symlinked_explicit_target_is_resolved_too() {
    let fs = MockFilesystem::new();
    fs.create_symlink(Path::new("/mnt"), Path::new("/data"))
        .unwrap();
    let config = explicit(config_with_root("/mnt/hv"), &["/data"]);

    let result = run(config, None, &fs);

    assert!(result.is_fail());
    assert!(
        result
            .message()
            .contains("under overlay target /data (resolves to /mnt); "),
        "{}",
        result.message()
    );
    assert!(result.message().ends_with("remove the /data overlay"));
}

#[test]
fn binary_on_another_filesystem_below_a_target_is_refused() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/home", "/media", "/mnt"]);
    let result = run(config_with_root("/mnt/hv"), Some("/media/usb/nails"), &fs);

    assert!(result.is_fail());
    assert_eq!(
        result.message(),
        "nails binary /media/usb/nails is under overlay target /media; run nails from \
         the hidden volume, or add /media to overlay_exclusions"
    );
}

#[test]
fn binary_on_the_target_filesystem_stays_visible() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/home", "/mnt", "/nix"]);
    let binary = "/nix/store/abc-nails/bin/nails";
    fs.mock_set_device_id(Path::new("/nix"), 7);
    fs.mock_set_device_id(Path::new(binary), 7);

    let result = run(config_with_root("/mnt/hv"), Some(binary), &fs);

    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn each_load_bearing_exclusion_fails_until_allowed() {
    for dir in LOAD_BEARING_DIRECTORIES {
        let fs = MockFilesystem::new();
        root_dirs(
            &fs,
            &[
                "/etc", "/home", "/mnt", "/nix", "/opt", "/root", "/srv", "/var",
            ],
        );
        let mut config = config_with_root("/mnt/hv");
        config.overlay_exclusions = vec![PathBuf::from(dir)];

        let refused = run(config.clone(), None, &fs);
        assert!(refused.is_fail(), "{dir}");
        assert!(
            refused.message().starts_with(&format!(
                "overlay_exclusions leaves {dir} on the decoy disk"
            )),
            "{}",
            refused.message()
        );

        config.allow_leaky_exclusions = vec![PathBuf::from(dir)];
        let accepted = run(config, None, &fs);
        assert!(accepted.is_warn(), "{dir}: {}", accepted.message());
        assert!(accepted.message().contains(dir));
    }
}

#[test]
fn tmpfs_tmp_may_be_excluded() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/home", "/mnt", "/tmp"]);
    fs.mock_set_filesystem_type(Path::new("/tmp"), "tmpfs");
    let mut config = config_with_root("/mnt/hv");
    config.overlay_exclusions = vec![PathBuf::from("/tmp")];

    let result = run(config, None, &fs);

    assert!(result.is_pass(), "{}", result.message());
}

#[test]
fn disk_backed_tmp_exclusion_is_refused_until_allowed() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/home", "/mnt", "/tmp"]);
    fs.mock_set_filesystem_type(Path::new("/tmp"), "ext4");
    let mut config = config_with_root("/mnt/hv");
    config.overlay_exclusions = vec![PathBuf::from("/tmp")];

    let refused = run(config.clone(), None, &fs);
    assert!(refused.is_fail());
    assert!(
        refused.message().contains("/tmp (not a tmpfs)"),
        "{}",
        refused.message()
    );

    config.allow_leaky_exclusions = vec![PathBuf::from("/tmp")];
    assert!(run(config, None, &fs).is_warn());
}

#[test]
fn covered_root_and_leaky_exclusion_are_both_reported() {
    let fs = MockFilesystem::new();
    root_dirs(&fs, &["/home", "/media", "/mnt"]);
    let mut config = config_with_root(MEDIA_ROOT);
    config.overlay_exclusions = vec![PathBuf::from("/home")];

    let result = run(config, None, &fs);

    assert!(result.is_fail());
    assert!(result.message().contains("overlay target /media"));
    assert!(result.message().contains("leaves /home on the decoy disk"));
}

#[test]
fn explicit_mode_ignores_exclusions() {
    let fs = MockFilesystem::new();
    let mut config = explicit(config_with_root("/mnt/hv"), &["/home"]);
    config.overlay_exclusions = vec![PathBuf::from("/var")];

    assert!(run(config, None, &fs).is_pass());
}

#[test]
fn ensure_targets_clear_refuses_a_covering_target() {
    let fs = MockFilesystem::new();
    let config = config_with_root(MEDIA_ROOT);

    let err = ensure_targets_clear(
        &fs,
        &config,
        &[PathBuf::from("/home"), PathBuf::from("/media")],
    )
    .unwrap_err();

    match err {
        NailsError::ConfigError(message) => assert!(
            message.starts_with("hidden root /media/veracrypt1 is under overlay target /media"),
            "{message}"
        ),
        other => panic!("expected ConfigError, got {other:?}"),
    }
    ensure_targets_clear(&fs, &config, &[PathBuf::from("/home")])
        .expect("a target beside the hidden root is fine");
}

#[test]
fn resolve_path_keeps_missing_components() {
    let fs = MockFilesystem::new();
    fs.create_symlink(Path::new(MEDIA_ROOT), Path::new("/mnt/hv"))
        .unwrap();

    assert_eq!(
        resolve_path(&fs, Path::new("/mnt/hv/logs/nails.log")).unwrap(),
        Path::new("/media/veracrypt1/logs/nails.log")
    );
}

#[test]
fn resolve_path_walks_up_past_missing_components_on_a_real_filesystem() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    std::fs::create_dir(base.join("real")).unwrap();
    std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();

    let resolved = resolve_path(
        &crate::RealFilesystem,
        &base.join("link/not-yet/state.json"),
    )
    .unwrap();

    assert_eq!(resolved, base.join("real/not-yet/state.json"));
}
