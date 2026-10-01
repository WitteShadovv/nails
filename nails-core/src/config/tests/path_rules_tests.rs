//! Tests for the rules every configured path must follow

use crate::config::{Config, ConfigBuilder, OverlayConfig, OverlayMode, PathProblem};
use crate::error::{NailsError, Result};
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::{NamedTempFile, TempDir};

/// The setting and rule an unsafe path was rejected for.
fn rejection(result: Result<Config>) -> (String, PathProblem) {
    match result {
        Err(NailsError::UnsafeConfigPath { key, problem, .. }) => (key, problem),
        other => panic!("expected UnsafeConfigPath, got {other:?}"),
    }
}

fn build_with_root(root: &str) -> Result<Config> {
    ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from(root))
        .build()
}

fn overlay(lower: &str, upper: &str, work: &str, target: &str) -> OverlayConfig {
    OverlayConfig {
        name: "home".to_string(),
        lower: PathBuf::from(lower),
        upper: PathBuf::from(upper),
        work: PathBuf::from(work),
        target: PathBuf::from(target),
    }
}

fn build_with_overlay(overlay: OverlayConfig) -> Result<Config> {
    ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hv"))
        .overlay_mode(OverlayMode::Explicit)
        .overlays(vec![overlay])
        .build()
}

/// A tempdir with every symlink resolved, so only links a test creates
/// itself can trip the symlink rule.
fn real_tempdir() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

fn load(contents: &str) -> (NamedTempFile, Result<Config>) {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    let result = Config::load(file.path());
    (file, result)
}

#[test]
fn relative_root_is_rejected() {
    let (key, problem) = rejection(build_with_root("mnt/hv"));

    assert_eq!(key, "hidden_volume_root");
    assert_eq!(problem, PathProblem::NotAbsolute);
}

#[test]
fn parent_dir_segment_in_root_is_rejected() {
    let (key, problem) = rejection(build_with_root("/mnt/hv/../../etc"));

    assert_eq!(key, "hidden_volume_root");
    assert_eq!(problem, PathProblem::NotNormalized);
}

#[test]
fn interior_current_dir_segment_is_rejected() {
    // `Path::components` drops this `.`, so it must be caught on the raw path.
    let (_, problem) = rejection(build_with_root("/mnt/./hv"));

    assert_eq!(problem, PathProblem::NotNormalized);
}

#[test]
fn parent_dir_segment_in_overlay_upper_is_rejected() {
    let result = build_with_overlay(overlay(
        "/home",
        "/mnt/hv/../../etc/home",
        "/mnt/hv/.work/home",
        "/home",
    ));
    let (key, problem) = rejection(result);

    assert_eq!(key, "overlays[0].upper");
    assert_eq!(problem, PathProblem::NotNormalized);
}

#[test]
fn symlinked_root_is_rejected() {
    let (_dir, base) = real_tempdir();
    std::fs::create_dir(base.join("volume")).unwrap();
    symlink(base.join("volume"), base.join("link")).unwrap();

    let (key, problem) = rejection(build_with_root(base.join("link").to_str().unwrap()));

    assert_eq!(key, "hidden_volume_root");
    assert_eq!(problem, PathProblem::Symlink(base.join("link")));
}

#[test]
fn root_below_a_symlinked_directory_is_rejected() {
    let (_dir, base) = real_tempdir();
    std::fs::create_dir_all(base.join("real/volume")).unwrap();
    symlink("real", base.join("link")).unwrap();

    let (_, problem) = rejection(build_with_root(base.join("link/volume").to_str().unwrap()));

    assert_eq!(problem, PathProblem::Symlink(base.join("link")));
}

#[test]
fn symlink_inside_the_root_is_rejected_for_hidden_data() {
    let (_dir, base) = real_tempdir();
    let outside = base.join("outside");
    std::fs::create_dir_all(base.join("volume")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, base.join("volume/state")).unwrap();

    let result = ConfigBuilder::new()
        .hidden_volume_root(base.join("volume"))
        .state_file_path(base.join("volume/state/state.json"))
        .build();
    let (key, problem) = rejection(result);

    assert_eq!(key, "state_file_path");
    assert_eq!(problem, PathProblem::Symlink(base.join("volume/state")));
}

#[test]
fn existing_real_root_with_missing_children_is_accepted() {
    let (_dir, base) = real_tempdir();

    let config = build_with_root(base.to_str().unwrap()).expect("real root must be accepted");

    assert_eq!(config.state_file_path, base.join("state.json"));
}

#[test]
fn comma_in_overlay_lower_is_rejected() {
    let result = build_with_overlay(overlay(
        "/home,upperdir=/tmp",
        "/mnt/hv/home",
        "/mnt/hv/.work/home",
        "/home",
    ));
    let (key, problem) = rejection(result);

    assert_eq!(key, "overlays[0].lower");
    assert_eq!(problem, PathProblem::ForbiddenCharacter(','));
}

#[test]
fn colon_in_overlay_work_is_rejected() {
    let result = build_with_overlay(overlay(
        "/home",
        "/mnt/hv/home",
        "/mnt/hv/.work:/home",
        "/home",
    ));
    let (key, problem) = rejection(result);

    assert_eq!(key, "overlays[0].work");
    assert_eq!(problem, PathProblem::ForbiddenCharacter(':'));
}

#[test]
fn colon_in_root_is_rejected_because_upper_dirs_derive_from_it() {
    let (key, problem) = rejection(build_with_root("/mnt/a:b"));

    assert_eq!(key, "hidden_volume_root");
    assert_eq!(problem, PathProblem::ForbiddenCharacter(':'));
}

#[test]
fn newline_in_an_exclusion_is_rejected() {
    let result = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hv"))
        .overlay_exclusions(vec![PathBuf::from("/srv"), PathBuf::from("/opt\n/etc")])
        .build();
    let (key, problem) = rejection(result);

    assert_eq!(key, "overlay_exclusions[1]");
    assert_eq!(problem, PathProblem::ForbiddenCharacter('\n'));
}

#[test]
fn relative_exclusion_removal_is_rejected() {
    let result = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hv"))
        .overlay_exclusions_remove(vec![PathBuf::from("mnt")])
        .build();
    let (key, problem) = rejection(result);

    assert_eq!(key, "overlay_exclusions_remove[0]");
    assert_eq!(problem, PathProblem::NotAbsolute);
}

#[test]
fn root_inside_an_overlay_target_is_rejected() {
    let result = build_with_overlay(overlay("/mnt", "/mnt/hv/mnt", "/mnt/hv/.work/mnt", "/mnt"));
    let (key, problem) = rejection(result);

    assert_eq!(key, "hidden_volume_root");
    assert_eq!(
        problem,
        PathProblem::InsideOverlayTarget(PathBuf::from("/mnt"))
    );
}

#[test]
fn filesystem_root_as_hidden_root_is_rejected() {
    let (_, problem) = rejection(build_with_root("/"));

    assert_eq!(problem, PathProblem::FilesystemRoot);
}

#[test]
fn hidden_data_outside_the_root_is_rejected() {
    let outside = PathProblem::OutsideHiddenRoot(PathBuf::from("/mnt/hv"));

    let state = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hv"))
        .state_file_path(PathBuf::from("/var/lib/nails/state.json"))
        .build();
    assert_eq!(
        rejection(state),
        ("state_file_path".into(), outside.clone())
    );

    // A sibling that shares the root as a text prefix is still outside.
    let log = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hv"))
        .log_path(PathBuf::from("/mnt/hv2/logs"))
        .build();
    assert_eq!(rejection(log), ("log_path".into(), outside.clone()));

    let upper = build_with_overlay(overlay("/home", "/home/.upper", "/mnt/hv/w", "/home"));
    assert_eq!(rejection(upper), ("overlays[0].upper".into(), outside));
}

#[test]
fn hidden_data_at_the_root_itself_is_rejected() {
    let result = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/mnt/hv"))
        .log_path(PathBuf::from("/mnt/hv"))
        .build();

    assert_eq!(
        rejection(result).1,
        PathProblem::OutsideHiddenRoot(PathBuf::from("/mnt/hv"))
    );
}

#[test]
fn paths_with_spaces_are_accepted() {
    // A space is escaped wherever it is used, unlike `,` and `:`.
    let config = ConfigBuilder::new()
        .hidden_volume_root(PathBuf::from("/media/user/My Volume"))
        .overlay_mode(OverlayMode::Explicit)
        .overlays(vec![overlay(
            "/srv/shared data",
            "/media/user/My Volume/shared data",
            "/media/user/My Volume/.work/shared data",
            "/srv/shared data",
        )])
        .build()
        .expect("spaces must be accepted");

    assert_eq!(
        config.log_path,
        Path::new("/media/user/My Volume").join("logs")
    );
}

#[test]
fn unsafe_path_in_a_file_is_rejected_naming_the_file() {
    let (file, result) = load("hidden_volume_root = \"../../etc\"\n");
    let err = result.unwrap_err();

    match &err {
        NailsError::UnsafeConfigPath { file: Some(f), .. } => assert_eq!(f, file.path()),
        other => panic!("expected UnsafeConfigPath with a file, got {other:?}"),
    }
    let message = err.to_string();
    assert!(
        message.starts_with(&format!("invalid config {}: ", file.path().display())),
        "{message}"
    );
    assert!(
        message.contains("hidden_volume_root = \"../../etc\": must be an absolute path"),
        "{message}"
    );
}

#[test]
fn derived_paths_in_a_file_follow_a_valid_root() {
    let (_file, result) = load("hidden_volume_root = \"/mnt/hv\"\n");
    let config = result.expect("valid root must load");

    assert_eq!(config.state_file_path, PathBuf::from("/mnt/hv/state.json"));
    assert_eq!(config.log_path, PathBuf::from("/mnt/hv/logs"));
}

#[test]
fn uninspectable_component_is_refused() {
    if nix::unistd::geteuid().is_root() {
        // root bypasses directory permissions, so nothing is uninspectable.
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let (_dir, base) = real_tempdir();
    let locked = base.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let result = build_with_root(locked.join("volume").to_str().unwrap());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        matches!(rejection(result).1, PathProblem::Uninspectable(_)),
        "a component that cannot be inspected must not be assumed safe"
    );
}
