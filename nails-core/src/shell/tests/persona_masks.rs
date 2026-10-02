use super::*;

use crate::config::{PersonaConfig, PersonaMode};
use crate::target_user::TargetUser;

fn mask_config(mask_inherited: Vec<String>) -> Config {
    Config {
        hidden_volume_root: "/mnt/data".into(),
        persona: PersonaConfig {
            mode: PersonaMode::SharedHome,
            mask_inherited,
        },
        ..Default::default()
    }
}

fn operator() -> TargetUser {
    TargetUser::for_test(1000, 1000, "testuser", "/home/testuser", "/bin/bash")
}

fn seed_user_autostart(fs: &MockFilesystem, stem: &str) {
    let dir = PathBuf::from("/home/testuser/.config/autostart");
    let entry = dir.join(format!("{stem}.desktop"));
    fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
    fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
}

fn seed_user_unit(fs: &MockFilesystem, unit: &str) {
    let dir = PathBuf::from("/home/testuser/.config/systemd/user");
    let wants = dir.join("default.target.wants");
    fs.mock_set_directory_contents(&dir, vec![wants.clone()]);
    fs.mock_set_directory_contents(&wants, vec![wants.join(unit)]);
}

#[test]
fn write_persona_masks_is_a_no_op_when_the_list_is_empty() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, "dropbox");

    let shell =
        ShellInstrumentation::new(fs.clone(), mask_config(vec![])).with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    assert_eq!(shell.write_persona_masks().unwrap(), 0);
    // No override was written.
    let override_path = PathBuf::from("/home/testuser/.config/autostart/dropbox.desktop");
    let written = fs.read_file_content(&override_path).unwrap();
    assert!(!written.contains("Hidden=true"));
}

#[test]
fn write_persona_masks_writes_override_and_unit_mask_through_the_merged_view() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, "dropbox");
    seed_user_unit(&fs, "syncthing.service");

    let config = mask_config(vec!["dropbox".to_string(), "syncthing.service".to_string()]);
    let shell = ShellInstrumentation::new(fs.clone(), config).with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    assert_eq!(shell.write_persona_masks().unwrap(), 2);

    let override_path = PathBuf::from("/home/testuser/.config/autostart/dropbox.desktop");
    let override_content = fs.read_file_content(&override_path).unwrap();
    assert!(override_content.contains("Hidden=true"));
    // The override is owned by the operator, not root.
    assert_eq!(fs.mock_get_owner(&override_path), Some((1000, 1000)));

    let unit_mask = PathBuf::from("/home/testuser/.config/systemd/user/syncthing.service");
    assert_eq!(
        fs.mock_get_symlink_target(&unit_mask),
        Some(PathBuf::from("/dev/null"))
    );
}

#[test]
fn write_persona_masks_skips_when_home_is_not_on_a_hidden_overlay() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, "dropbox");

    let shell = ShellInstrumentation::new(fs.clone(), mask_config(vec!["dropbox".to_string()]))
        .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_DECOY_DISK);

    assert_eq!(shell.write_persona_masks().unwrap(), 0);
    let override_path = PathBuf::from("/home/testuser/.config/autostart/dropbox.desktop");
    let written = fs.read_file_content(&override_path).unwrap();
    assert!(!written.contains("Hidden=true"));
}

#[test]
fn mask_all_sentinel_masks_every_maskable_entry_but_not_linger() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, "dropbox");
    seed_user_unit(&fs, "syncthing.service");
    fs.mock_set_path_exists("/var/lib/systemd/linger/testuser", true);

    let shell = ShellInstrumentation::new(fs.clone(), mask_config(vec!["*".to_string()]))
        .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    // Autostart + unit are masked; lingering is reported but never masked.
    assert_eq!(shell.write_persona_masks().unwrap(), 2);
}

#[test]
fn write_persona_masks_ignores_names_that_are_not_inherited() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, "dropbox");

    let shell = ShellInstrumentation::new(fs.clone(), mask_config(vec!["telegram".to_string()]))
        .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    // The configured name is not in the inventory, so nothing is masked.
    assert_eq!(shell.write_persona_masks().unwrap(), 0);
}

#[test]
fn an_autostart_mask_write_failure_is_not_counted() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, "dropbox");
    fs.mock_set_write_should_fail("/home/testuser/.config/autostart/dropbox.desktop", true);

    let shell = ShellInstrumentation::new(fs.clone(), mask_config(vec!["dropbox".to_string()]))
        .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    assert_eq!(shell.write_persona_masks().unwrap(), 0);
}

#[test]
fn a_unit_mask_replaces_an_existing_entry_at_the_path() {
    let fs = MockFilesystem::new();
    seed_user_unit(&fs, "syncthing.service");
    // An inherited entry already shows through the merged view at the mask path.
    let link = "/home/testuser/.config/systemd/user/syncthing.service";
    fs.mock_set_path_exists(link, true);
    fs.mock_set_path_exists("/home/testuser/.config/systemd/user", true);

    let shell = ShellInstrumentation::new(
        fs.clone(),
        mask_config(vec!["syncthing.service".to_string()]),
    )
    .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    assert_eq!(shell.write_persona_masks().unwrap(), 1);
    assert_eq!(
        fs.mock_get_symlink_target(&PathBuf::from(link)),
        Some(PathBuf::from("/dev/null"))
    );
}

#[test]
fn a_unit_mask_is_not_counted_when_the_unit_directory_cannot_be_created() {
    let fs = MockFilesystem::new();
    // The inventory sees the enabled unit through the listed .wants directory ...
    let user_dir = PathBuf::from("/home/testuser/.config/systemd/user");
    let wants = user_dir.join("default.target.wants");
    fs.mock_set_directory_contents(&user_dir, vec![wants.clone()]);
    fs.mock_set_directory_contents(&wants, vec![wants.join("syncthing.service")]);
    // ... but the user unit directory does not exist and cannot be created,
    // because its parent is present and not writable.
    fs.mock_set_path_exists("/home/testuser/.config", true);
    fs.mock_set_writable("/home/testuser/.config", false);

    let shell = ShellInstrumentation::new(
        fs.clone(),
        mask_config(vec!["syncthing.service".to_string()]),
    )
    .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    assert_eq!(shell.write_persona_masks().unwrap(), 0);
}

#[test]
fn a_unit_mask_that_cannot_be_written_is_not_counted() {
    let fs = MockFilesystem::new();
    seed_user_unit(&fs, "syncthing.service");
    // A plain file already occupies the mask path and cannot be removed, so the
    // symlink creation fails and the entry is reported as not masked.
    let link = "/home/testuser/.config/systemd/user/syncthing.service";
    fs.mock_set_path_exists(link, true);
    fs.mock_set_path_exists("/home/testuser/.config/systemd/user", true);
    fs.mock_set_remove_should_fail(link, true);

    let shell = ShellInstrumentation::new(
        fs.clone(),
        mask_config(vec!["syncthing.service".to_string()]),
    )
    .with_target_user(operator());
    shell.set_mountinfo_override(HOME_ON_HIDDEN_OVERLAY);

    assert_eq!(shell.write_persona_masks().unwrap(), 0);
}
