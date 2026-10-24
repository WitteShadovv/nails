// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;
use std::path::PathBuf;

const USER: &str = "alice";
const HOME: &str = "/home/alice";

fn collect(fs: &MockFilesystem, fresh_home: bool) -> PersonaInventory {
    collect_inherited_persona(fs, Path::new(HOME), USER, fresh_home)
}

fn names_for(inventory: &PersonaInventory, source: InheritedSource) -> Vec<String> {
    inventory
        .entries
        .iter()
        .filter(|entry| entry.source == source)
        .map(|entry| entry.name.clone())
        .collect()
}

#[test]
fn empty_system_yields_empty_inventory() {
    let fs = MockFilesystem::new();
    assert!(collect(&fs, false).is_empty());
    assert_eq!(collect(&fs, false).len(), 0);
}

#[test]
fn lists_user_autostart_and_skips_hidden_and_own_entry() {
    let fs = MockFilesystem::new();
    let dir = PathBuf::from("/home/alice/.config/autostart");
    let dropbox = dir.join("dropbox.desktop");
    let hidden = dir.join("telegram.desktop");
    let own = dir.join("nails-notify.desktop");
    let editor = dir.join("editor.desktop");
    // A non-.desktop file in the directory must be ignored.
    let readme = dir.join("README");
    fs.mock_set_directory_contents(
        &dir,
        vec![
            dropbox.clone(),
            hidden.clone(),
            own.clone(),
            editor.clone(),
            readme.clone(),
        ],
    );
    fs.mock_set_file_content(dropbox.to_str().unwrap(), "[Desktop Entry]\nName=Dropbox\n");
    fs.mock_set_file_content(
        hidden.to_str().unwrap(),
        "[Desktop Entry]\nName=Telegram\nHidden=true\n",
    );
    fs.mock_set_file_content(own.to_str().unwrap(), "[Desktop Entry]\nName=Notify\n");
    fs.mock_set_file_content(editor.to_str().unwrap(), "[Desktop Entry]\nName=Editor\n");
    fs.mock_set_file_content(readme.to_str().unwrap(), "not a desktop entry\n");

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::UserAutostart),
        vec!["dropbox".to_string(), "editor".to_string()]
    );
    // Telegram (remote-linked) is hidden and skipped; the own notify entry is
    // skipped too, so only the visible Dropbox entry is tagged remote-linked.
    assert_eq!(inventory.remote_linked_names(), vec!["dropbox".to_string()]);
}

#[test]
fn remote_client_names_are_tagged() {
    let fs = MockFilesystem::new();
    let dir = PathBuf::from("/home/alice/.config/autostart");
    let sync = dir.join("nextcloud.desktop");
    let plain = dir.join("screenshot-tool.desktop");
    fs.mock_set_directory_contents(&dir, vec![sync.clone(), plain.clone()]);
    fs.mock_set_file_content(sync.to_str().unwrap(), "[Desktop Entry]\n");
    fs.mock_set_file_content(plain.to_str().unwrap(), "[Desktop Entry]\n");

    let inventory = collect(&fs, false);
    assert_eq!(
        inventory.remote_linked_names(),
        vec!["nextcloud".to_string()]
    );
    let plain_entry = inventory
        .entries
        .iter()
        .find(|entry| entry.name == "screenshot-tool")
        .unwrap();
    assert!(!plain_entry.remote_linked);
}

#[test]
fn lists_global_autostart() {
    let fs = MockFilesystem::new();
    let dir = PathBuf::from("/etc/xdg/autostart");
    let entry = dir.join("syncthing.desktop");
    fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
    fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec!["syncthing".to_string()]
    );
    assert_eq!(
        inventory.remote_linked_names(),
        vec!["syncthing".to_string()]
    );
}

#[test]
fn lists_user_and_global_wants_units() {
    let fs = MockFilesystem::new();
    let user_dir = PathBuf::from("/home/alice/.config/systemd/user");
    let user_wants = user_dir.join("default.target.wants");
    fs.mock_set_directory_contents(&user_dir, vec![user_wants.clone()]);
    fs.mock_set_directory_contents(&user_wants, vec![user_wants.join("syncthing.service")]);

    let global_dir = PathBuf::from("/etc/systemd/user");
    let global_wants = global_dir.join("timers.target.wants");
    fs.mock_set_directory_contents(&global_dir, vec![global_wants.clone()]);
    fs.mock_set_directory_contents(&global_wants, vec![global_wants.join("backup.timer")]);

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::UserUnit),
        vec!["syncthing.service".to_string()]
    );
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalUnit),
        vec!["backup.timer".to_string()]
    );
}

#[test]
fn ignores_non_wants_directories_in_systemd_user() {
    let fs = MockFilesystem::new();
    let user_dir = PathBuf::from("/home/alice/.config/systemd/user");
    // A plain unit file dropped in the directory is not an enabled unit.
    fs.mock_set_directory_contents(&user_dir, vec![user_dir.join("custom.service")]);

    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::UserUnit).is_empty());
}

#[test]
fn reports_linger_when_present() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Linger),
        vec!["alice".to_string()]
    );
}

#[test]
fn no_linger_entry_when_absent() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", false);

    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Linger).is_empty());
}

#[test]
fn reports_gdm_autologin() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/gdm3/custom.conf",
        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
    );

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["bob".to_string()]
    );
}

#[test]
fn reports_gdm_autologin_from_debians_daemon_conf() {
    // Debian's gdm3 reads /etc/gdm3/daemon.conf, which ships with the
    // settings commented out.
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/gdm3/daemon.conf",
        "[daemon]\n#  AutomaticLoginEnable = true\n#  AutomaticLogin = user1\n\
         AutomaticLoginEnable = true\nAutomaticLogin = carol\n",
    );

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["carol".to_string()]
    );

    fs.mock_set_file_content(
        "/etc/gdm3/daemon.conf",
        "[daemon]\n#  AutomaticLoginEnable = true\n#  AutomaticLogin = user1\n",
    );
    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
}

#[test]
fn ignores_gdm_when_autologin_disabled() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/gdm/custom.conf",
        "[daemon]\nAutomaticLoginEnable=false\nAutomaticLogin=bob\n",
    );

    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
}

#[test]
fn gdm_autologin_enabled_without_named_user_falls_back_to_operator() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/gdm/custom.conf",
        "[daemon]\nAutomaticLoginEnable=true\n",
    );

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["alice".to_string()]
    );
}

#[test]
fn reports_sddm_autologin_from_conf_d() {
    let fs = MockFilesystem::new();
    // The main file, which SDDM reads last, does not set the user, so the
    // drop-in's stands.
    fs.mock_set_file_content("/etc/sddm.conf", "[General]\nNumlock=on\n");
    let dir = PathBuf::from("/etc/sddm.conf.d");
    let drop_in = dir.join("10-autologin.conf");
    let note = dir.join("notes.txt");
    fs.mock_set_directory_contents(&dir, vec![drop_in.clone(), note.clone()]);
    fs.mock_set_file_content(drop_in.to_str().unwrap(), "[Autologin]\nUser=carol\n");
    fs.mock_set_file_content(note.to_str().unwrap(), "no setting in here\n");

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["carol".to_string()]
    );

    // An empty user there turns autologin off.
    fs.mock_set_file_content("/etc/sddm.conf", "[Autologin]\nUser=\n");
    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
}

#[test]
fn sddm_without_autologin_user_reports_nothing() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content("/etc/sddm.conf", "[General]\nNumlock=on\n");

    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
}

#[test]
fn reports_lightdm_autologin() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/lightdm/lightdm.conf",
        "[Seat:*]\nautologin-user=dave\n",
    );

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["dave".to_string()]
    );
}

#[test]
fn reports_lightdm_autologin_from_conf_d_unless_the_main_file_empties_it() {
    let fs = MockFilesystem::new();
    // The main file, which LightDM reads last, does not set the user.
    fs.mock_set_file_content("/etc/lightdm/lightdm.conf", "[Seat:*]\n#autologin-user=\n");
    let dir = PathBuf::from("/etc/lightdm/lightdm.conf.d");
    let drop_in = dir.join("50-autologin.conf");
    fs.mock_set_directory_contents(&dir, vec![drop_in.clone()]);
    fs.mock_set_file_content(drop_in.to_str().unwrap(), "[Seat:*]\nautologin-user=erin\n");

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["erin".to_string()]
    );

    fs.mock_set_file_content("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=\n");
    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Autologin).is_empty());
}

#[test]
fn fresh_home_drops_user_level_sources_only() {
    let fs = MockFilesystem::new();

    // User-level sources that fresh-home must drop.
    let user_autostart = PathBuf::from("/home/alice/.config/autostart");
    let user_entry = user_autostart.join("dropbox.desktop");
    fs.mock_set_directory_contents(&user_autostart, vec![user_entry.clone()]);
    fs.mock_set_file_content(user_entry.to_str().unwrap(), "[Desktop Entry]\n");

    let user_units = PathBuf::from("/home/alice/.config/systemd/user");
    let user_wants = user_units.join("default.target.wants");
    fs.mock_set_directory_contents(&user_units, vec![user_wants.clone()]);
    fs.mock_set_directory_contents(&user_wants, vec![user_wants.join("syncthing.service")]);

    // System-level sources that must survive.
    let global_autostart = PathBuf::from("/etc/xdg/autostart");
    let global_entry = global_autostart.join("evolution.desktop");
    fs.mock_set_directory_contents(&global_autostart, vec![global_entry.clone()]);
    fs.mock_set_file_content(global_entry.to_str().unwrap(), "[Desktop Entry]\n");
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

    let inventory = collect(&fs, true);
    assert!(names_for(&inventory, InheritedSource::UserAutostart).is_empty());
    assert!(names_for(&inventory, InheritedSource::UserUnit).is_empty());
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec!["evolution".to_string()]
    );
    assert_eq!(
        names_for(&inventory, InheritedSource::Linger),
        vec!["alice".to_string()]
    );
}

#[test]
fn maskable_covers_autostart_and_units_only() {
    let fs = MockFilesystem::new();
    let autostart = PathBuf::from("/home/alice/.config/autostart");
    let entry = autostart.join("dropbox.desktop");
    fs.mock_set_directory_contents(&autostart, vec![entry.clone()]);
    fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

    let inventory = collect(&fs, false);
    let maskable: Vec<&str> = inventory
        .maskable()
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(maskable, vec!["dropbox"]);
}

#[test]
fn source_metadata_is_stable() {
    assert_eq!(InheritedSource::UserAutostart.as_str(), "user-autostart");
    assert_eq!(
        InheritedSource::GlobalAutostart.as_str(),
        "global-autostart"
    );
    assert_eq!(InheritedSource::UserUnit.as_str(), "user-unit");
    assert_eq!(InheritedSource::GlobalUnit.as_str(), "global-unit");
    assert_eq!(InheritedSource::Linger.as_str(), "linger");
    assert_eq!(InheritedSource::Autologin.as_str(), "autologin");

    assert!(InheritedSource::UserAutostart.is_user_level());
    assert!(InheritedSource::UserUnit.is_user_level());
    assert!(!InheritedSource::GlobalAutostart.is_user_level());
    assert!(!InheritedSource::Linger.is_user_level());

    assert!(InheritedSource::GlobalAutostart.is_autostart());
    assert!(InheritedSource::GlobalUnit.is_unit());
    assert!(!InheritedSource::Linger.is_maskable());
    assert!(!InheritedSource::Autologin.is_maskable());
}

#[test]
fn empty_user_skips_linger_lookup() {
    let fs = MockFilesystem::new();
    // With no resolved operator the linger file cannot be named, so no
    // lookup is attempted and nothing is reported.
    let inventory = collect_inherited_persona(&fs, Path::new(HOME), "", false);
    assert!(names_for(&inventory, InheritedSource::Linger).is_empty());
}

#[test]
fn system_entries_know_whether_the_desktop_ships_them() {
    let fs = MockFilesystem::new();
    let global = PathBuf::from("/etc/xdg/autostart");
    let keyring = global.join("gnome-keyring-secrets.desktop");
    let portmaster = global.join("portmaster.desktop");
    fs.mock_set_directory_contents(&global, vec![keyring.clone(), portmaster.clone()]);
    fs.mock_set_file_content(keyring.to_str().unwrap(), "[Desktop Entry]\n");
    fs.mock_set_file_content(portmaster.to_str().unwrap(), "[Desktop Entry]\n");
    // The same desktop component's name in the home is the user's own copy.
    let user = PathBuf::from("/home/alice/.config/systemd/user");
    let wants = user.join("default.target.wants");
    fs.mock_set_directory_contents(&user, vec![wants.clone()]);
    fs.mock_set_directory_contents(&wants, vec![wants.join("pipewire.service")]);

    let inventory = collect(&fs, false);
    let desktop = |name: &str| {
        inventory
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .unwrap()
            .desktop
    };
    assert!(desktop("gnome-keyring-secrets"));
    assert!(!desktop("portmaster"));
    assert!(!desktop("pipewire.service"));
}

#[test]
fn a_nixos_decoy_lists_the_autostart_entries_of_its_system_profile() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/run/current-system", true);
    let sw = PathBuf::from("/run/current-system/sw/etc/xdg/autostart");
    let entries: Vec<PathBuf> = ["at-spi-dbus-bus", "gnome-keyring-pkcs11", "portmaster"]
        .iter()
        .map(|name| sw.join(format!("{name}.desktop")))
        .collect();
    fs.mock_set_directory_contents(&sw, entries.clone());
    for entry in &entries {
        fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
    }

    let inventory = collect(&fs, true);
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec![
            "at-spi-dbus-bus".to_string(),
            "gnome-keyring-pkcs11".to_string(),
            "portmaster".to_string(),
        ]
    );
}

#[test]
fn a_user_override_that_hides_a_system_entry_counts_in_shared_home_only() {
    let fs = MockFilesystem::new();
    let global = PathBuf::from("/etc/xdg/autostart/tracker-miner-fs-3.desktop");
    fs.mock_set_directory_contents(Path::new("/etc/xdg/autostart"), vec![global.clone()]);
    fs.mock_set_file_content(global.to_str().unwrap(), "[Desktop Entry]\n");
    let user = PathBuf::from("/home/alice/.config/autostart/tracker-miner-fs-3.desktop");
    fs.mock_set_directory_contents(
        Path::new("/home/alice/.config/autostart"),
        vec![user.clone()],
    );
    fs.mock_set_file_content(user.to_str().unwrap(), "[Desktop Entry]\nHidden=true\n");

    assert!(collect(&fs, false).is_empty(), "hidden by the home");
    assert_eq!(
        names_for(&collect(&fs, true), InheritedSource::GlobalAutostart),
        vec!["tracker-miner-fs-3".to_string()],
        "the fresh home does not carry the override"
    );
}
