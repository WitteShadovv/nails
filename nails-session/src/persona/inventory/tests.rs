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
fn reports_plasma_login_manager_autologin() {
    let fs = MockFilesystem::new();
    let dir = PathBuf::from("/etc/plasmalogin.conf.d");
    let drop_in = dir.join("kde_settings.conf");
    fs.mock_set_directory_contents(&dir, vec![drop_in.clone()]);
    fs.mock_set_file_content(
        drop_in.to_str().unwrap(),
        "[Autologin]\nRelogin=false\nSession=plasma\nUser=frank\n",
    );

    let inventory = collect(&fs, true);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["frank".to_string()]
    );
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

/// The place of `inventory` not read at `path`.
fn not_read_at<'a>(inventory: &'a PersonaInventory, path: &str) -> Option<&'a NotRead> {
    inventory
        .not_read
        .iter()
        .find(|not_read| not_read.path == Path::new(path))
}

#[test]
fn a_place_that_cannot_be_looked_up_is_not_read_and_the_rest_is_read_on() {
    let fs = MockFilesystem::new();
    let dir = PathBuf::from("/etc/xdg/autostart");
    let entry = dir.join("syncthing.desktop");
    fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
    fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);
    fs.mock_set_lookup_error(
        "/var/lib/systemd/linger",
        std::io::ErrorKind::PermissionDenied,
    );

    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::Linger).is_empty());
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec!["syncthing".to_string()]
    );
    let linger = not_read_at(&inventory, "/var/lib/systemd/linger/alice").expect("not read");
    assert_eq!(
        linger.reason,
        "NAILS cannot look up /var/lib/systemd/linger/alice; run the command again with sudo"
    );
    assert_eq!(linger.automount_point, None);
    assert_eq!(linger.entry, None);
    assert_eq!(inventory.not_read.len(), 1, "{:?}", inventory.not_read);
    // A place that is not there is nothing, never one not read.
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/var/lib/systemd/linger", std::io::ErrorKind::NotFound);
    assert!(collect(&fs, false).not_read.is_empty());
}

/// A `/run/current-system` NAILS cannot look up counts as NixOS: the
/// profile directories are searched as well, and the marker is not read.
#[test]
fn a_nixos_marker_that_cannot_be_looked_up_counts_as_nixos() {
    let fs = MockFilesystem::new();
    let dir = PathBuf::from("/nix/var/nix/profiles/default/etc/xdg/autostart");
    let entry = dir.join("kdeconnect-indicator.desktop");
    fs.mock_set_directory_contents(&dir, vec![entry.clone()]);
    fs.mock_set_file_content(entry.to_str().unwrap(), "[Desktop Entry]\n");
    assert!(collect(&fs, false).is_empty(), "not NixOS: not searched");

    fs.mock_set_lookup_error("/run/current-system", std::io::ErrorKind::Other);
    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec!["kdeconnect-indicator".to_string()]
    );
    let marker = not_read_at(&inventory, "/run/current-system").expect("not read");
    assert!(
        marker
            .reason
            .starts_with("NAILS cannot look up /run/current-system ("),
        "{marker:?}"
    );
}

/// A file of a name NAILS cannot look up may decide the name: no file of it
/// further down the search path does, and the name is undecided.
#[test]
fn an_autostart_file_that_cannot_be_looked_up_leaves_its_name_undecided() {
    let fs = MockFilesystem::new();
    seed_entry(&fs, "/etc/xdg/autostart", "sync.desktop");
    seed_entry(&fs, "/home/alice/.config/autostart", "sync.desktop");
    seed_entry(&fs, "/home/alice/.config/autostart", "notes.desktop");
    fs.mock_set_lookup_error(
        "/home/alice/.config/autostart/sync.desktop",
        std::io::ErrorKind::Other,
    );

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::UserAutostart),
        vec!["notes".to_string()]
    );
    assert!(
        names_for(&inventory, InheritedSource::GlobalAutostart).is_empty(),
        "the file further down does not decide the name"
    );
    let file =
        not_read_at(&inventory, "/home/alice/.config/autostart/sync.desktop").expect("not read");
    assert_eq!(
        file.entry,
        Some(("sync".to_string(), InheritedSource::UserAutostart))
    );
    assert_eq!(
        inventory.undecided().collect::<Vec<_>>(),
        vec![("sync", InheritedSource::UserAutostart)]
    );
    // In fresh-home the home is not read, and the system's file decides.
    let fresh = collect(&fs, true);
    assert!(fresh.not_read.is_empty(), "{:?}", fresh.not_read);
    assert_eq!(
        names_for(&fresh, InheritedSource::GlobalAutostart),
        vec!["sync".to_string()]
    );
}

/// A display-manager file NAILS cannot look up is not read: the accounts
/// the other files name are still listed.
#[test]
fn a_display_manager_file_that_cannot_be_looked_up_is_not_read() {
    let fs = MockFilesystem::new();
    fs.mock_set_file_content(
        "/etc/gdm3/custom.conf",
        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
    );
    fs.mock_set_lookup_error("/etc/gdm3/custom.conf", std::io::ErrorKind::Other);
    fs.mock_set_file_content(
        "/etc/lightdm/lightdm.conf",
        "[Seat:*]\nautologin-user=dave\n",
    );
    let dir = PathBuf::from("/etc/sddm.conf.d");
    let drop_in = dir.join("10-autologin.conf");
    fs.mock_set_directory_contents(&dir, vec![drop_in.clone()]);
    fs.mock_set_file_content(drop_in.to_str().unwrap(), "[Autologin]\nUser=carol\n");
    fs.mock_set_lookup_error(drop_in.to_str().unwrap(), std::io::ErrorKind::Other);

    let inventory = collect(&fs, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::Autologin),
        vec!["dave".to_string()]
    );
    let paths: Vec<&Path> = inventory
        .not_read
        .iter()
        .map(|not_read| not_read.path.as_path())
        .collect();
    assert_eq!(
        paths,
        [Path::new("/etc/gdm3/custom.conf"), drop_in.as_path()],
        "{:?}",
        inventory.not_read
    );
}

/// A file seen to be a regular one whose read the automount guard then does
/// not make, where a point was set up after the lookup, is not read either:
/// a display manager's file is noted, and an autostart file leaves its name
/// undecided, as one that cannot be looked up does.
#[test]
fn a_file_whose_read_is_not_made_after_its_lookup_is_not_read() {
    use crate::filesystem::{MockFailure, MockLookup};
    let fs = MockFilesystem::new();
    let point = PathBuf::from("/usr/local");
    let gdm = Path::new("/etc/gdm3/custom.conf");
    fs.mock_set_file_content(
        gdm.to_str().unwrap(),
        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n",
    );
    fs.mock_fail_only(
        gdm,
        MockLookup::Read,
        MockFailure::NotLookedUp(point.clone()),
    );
    seed_entry(&fs, "/home/alice/.config/autostart", "sync.desktop");
    let sync = Path::new("/home/alice/.config/autostart/sync.desktop");
    fs.mock_fail_only(
        sync,
        MockLookup::Read,
        MockFailure::NotLookedUp(point.clone()),
    );

    let inventory = collect(&fs, false);
    assert!(
        names_for(&inventory, InheritedSource::Autologin).is_empty(),
        "{:?}",
        inventory.entries
    );
    let dm = not_read_at(&inventory, "/etc/gdm3/custom.conf").expect("not read");
    assert_eq!(dm.automount_point.as_ref(), Some(&point));
    assert_eq!(
        dm.reason,
        "NAILS does not look up /etc/gdm3/custom.conf, since the lookup would mount the \
         automount point /usr/local"
    );
    let file = not_read_at(&inventory, sync.to_str().unwrap()).expect("not read");
    assert_eq!(
        file.entry,
        Some(("sync".to_string(), InheritedSource::UserAutostart))
    );
    assert_eq!(
        inventory.undecided().collect::<Vec<_>>(),
        vec![("sync", InheritedSource::UserAutostart)]
    );
}

/// Through the automount guard, a home behind an automount point that
/// nothing is mounted on yet is not read: each place names the point, and
/// nothing at or below it is looked up.
#[test]
fn a_home_behind_an_automount_point_is_not_read_and_not_looked_up() {
    use crate::filesystem::automount::{Guarded, Snapshot};
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table(
        "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
         31 1 0:51 / /home/alice rw,relatime - autofs systemd-1 \
         rw,fd=1,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=1\n",
    );
    seed_entry(&fs, "/home/alice/.config/autostart", "dropbox.desktop");
    seed_entry(&fs, "/etc/xdg/autostart", "syncthing.desktop");
    fs.mock_clear_lookups();
    let guarded = Guarded::new(fs.clone(), &Snapshot::read(&fs, Path::new("/")));

    let inventory = collect_inherited_persona(&guarded, Path::new(HOME), USER, false);
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec!["syncthing".to_string()]
    );
    assert!(names_for(&inventory, InheritedSource::UserAutostart).is_empty());
    let autostart = not_read_at(&inventory, "/home/alice/.config/autostart").expect("not read");
    assert_eq!(
        autostart.reason,
        "NAILS does not look up /home/alice/.config/autostart, since the lookup would mount the \
         automount point /home/alice"
    );
    assert_eq!(
        autostart.automount_point.as_deref(),
        Some(Path::new("/home/alice"))
    );
    assert!(not_read_at(&inventory, "/home/alice/.config/systemd/user").is_some());
    assert!(
        fs.mock_lookups()
            .iter()
            .all(|path| !path.starts_with("/home/alice")),
        "{:?}",
        fs.mock_lookups()
    );
}

/// A FIFO is no regular file, so it is skipped unread as before and never
/// counts as a place NAILS could not read.
#[test]
fn a_fifo_is_no_place_not_read() {
    use crate::filesystem::RealFilesystem;
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".config/autostart");
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("nails-test-fifo.desktop");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let inventory = crate::test_fifo::releasing_readers(&fifo, || {
        collect_inherited_persona(&RealFilesystem, home.path(), "alice", false)
    });
    assert!(names_for(&inventory, InheritedSource::UserAutostart).is_empty());
    assert!(
        inventory
            .not_read
            .iter()
            .all(|not_read| !not_read.path.starts_with(home.path())),
        "{:?}",
        inventory.not_read
    );
}

/// A home whose `~/.config` NAILS cannot search, as root on a root-squashed
/// NFS home or a FUSE home mounted without `allow_other`: the autostart
/// entries and user units below it are not read, so each directory is
/// listed as not read with the error, and nothing is taken for missing.
#[test]
fn a_directory_that_cannot_be_looked_up_is_not_read() {
    let fs = MockFilesystem::new();
    seed_entry(&fs, "/home/alice/.config/autostart", "sync.desktop");
    seed_entry(&fs, "/etc/xdg/autostart", "syncthing.desktop");
    assert_eq!(
        names_for(&collect(&fs, false), InheritedSource::UserAutostart),
        vec!["sync".to_string()]
    );
    fs.mock_set_lookup_error("/home/alice/.config", std::io::ErrorKind::PermissionDenied);

    let inventory = collect(&fs, false);
    assert!(names_for(&inventory, InheritedSource::UserAutostart).is_empty());
    assert_eq!(
        names_for(&inventory, InheritedSource::GlobalAutostart),
        vec!["syncthing".to_string()]
    );
    let autostart = not_read_at(&inventory, "/home/alice/.config/autostart").expect("not read");
    assert_eq!(
        autostart.reason,
        "NAILS cannot look up /home/alice/.config/autostart; run the command again with sudo"
    );
    assert_eq!(autostart.automount_point, None);
    assert_eq!(autostart.entry, None);
    assert!(not_read_at(&inventory, "/home/alice/.config/systemd/user").is_some());

    // A listing that fails for another reason names its error.
    let fs = MockFilesystem::new();
    fs.mock_set_lookup_error("/etc/systemd/user", std::io::ErrorKind::Other);
    let units = not_read_at(&collect(&fs, false), "/etc/systemd/user")
        .expect("not read")
        .clone();
    assert!(
        units
            .reason
            .starts_with("NAILS cannot look up /etc/systemd/user ("),
        "{units:?}"
    );
}

/// Only a directory that is not there, or one below a file, is nothing.
#[test]
fn a_directory_that_is_not_there_is_nothing() {
    for kind in [
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::NotADirectory,
    ] {
        let fs = MockFilesystem::new();
        fs.mock_set_lookup_error("/home/alice/.config", kind);
        let inventory = collect(&fs, false);
        assert!(inventory.is_empty(), "{kind:?}");
        assert!(
            inventory.not_read.is_empty(),
            "{kind:?}: {:?}",
            inventory.not_read
        );
    }
}

/// A file that is read but holds no text is read as an empty one, as
/// before: it is no place that could not be looked up.
#[test]
fn a_file_that_holds_no_text_is_no_place_not_read() {
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/etc/gdm3/custom.conf", crate::filesystem::PathKind::File);
    fs.mock_set_file_bytes("/etc/gdm3/custom.conf", b"\xff\xfe");
    let inventory = collect(&fs, false);
    assert!(inventory.is_empty());
    assert!(inventory.not_read.is_empty(), "{:?}", inventory.not_read);
}

/// A source read on its own, outside an inventory, keeps no note: the
/// inventory that reads it next starts with none.
#[test]
fn a_source_outside_an_inventory_keeps_no_note() {
    let fs = MockFilesystem::new();
    let path = Path::new("/etc/xdg/autostart");
    fs.note(NotRead::of(
        path,
        &NailsError::io(path, std::io::Error::from(std::io::ErrorKind::Other)),
    ));
    assert!(collect(&fs, false).not_read.is_empty());
}

/// A place noted twice is listed once, where it was first noted: the note
/// that names an undecided autostart entry wins, whichever came first, so
/// the entry stays undecided.
#[test]
fn a_place_noted_twice_is_listed_once_with_its_entry() {
    let fs = MockFilesystem::new();
    let path = Path::new("/home/alice/.config/autostart/sync.desktop");
    let error = NailsError::io(path, std::io::Error::from(std::io::ErrorKind::Other));
    let plain = || NotRead::of(path, &error);
    let entry = || plain().of_entry("sync", InheritedSource::UserAutostart);
    let other = || NotRead::of(Path::new("/etc/xdg/autostart"), &error);
    for notes in [[plain(), entry(), other()], [entry(), plain(), other()]] {
        let noting = Noting::new(&fs);
        for note in notes {
            noting.note(note);
        }
        assert_eq!(noting.into_not_read(), [entry(), other()]);
    }
}

/// An entry file `name` in the autostart directory `dir`.
fn seed_entry(fs: &MockFilesystem, dir: &str, name: &str) {
    let path = PathBuf::from(dir).join(name);
    let mut listing = fs.list_directory(Path::new(dir)).unwrap_or_default();
    listing.push(path.clone());
    fs.mock_set_directory_contents(Path::new(dir), listing);
    fs.mock_set_file_content(path.to_str().unwrap(), "[Desktop Entry]\n");
}
