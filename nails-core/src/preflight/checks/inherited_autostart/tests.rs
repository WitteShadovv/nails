// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The system-wide autostart entries of a stock Ubuntu 24.04 GNOME decoy, as
/// `nails check` listed them on one.
const UBUNTU_AUTOSTART: &[&str] = &[
    "at-spi-dbus-bus",
    "geoclue-demo-agent",
    "gnome-keyring-pkcs11",
    "gnome-keyring-secrets",
    "gnome-keyring-ssh",
    "org.gnome.SettingsDaemon.A11ySettings",
    "org.gnome.SettingsDaemon.Color",
    "org.gnome.SettingsDaemon.Datetime",
    "org.gnome.SettingsDaemon.Housekeeping",
    "org.gnome.SettingsDaemon.Keyboard",
    "org.gnome.SettingsDaemon.MediaKeys",
    "org.gnome.SettingsDaemon.Power",
    "org.gnome.SettingsDaemon.PrintNotifications",
    "org.gnome.SettingsDaemon.Rfkill",
    "org.gnome.SettingsDaemon.ScreensaverProxy",
    "org.gnome.SettingsDaemon.Sharing",
    "org.gnome.SettingsDaemon.Smartcard",
    "org.gnome.SettingsDaemon.Sound",
    "org.gnome.SettingsDaemon.UsbProtection",
    "org.gnome.SettingsDaemon.Wacom",
    "org.gnome.SettingsDaemon.Wwan",
    "org.gnome.SettingsDaemon.XSettings",
    "spice-vdagent",
    "tracker-miner-fs-3",
    "ubuntu-advantage-notification",
    "update-notifier",
    "user-dirs-update-gtk",
    "xdg-user-dirs",
];

/// The user units the same decoy enables for every user in
/// `/etc/systemd/user`, by the `.wants` directory that holds them.
const UBUNTU_UNITS: &[(&str, &str)] = &[
    ("sockets.target.wants", "dirmngr.socket"),
    ("default.target.wants", "filter-chain.service"),
    ("default.target.wants", "gcr-ssh-agent.service"),
    ("sockets.target.wants", "gcr-ssh-agent.socket"),
    ("default.target.wants", "gnome-keyring-daemon.service"),
    ("sockets.target.wants", "gnome-keyring-daemon.socket"),
    ("sockets.target.wants", "gpg-agent-browser.socket"),
    ("sockets.target.wants", "gpg-agent-extra.socket"),
    ("sockets.target.wants", "gpg-agent-ssh.socket"),
    ("sockets.target.wants", "gpg-agent.socket"),
    ("sockets.target.wants", "keyboxd.socket"),
    ("timers.target.wants", "launchpadlib-cache-clean.timer"),
    ("default.target.wants", "pipewire-pulse.service"),
    ("sockets.target.wants", "pipewire-pulse.socket"),
    ("default.target.wants", "pipewire.service"),
    ("sockets.target.wants", "pipewire.socket"),
    ("sockets.target.wants", "pk-debconf-helper.socket"),
    (
        "graphical-session-pre.target.wants",
        "session-migration.service",
    ),
    ("gnome-session.target.wants", "tracker-miner-fs-3.service"),
    ("pipewire.service.wants", "wireplumber.service"),
    (
        "graphical-session-pre.target.wants",
        "xdg-desktop-portal-rewrite-launchers.service",
    ),
];

/// The user units a NixOS GNOME decoy enables for every user.
const NIXOS_UNITS: &[(&str, &str)] = &[
    ("default.target.wants", "dbus.service"),
    ("sockets.target.wants", "dbus.socket"),
    ("default.target.wants", "gcr-ssh-agent.service"),
    ("sockets.target.wants", "gcr-ssh-agent.socket"),
    ("default.target.wants", "nixos-activation.service"),
    ("sockets.target.wants", "pipewire-pulse.socket"),
    ("sockets.target.wants", "pipewire.socket"),
    ("timers.target.wants", "systemd-tmpfiles-clean.timer"),
    ("basic.target.wants", "systemd-tmpfiles-setup.service"),
    ("pipewire.service.wants", "wireplumber.service"),
];

/// The autostart entries gnome-session started on the same decoy, which NixOS
/// links from the system's packages.
const NIXOS_AUTOSTART: &[&str] = &[
    "at-spi-dbus-bus",
    "gnome-keyring-pkcs11",
    "gnome-keyring-secrets",
    "xdg-user-dirs",
];

const NIXOS_SYSTEM_AUTOSTART: &str = "/run/current-system/sw/etc/xdg/autostart";

/// Add `.desktop` entries to an autostart directory.
fn add_autostart(fs: &MockFilesystem, dir: &str, names: &[&str], content: &str) {
    let mut listing = fs.list_directory(Path::new(dir)).unwrap_or_default();
    for name in names {
        let path = PathBuf::from(dir).join(format!("{name}.desktop"));
        fs.mock_set_file_content(path.to_str().unwrap(), content);
        listing.push(path);
    }
    fs.mock_set_directory_contents(Path::new(dir), listing);
}

/// Enable units in the `.wants` directories of a systemd user unit directory.
fn add_wants(fs: &MockFilesystem, dir: &str, units: &[(&str, &str)]) {
    let mut wants: BTreeMap<&str, Vec<PathBuf>> = BTreeMap::new();
    for (target, unit) in units {
        wants
            .entry(target)
            .or_default()
            .push(PathBuf::from(dir).join(target).join(unit));
    }
    let dirs = wants
        .keys()
        .map(|target| PathBuf::from(dir).join(target))
        .collect();
    fs.mock_set_directory_contents(Path::new(dir), dirs);
    for (target, units) in wants {
        fs.mock_set_directory_contents(&PathBuf::from(dir).join(target), units);
    }
}

fn ubuntu_gnome_decoy() -> MockFilesystem {
    let fs = MockFilesystem::new();
    add_autostart(
        &fs,
        "/etc/xdg/autostart",
        UBUNTU_AUTOSTART,
        "[Desktop Entry]\n",
    );
    add_wants(&fs, "/etc/systemd/user", UBUNTU_UNITS);
    fs
}

fn nixos_gnome_decoy() -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/run/current-system", true);
    add_autostart(
        &fs,
        NIXOS_SYSTEM_AUTOSTART,
        NIXOS_AUTOSTART,
        "[Desktop Entry]\n",
    );
    add_wants(&fs, "/etc/systemd/user", NIXOS_UNITS);
    fs
}

fn persona(mode: PersonaMode, masks: &[&str]) -> PersonaConfig {
    PersonaConfig {
        mode,
        mask_inherited: masks.iter().map(|name| name.to_string()).collect(),
    }
}

fn check_for(user: &str, persona: PersonaConfig) -> InheritedAutostartCheck {
    InheritedAutostartCheck::new(PathBuf::from(format!("/home/{user}")), user.into(), persona)
}

fn shared_home() -> InheritedAutostartCheck {
    check_for("alice", persona(PersonaMode::SharedHome, &[]))
}

fn seed_user_autostart(fs: &MockFilesystem, names: &[&str]) {
    add_autostart(
        fs,
        "/home/alice/.config/autostart",
        names,
        "[Desktop Entry]\n",
    );
}

#[test]
fn a_stock_ubuntu_gnome_decoy_is_clean_in_both_modes() {
    let fs = ubuntu_gnome_decoy();
    for mode in [PersonaMode::FreshHome, PersonaMode::SharedHome] {
        let result = check_for("alex", persona(mode, &[])).run(&fs).unwrap();
        assert!(result.is_pass(), "{mode:?}: {result:?}");
        assert!(
            result
                .message()
                .contains("49 desktop and distribution components not counted"),
            "{result:?}"
        );
    }
}

#[test]
fn a_nixos_gnome_decoy_is_clean() {
    let fs = nixos_gnome_decoy();
    let result = check_for("alex", persona(PersonaMode::SharedHome, &[]))
        .run(&fs)
        .unwrap();
    assert!(result.is_pass(), "{result:?}");
    // The ten global units and the four entries of the system profile.
    assert!(
        result
            .message()
            .contains("14 desktop and distribution components not counted"),
        "{result:?}"
    );
}

#[test]
fn the_speech_service_nixos_desktops_enable_for_everyone_is_not_reported() {
    // NixOS turns on speech-dispatcher for every graphical desktop, and KDE
    // Plasma adds its own cache rebuild; both are the distribution's own.
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/run/current-system", true);
    let mut units = NIXOS_UNITS.to_vec();
    units.push(("sockets.target.wants", "speech-dispatcher.socket"));
    units.push((
        "graphical-session-pre.target.wants",
        "nixos-rebuild-sycoca.service",
    ));
    add_wants(&fs, "/etc/systemd/user", &units);
    let result = check_for("alex", persona(PersonaMode::SharedHome, &[]))
        .run(&fs)
        .unwrap();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn autologin_on_a_stock_ubuntu_decoy_is_the_only_item_to_review() {
    let fs = ubuntu_gnome_decoy();
    fs.mock_set_file_content(
        "/etc/gdm3/custom.conf",
        "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=alex\n",
    );
    let result = check_for("alex", persona(PersonaMode::FreshHome, &[]))
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains("inherit 1 decoy item to review"),
        "{message}"
    );
    assert!(message.contains("To keep it out of"), "{message}");
    assert!(message.contains("alex (autologin)"), "{message}");
    assert!(
        message.contains("turn autologin off for the hidden session only")
            && message.contains("autologin stays listed here while the decoy keeps it")
            && !message.contains("on the decoy;"),
        "{message}"
    );
    assert!(
        !message.contains("mask_inherited in nails.toml"),
        "{message}"
    );
    assert!(!message.contains("keyring"), "{message}");
}

#[test]
fn a_desktop_component_on_the_trace_writer_list_is_reported() {
    // A default NixOS GNOME decoy also links Evolution's alarm notifier.
    let fs = nixos_gnome_decoy();
    add_autostart(
        &fs,
        NIXOS_SYSTEM_AUTOSTART,
        &["org.gnome.Evolution-alarm-notify"],
        "[Desktop Entry]\n",
    );
    let result = check_for("alex", persona(PersonaMode::SharedHome, &[]))
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("org.gnome.Evolution-alarm-notify (global-autostart, remote-linked)"),
        "{result:?}"
    );

    // Masking it handles it.
    let masked = check_for(
        "alex",
        persona(
            PersonaMode::SharedHome,
            &["org.gnome.Evolution-alarm-notify"],
        ),
    )
    .run(&fs)
    .unwrap();
    assert!(masked.is_pass(), "{masked:?}");
    assert!(masked.message().contains("1 masked"), "{masked:?}");
}

#[test]
fn entries_added_by_the_user_or_third_party_software_are_reported() {
    let fs = ubuntu_gnome_decoy();
    seed_user_autostart(&fs, &["dropbox", "my-script"]);
    add_autostart(
        &fs,
        "/etc/xdg/autostart",
        &["portmaster"],
        "[Desktop Entry]\n",
    );

    let result = shared_home().run(&fs).unwrap();
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains("inherit 3 decoy items to review"),
        "{message}"
    );
    assert!(
        message.contains("dropbox (user-autostart, remote-linked)"),
        "{message}"
    );
    assert!(message.contains("my-script (user-autostart)"), "{message}");
    assert!(
        message.contains("portmaster (global-autostart)"),
        "{message}"
    );
    assert!(
        message.contains("mask_inherited in nails.toml"),
        "{message}"
    );
    assert!(
        message.contains("(49 desktop and distribution components not counted)"),
        "{message}"
    );
    assert!(!message.contains("from the decoy account"), "{message}");
}

#[test]
fn masked_entries_count_as_handled() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, &["dropbox"]);

    let unmasked = shared_home().run(&fs).unwrap();
    assert!(unmasked.is_warn(), "{unmasked:?}");

    let masked = check_for("alice", persona(PersonaMode::SharedHome, &["dropbox"]))
        .run(&fs)
        .unwrap();
    assert!(masked.is_pass(), "{masked:?}");
    assert_eq!(
        masked.message(),
        "No inherited decoy item needs review (1 masked with [persona] mask_inherited)"
    );
}

#[test]
fn a_star_mask_handles_entries_but_not_lingering() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, &["dropbox"]);
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

    let result = check_for("alice", persona(PersonaMode::SharedHome, &["*"]))
        .run(&fs)
        .unwrap();
    assert!(result.is_warn(), "{result:?}");
    let message = result.message();
    assert!(message.contains("alice (linger)"), "{message}");
    assert!(
        message.contains("turn off lingering on the decoy"),
        "{message}"
    );
    assert!(!message.contains("dropbox"), "{message}");
    assert!(message.contains("1 masked"), "{message}");
}

#[test]
fn a_long_list_names_six_entries_and_counts_the_rest() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, &["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"]);
    let result = shared_home().run(&fs).unwrap();
    let message = result.message();
    assert!(
        message.contains("inherit 8 decoy items to review"),
        "{message}"
    );
    assert!(
        message.contains("a6 (user-autostart), and 2 more"),
        "{message}"
    );
    assert!(!message.contains("a7"), "{message}");
}

#[test]
fn passes_on_empty_inventory() {
    let fs = MockFilesystem::new();
    let result = shared_home().run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().starts_with("No decoy autostart entries"));
}

#[test]
fn never_fails_even_with_many_entries() {
    let fs = ubuntu_gnome_decoy();
    seed_user_autostart(&fs, &["dropbox", "telegram", "my-script"]);
    fs.mock_set_path_exists("/var/lib/systemd/linger/alice", true);

    let result = shared_home().run(&fs).unwrap();
    assert!(result.is_warn());
    assert!(!result.is_fail());
}

#[test]
fn disabled_check_passes_without_inspecting() {
    let fs = MockFilesystem::new();
    seed_user_autostart(&fs, &["dropbox"]);

    let result = InheritedAutostartCheck::disabled().run(&fs).unwrap();
    assert!(result.is_pass());
    assert!(result.message().contains("could not be resolved"));
}

#[test]
fn metadata_is_stable() {
    let check = InheritedAutostartCheck::disabled();
    assert_eq!(
        <InheritedAutostartCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "inherited-autostart"
    );
    assert!(
        <InheritedAutostartCheck as PreFlightCheck<MockFilesystem>>::description(&check)
            .contains("inherit")
    );
}

#[test]
fn fresh_home_reports_only_system_level_entries() {
    let fs = MockFilesystem::new();
    // A user-level autostart entry that fresh-home must not report.
    seed_user_autostart(&fs, &["dropbox"]);

    let check = check_for("alice", persona(PersonaMode::FreshHome, &[]));
    let result = check.run(&fs).unwrap();
    // Nothing system-level is seeded, so fresh-home sees an empty inventory.
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn the_check_writes_nothing() {
    let fs = nixos_gnome_decoy();
    seed_user_autostart(&fs, &["dropbox"]);
    let before = fs.mock_ops().len();
    let _ = shared_home().run(&fs).unwrap();
    assert!(fs.mock_written_paths().is_empty());
    assert_eq!(fs.mock_ops().len(), before, "{:?}", fs.mock_ops());
}
