// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which inherited entries need the operator's review, by name.
//!
//! Two fixed lists decide it, and both match names only: they make no claim
//! about what an entry does or whether a client is signed in.
//!
//! - [`TRACE_WRITERS`]: clients known to carry data, or the fact that the
//!   machine is running, off the machine: sync and cloud storage, backup,
//!   messaging, mail, calendar and online accounts, phone links. An inherited
//!   entry on this list is always reported, wherever it comes from, and is
//!   tagged remote-linked.
//! - [`DESKTOP_COMPONENTS`]: components the installed desktop or distribution
//!   ships itself (settings daemons, the keyring, the audio and session buses,
//!   the GnuPG agents, input methods, update notifiers). A system-wide entry on
//!   this list is not reported: masking it would break or degrade the hidden
//!   desktop, and it does nothing the decoy's own session does not do.
//!
//! Everything else that is inherited is taken as added by the user or by
//! third-party software and is reported, so an entry this module does not know
//! errs on the side of a warning.

/// Name fragments of clients known to carry data off the machine. A match is
/// a case-insensitive substring of the entry name.
pub const TRACE_WRITERS: &[&str] = &[
    // Sync and cloud storage.
    "dropbox",
    "nextcloud",
    "owncloud",
    "syncthing",
    "megasync",
    "insync",
    "onedrive",
    "rclone",
    // Backup tools that copy the home elsewhere on a schedule.
    "dejadup",
    "deja-dup",
    "pikabackup",
    "vorta",
    "backintime",
    // Messaging and meetings.
    "telegram",
    "signal",
    "slack",
    "discord",
    "element-desktop",
    "im.riot",
    "keybase",
    "zoom",
    "teams",
    // Mail, calendar and online accounts.
    "thunderbird",
    "evolution",
    "geary",
    "gnome-online-accounts",
    "goa-daemon",
    "kaccounts",
    // Phone links.
    "kdeconnect",
    "gsconnect",
    "valent",
];

/// Names of components the installed desktop or distribution ships. An entry
/// ending in `*` matches every name that starts with the part before it; any
/// other entry matches the whole name, or a unit of that name with any unit
/// suffix. Matching ignores ASCII case. Autostart entries are matched by their
/// `.desktop` stem, user units by their full name.
pub const DESKTOP_COMPONENTS: &[&str] = &[
    // GNOME and the freedesktop.org services every desktop uses.
    "org.gnome.*",
    "gnome-*",
    "org.freedesktop.*",
    "at-spi-*",
    "geoclue-*",
    "tracker-*",
    "localsearch*",
    "xdg-user-dirs*",
    "user-dirs-update-gtk",
    "xdg-desktop-portal*",
    "xdg-document-portal*",
    "xdg-permission-store*",
    "orca-autostart",
    "polkit-*",
    "nm-applet",
    "blueman*",
    "print-applet",
    // KDE Plasma.
    "org.kde.*",
    "baloo_file",
    "kaccess",
    "klipper",
    "kwalletd*",
    "pam_kwallet_init",
    "xembedsniproxy",
    "gmenudbusmenuproxy",
    "powerdevil",
    "plasma-*",
    // Xfce, MATE, Cinnamon, LXQt, Budgie, elementary and Lomiri.
    "xfce4-*",
    "xfsettingsd",
    "xiccd",
    "light-locker",
    "mate-*",
    "cinnamon-*",
    "nemo-autostart",
    "xapp-*",
    "lxqt-*",
    "lxpolkit",
    "budgie-*",
    "org.buddiesofbudgie.*",
    "io.elementary.*",
    "lomiri-*",
    // Input methods.
    "ibus*",
    "fcitx*",
    "org.fcitx.*",
    "im-launch",
    // Speech for the screen reader, on by default on NixOS desktops.
    "speech-dispatcher*",
    // Audio, the session bus, the keyring and the GnuPG and SSH agents.
    "pipewire*",
    "wireplumber*",
    "filter-chain*",
    "pulseaudio*",
    "dbus.*",
    "dbus-broker*",
    "gpg-agent*",
    "dirmngr*",
    "keyboxd*",
    "gcr-ssh-agent*",
    "ssh-agent*",
    "p11-kit-*",
    // systemd, NixOS's own user units, Flatpak and snapd.
    "systemd-*",
    "nixos-*",
    "flatpak-*",
    "snapd.*",
    "snap-userd-autostart",
    // Distribution tools: update and crash notifiers, migrations, VM agents.
    "update-notifier",
    "ubuntu-*",
    "apport*",
    "session-migration*",
    "launchpadlib-cache-clean*",
    "pk-debconf-helper*",
    "abrt-applet",
    "imsettings-start",
    "mintupdate",
    "mintwelcome",
    "mintreport*",
    "spice-vdagent",
];

/// The suffixes of systemd unit names.
pub const UNIT_SUFFIXES: &[&str] = &[
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".target",
    ".mount",
    ".automount",
    ".swap",
    ".slice",
    ".scope",
    ".device",
];

/// `name` without its systemd unit suffix, or `None` when it has none.
pub fn unit_stem(name: &str) -> Option<&str> {
    UNIT_SUFFIXES
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .filter(|stem| !stem.is_empty())
}

/// Whether `name` matches one of [`TRACE_WRITERS`].
pub fn is_trace_writer(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TRACE_WRITERS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

/// Whether `name` matches one of [`DESKTOP_COMPONENTS`].
pub fn is_desktop_component(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = unit_stem(&lower);
    DESKTOP_COMPONENTS
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => lower.starts_with(&prefix.to_ascii_lowercase()),
            None => {
                let whole = pattern.to_ascii_lowercase();
                lower == whole || stem == Some(whole.as_str())
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_writers_match_case_insensitive_fragments() {
        for name in [
            "dropbox",
            "com.nextcloud.desktopclient.nextcloud",
            "syncthing.service",
            "org.gnome.DejaDup.Monitor",
            "org.gnome.World.PikaBackup.Monitor",
            "org.gnome.Evolution-alarm-notify",
            "org.kde.kdeconnect.daemon",
            "signal-desktop",
            "element-desktop",
        ] {
            assert!(is_trace_writer(name), "{name}");
        }
        for name in [
            "org.gnome.SettingsDaemon.Power",
            "pipewire.socket",
            "io.elementary.desktop.agent-polkit",
            "screenshot-tool",
        ] {
            assert!(!is_trace_writer(name), "{name}");
        }
    }

    #[test]
    fn desktop_components_match_whole_names_or_prefixes() {
        for name in [
            "org.gnome.SettingsDaemon.Wacom",
            "gnome-keyring-pkcs11",
            "at-spi-dbus-bus",
            "pipewire-pulse.socket",
            "dbus.socket",
            "systemd-tmpfiles-clean.timer",
            "nixos-activation.service",
            "update-notifier",
            "SPICE-VDAGENT",
            // A whole-name entry also matches the unit of that name.
            "nm-applet.service",
            "speech-dispatcher.socket",
            "nixos-rebuild-sycoca.service",
        ] {
            assert!(is_desktop_component(name), "{name}");
        }
        for name in [
            // A whole-name entry does not match a longer name.
            "update-notifier-extra",
            "spice-vdagent-helper",
            "nm-applet.desktop-helper",
            // Neither prefixes nor whole names of the list.
            "dbusx.service",
            "portmaster",
            "my-backup",
            "dropbox",
        ] {
            assert!(!is_desktop_component(name), "{name}");
        }
    }

    #[test]
    fn unit_stems_drop_exactly_one_unit_suffix() {
        assert_eq!(
            unit_stem("speech-dispatcher.socket"),
            Some("speech-dispatcher")
        );
        assert_eq!(unit_stem("backup.timer"), Some("backup"));
        assert_eq!(unit_stem("org.gnome.Evolution-alarm-notify"), None);
        assert_eq!(unit_stem(".service"), None);
        assert_eq!(unit_stem("dropbox"), None);
    }

    #[test]
    fn no_desktop_pattern_is_itself_a_trace_writer_or_too_broad() {
        // A desktop component whose name is also on the trace-writer list
        // (Evolution's alarm notifier, KDE Connect) is still reported; the
        // desktop list must never name such a client outright, and none of
        // its prefixes may be so short that it covers unrelated programs.
        for fragment in TRACE_WRITERS {
            assert!(
                !fragment.is_empty() && !fragment.contains('*'),
                "{fragment}"
            );
        }
        for pattern in DESKTOP_COMPONENTS {
            let stem = pattern.trim_end_matches('*');
            assert!(stem.len() >= 3, "{pattern} is too broad");
            assert!(!is_trace_writer(stem), "{pattern} names a trace writer");
        }
    }
}
