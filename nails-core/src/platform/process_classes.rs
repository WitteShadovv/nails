// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process-name tables that drive restart classification, kept as platform data.
//!
//! The process classifier (`crate::process::classification`) decides whether a
//! process still referencing an overlay target is safe to restart, risky, or must
//! be left alone. That decision leans on *names*: `firefox` loses the user's work
//! if restarted, `systemd-journald` does not, `dbus-daemon` is risky to cycle. The
//! names themselves are host facts — a distribution ships GDM as `gdm` or `gdm3`,
//! an audio stack as `pulseaudio` or `pipewire` — so they belong in the platform
//! layer next to [`super::DEFAULT_DISPLAY_MANAGER_UNITS`], not hard-coded in the
//! classifier.
//!
//! Today every supported host shares one table, so the classifier reads
//! [`DEFAULT`]. Keeping the data here (rather than inline in the classifier) is
//! what lets a future backend override a single category — a Fedora backend that
//! adds `gnome-text-editor`, say — without touching the classification logic.

/// The process-name tables one host uses to classify restart safety.
///
/// Each field lists the `comm` names (`/proc/<pid>/comm`) a category covers.
/// Membership is matched exactly: the classifier compares a process's name
/// against these slices, never by substring, so `code` matches the editor but not
/// `codec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessClasses {
    /// Display servers / compositors. Restarting one kills the graphical session,
    /// so they are never auto-restarted.
    pub display_servers: &'static [&'static str],
    /// Web browsers. Restarting one loses open tabs and unsaved form state.
    pub web_browsers: &'static [&'static str],
    /// Interactive text editors. Restarting one loses unsaved buffers.
    pub text_editors: &'static [&'static str],
    /// Audio servers. Cycling one is an audible glitch but not data loss, so it is
    /// risky rather than forbidden.
    pub audio_servers: &'static [&'static str],
    /// Services that are safe to restart when they reference `/var` (stateless or
    /// designed to be cycled: journald, syslog, resolved).
    pub var_safe_services: &'static [&'static str],
    /// Services that are risky to restart when they reference `/etc` (critical
    /// buses whose restart briefly disrupts dependants). Every other `/etc`
    /// consumer is merely reading configuration and is safe to restart.
    pub etc_risky_services: &'static [&'static str],
}

impl ProcessClasses {
    /// Whether `name` is a display server / compositor.
    pub(crate) fn is_display_server(&self, name: &str) -> bool {
        self.display_servers.contains(&name)
    }

    /// Whether `name` is a web browser.
    pub(crate) fn is_web_browser(&self, name: &str) -> bool {
        self.web_browsers.contains(&name)
    }

    /// Whether `name` is an interactive text editor.
    pub(crate) fn is_text_editor(&self, name: &str) -> bool {
        self.text_editors.contains(&name)
    }

    /// Whether `name` is an audio server.
    pub(crate) fn is_audio_server(&self, name: &str) -> bool {
        self.audio_servers.contains(&name)
    }

    /// Whether `name` is a service safe to restart against `/var`.
    pub(crate) fn is_var_safe_service(&self, name: &str) -> bool {
        self.var_safe_services.contains(&name)
    }

    /// Whether `name` is a service risky to restart against `/etc`.
    pub(crate) fn is_etc_risky_service(&self, name: &str) -> bool {
        self.etc_risky_services.contains(&name)
    }
}

/// The process-name tables in force on this host.
///
/// Every supported host shares [`DEFAULT`] today. This accessor is the seam a
/// future per-backend table plugs into, so the classifier asks the platform layer
/// for the data rather than carrying it inline.
pub(crate) fn host_process_classes() -> ProcessClasses {
    DEFAULT
}

/// The table every supported host shares today.
///
/// A backend that needs to differ returns its own [`ProcessClasses`] from
/// [`host_process_classes`]; the default returns this.
pub(crate) const DEFAULT: ProcessClasses = ProcessClasses {
    display_servers: &["sway", "Hyprland", "gnome-shell", "kwin_wayland", "Xorg"],
    web_browsers: &[
        "firefox",
        "librewolf",
        "chromium",
        "chrome",
        "google-chrome",
    ],
    text_editors: &["code", "vim", "emacs", "nvim", "neovim"],
    audio_servers: &["pulseaudio", "pipewire", "pipewire-pulse"],
    var_safe_services: &[
        "systemd-journal",
        "systemd-journald",
        "rsyslogd",
        "systemd-resolved",
    ],
    etc_risky_services: &["dbus-daemon"],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tables_group_names_by_category() {
        let c = host_process_classes();
        assert!(c.is_display_server("sway"));
        assert!(c.is_display_server("Xorg"));
        assert!(c.is_web_browser("firefox"));
        assert!(c.is_text_editor("nvim"));
        assert!(c.is_audio_server("pipewire"));
        assert!(c.is_var_safe_service("systemd-journald"));
        assert!(c.is_etc_risky_service("dbus-daemon"));
    }

    #[test]
    fn membership_is_exact_not_substring() {
        let c = host_process_classes();
        // The classifier must not treat `codec` as the editor `code`.
        assert!(c.is_text_editor("code"));
        assert!(!c.is_text_editor("codec"));
        assert!(!c.is_web_browser("firefox-bin"));
        assert!(!c.is_display_server("sways"));
    }
}
