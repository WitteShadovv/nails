//! Process Classification
//!
//! Classifies processes by restart safety based on volume-specific rules.
//!
//! # Classification Strategy
//!
//! Different volumes have different classification rules:
//! - **`/var`**: Most processes safe to restart (logs, caches)
//! - **`/etc`**: Config readers mostly safe, critical services risky
//! - **`/home`**: GUI apps cannot restart (lose work), audio risky
//! - **`/nix/store`**: Most safe, only `cwd` users risky
//! - **Unknown volumes**: Generic overlay process classification (Story 14.10)
//!
//! With dynamic overlay enumeration (Story 14.10), any directory under `/` can
//! be an overlay target. Unknown volumes use a conservative fallback that treats
//! processes with `cwd` in the target as `Risky` and others as `Safe`.
//!
//! See `/docs/architecture/universal-overlay-mounting-strategy.md` for full rationale.
//!
//! # Example
//!
//! ```no_run
//! use nails_core::process::{ProcessInfo, classify_process, RestartStrategy};
//! use std::path::{Path, PathBuf};
//!
//! let proc = ProcessInfo {
//!     pid: 1234,
//!     name: "firefox".to_string(),
//!     cmdline: "/usr/bin/firefox".to_string(),
//!     cwd: PathBuf::from("/home/user"),
//!     has_cwd_in_target: true,
//!     has_open_fds_in_target: false,
//!     has_mmap_in_target: false,
//!     service_name: None,
//! };
//!
//! let strategy = classify_process(&proc, Path::new("/home"));
//! assert!(matches!(strategy, RestartStrategy::NoRestart));
//! ```

use crate::process::detection::ProcessInfo;
use std::path::Path;

/// Restart strategy for a process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartStrategy {
    /// Safe to restart automatically without prompting
    ///
    /// Examples: `systemd-journald`, `nix-daemon`, `rsyslogd`
    Safe,

    /// Risky to restart - prompt user before restarting
    ///
    /// Examples: `NetworkManager`, `dbus-daemon`, `pulseaudio`
    Risky,

    /// Cannot restart safely - would lose user work or kill session
    ///
    /// Examples: `firefox`, `sway`, `Xorg`, `vim`
    NoRestart,
}

/// Classify a process by restart safety
///
/// Classification rules are volume-specific and documented in
/// `/docs/architecture/universal-overlay-mounting-strategy.md`.
///
/// # Arguments
///
/// * `proc` - Process information
/// * `target` - Target directory being mounted/unmounted
///
/// # Returns
///
/// * `RestartStrategy` - Classification result
///
/// # Example
///
/// ```no_run
/// use nails_core::process::{ProcessInfo, classify_process};
/// use std::path::{Path, PathBuf};
/// # use nails_core::process::RestartStrategy;
///
/// let proc = ProcessInfo {
///     pid: 234,
///     name: "systemd-journald".to_string(),
///     cmdline: "/usr/lib/systemd/systemd-journald".to_string(),
///     cwd: PathBuf::from("/"),
///     has_cwd_in_target: false,
///     has_open_fds_in_target: true,
///     has_mmap_in_target: false,
///     service_name: Some("systemd-journald".to_string()),
/// };
///
/// let strategy = classify_process(&proc, Path::new("/var"));
/// assert!(matches!(strategy, RestartStrategy::Safe));
/// ```
pub fn classify_process(proc: &ProcessInfo, target: &Path) -> RestartStrategy {
    let target_str = target.to_string_lossy();

    match target_str.as_ref() {
        "/var" => classify_var_process(proc),
        "/etc" => classify_etc_process(proc),
        "/home" => classify_home_process(proc),
        "/nix/store" => classify_nix_store_process(proc),
        _ => classify_generic_overlay_process(proc, &target_str),
    }
}

/// Classify process for an arbitrary overlay target (Story 14.10)
///
/// With dynamic overlay enumeration, any directory under `/` can be an overlay
/// target (e.g., `/tmp`, `/opt`, `/srv`, `/boot`, `/root`, `/usr`, `/nix`,
/// `/persistent`). This provides a conservative fallback classification:
///
/// - **`/home` subdirectories**: NoRestart (user data, GUI apps)
/// - **`/root`**: NoRestart (root user home directory)
/// - **Processes with `cwd` in target**: Risky (may block mount)
/// - **All other system directories**: Safe (generic overlay process)
fn classify_generic_overlay_process(proc: &ProcessInfo, target_str: &str) -> RestartStrategy {
    // Home subdirectories: treat like /home (user data, GUI apps)
    if target_str.starts_with("/home") {
        return RestartStrategy::NoRestart;
    }

    // /root is the root user's home directory - treat like /home
    if target_str == "/root" {
        return classify_home_process(proc);
    }

    // For any other system directory: processes with cwd in target are risky
    // (they may block the overlay mount), others are safe
    if proc.has_cwd_in_target {
        RestartStrategy::Risky
    } else {
        RestartStrategy::Safe
    }
}

/// Classify process using `/var`
fn classify_var_process(proc: &ProcessInfo) -> RestartStrategy {
    match proc.name.as_str() {
        // Safe to restart - stateless or designed for it
        "systemd-journal" | "systemd-journald" | "rsyslogd" | "systemd-resolved" => {
            RestartStrategy::Safe
        }

        // Risky - may cause brief disruption
        "NetworkManager" => RestartStrategy::Risky,

        // Most /var users are safe (logs, caches, temp files)
        _ => RestartStrategy::Safe,
    }
}

/// Classify process using `/etc`
fn classify_etc_process(proc: &ProcessInfo) -> RestartStrategy {
    match proc.name.as_str() {
        // Never restart PID 1
        "systemd" if proc.pid == 1 => RestartStrategy::NoRestart,

        // Risky - critical system services
        "dbus-daemon" => RestartStrategy::Risky,

        // Safe - designed for restarts
        "NetworkManager" | "systemd-resolved" => RestartStrategy::Safe,

        // Most processes using /etc are just reading config files - safe
        _ => RestartStrategy::Safe,
    }
}

/// Classify process using `/home`
fn classify_home_process(proc: &ProcessInfo) -> RestartStrategy {
    match proc.name.as_str() {
        // Display servers - cannot restart without killing session
        "sway" | "Hyprland" | "gnome-shell" | "kwin_wayland" | "Xorg" => RestartStrategy::NoRestart,

        // Web browsers - cannot restart without losing work
        "firefox" | "librewolf" | "chromium" | "chrome" | "google-chrome" => {
            RestartStrategy::NoRestart
        }

        // Text editors - cannot restart without losing work
        "code" | "vim" | "emacs" | "nvim" | "neovim" => RestartStrategy::NoRestart,

        // Audio servers - annoying but safe
        "pulseaudio" | "pipewire" | "pipewire-pulse" => RestartStrategy::Risky,

        // Everything else using /home is probably GUI apps
        _ => RestartStrategy::NoRestart,
    }
}

/// Classify process using `/nix/store`
fn classify_nix_store_process(proc: &ProcessInfo) -> RestartStrategy {
    match proc.name.as_str() {
        // Safe to restart
        "nix-daemon" => RestartStrategy::Safe,

        _ => {
            // Check if process has cwd in /nix/store (blocks mount)
            if proc.has_cwd_in_target {
                RestartStrategy::Risky
            } else {
                // Just has files open - doesn't block direct mount
                RestartStrategy::Safe
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_test_process(name: &str, pid: u32, has_cwd: bool) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            cmdline: format!("/usr/bin/{}", name),
            cwd: PathBuf::from("/"),
            has_cwd_in_target: has_cwd,
            has_open_fds_in_target: false,
            has_mmap_in_target: false,
            service_name: None,
        }
    }

    // Tests for /var classification
    #[test]
    fn test_var_systemd_journald_safe() {
        let proc = make_test_process("systemd-journald", 234, false);
        let strategy = classify_process(&proc, Path::new("/var"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_var_rsyslogd_safe() {
        let proc = make_test_process("rsyslogd", 345, false);
        let strategy = classify_process(&proc, Path::new("/var"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_var_systemd_resolved_safe() {
        let proc = make_test_process("systemd-resolved", 456, false);
        let strategy = classify_process(&proc, Path::new("/var"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_var_networkmanager_risky() {
        let proc = make_test_process("NetworkManager", 567, false);
        let strategy = classify_process(&proc, Path::new("/var"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_var_unknown_process_safe() {
        let proc = make_test_process("unknown-daemon", 678, false);
        let strategy = classify_process(&proc, Path::new("/var"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    // Tests for /etc classification
    #[test]
    fn test_etc_systemd_pid1_no_restart() {
        let proc = make_test_process("systemd", 1, false);
        let strategy = classify_process(&proc, Path::new("/etc"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_etc_systemd_not_pid1_safe() {
        let proc = make_test_process("systemd", 1234, false);
        let strategy = classify_process(&proc, Path::new("/etc"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_etc_dbus_daemon_risky() {
        let proc = make_test_process("dbus-daemon", 345, false);
        let strategy = classify_process(&proc, Path::new("/etc"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_etc_networkmanager_safe() {
        let proc = make_test_process("NetworkManager", 456, false);
        let strategy = classify_process(&proc, Path::new("/etc"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_etc_systemd_resolved_safe() {
        let proc = make_test_process("systemd-resolved", 567, false);
        let strategy = classify_process(&proc, Path::new("/etc"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_etc_unknown_process_safe() {
        let proc = make_test_process("some-config-reader", 678, false);
        let strategy = classify_process(&proc, Path::new("/etc"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    // Tests for /home classification
    #[test]
    fn test_home_sway_no_restart() {
        let proc = make_test_process("sway", 1234, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_hyprland_no_restart() {
        let proc = make_test_process("Hyprland", 1235, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_gnome_shell_no_restart() {
        let proc = make_test_process("gnome-shell", 1236, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_xorg_no_restart() {
        let proc = make_test_process("Xorg", 1237, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_firefox_no_restart() {
        let proc = make_test_process("firefox", 5678, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_chrome_no_restart() {
        let proc = make_test_process("chrome", 5679, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_code_no_restart() {
        let proc = make_test_process("code", 5680, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_vim_no_restart() {
        let proc = make_test_process("vim", 5681, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_home_pulseaudio_risky() {
        let proc = make_test_process("pulseaudio", 6789, false);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_home_pipewire_risky() {
        let proc = make_test_process("pipewire", 6790, false);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_home_unknown_process_no_restart() {
        let proc = make_test_process("unknown-gui-app", 7890, true);
        let strategy = classify_process(&proc, Path::new("/home"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    // Tests for /nix/store classification
    #[test]
    fn test_nix_store_nix_daemon_safe() {
        let proc = make_test_process("nix-daemon", 234, false);
        let strategy = classify_process(&proc, Path::new("/nix/store"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_nix_store_cwd_in_target_risky() {
        let proc = make_test_process("build-process", 345, true);
        let strategy = classify_process(&proc, Path::new("/nix/store"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_nix_store_only_open_files_safe() {
        let mut proc = make_test_process("any-binary", 456, false);
        proc.has_open_fds_in_target = true;
        let strategy = classify_process(&proc, Path::new("/nix/store"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    // Tests for generic overlay process classification (Story 14.10)
    #[test]
    fn test_unknown_volume_user_no_restart() {
        let proc = make_test_process("some-app", 1234, true);
        let strategy = classify_process(&proc, Path::new("/home/user"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_unknown_volume_system_safe() {
        let proc = make_test_process("some-daemon", 1234, false);
        let strategy = classify_process(&proc, Path::new("/opt"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_tmp_safe() {
        let proc = make_test_process("some-daemon", 1234, false);
        let strategy = classify_process(&proc, Path::new("/tmp"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_srv_safe() {
        let proc = make_test_process("httpd", 1234, false);
        let strategy = classify_process(&proc, Path::new("/srv"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_usr_safe() {
        let proc = make_test_process("some-binary", 1234, false);
        let strategy = classify_process(&proc, Path::new("/usr"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_boot_safe() {
        let proc = make_test_process("grub-probe", 1234, false);
        let strategy = classify_process(&proc, Path::new("/boot"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_nix_safe() {
        let proc = make_test_process("nix-build", 1234, false);
        let strategy = classify_process(&proc, Path::new("/nix"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_persistent_safe() {
        let proc = make_test_process("some-daemon", 1234, false);
        let strategy = classify_process(&proc, Path::new("/persistent"));
        assert_eq!(strategy, RestartStrategy::Safe);
    }

    #[test]
    fn test_generic_overlay_cwd_in_target_risky() {
        let proc = make_test_process("some-process", 1234, true);
        let strategy = classify_process(&proc, Path::new("/opt"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_generic_overlay_cwd_in_tmp_risky() {
        let proc = make_test_process("build-runner", 1234, true);
        let strategy = classify_process(&proc, Path::new("/tmp"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_generic_overlay_root_homedir_uses_home_rules() {
        // /root is root's home dir - firefox there should be NoRestart
        let proc = make_test_process("firefox", 1234, true);
        let strategy = classify_process(&proc, Path::new("/root"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    #[test]
    fn test_generic_overlay_root_homedir_audio_risky() {
        let proc = make_test_process("pulseaudio", 1234, false);
        let strategy = classify_process(&proc, Path::new("/root"));
        assert_eq!(strategy, RestartStrategy::Risky);
    }

    #[test]
    fn test_generic_overlay_root_homedir_unknown_no_restart() {
        let proc = make_test_process("unknown-app", 1234, false);
        let strategy = classify_process(&proc, Path::new("/root"));
        assert_eq!(strategy, RestartStrategy::NoRestart);
    }

    // Edge cases
    #[test]
    fn test_restart_strategy_enum_equality() {
        assert_eq!(RestartStrategy::Safe, RestartStrategy::Safe);
        assert_eq!(RestartStrategy::Risky, RestartStrategy::Risky);
        assert_eq!(RestartStrategy::NoRestart, RestartStrategy::NoRestart);
        assert_ne!(RestartStrategy::Safe, RestartStrategy::Risky);
    }

    #[test]
    fn test_restart_strategy_debug() {
        let strategy = RestartStrategy::Safe;
        let debug_str = format!("{:?}", strategy);
        assert_eq!(debug_str, "Safe");
    }
}
