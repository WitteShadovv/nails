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
//! - **`/nix`** (or `/nix/store`): `Skip` for read-only consumers, `Risky` for `cwd`, nix-daemon `Safe`
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

    /// Process uses the target but does not block mounting and must not be killed.
    ///
    /// Used for processes that only have open file descriptors or memory-mapped
    /// files from the target directory (no cwd). These processes are read-only
    /// consumers that do not prevent overlayfs mount and would cause system
    /// failure if killed.
    ///
    /// Currently only used for `/nix` on NixOS, where every process has mmaps
    /// from `/nix/store` (loaded binaries) but cannot write to it due to the
    /// kernel-enforced read-only bind mount.
    Skip,
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
        "/nix/store" | "/nix" => classify_nix_process(proc),
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

/// Classify process using `/nix` or `/nix/store`
///
/// On NixOS, every process has memory-mapped files from `/nix/store` (loaded
/// binaries and shared libraries). These processes are read-only consumers
/// that do NOT block overlayfs mount and would cause catastrophic system
/// failure if killed.
///
/// Only nix-daemon (the sole writer to `/nix`) and processes with cwd in
/// the target need special handling.
fn classify_nix_process(proc: &ProcessInfo) -> RestartStrategy {
    match proc.name.as_str() {
        // nix-daemon is the only writer to /nix/store — safe to stop/restart
        "nix-daemon" => RestartStrategy::Safe,

        _ => {
            if proc.has_cwd_in_target {
                // Process has cwd in /nix — may block the mount
                RestartStrategy::Risky
            } else {
                // Process just has mmaps/FDs from /nix/store (loaded binaries).
                // /nix/store is read-only (kernel-enforced bind mount).
                // /nix/var is only written by nix-daemon (stopped separately).
                // Killing this process serves no purpose and may crash the system.
                RestartStrategy::Skip
            }
        }
    }
}

#[cfg(test)]
mod tests;
