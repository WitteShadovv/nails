// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
//! - **Unknown volumes**: Generic overlay process classification
//!
//! With dynamic overlay enumeration, any directory under `/` can
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
//!     has_writable_fd_in_target: false,
//!     has_dir_fd_in_target: false,
//!     has_shared_write_map_in_target: false,
//!     has_root_in_target: false,
//!     is_unverifiable_writer: false,
//!     service_name: None,
//!     is_interactive: false,
//! };
//!
//! let strategy = classify_process(&proc, Path::new("/home"));
//! assert!(matches!(strategy, RestartStrategy::NoRestart));
//! ```

use crate::process::detection::ProcessInfo;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// What to do with processes classified as `Risky` to restart (services such as
/// NetworkManager, dbus-daemon or the audio server) when they still reference an
/// overlay target.
///
/// Leaving a risky service running keeps it writing to the decoy lower tree, so
/// the choice is a security trade-off the operator must make deliberately. It is
/// surfaced as the `risky_services` config key and the `--risky-services` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskyServicePolicy {
    /// Restart the risky services so they no longer reference the decoy.
    Restart,
    /// Leave them running; they are reported as surviving writers.
    Skip,
}

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

    /// Process references the target but cannot write to the decoy through that
    /// reference, so it does not block the mount and must not be killed.
    ///
    /// Applies to any read-only consumer: a process that holds only non-writable
    /// fds or private/read-only mappings of files in the target (no `cwd`, no
    /// writable or directory fd, no shared-writable mapping). Killing such a
    /// process serves no security purpose and may crash the system — on NixOS,
    /// for instance, every process mmaps loaded binaries from the read-only
    /// `/nix/store`.
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
///     has_writable_fd_in_target: false,
///     has_dir_fd_in_target: false,
///     has_shared_write_map_in_target: false,
///     has_root_in_target: false,
///     is_unverifiable_writer: false,
///     service_name: Some("systemd-journald".to_string()),
///     is_interactive: false,
/// };
///
/// let strategy = classify_process(&proc, Path::new("/var"));
/// assert!(matches!(strategy, RestartStrategy::Safe));
/// ```
pub fn classify_process(proc: &ProcessInfo, target: &Path) -> RestartStrategy {
    // An overlay redirects new path lookups, but it cannot revoke the write
    // access a process already holds. The relevant question is therefore whether
    // the process can still *write* to the decoy lower tree. A process that holds
    // only read-only references (an open fd that is not writable, a private or
    // read-only mapping) cannot, so leaving it running is safe on any target and
    // restarting it would only disrupt the user for no security gain.
    if proc.is_read_only_consumer() {
        return RestartStrategy::Skip;
    }

    let target_str = target.to_string_lossy();

    match target_str.as_ref() {
        "/var" => classify_var_process(proc),
        "/etc" => classify_etc_process(proc),
        "/home" => classify_home_process(proc),
        "/nix/store" | "/nix" => classify_nix_process(proc),
        _ => classify_generic_overlay_process(proc, &target_str),
    }
}

/// Classify process for an arbitrary overlay target
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
