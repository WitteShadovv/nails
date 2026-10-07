// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the session mode needs from systemd: `systemctl soft-reboot` (systemd
//! 254) and the two units that implement it.
//!
//! | Release | systemd | |
//! | --- | --- | --- |
//! | Debian 12 bookworm | 252 | refused |
//! | Debian 13 trixie | 257 | supported |
//! | Ubuntu 22.04 jammy | 249 | refused |
//! | Ubuntu 24.04 noble | 255 | supported |
//! | NixOS (current) | 259 | supported; the pinned nixpkgs lacks the two units, see [`NIXOS_UNITS_SNIPPET`] |

use crate::process::{ProcessCommand, ProcessRunner};
use std::path::Path;

/// The first systemd release with `systemctl soft-reboot`.
pub const MIN_SYSTEMD: u32 = 254;

/// The units a soft-reboot needs.
pub const SOFT_REBOOT_UNITS: &[&str] = &["soft-reboot.target", "systemd-soft-reboot.service"];

/// Where unit files live, relative to a root (NixOS links its units into
/// `/etc/systemd/system`).
const UNIT_DIRS: &[&str] = &[
    "etc/systemd/system",
    "run/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
];

/// The NixOS module text that installs the two units on a nixpkgs that does
/// not ship them yet (nixpkgs PR #514100). Both the decoy and a hidden NixOS
/// configuration need it.
pub const NIXOS_UNITS_SNIPPET: &str = r#"systemd.units."soft-reboot.target".text = ''
  [Unit]
  Description=Reboot System Userspace
  DefaultDependencies=no
  Requires=systemd-soft-reboot.service
  After=systemd-soft-reboot.service
  AllowIsolate=yes
  JobTimeoutSec=30min
  JobTimeoutAction=soft-reboot-force
'';
systemd.units."systemd-soft-reboot.service".text = ''
  [Unit]
  Description=Reboot System Userspace
  DefaultDependencies=no
  Requires=shutdown.target umount.target final.target
  After=shutdown.target umount.target final.target
  SuccessAction=soft-reboot-force
'';"#;

/// The major version in a systemd version string: `255.4-1ubuntu8`, `259`,
/// or `systemd 257 (257.13-1)` (the first line of `systemctl --version`).
pub fn parse_version(text: &str) -> Option<u32> {
    let text = text.trim();
    let text = text.strip_prefix("systemd ").unwrap_or(text);
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The version of the running service manager (PID 1), not of the
/// `systemctl` client: `systemctl show -p Version --value`, falling back to
/// `systemctl --version`.
pub fn running_version(runner: &dyn ProcessRunner) -> Option<u32> {
    let show = ProcessCommand::tool("systemctl")
        .args(["show", "-p", "Version", "--value"])
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    if let Ok((true, out, _)) = runner.run_text(&show)
        && let Some(version) = parse_version(&out)
    {
        return Some(version);
    }
    let version = ProcessCommand::tool("systemctl")
        .arg("--version")
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    runner
        .run_text(&version)
        .ok()
        .and_then(|(ok, out, _)| ok.then(|| parse_version(out.lines().next().unwrap_or(""))))
        .flatten()
}

/// The soft-reboot units missing below `root`.
pub fn missing_soft_reboot_units(root: &Path) -> Vec<&'static str> {
    SOFT_REBOOT_UNITS
        .iter()
        .copied()
        .filter(|unit| {
            !UNIT_DIRS
                .iter()
                .any(|dir| root.join(dir).join(unit).exists())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_from_every_form_systemd_prints() {
        assert_eq!(parse_version("255.4-1ubuntu8\n"), Some(255));
        assert_eq!(parse_version("259"), Some(259));
        assert_eq!(parse_version("systemd 257 (257.13-1)"), Some(257));
        assert_eq!(parse_version("systemd 252 (252.39-1~deb12u1)"), Some(252));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("unknown"), None);
    }

    #[test]
    fn units_are_found_in_any_unit_directory_of_the_root() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(missing_soft_reboot_units(root.path()), SOFT_REBOOT_UNITS);
        std::fs::create_dir_all(root.path().join("usr/lib/systemd/system")).unwrap();
        std::fs::write(
            root.path()
                .join("usr/lib/systemd/system/soft-reboot.target"),
            "",
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("etc/systemd/system")).unwrap();
        std::os::unix::fs::symlink(
            "/nix/store/x-unit/systemd-soft-reboot.service",
            root.path()
                .join("etc/systemd/system/systemd-soft-reboot.service"),
        )
        .unwrap();
        // A dangling link (a store path on another root) is not a unit here.
        assert_eq!(
            missing_soft_reboot_units(root.path()),
            ["systemd-soft-reboot.service"]
        );
    }
}
