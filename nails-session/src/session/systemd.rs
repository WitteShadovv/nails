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
//! | Ubuntu 26.04 resolute | 259 | supported |
//! | NixOS 25.11 | 258 | supported; its nixpkgs lacks the two units, see [`NIXOS_UNITS_SNIPPET`] |
//! | NixOS 26.05 and later | 260+ | supported |

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
/// `systemctl` client: its `Version` property, falling back to `systemctl
/// --version`.
///
/// The property is asked for alone (`busctl get-property`, the `Get` call).
/// `systemctl show -p Version` asks for every property of PID 1 and picks one
/// (`GetAll`), and PID 1 then works out its taint list as well, for which it
/// reads `/etc/os-release` and `/etc/adjtime` on the decoy disk and updates
/// their access times.
pub fn running_version(runner: &dyn ProcessRunner) -> Option<u32> {
    let get = ProcessCommand::tool("busctl")
        .args([
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "Version",
        ])
        .deadline(crate::process::run::SYSTEMCTL_PROBE_BUDGET);
    if let Ok((true, out, _)) = runner.run_text(&get)
        && let Some(version) = busctl_string(&out).and_then(parse_version)
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

/// The value `busctl get-property` prints for a property of type `s`, its
/// signature and quotes taken off: `s "257.9-1~deb13u1"` is `257.9-1~deb13u1`.
fn busctl_string(text: &str) -> Option<&str> {
    text.trim()
        .strip_prefix("s ")?
        .strip_prefix('"')?
        .strip_suffix('"')
}

/// Whether `unit` is installed in `root`, resolved as if `root` were `/`: on
/// NixOS the unit directory is a link into `/etc/static` and the store, so
/// following it on the running system would look at the wrong root's units.
fn unit_in_root(root: &Path, unit: &str) -> bool {
    UNIT_DIRS.iter().any(|dir| {
        nails_teardown::whole_root::nextroot::exists_in_root(
            root,
            &Path::new("/").join(dir).join(unit),
        )
    })
}

/// The soft-reboot units missing in `root`.
pub fn missing_soft_reboot_units(root: &Path) -> Vec<&'static str> {
    SOFT_REBOOT_UNITS
        .iter()
        .copied()
        .filter(|unit| !unit_in_root(root, unit))
        .collect()
}

/// The `units` installed in `root`.
pub fn units_in_root(root: &Path, units: &[&str]) -> Vec<String> {
    units
        .iter()
        .filter(|unit| unit_in_root(root, unit))
        .map(|unit| (*unit).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_property_parses_as_busctl_prints_it() {
        let parsed = |text: &str| busctl_string(text).and_then(parse_version);
        assert_eq!(parsed("s \"257.9-1~deb13u1\"\n"), Some(257));
        assert_eq!(parsed("s \"259\""), Some(259));
        assert_eq!(parsed("s \"\""), None);
        assert_eq!(parsed("257.9"), None, "no signature");
        assert_eq!(parsed("u 257"), None, "not a string");
    }

    /// A runner that answers `busctl` with `busctl` and `systemctl` with
    /// `systemctl`, an empty answer as a failure, and records each command.
    struct Answers {
        busctl: &'static str,
        systemctl: &'static str,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl ProcessRunner for Answers {
        fn run(&self, command: &ProcessCommand) -> crate::Result<std::process::Output> {
            use std::os::unix::process::ExitStatusExt;
            let asked = format!("{command:?}");
            let answer = if asked.contains("Tool(\"busctl\")") {
                self.busctl
            } else {
                self.systemctl
            };
            self.asked.borrow_mut().push(asked);
            let code = if answer.is_empty() { 1 } else { 0 };
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: answer.as_bytes().to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    /// The version comes from PID 1's one property, asked for alone, never
    /// with `systemctl show`, and from the client's `--version` where that
    /// fails.
    #[test]
    fn the_running_version_asks_pid_1_for_its_version_alone() {
        let runner = Answers {
            busctl: "s \"258.1\"\n",
            systemctl: "systemd 257 (257.9-1)\n",
            asked: Default::default(),
        };
        assert_eq!(running_version(&runner), Some(258));
        let asked = runner.asked.borrow();
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert!(asked[0].contains("\"get-property\""), "{asked:?}");
        assert!(asked[0].contains("\"Version\""), "{asked:?}");

        let runner = Answers {
            busctl: "",
            systemctl: "systemd 257 (257.9-1)\n",
            asked: Default::default(),
        };
        assert_eq!(running_version(&runner), Some(257));
        let asked = runner.asked.borrow();
        assert!(
            asked.iter().all(|call| !call.contains("\"show\"")),
            "{asked:?}"
        );
    }

    #[test]
    fn versions_parse_from_every_form_systemd_prints() {
        assert_eq!(parse_version("255.4-1ubuntu8\n"), Some(255));
        assert_eq!(parse_version("259"), Some(259));
        assert_eq!(parse_version("systemd 257 (257.13-1)"), Some(257));
        assert_eq!(parse_version("systemd 252 (252.39-1~deb12u1)"), Some(252));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("unknown"), None);
    }

    /// The version as the two probes print it in a NixOS VM (fixture README):
    /// the first line of `systemctl --version`, and `systemctl show -p Version
    /// --value` when that capture exists.
    #[test]
    fn the_captured_systemd_versions_parse() {
        let Some(line) = crate::kernel_fixtures::vm("systemd-version.txt") else {
            return;
        };
        let version = parse_version(&line).expect("the captured --version line parses");
        assert!(version >= MIN_SYSTEMD, "{line}");
        if let Some(show) = crate::kernel_fixtures::vm("systemd-show-version.txt") {
            assert_eq!(parse_version(&show), Some(version), "{show}");
        }
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

    #[test]
    fn only_the_units_the_root_has_are_named() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("lib/systemd/system")).unwrap();
        std::fs::write(
            root.path().join("lib/systemd/system/grub-common.service"),
            "",
        )
        .unwrap();
        assert_eq!(
            units_in_root(
                root.path(),
                &["systemd-boot-random-seed.service", "grub-common.service"]
            ),
            ["grub-common.service"]
        );
        assert!(units_in_root(root.path(), &[]).is_empty());
    }

    #[test]
    fn an_absolute_link_resolves_inside_the_root() {
        // NixOS: /etc/systemd/system -> /etc/static/systemd/system, an absolute
        // link that must resolve in this root, not on the running system.
        let root = tempfile::tempdir().unwrap();
        let units = root.path().join("etc/static/systemd/system");
        std::fs::create_dir_all(&units).unwrap();
        for unit in SOFT_REBOOT_UNITS {
            std::fs::write(units.join(unit), "").unwrap();
        }
        std::fs::create_dir_all(root.path().join("etc/systemd")).unwrap();
        std::os::unix::fs::symlink(
            "/etc/static/systemd/system",
            root.path().join("etc/systemd/system"),
        )
        .unwrap();
        assert!(missing_soft_reboot_units(root.path()).is_empty());
        std::fs::remove_dir_all(&units).unwrap();
        assert_eq!(missing_soft_reboot_units(root.path()), SOFT_REBOOT_UNITS);
    }
}
