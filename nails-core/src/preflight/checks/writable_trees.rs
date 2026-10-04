// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Refuse activation when a base-OS tree would be left writable on the decoy.
//!
//! The decoy-stays-read-only invariant ([`crate::platform::ro_guard`]) says every
//! writable OS tree is either overlaid (hidden writes land in the upper) or kept
//! read-only (hidden writes are refused). This check verifies the invariant for
//! the computed plan *before* anything is mounted: it takes the platform's overlay
//! policy, the overlay targets the configuration resolves to, and the read-only
//! trees the policy guards, and fails if any base-OS tree that is a real directory
//! on the host is neither overlaid nor read-only. That catches, for example, a
//! configuration that excludes `/usr` from overlay on a host whose policy does not
//! keep `/usr` read-only, which would leak package payloads to the decoy disk.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::config::{Config, OverlayMode};
use crate::filesystem::Filesystem;
use crate::preflight::{CheckResult, PreFlightCheck};

/// Top-level trees that hold executables and libraries. A writable, non-overlaid
/// one of these leaks package payloads and `/usr/local` writes to the decoy disk,
/// where `debsums`/`rpm -Va` detect the unowned files.
const OS_TREES: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];

/// Pre-flight check for the writable-tree invariant.
#[derive(Debug, Clone)]
pub struct WritableTreesCheck {
    config: Config,
}

impl WritableTreesCheck {
    /// Create the check for `config`.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn overlay_targets<F: Filesystem>(&self, fs: &F) -> Result<Vec<PathBuf>> {
        match self.config.overlay_mode {
            OverlayMode::Auto => crate::build_overlay_targets(fs, &self.config),
            OverlayMode::Explicit => Ok(self
                .config
                .overlays
                .iter()
                .map(|overlay| overlay.target.clone())
                .collect()),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for WritableTreesCheck {
    fn name(&self) -> &'static str {
        "writable-trees"
    }

    fn description(&self) -> &'static str {
        "Refuses activation when a base-OS tree would stay writable on the decoy (neither overlaid nor read-only)"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let policy = crate::platform::detect_platform(fs)?.overlay_policy();
        let targets = self.overlay_targets(fs)?;
        let read_only = policy.resolve_read_only(fs)?;

        let mut leaking = Vec::new();
        for tree in OS_TREES {
            let path = Path::new(tree);
            // A usr-merge symlink resolves into /usr, which is checked on its own.
            if fs.is_symlink(path)? {
                continue;
            }
            // Only trees that actually exist as directories can leak.
            if !fs.is_directory(path)? {
                continue;
            }
            let overlaid = targets.iter().any(|target| target == path);
            let guarded = read_only.iter().any(|guarded| guarded == path);
            if !overlaid && !guarded {
                leaking.push(path.display().to_string());
            }
        }

        if !leaking.is_empty() {
            return Ok(CheckResult::fail(format!(
                "these base-OS trees would stay writable on the decoy (neither overlaid nor kept \
                 read-only), leaking the hidden session's package and /usr writes to the decoy \
                 disk: {}. Overlay them or keep them read-only for the session.",
                leaking.join(", ")
            )));
        }

        Ok(CheckResult::Pass(format!(
            "every base-OS tree is overlaid or kept read-only ({} overlay target(s), {} read-only tree(s))",
            targets.len(),
            read_only.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OverlayMode;
    use crate::filesystem::{MockFilesystem, PathKind};

    /// A mock host with the given os-release ID and a systemd PID 1, plus the
    /// root directories a session would enumerate.
    fn host(os_release: &str, roots: &[&str]) -> MockFilesystem {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", os_release);
        fs.mock_add_file("/proc/1/comm", "systemd");
        fs.mock_set_path_type("/", PathKind::Dir);
        fs.mock_set_root_directories(roots.iter().map(PathBuf::from).collect());
        for root in roots {
            fs.mock_set_path_type(root, PathKind::Dir);
        }
        fs
    }

    fn auto_config() -> Config {
        Config {
            overlay_mode: OverlayMode::Auto,
            ..Config::default()
        }
    }

    #[test]
    fn debian_default_keeps_usr_read_only_and_passes() {
        // /usr real, the core-root symlinks resolve into it.
        let fs = host(
            "ID=debian\nVERSION_ID=\"12\"\n",
            &["/usr", "/etc", "/home", "/var"],
        );
        for link in ["/bin", "/sbin", "/lib", "/lib64"] {
            fs.mock_set_is_symlink(link, true);
        }

        let result = WritableTreesCheck::new(auto_config()).run(&fs).unwrap();
        assert!(result.is_pass(), "{}", result.message());
    }

    #[test]
    fn nixos_default_overlays_usr_and_passes() {
        // On NixOS /usr and /bin are overlay targets, so neither leaks.
        let fs = host(
            "ID=nixos\nVERSION_ID=\"24.11\"\n",
            &["/usr", "/bin", "/etc", "/nix"],
        );

        let result = WritableTreesCheck::new(auto_config()).run(&fs).unwrap();
        assert!(result.is_pass(), "{}", result.message());
    }

    #[test]
    fn nixos_auto_mode_overlays_a_real_lib64() {
        // A stock NixOS root keeps a real /lib64 for the ld-linux shim. Auto mode
        // must overlay it, since the NixOS policy keeps nothing read-only.
        let fs = host(
            "ID=nixos\nVERSION_ID=\"24.11\"\n",
            &["/usr", "/bin", "/lib64", "/etc", "/nix"],
        );

        let result = WritableTreesCheck::new(auto_config()).run(&fs).unwrap();
        assert!(result.is_pass(), "{}", result.message());
    }

    #[test]
    fn excluding_usr_without_a_read_only_guard_is_refused() {
        // A NixOS host (no read-only guard) where the operator excludes /usr from
        // overlay: /usr is then neither overlaid nor read-only, which must fail.
        let fs = host(
            "ID=nixos\nVERSION_ID=\"24.11\"\n",
            &["/usr", "/etc", "/nix"],
        );
        let mut config = auto_config();
        config.overlay_exclusions = vec![PathBuf::from("/usr")];

        let result = WritableTreesCheck::new(config).run(&fs).unwrap();
        assert!(result.is_fail(), "{}", result.message());
        assert!(result.message().contains("/usr"), "{}", result.message());
    }
}
