// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-tool availability pre-flight check.
//!
//! NAILS shells out to a small, fixed set of host tools around a session:
//! `systemctl` enqueues the soft-reboot and power actions and reads unit state,
//! `loginctl` resolves the operator's session, and on NixOS `nix` builds the
//! hidden system. Everything else NAILS once seemed to need is done without a
//! child process: files are copied, owned and synced through syscalls, swap and
//! mounts are masked as systemd units, and programs are killed through their
//! cgroup, so `systemd-run`, `cp`, `chown`, `sync`, `swapoff` and `kill` are
//! never spawned and are not required here.
//!
//! On a host missing one of the tools that *is* spawned, the first spawn fails
//! late, after the user session may already be gone. This check resolves every
//! required tool for the detected platform through the same [`HostCommands`]
//! resolver the runner uses, and fails *before* any state is written, naming each
//! missing tool and how to install it on the detected host's family.

use super::super::{CheckResult, PreFlightCheck};
use crate::platform::{HostCommands, PlatformKind};
use crate::{Filesystem, Result};
use nails_base::Family;
use std::path::PathBuf;

/// A host tool NAILS requires, with the package that provides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequiredTool {
    tool: &'static str,
    package: &'static str,
}

/// Tools every supported platform must provide.
///
/// `systemctl` enqueues the soft-reboot and power actions and reads unit and
/// version state; `loginctl` resolves the operator's login session. Both ship in
/// the `systemd` package on every family.
const COMMON_TOOLS: &[RequiredTool] = &[
    RequiredTool {
        tool: "systemctl",
        package: "systemd",
    },
    RequiredTool {
        tool: "loginctl",
        package: "systemd",
    },
];

/// Tools only a NixOS host needs on top of [`COMMON_TOOLS`].
///
/// A hidden NixOS system is built with `nix` (flake builds) — the backend
/// spawns it directly; `nixos-rebuild` is never run.
const NIXOS_TOOLS: &[RequiredTool] = &[RequiredTool {
    tool: "nix",
    package: "nix",
}];

/// The tools required for a given platform.
fn required_tools(kind: PlatformKind) -> Vec<RequiredTool> {
    let mut tools = COMMON_TOOLS.to_vec();
    if kind == PlatformKind::NixOs {
        tools.extend_from_slice(NIXOS_TOOLS);
    }
    tools
}

/// How to install `package` on the detected host, named for its family.
fn install_hint(kind: PlatformKind, family: Option<Family>, package: &str) -> String {
    if kind == PlatformKind::NixOs {
        return format!("add {package} to the hidden system's environment.systemPackages");
    }
    match family {
        Some(Family::Debian) => format!("apt install {package}"),
        Some(Family::Fedora) => format!("dnf install {package}"),
        Some(Family::Arch) => format!("pacman -S {package}"),
        None => format!("install the {package} package"),
    }
}

/// A test override for [`HostToolsCheck`]: the search directories, the tool set
/// and the platform they stand in for. Resolution runs without the root-trust
/// check, since the sandbox is unprivileged.
#[cfg(test)]
#[derive(Debug)]
struct ProbeOverride {
    dirs: Vec<PathBuf>,
    tools: Vec<RequiredTool>,
    kind: PlatformKind,
    family: Option<Family>,
}

/// Pre-flight check that every required host tool resolves on this platform.
#[derive(Debug, Default)]
pub struct HostToolsCheck {
    /// Test override of the platform and tool set. Production leaves this `None`
    /// and detects the platform at run time.
    #[cfg(test)]
    probe: Option<ProbeOverride>,
}

impl HostToolsCheck {
    /// Create a check that detects the platform and resolves its required tools.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve each tool through `resolver`, collecting those that do not, and
    /// name how to install each missing one on the detected host's family.
    fn evaluate(
        resolver: &HostCommands,
        tools: &[RequiredTool],
        kind: PlatformKind,
        family: Option<Family>,
    ) -> CheckResult {
        let missing: Vec<RequiredTool> = tools
            .iter()
            .copied()
            .filter(|required| resolver.resolve(required.tool).is_err())
            .collect();

        if missing.is_empty() {
            return CheckResult::Pass(format!(
                "All {} required host tools are present",
                tools.len()
            ));
        }

        let mut message = String::from("Required host tools are missing. Install them and retry:");
        for item in &missing {
            message.push_str(&format!(
                "\n  {} ({})",
                item.tool,
                install_hint(kind, family, item.package)
            ));
        }
        CheckResult::fail(message)
    }
}

impl<F: Filesystem> PreFlightCheck<F> for HostToolsCheck {
    fn name(&self) -> &'static str {
        "host-tools"
    }

    fn description(&self) -> &'static str {
        "Validates the host tools NAILS spawns are present on this platform"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            let resolver = HostCommands::new(probe.dirs.iter()).with_trust_enforcement(false);
            return Ok(Self::evaluate(
                &resolver,
                &probe.tools,
                probe.kind,
                probe.family,
            ));
        }

        // Resolving real host tools touches the running host, so skip in a test
        // or test-like context exactly as the rest of the host-interacting code
        // does; the dedicated unit tests exercise the resolution directly.
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(CheckResult::Pass(
                "Host tool check skipped in test/test-like context".into(),
            ));
        }

        let profile = crate::platform::detect(fs)?;
        if profile.kind == PlatformKind::Unsupported {
            // A refused host is declined with a typed error elsewhere; there is
            // no platform search list to resolve against here.
            return Ok(CheckResult::Pass(
                "Host tool check skipped on an unsupported host".into(),
            ));
        }

        let dirs: Vec<PathBuf> = crate::platform::platform_for::<F>(&profile)
            .host_command_dirs()
            .iter()
            .map(PathBuf::from)
            .collect();
        let resolver = HostCommands::new(dirs.iter());
        Ok(Self::evaluate(
            &resolver,
            &required_tools(profile.kind),
            profile.kind,
            profile.family,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    impl HostToolsCheck {
        fn with_probe(
            dirs: Vec<PathBuf>,
            tools: Vec<RequiredTool>,
            kind: PlatformKind,
            family: Option<Family>,
        ) -> Self {
            Self {
                probe: Some(ProbeOverride {
                    dirs,
                    tools,
                    kind,
                    family,
                }),
            }
        }
    }

    fn write_executable(path: &std::path::Path) {
        fs::write(path, "#!/bin/sh\n").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn passes_when_every_required_tool_resolves() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        write_executable(&dir.join("systemctl"));
        write_executable(&dir.join("loginctl"));

        let check = HostToolsCheck::with_probe(
            vec![dir],
            COMMON_TOOLS.to_vec(),
            PlatformKind::Fhs,
            Some(Family::Debian),
        );
        let result = check.run(&MockFilesystem::new()).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn fails_with_a_per_family_install_hint_when_a_tool_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        write_executable(&dir.join("systemctl"));
        // `loginctl` is deliberately absent.

        for (family, hint) in [
            (Family::Debian, "apt install systemd"),
            (Family::Fedora, "dnf install systemd"),
            (Family::Arch, "pacman -S systemd"),
        ] {
            let check = HostToolsCheck::with_probe(
                vec![dir.clone()],
                COMMON_TOOLS.to_vec(),
                PlatformKind::Fhs,
                Some(family),
            );
            let result = check.run(&MockFilesystem::new()).unwrap();
            assert!(result.is_fail(), "{family:?}: {result:?}");
            let message = result.message();
            assert!(message.contains("loginctl"), "{message}");
            assert!(message.contains(hint), "{family:?}: {message}");
            // A present tool is not named in the remediation list.
            assert!(!message.contains("systemctl ("), "{message}");
        }
    }

    #[test]
    fn a_missing_tool_on_nixos_points_at_the_hidden_system() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("bin");
        fs::create_dir_all(&dir).unwrap();
        // Nothing is installed, so `nix` is reported missing.
        let check =
            HostToolsCheck::with_probe(vec![dir], NIXOS_TOOLS.to_vec(), PlatformKind::NixOs, None);
        let result = check.run(&MockFilesystem::new()).unwrap();
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains("environment.systemPackages"),
            "{}",
            result.message()
        );
    }

    #[test]
    fn skips_in_test_context_without_a_probe() {
        // Without a probe override the check short-circuits to a skipped Pass in a
        // test runtime, so it never touches the real host from the shared registry.
        let check = HostToolsCheck::new();
        let result = check.run(&MockFilesystem::new()).unwrap();
        assert!(result.is_pass(), "{result:?}");
    }

    #[test]
    fn tools_nails_never_spawns_are_not_required() {
        // Audited away: `systemd-run` is never run; `cp`, `chown` and `sync` are
        // syscalls, not binaries; `swapoff` is a masked systemd unit; `kill` goes
        // through the cgroup; `nixos-rebuild` is replaced by `nix`. Opaque handling
        // and directory walks are in-process, so `getfattr`/`du`/`find` are gone
        // too. Requiring any of them would refuse pre-flight on a host without a
        // package it does not need.
        let fhs = required_tools(PlatformKind::Fhs);
        let nixos = required_tools(PlatformKind::NixOs);
        for absent in [
            "systemd-run",
            "cp",
            "chown",
            "sync",
            "swapoff",
            "kill",
            "nixos-rebuild",
            "getfattr",
            "setfattr",
            "du",
            "find",
        ] {
            assert!(
                !fhs.iter().chain(&nixos).any(|t| t.tool == absent),
                "{absent} is no longer spawned and must not be required"
            );
        }
    }

    #[test]
    fn nixos_requires_nix_on_top_of_the_common_set() {
        let nixos = required_tools(PlatformKind::NixOs);
        let fhs = required_tools(PlatformKind::Fhs);
        assert!(nixos.iter().any(|t| t.tool == "nix"));
        assert!(!fhs.iter().any(|t| t.tool == "nix"));
        for common in ["systemctl", "loginctl"] {
            assert!(fhs.iter().any(|t| t.tool == common), "{common}");
            assert!(nixos.iter().any(|t| t.tool == common), "{common}");
        }
    }

    /// Every tool the check requires must have a real spawn site in the product
    /// source, so the audited-away tools cannot creep back into the required set.
    #[test]
    fn every_required_tool_has_a_spawn_site() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root is above nails-core");
        let mut sources = String::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(read) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in read.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    // The crate sources only: skip build output, VCS and hidden dirs.
                    if name == "target" || name.starts_with('.') {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if !path.extension().is_some_and(|ext| ext == "rs") {
                    continue;
                }
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Skip test code (so a test-only spawn cannot validate a tool) and
                // this module, which holds the required-tool table, not a spawn.
                if name == "tests.rs"
                    || name.ends_with("_tests.rs")
                    || name == "host_tools.rs"
                    || path
                        .components()
                        .any(|c| c.as_os_str().to_str() == Some("tests"))
                {
                    continue;
                }
                if let Ok(text) = fs::read_to_string(&path) {
                    sources.push_str(&text);
                }
            }
        }
        // Guard against the scan reading nothing (a moved workspace root).
        assert!(
            sources.contains("tool(\"systemctl\")"),
            "the source scan found no spawn sites at all"
        );
        for required in required_tools(PlatformKind::NixOs) {
            let spawned = sources.contains(&format!("tool(\"{}\")", required.tool))
                || sources.contains(&format!("caller_path(\"{}\")", required.tool));
            assert!(
                spawned,
                "{} is required but NAILS has no spawn site for it",
                required.tool
            );
        }
    }
}
