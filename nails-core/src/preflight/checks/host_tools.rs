// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-tool availability pre-flight check.
//!
//! NAILS shells out to a small, fixed set of host tools around a session:
//! `systemctl` enqueues the soft-reboot and power actions and reads unit state,
//! `loginctl` resolves the operator's session, and on NixOS `nix` builds the
//! hidden system. The way back runs two more: `ip` deletes the links a session
//! made and sets each device's recorded hardware address back, and, when the
//! hidden volume is backed by device-mapper (dm-crypt, LUKS, a VeraCrypt
//! mapping), `dmsetup` marks that stack for deferred removal, so the mapping and
//! its key leave the kernel at the switch. Everything else NAILS once seemed to
//! need is done without a child process: files are copied, owned and synced
//! through syscalls, swap and mounts are masked as systemd units, and programs
//! are killed through their cgroup, so `systemd-run`, `cp`, `chown`, `sync`,
//! `swapoff` and `kill` are never spawned and are not required here.
//!
//! On a host missing one of the tools that *is* spawned, the first spawn fails
//! late, after the user session may already be gone, and the way back, best
//! effort throughout, skips the work of a tool it cannot find without a word: the
//! hidden mapping would stay open on the decoy, or a session's links and
//! addresses would stay behind. This check resolves every required tool for the
//! detected platform and hidden-volume backend through the same
//! [`HostCommands`] resolver the runner uses, and fails *before* any state is
//! written, naming each missing tool and how to install it with the package
//! manager of the detected host's family ([`install_hint`]).

use super::super::{CheckResult, PreFlightCheck};
use crate::backend_lock::resolve_backend_chain;
use crate::platform::{HostCommands, Package, PlatformKind, install_hint};
use crate::{Filesystem, Result};
use nails_base::Family;
use std::path::{Path, PathBuf};

/// A host tool NAILS requires, with the package that provides it on each
/// family. The names can differ: Fedora ships `ip` in `iproute`, Fedora and
/// Arch ship `dmsetup` in `device-mapper`, and nixpkgs ships it in `lvm2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequiredTool {
    tool: &'static str,
    package: Package,
}

/// Tools every supported platform must provide.
///
/// `systemctl` enqueues the soft-reboot and power actions and reads unit and
/// version state; `loginctl` resolves the operator's login session. Both ship in
/// the `systemd` package on every family. Every way back runs `ip` (iproute2)
/// to delete the links a session made and set hardware addresses back.
const COMMON_TOOLS: &[RequiredTool] = &[
    RequiredTool {
        tool: "systemctl",
        package: Package::everywhere("systemd"),
    },
    RequiredTool {
        tool: "loginctl",
        package: Package::everywhere("systemd"),
    },
    RequiredTool {
        tool: "ip",
        package: Package {
            debian: "iproute2",
            fedora: "iproute",
            arch: "iproute2",
            nixos: "iproute2",
        },
    },
];

/// Tools only a NixOS host needs on top of [`COMMON_TOOLS`].
///
/// A hidden NixOS system is built with `nix` (flake builds) — the backend
/// spawns it directly; `nixos-rebuild` is never run.
const NIXOS_TOOLS: &[RequiredTool] = &[RequiredTool {
    tool: "nix",
    package: Package::everywhere("nix"),
}];

/// Tools a hidden volume backed by device-mapper needs on top of
/// [`COMMON_TOOLS`].
///
/// The way back marks the hidden volume's device-mapper stack for deferred
/// removal with `dmsetup`, and the decoy side closes what an interrupted entry
/// left open with it.
const DEVICE_MAPPER_TOOLS: &[RequiredTool] = &[RequiredTool {
    tool: "dmsetup",
    package: Package {
        debian: "dmsetup",
        fedora: "device-mapper",
        arch: "device-mapper",
        nixos: "lvm2",
    },
}];

/// The tools required for a given platform and hidden-volume backend.
fn required_tools(kind: PlatformKind, device_mapper: bool) -> Vec<RequiredTool> {
    let mut tools = COMMON_TOOLS.to_vec();
    if kind == PlatformKind::NixOs {
        tools.extend_from_slice(NIXOS_TOOLS);
    }
    if device_mapper {
        tools.extend_from_slice(DEVICE_MAPPER_TOOLS);
    }
    tools
}

/// Whether the way back may run `dmsetup` for the hidden volume at
/// `hidden_root`.
///
/// Activation records the device-mapper stack [`resolve_backend_chain`] finds
/// behind the hidden root, and the way back runs `dmsetup` on each name in it; a
/// plain block device records none. When the stack cannot be resolved (the
/// mount table is unreadable, or nothing is mounted at the hidden root yet) the
/// backend is unknown and counts as device-mapper, so `dmsetup` is required.
fn backend_may_be_device_mapper<F: Filesystem>(fs: &F, hidden_root: &Path) -> bool {
    match resolve_backend_chain(fs, hidden_root) {
        Ok(Some(chain)) => chain.is_device_mapper(),
        Ok(None) | Err(_) => true,
    }
}

/// A test override for [`HostToolsCheck`]: the search directories and the
/// platform they stand in for. Resolution runs without the root-trust check,
/// since the sandbox is unprivileged.
#[cfg(test)]
#[derive(Debug)]
struct ProbeOverride {
    dirs: Vec<PathBuf>,
    kind: PlatformKind,
    family: Option<Family>,
}

/// Pre-flight check that every required host tool resolves on this platform.
#[derive(Debug)]
pub struct HostToolsCheck {
    /// The hidden volume root, whose backend decides whether `dmsetup` is
    /// required.
    hidden_volume_root: PathBuf,
    /// Test override of the platform. Production leaves this `None` and detects
    /// the platform at run time.
    #[cfg(test)]
    probe: Option<ProbeOverride>,
}

impl HostToolsCheck {
    /// Create a check that detects the platform and the backend of the hidden
    /// volume at `hidden_volume_root`, and resolves the tools they require.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            #[cfg(test)]
            probe: None,
        }
    }

    /// The tools this host requires: the platform's, and `dmsetup` when the
    /// hidden volume is, or may be, backed by device-mapper.
    fn required<F: Filesystem>(&self, fs: &F, kind: PlatformKind) -> Vec<RequiredTool> {
        required_tools(
            kind,
            backend_may_be_device_mapper(fs, &self.hidden_volume_root),
        )
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
                &self.required(fs, probe.kind),
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
            &self.required(fs, profile.kind),
            profile.kind,
            profile.family,
        ))
    }
}

#[cfg(test)]
#[path = "host_tools_tests.rs"]
mod tests;
