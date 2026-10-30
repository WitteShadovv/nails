// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! NixOS build target validation pre-flight check
//!
//! Validates that the NixOS build target (flake reference or legacy config)
//! will resolve before any destructive operations begin.

use super::super::{CheckResult, PreFlightCheck};
use crate::nixos::{resolve_local_flake_dir, split_flake_ref};
use crate::platform::{HiddenFlake, HostTarget, hidden_flake};
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// Validates the NixOS build target reference will resolve
///
/// When an explicit `--flake` is provided, validates:
/// - It is one NAILS can tell how Nix reads: a path (absolute, or `./`,
///   `../`, `.` or `..`), a `path:` reference, a URL whose transport is a
///   local file with no authority (`git+file:///srv/cfg`), or a plain remote
///   reference (`github:owner/repo`, `git+https://example.org/repo`). Any
///   other is refused whatever it names: a local URL with an authority
///   (`git+file://../../etc/nixos`) and any other reference Nix may read as
///   a path relative to the working directory (`a_b:x`), a registry alias
///   written `flake:<name>`, which Nix looks up in its registries, and a
///   relative path without `./`, which takes in a name alone
/// - The directory exists
/// - The directory contains a `flake.nix`
/// - It is not the decoy's own `/etc/nixos` flake or a directory below it,
///   compared by device and inode, the links on the way followed (discovery
///   reports that as [`HostTarget::DecoyFlake`]). These readings are
///   checked: a local reference's path in each spelling (percent-escapes
///   decoded or not, a `dir` parameter, a repository's `.git` directory),
///   and the whole reference as a path relative to the working directory, as
///   Nix reads one it cannot parse as a URL, where that path exists; each as
///   written, its links and `..` resolved by the kernel as Nix resolves a
///   path and `git+file:`, and with `.` and `..` applied by the text as Nix
///   applies them to `path:`
///
/// When no flake is specified, it reports the target the host's platform
/// discovered ([`discover_host_target`](crate::platform::discover_host_target)),
/// the same answer activation and `check`/`--dry-run` use. It fails when the
/// platform found none, or only the decoy's own flake, which activation
/// refuses to build (with instructions for a hidden flake).
///
/// This is separate from `NixOSConfigCheck` which validates the hidden storage
/// overlay structure (symlinks, imports). This check validates the build target
/// reference itself.
#[derive(Debug, Clone)]
pub struct NixOSBuildTargetCheck {
    nixos_flake: Option<String>,
    selected_flake_dir: Option<PathBuf>,
    discovered: HostTarget,
}

impl NixOSBuildTargetCheck {
    /// Create a new NixOSBuildTargetCheck
    ///
    /// # Arguments
    ///
    /// * `nixos_flake` - Optional flake reference from config/CLI (e.g., "/mnt/data/nixos#my-host")
    /// * `discovered` - The build target the host's platform discovered
    pub fn new(nixos_flake: Option<String>, discovered: HostTarget) -> Self {
        Self {
            nixos_flake,
            selected_flake_dir: None,
            discovered,
        }
    }

    /// Create a new NixOSBuildTargetCheck for a pre-selected flake build target.
    ///
    /// This is used when activation has already selected a flake directory via
    /// auto-discovery. In that case preflight must validate the chosen flake
    /// directly rather than falling back to legacy detection.
    pub fn with_selected_flake_dir(
        nixos_flake: Option<String>,
        selected_flake_dir: Option<PathBuf>,
        discovered: HostTarget,
    ) -> Self {
        Self {
            nixos_flake,
            selected_flake_dir,
            discovered,
        }
    }

    /// Validate an explicit flake reference
    fn check_explicit_flake<F: Filesystem>(&self, fs: &F, flake_ref: &str) -> Result<CheckResult> {
        let (base_ref, _) = split_flake_ref(flake_ref);
        let Some(dir) = resolve_local_flake_dir(base_ref)? else {
            return Ok(CheckResult::Pass(format!(
                "Flake build target '{}' validated as a generic flake reference",
                flake_ref
            )));
        };

        // Check 2: Directory must exist
        if !fs.path_exists(&dir)? {
            return Ok(CheckResult::fail(format!(
                "Flake directory '{}' not found.",
                dir.display()
            )));
        }

        // Check 3: flake.nix must exist in directory
        let flake_nix = dir.join("flake.nix");
        if !fs.path_exists(&flake_nix)? {
            return Ok(CheckResult::fail(format!(
                "flake.nix not found in '{}'.",
                dir.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Flake build target '{}' validated (attribute selection deferred to build time)",
            flake_ref
        )))
    }

    fn check_selected_flake_dir<F: Filesystem>(&self, fs: &F, dir: &Path) -> Result<CheckResult> {
        if !fs.path_exists(dir)? {
            return Ok(CheckResult::fail(format!(
                "Flake directory '{}' not found.",
                dir.display()
            )));
        }

        let flake_nix = dir.join("flake.nix");
        if !fs.path_exists(&flake_nix)? {
            return Ok(CheckResult::fail(format!(
                "flake.nix not found in '{}'.",
                dir.display()
            )));
        }

        Ok(CheckResult::Pass(format!(
            "Flake build target '{}' validated",
            dir.display()
        )))
    }

    /// Report the auto-discovered build target.
    ///
    /// The target comes from the host's platform through
    /// [`discover_host_target`](crate::platform::discover_host_target), shared with
    /// activation and the `check`/`--dry-run` summary, so the pre-flight check can
    /// never disagree with the target activation would actually build. In
    /// particular a lone system profile resolves to the same legacy build target
    /// here as it does on the activation path.
    fn check_auto_discovery(&self) -> CheckResult {
        match &self.discovered {
            HostTarget::Flake(dir) => {
                CheckResult::Pass(format!("Auto-discovered flake at {}", dir.display()))
            }
            HostTarget::DecoyFlake {
                dir,
                hidden_volume_root,
            } => decoy_flake_refusal(dir, hidden_volume_root, HiddenFlake::Missing),
            HostTarget::Legacy(path) => CheckResult::Pass(format!(
                "Auto-discovered legacy config at {}",
                path.display()
            )),
            // An explicit reference is validated by `check_explicit_flake` before
            // this runs; mapping it keeps the check total.
            HostTarget::ExplicitFlake(flake_ref) => {
                CheckResult::Pass(format!("Auto-discovered flake reference {flake_ref}"))
            }
            HostTarget::OverlayOnly => {
                CheckResult::Pass("Overlay-only: no NixOS build target".to_string())
            }
            HostTarget::None => CheckResult::fail(
                "No NixOS configuration found. Provide --nixos-flake, put a hidden flake in <hidden-root>/nixos, or ensure /etc/nixos contains configuration.nix.".to_string()
            ),
        }
    }
}

/// The refusal of the decoy's own flake in `dir`, with what to put in its
/// place on the hidden volume at `hidden_volume_root`. `hidden` tells a hidden
/// flake that is there but not chosen (the decoy's flake was named with
/// `--nixos-flake` or `nixos_flake`) from one that is missing, and from a
/// hidden flake directory that is the decoy's flake, or a directory below
/// it, through a link or a bind mount.
pub(crate) fn decoy_flake_refusal(
    dir: &Path,
    hidden_volume_root: &Path,
    hidden: HiddenFlake,
) -> CheckResult {
    let hidden_flake = hidden_volume_root.join("nixos");
    let write = format!(
        "Write a self-contained flake in {} and lock it from inside a hidden session \
         (`activate --overlay-only` enters one with the decoy's own system), never on \
         the decoy, where an editor, nix's cache and the nixpkgs it fetches would leave \
         traces. Its configuration for this machine's hostname imports the hidden \
         module {} and reads no file of the decoy: copy what it needs from {} into the \
         flake. Activation never updates flake.lock, so it must exist. --nixos-flake \
         names such a flake elsewhere.",
        hidden_flake.display(),
        hidden_volume_root
            .join("config/nixos/configuration.nix")
            .display(),
        dir.display()
    );
    let (found, remedy) = match hidden {
        HiddenFlake::Present => (
            format!(
                "{} holds the decoy's own flake, and --nixos-flake or nixos_flake names it",
                dir.display()
            ),
            format!(
                "Name the hidden flake in {} instead, or leave --nixos-flake and nixos_flake \
                 unset: activation then builds that flake by itself.",
                hidden_flake.display()
            ),
        ),
        HiddenFlake::Missing => (
            format!(
                "{} holds the decoy's own flake and {} holds none",
                dir.display(),
                hidden_flake.display()
            ),
            write,
        ),
        HiddenFlake::DecoyFlake => (
            format!(
                "{} is {} or a directory below it, the decoy's own flake, through a link or a \
                 bind mount",
                hidden_flake.display(),
                dir.display()
            ),
            format!(
                "Remove the link or the bind mount {}. {write}",
                hidden_flake.display()
            ),
        ),
    };
    CheckResult::fail_with(
        format!(
            "{found}. A hidden system built from the decoy's files would lack the hidden \
             module and the hidden hardware configuration (the one without the decoy's \
             swap), so activation does not build it."
        ),
        remedy,
    )
}

impl<F: Filesystem> PreFlightCheck<F> for NixOSBuildTargetCheck {
    fn name(&self) -> &'static str {
        "nixos-build-target"
    }

    fn description(&self) -> &'static str {
        "Validates NixOS build target reference will resolve"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // The decoy's own flake is refused however it was reached: found by
        // the probes, or named with --nixos-flake or `nixos_flake` (in each
        // local spelling of /etc/nixos that discovery resolves).
        if let HostTarget::DecoyFlake {
            dir,
            hidden_volume_root,
        } = &self.discovered
        {
            let hidden = hidden_flake(fs, hidden_volume_root)?;
            return Ok(decoy_flake_refusal(dir, hidden_volume_root, hidden));
        }
        if let Some(ref flake_ref) = self.nixos_flake {
            self.check_explicit_flake(fs, flake_ref)
        } else if let Some(ref selected_flake_dir) = self.selected_flake_dir {
            self.check_selected_flake_dir(fs, selected_flake_dir)
        } else {
            Ok(self.check_auto_discovery())
        }
    }
}

#[cfg(test)]
#[path = "nixos_build_target_tests.rs"]
mod tests;
