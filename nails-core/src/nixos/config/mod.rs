// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! NixOS Configuration Manipulation
//!
//! Provides functions for preparing, validating, and injecting NixOS
//! configuration overlays.
//!
//! # Key Concepts
//!
//! **Property 1: Forensically Clean Base**
//! Base /etc/nixos/hardware-configuration.nix contains zero evidence of
//! hidden environment. Indistinguishable from standard NixOS installation.
//!
//! **Property 2: Standard NixOS Mechanism**
//! Uses native NixOS `imports = [...]` array for configuration injection.
//! No custom patches or binary modifications required.
//!
//! **Property 3: Atomic Transitions**
//! Overlay mount is atomic (all-or-nothing). Config switch happens instantly
//! via /etc overlay. Clean rollback on failure.
//!
//! # Architecture
//!
//! The configuration overlay works by:
//! 1. Validating hidden storage has required NixOS configuration structure
//! 2. Staging a symlink from `{hidden}/etc/nixos/nails/configuration.nix` to
//!    `{hidden}/config/nixos/configuration.nix`
//! 3. Moving the original `hardware-configuration.nix` aside to
//!    `hardware-configuration.base.nix` and replacing it with a fixed wrapper
//!    that imports both the base file and `./nails/configuration.nix`
//! 4. The wrapper is always valid Nix regardless of the original file's shape,
//!    and the import resolves via the symlink to the hidden configuration
//!
//! The wrapper never parses or edits the original Nix source, so it cannot
//! produce invalid output; a preflight step runs `nix-instantiate --parse` over
//! the composed files to catch syntax errors before any overlay is mounted.

mod inject;
mod prepare;
mod verify;

#[cfg(test)]
mod tests;

// Re-export public API
pub use inject::{NixParser, RealNixParser, inject_import_block, parse_check_composed_config};
pub use prepare::{
    ensure_hidden_configuration_module, ensure_hidden_hardware_configuration,
    prepare_nixos_config_overlay, stage_hidden_config_symlink, stage_hidden_nixos_config,
};
pub use verify::verify_base_config_clean;

use std::path::PathBuf;

/// Seed written as the hidden module when a volume has none yet.
///
/// It is a complete, valid NixOS module whose optional settings are commented
/// out, so a fresh volume composes and parses without changing the decoy's
/// behaviour beyond the always-on safety settings. The
/// operator uncomments the hidden-session settings they want. Keeping it a
/// commented template (not an empty module) documents the switches that exist —
/// volatile journald, an emergency teardown unit and a session indicator —
/// without turning them on by default. Two settings are always on: the decoy's
/// automatic upgrade is forced off, and interactive shells keep no history file,
/// so a hidden-session shell that outlives the teardown cannot write its history
/// to the decoy home. It must stay
/// valid Nix: `nix-instantiate --parse` runs over the composed configuration
/// before any overlay is mounted.
pub(crate) const AUTO_GENERATED_HIDDEN_CONFIGURATION: &str = r#"{ config, lib, pkgs, ... }:
# Hidden-session configuration.
#
# This module is imported only while the hidden environment is active. The
# optional settings below are commented out: uncomment the ones you want and keep
# the file valid Nix (the trailing attribute set must stay intact).
{
  # Force the decoy's automatic upgrade off while the hidden session is active.
  # An unattended rebuild would rewrite the decoy system profile and can touch
  # EFI NVRAM, both of which are forensic tells; this stays on unconditionally.
  system.autoUpgrade.enable = lib.mkForce false;

  # Keep the systemd journal in RAM so the hidden session leaves no log trail on
  # the disk.
  # services.journald.extraConfig = ''
  #   Storage=volatile
  # '';

  # Keep hidden-session shell history in memory only. A shell started in the
  # hidden session that outlives the teardown would otherwise write its history
  # into the (by then decoy) home when it exits. This stays on unconditionally.
  environment.interactiveShellInit = ''
    unset HISTFILE
  '';
  programs.fish.interactiveShellInit = ''
    set -g fish_history ""
  '';

  # An emergency teardown unit you can trigger to leave the hidden session in a
  # hurry. Point ExecStart at your own `nails emergency` wrapper.
  # systemd.services.nails-panic = {
  #   description = "Emergency teardown of the hidden session";
  #   serviceConfig = {
  #     Type = "oneshot";
  #     ExecStart = "/run/current-system/sw/bin/true";
  #   };
  # };

  # A discreet prompt indicator that the hidden session is active. Any on-screen
  # marker is a shoulder-surfing and screenshot liability, so it is off by
  # default.
  # programs.bash.promptInit = ''
  #   PS1="(session) $PS1"
  # '';
}
"#;

/// The live hardware configuration file NixOS reads at build time.
pub(crate) const HARDWARE_CONFIG_FILE: &str = "hardware-configuration.nix";

/// The original hardware configuration, moved aside so the wrapper can import it.
pub(crate) const HARDWARE_BASE_CONFIG_FILE: &str = "hardware-configuration.base.nix";

/// Fixed wrapper written as `hardware-configuration.nix`.
///
/// It imports the preserved original plus the hidden module via the staged
/// `./nails/configuration.nix` symlink. Being a constant, it is always valid
/// Nix and never depends on the shape of the file it replaces.
pub(crate) const HARDWARE_WRAPPER: &str = "{ ... }: {\n  imports = [\n    ./hardware-configuration.base.nix\n    ./nails/configuration.nix\n  ];\n}\n";

/// NixOS configuration overlay information
///
/// Contains paths to the key files in the NixOS configuration overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixOSConfigInfo {
    /// Path to modified hardware-configuration.nix in hidden storage
    pub hardware_config_path: PathBuf,

    /// Path to hidden configuration.nix
    pub hidden_config_path: PathBuf,

    /// Path to etc/nixos overlay directory in hidden storage
    pub etc_nixos_overlay: PathBuf,
}

/// Strip Nix comments from source text (lines starting with # and /* */ blocks).
///
/// This is a lightweight sanitizer for import validation; it is not a full Nix parser.
pub(crate) fn strip_nix_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_block_comment = false;

    while let Some(c) = chars.next() {
        if in_block_comment {
            if c == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        if c == '/' && matches!(chars.peek(), Some('*')) {
            chars.next();
            in_block_comment = true;
            continue;
        }

        if c == '#' {
            // Skip to end of line, preserving newline.
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
            continue;
        }

        output.push(c);
    }

    output
}

/// Return true if the hardware configuration contains the expected import.
///
/// This ignores comment-only references to avoid false positives.
pub fn contains_nails_import(content: &str) -> bool {
    let stripped = strip_nix_comments(content);
    stripped.contains(crate::artifacts::NIXOS_IMPORT_MARKER)
}
