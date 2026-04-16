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
//! 3. Injecting an import statement into the overlayed hardware-configuration.nix
//! 4. The import resolves via the symlink to the hidden configuration

mod inject;
mod prepare;
mod verify;

#[cfg(test)]
mod tests;

// Re-export public API
pub use inject::{ensure_nails_import_block, inject_import_block};
pub use prepare::{
    ensure_hidden_configuration_module, ensure_hidden_hardware_configuration,
    prepare_nixos_config_overlay, stage_hidden_config_symlink,
};
pub use verify::verify_base_config_clean;

use std::path::PathBuf;

pub(crate) const AUTO_GENERATED_HIDDEN_CONFIGURATION: &str =
    "{ pkgs, ... }: {\n  environment.systemPackages = [ pkgs.ripgrep ];\n}\n";

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
    stripped.contains("./nails/configuration.nix")
}
