// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The arguments of the window's operations and the data of their plans.
//!
//! Each argument type holds the options of one CLI command a window can give,
//! by the same names, each absent flag off. A path is a string the decoder
//! checks for shape ([`super::validate`]): absolute, with no control
//! character. The data of a plan is what the window shows before it asks; its
//! token is what the apply request carries back.

use serde::{Deserialize, Serialize};

/// The options of `nails check`, each absent one off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckArgs {
    /// `--overlay-only`.
    pub overlay_only: bool,
    /// `--nixos-flake`.
    pub nixos_flake: Option<String>,
    /// `--allow-persistent-decoy`.
    pub allow_persistent_decoy: bool,
    /// `--allow-decoy-storage`.
    pub allow_decoy_storage: bool,
    /// `--allow-discards`.
    pub allow_discards: bool,
}

/// The options of `nails config show` a window can give. The commented
/// example (`--example`) is not one: the CLI prints it only as TOML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigShowArgs {
    /// `--nixos-flake`.
    pub nixos_flake: Option<String>,
}

/// The arguments of `nails discard` a plan takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscardPlanArgs {
    /// The absolute path whose hidden copy is discarded.
    pub target: String,
    /// `--allow-decoy-storage`.
    #[serde(default)]
    pub allow_decoy_storage: bool,
}

/// The options of `nails activate` a plan takes. The plan and its apply are
/// the confirmation (`-y`); `--dry-run` is the check operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActivateArgs {
    /// `--overlay-only`.
    pub overlay_only: bool,
    /// `--nixos-flake`.
    pub nixos_flake: Option<String>,
    /// `--allow-persistent-decoy`.
    pub allow_persistent_decoy: bool,
    /// `--allow-decoy-storage`.
    pub allow_decoy_storage: bool,
    /// `--allow-discards`.
    pub allow_discards: bool,
}

/// The options of `nails deactivate` a plan takes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeactivateArgs {
    /// `--poweroff`: power off instead of returning to the decoy.
    pub poweroff: bool,
}

/// The options of `nails emergency`. The countdown (`--countdown`) is the
/// window's to show; the helper acts at once.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmergencyArgs {
    /// `--poweroff`.
    pub poweroff: bool,
    /// `--reboot`.
    pub reboot: bool,
}

/// The options of `nails verify`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerifyArgs {
    /// `--deep`.
    pub deep: bool,
    /// `--offline`.
    pub offline: bool,
    /// `--root`: the mounted decoy image an offline scan reads.
    pub root: Option<String>,
    /// `--examiner`.
    pub examiner: bool,
    /// `--disk`: the device the examiner's view reads.
    pub disk: Option<String>,
}

/// The options of `nails rehearse plant`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RehearsePlantArgs {
    /// `--user`: the account whose session the canary is planted for.
    pub user: Option<String>,
}

/// The options of `nails rehearse scan`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RehearseScanArgs {
    /// `--device`, each one given.
    pub devices: Vec<String>,
    /// `--offline`.
    pub offline: bool,
    /// `--image`, each one given.
    pub images: Vec<String>,
    /// `--token-file`.
    pub token_file: Option<String>,
    /// `--allow-same-boot`.
    pub allow_same_boot: bool,
    /// `--max-bytes`.
    pub max_bytes: Option<u64>,
}

/// The arguments of `nails init` a plan takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitArgs {
    /// The hidden volume to lay out.
    pub path: String,
    /// `--allow-decoy-storage`.
    #[serde(default)]
    pub allow_decoy_storage: bool,
    /// `--hardware-config`.
    #[serde(default)]
    pub hardware_config: Option<String>,
    /// `--no-hardware-config`.
    #[serde(default)]
    pub no_hardware_config: bool,
}

/// The token of a plan, which its apply request carries back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    /// [`super::TOKEN_HEX_DIGITS`] lowercase hexadecimal digits.
    pub token: String,
}

/// The data of the answer to [`super::Op::DiscardPlan`] when there is
/// something to delete: what the apply would remove, and the token that
/// applies it. (With nothing to delete the answer is the envelope `nails
/// discard` prints, and there is no token.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscardPlanData {
    /// The path whose hidden copy the apply discards.
    pub target: String,
    /// The directories and files the apply removes.
    pub removals: Vec<String>,
    /// Whether the apply drops the hidden Nix database and store paths.
    pub resets_nix_store: bool,
    /// The token the apply request carries back.
    pub token: String,
}

/// The data of the answer to [`super::Op::ActivatePlan`] once the gates passed
/// and the state lock is held: what the window says before it asks, as the
/// CLI does at its prompt. (An activation that ends before the lock, refused
/// or already active, answers with the envelope `nails activate` prints, and
/// there is no token.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatePlanData {
    /// The warning the attach gate raised for a risk the arguments allowed.
    pub warning: Option<String>,
    /// That a configuration file was not found and the built-in defaults hold.
    pub defaults_notice: Option<String>,
    /// Whether the activation builds a hidden NixOS system.
    pub builds_hidden_system: bool,
    /// The token the apply request carries back.
    pub token: String,
}

/// The data of the answer to [`super::Op::DeactivatePlan`] in a hidden session
/// with a way back. (Anywhere else the answer is the envelope `nails
/// deactivate` prints, and there is no token.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivatePlanData {
    /// Whether the apply powers off instead of returning to the decoy.
    pub poweroff: bool,
    /// What the return will not put back, one sentence each.
    pub warnings: Vec<String>,
    /// The token the apply request carries back.
    pub token: String,
}

/// The data of the answer to [`super::Op::InitPlan`] when every precondition
/// that can be read holds. (A refused one answers with the envelope `nails
/// init` prints, and there is no token.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitPlanData {
    /// The hidden volume the apply lays out.
    pub path: String,
    /// The base hardware configuration of the hidden NixOS layout, when the
    /// apply writes one.
    pub hardware_config: Option<String>,
    /// Why the apply skips the hidden NixOS layout, when it does.
    pub skipped: Option<String>,
    /// The warnings the apply reports with its layout.
    pub warnings: Vec<String>,
    /// The token the apply request carries back.
    pub token: String,
}
