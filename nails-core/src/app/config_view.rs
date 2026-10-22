// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `config` read view: the effective configuration with CLI overrides
//! applied, ready for a front end to render as annotated TOML or JSON.

use std::path::Path;

use crate::{CliOverrides, LoadedConfig, NailsError};

/// Resolve the configuration for a read-only view, with the command-line
/// overrides applied on top of the file and the defaults.
///
/// This is the one operation behind `config show`: a front end renders the
/// returned [`LoadedConfig`] (its `to_annotated_toml` or `to_json`), and the
/// value sources it carries say where each setting came from. A missing,
/// unreadable or invalid file is an error, left for the front end to report.
pub fn config_view(
    config_override: Option<&Path>,
    overrides: &CliOverrides,
) -> Result<LoadedConfig, NailsError> {
    let mut loaded = super::config::resolve_config(config_override)?;
    loaded.apply_cli_overrides(overrides);
    Ok(loaded)
}
