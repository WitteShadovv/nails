// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared configuration resolution for the facade.
//!
//! One place turns the optional `--config` path into a [`LoadedConfig`], so no
//! operation and no front end can disagree on where the configuration came from
//! or treat a broken file as if it were the built-in defaults.

use std::path::Path;

use crate::{LoadedConfig, NailsError};

/// Resolve and load the configuration strictly.
///
/// * `config_override` is `Some` (`--config`): the file must exist.
/// * `config_override` is `None`: the binary-relative file is optional and
///   built-in defaults apply when it is missing.
///
/// Either way an unreadable or invalid file is an error. `loaded_config_path`
/// is set to the consulted path so cleanup preserves it.
pub fn resolve_config(config_override: Option<&Path>) -> Result<LoadedConfig, NailsError> {
    let path = crate::config::discover_config_path(config_override);
    let mut loaded = if config_override.is_some() {
        LoadedConfig::load(&path)?
    } else {
        LoadedConfig::load_or_default(&path)?
    };
    loaded.config.loaded_config_path = Some(path);
    Ok(loaded)
}
