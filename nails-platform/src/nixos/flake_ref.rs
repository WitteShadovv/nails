// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Flake references: splitting `<base>#<name>`, finding a local flake
//! directory, and the `nixosConfigurations` attribute a build selects.

use std::path::PathBuf;

pub fn split_flake_ref(flake_ref: &str) -> (&str, Option<&str>) {
    match flake_ref.split_once('#') {
        Some((base_ref, fragment)) if !fragment.is_empty() => (base_ref, Some(fragment)),
        Some((base_ref, _)) => (base_ref, None),
        None => (flake_ref, None),
    }
}

#[cfg(test)]
pub(crate) fn local_flake_dir(base_ref: &str) -> Option<PathBuf> {
    resolve_local_flake_dir(base_ref).ok().flatten()
}

/// A flake reference without its `#` fragment, split into its location and
/// its `dir` parameter, the subdirectory that holds `flake.nix`: `path:/etc?dir=nixos`
/// is `path:/etc` and `nixos`. Other parameters (`?ref=main`) are dropped.
pub fn location_and_dir(base_ref: &str) -> (&str, Option<&str>) {
    let (location, query) = base_ref.split_once('?').unwrap_or((base_ref, ""));
    let dir = query
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("dir="))
        .filter(|dir| !dir.is_empty());
    (location, dir)
}

/// `path` with the flake reference's `dir` parameter applied.
pub fn with_dir(path: PathBuf, dir: Option<&str>) -> PathBuf {
    match dir {
        Some(dir) => path.join(dir),
        None => path,
    }
}

/// The local flake directory a flake reference without its fragment names:
/// a path (absolute, or `./`, `../`, `.` and `..` against the working
/// directory) or a `path:` reference, with any query dropped and its `dir`
/// parameter applied. `None` for any other reference (`github:`,
/// `git+file:`, …), which the pre-flight cannot judge from the filesystem.
pub fn resolve_local_flake_dir(base_ref: &str) -> crate::Result<Option<PathBuf>> {
    let (location, dir) = location_and_dir(base_ref);
    if location.starts_with('/') {
        return Ok(Some(with_dir(PathBuf::from(location), dir)));
    }

    if let Some(path_ref) = location.strip_prefix("path:") {
        return resolved_local_path(path_ref).map(|path| Some(with_dir(path, dir)));
    }

    if looks_like_explicit_relative_flake_ref(location) {
        return resolved_local_path(location).map(|path| Some(with_dir(path, dir)));
    }

    if looks_like_generic_flake_ref(base_ref) {
        return Ok(None);
    }

    Err(crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "flake path '{}' is relative. Use './path', '../path', '.', an absolute path, 'path:/absolute/path', or a generic flake ref such as 'github:owner/repo#name'. Fix the flake/configuration problem and retry activation.",
            base_ref
        ),
    })
}

fn resolved_local_path(path_ref: &str) -> crate::Result<PathBuf> {
    if path_ref.starts_with('/') {
        return Ok(PathBuf::from(path_ref));
    }

    let cwd = std::env::current_dir().map_err(|err| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "could not resolve current working directory for relative flake ref '{}': {}",
            path_ref, err
        ),
    })?;

    Ok(cwd.join(path_ref))
}

fn looks_like_generic_flake_ref(base_ref: &str) -> bool {
    !matches!(base_ref, "." | "..")
        && !base_ref.starts_with("./")
        && !base_ref.starts_with("../")
        && base_ref.contains(':')
}

fn looks_like_explicit_relative_flake_ref(base_ref: &str) -> bool {
    matches!(base_ref, "." | "..") || base_ref.starts_with("./") || base_ref.starts_with("../")
}

pub fn selected_nixos_configuration_fragment(
    explicit_fragment: Option<&str>,
) -> crate::Result<(String, bool)> {
    if let Some(fragment) = explicit_fragment.filter(|fragment| !fragment.is_empty()) {
        return Ok((fragment.to_string(), true));
    }

    let utsname = nix::sys::utsname::uname().map_err(|err| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "could not determine the local hostname needed to infer the default nixosConfiguration attribute: {}",
            err
        ),
    })?;

    let hostname = utsname.nodename().to_string_lossy().trim().to_string();
    if hostname.is_empty() {
        return Err(crate::NailsError::NixOSPreflightError {
            category: "configuration",
            message: "could not determine the local hostname needed to infer the default nixosConfiguration attribute"
                .to_string(),
        });
    }

    Ok((hostname, false))
}

#[cfg(test)]
#[path = "flake_ref_tests.rs"]
mod tests;
