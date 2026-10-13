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

pub fn resolve_local_flake_dir(base_ref: &str) -> crate::Result<Option<PathBuf>> {
    if base_ref.starts_with('/') {
        return Ok(Some(PathBuf::from(base_ref)));
    }

    if let Some(path_ref) = base_ref.strip_prefix("path:") {
        let (path_ref, _) = path_ref.split_once('?').unwrap_or((path_ref, ""));
        return resolved_local_path(path_ref).map(Some);
    }

    if looks_like_explicit_relative_flake_ref(base_ref) {
        return resolved_local_path(base_ref).map(Some);
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
mod tests {
    use super::*;

    #[test]
    fn split_flake_ref_separates_base_and_fragment() {
        assert_eq!(split_flake_ref("/cfg#host"), ("/cfg", Some("host")));
        assert_eq!(split_flake_ref("/cfg#"), ("/cfg", None));
        assert_eq!(split_flake_ref("github:me/cfg"), ("github:me/cfg", None));
    }

    #[test]
    fn local_flake_dir_only_returns_paths_for_local_refs() {
        assert_eq!(
            local_flake_dir("/etc/nixos"),
            Some(PathBuf::from("/etc/nixos"))
        );
        assert_eq!(
            local_flake_dir("path:/etc/nixos?x=1"),
            Some(PathBuf::from("/etc/nixos"))
        );
        assert_eq!(local_flake_dir("github:me/cfg"), None);
        assert!(resolve_local_flake_dir("relative").is_err());
        assert!(local_flake_dir("./cfg").unwrap().ends_with("cfg"));
    }

    #[test]
    fn an_explicit_fragment_wins_over_the_hostname() {
        assert_eq!(
            selected_nixos_configuration_fragment(Some("hidden")).unwrap(),
            ("hidden".to_string(), true)
        );
        let (name, explicit) = selected_nixos_configuration_fragment(None).unwrap();
        assert!(!name.is_empty());
        assert!(!explicit);
    }
}
