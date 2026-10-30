// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Flake references: splitting `<base>#<name>`, finding a local flake
//! directory, and the `nixosConfigurations` attribute a build selects.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

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
/// its `dir` parameter, the subdirectory that holds `flake.nix`, as Nix reads
/// them: `path:/etc?dir=nixos` is `path:/etc` and `nixos`, and Nix decodes
/// the parameter's percent-escapes (`dir=%6Eixos` is `nixos`). Other
/// parameters (`?ref=main`) are dropped.
pub fn location_and_dir(base_ref: &str) -> (&str, Option<PathBuf>) {
    let (location, query) = base_ref.split_once('?').unwrap_or((base_ref, ""));
    let dir = query
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("dir="))
        .map(|dir| percent_decoded(dir).unwrap_or_else(|| PathBuf::from(dir)))
        .filter(|dir| !dir.as_os_str().is_empty());
    (location, dir)
}

/// `path` with the flake reference's `dir` parameter applied. Nix appends
/// the parameter to the path, so a `/` in front of it does not make it
/// absolute: `dir=/nixos` below `/etc` is `/etc/nixos`.
pub fn with_dir(path: PathBuf, dir: Option<&Path>) -> PathBuf {
    match dir {
        Some(dir) => path.join(dir.strip_prefix("/").unwrap_or(dir)),
        None => path,
    }
}

/// The local flake directory a flake reference without its fragment names,
/// as Nix reads it: a path (absolute, or `./`, `../`, `.` and `..` against
/// the working directory) or a `path:` reference, whose percent-escapes Nix
/// decodes (`path:/srv/my%20flake`), with any query dropped and its `dir`
/// parameter applied. `None` for any other reference (`github:`,
/// `git+file:`, …), which the pre-flight cannot judge from the filesystem.
///
/// # Errors
///
/// A local URL with an authority (`git+file://../../etc/nixos`): Nix takes
/// none there, and reads such a file URL, the whole reference, as a path
/// relative to the working directory. A registry alias written
/// `flake:<name>`: Nix looks it up in its flake registries, so it could
/// name any flake, the decoy's own `/etc/nixos` among them. A relative path
/// without `./`, which takes in a name alone such as `nixos-config`, the
/// other spelling of an alias.
pub fn resolve_local_flake_dir(base_ref: &str) -> crate::Result<Option<PathBuf>> {
    let (location, dir) = location_and_dir(base_ref);
    let dir = dir.as_deref();
    if let Some(LocalUrl::Authority(authority)) = local_url(location) {
        return Err(crate::NailsError::NixOSPreflightError {
            category: "configuration",
            message: format!(
                "flake reference '{base_ref}' gives a local URL the authority '{authority}', which Nix does not take there: it reads such a file URL as a path relative to the working directory, and refuses a path: reference with one. Name the flake by its absolute path, such as '/mnt/data/nixos#my-host' or 'git+file:///mnt/data/nixos#my-host', and retry activation."
            ),
        });
    }
    if location.starts_with('/') {
        return Ok(Some(with_dir(PathBuf::from(location), dir)));
    }

    if let Some(path_ref) = location.strip_prefix("path:") {
        let path = percent_decoded(path_ref).unwrap_or_else(|| PathBuf::from(path_ref));
        return resolved_local_path(path).map(|path| Some(with_dir(path, dir)));
    }

    if looks_like_explicit_relative_flake_ref(location) {
        return resolved_local_path(PathBuf::from(location)).map(|path| Some(with_dir(path, dir)));
    }

    if location.starts_with("flake:") {
        return Err(crate::NailsError::NixOSPreflightError {
            category: "configuration",
            message: format!(
                "flake reference '{base_ref}' is a registry alias, which Nix looks up in its flake registries, so NAILS cannot tell which flake it names: it could be the decoy's own /etc/nixos. Name the flake by its path or URL instead, such as '/mnt/data/nixos#my-host' or 'github:owner/repo#my-host', and retry activation."
            ),
        });
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

/// Every directory a local flake reference without its fragment may name,
/// for a refusal that must miss none of them. A local reference is a path
/// (absolute, or `./`, `../`, `.` and `..` against the working directory), a
/// `path:` reference, or a URL whose transport reads local files (`file:`,
/// `git+file:`, `hg+file:`, `tarball+file:`, …). With no authority or an
/// empty one (`git+file:///etc/nixos`) Nix reads the URL's path, an empty
/// one as `/`. With an authority (`git+file://../../etc/nixos`) it takes the
/// whole reference for a path relative to the working directory, and so
/// does this list. Each spelling counts: the location as written and with
/// its percent-escapes decoded (Nix decodes those of a URL,
/// `path:/etc/%6Eixos` is `/etc/nixos`), the work tree of a repository's
/// `.git` directory beside the directory itself (Nix fetches
/// `git+file:///etc/nixos/.git` from the repository it belongs to), each
/// with every `dir` parameter applied, its name and its value as written and
/// decoded, and each of these with its `.` and `..` components applied as
/// Nix applies them, by the text (`/etc/nixos/x/..` is `/etc/nixos` even
/// where `x` does not exist). Empty for any other reference.
pub(crate) fn local_flake_dirs(base_ref: &str) -> Vec<PathBuf> {
    let (location, query) = base_ref.split_once('?').unwrap_or((base_ref, ""));
    let mut dirs: Vec<Option<PathBuf>> = Vec::new();
    for (name, value) in query.split('&').filter_map(|p| p.split_once('=')) {
        if !spellings(name).iter().any(|name| name.as_os_str() == "dir") {
            continue;
        }
        // `%64ir` is `dir` only to a Nix that decodes a parameter's name.
        if name != "dir" {
            push_new(&mut dirs, None);
        }
        for value in spellings(value) {
            push_new(&mut dirs, Some(value).filter(|v| !v.as_os_str().is_empty()));
        }
    }
    if dirs.is_empty() {
        dirs.push(None);
    }
    let mut paths = Vec::new();
    for path in local_paths(location) {
        let work_tree = work_tree(&path);
        for path in std::iter::once(path).chain(work_tree) {
            for dir in &dirs {
                let path = with_dir(path.clone(), dir.as_deref());
                let applied = lexical(&path);
                push_new(&mut paths, path);
                push_new(&mut paths, applied);
            }
        }
    }
    paths
}

/// The paths a flake reference's location names when it is local, as
/// [`local_flake_dirs`] reads it, relative ones against the working
/// directory; none for any other location.
fn local_paths(location: &str) -> Vec<PathBuf> {
    let path = match local_url(location) {
        Some(LocalUrl::Path(path)) => path,
        Some(LocalUrl::Authority(_)) => location,
        None if location.starts_with('/') || looks_like_explicit_relative_flake_ref(location) => {
            location
        }
        None => return Vec::new(),
    };
    spellings(path)
        .into_iter()
        .filter_map(|path| resolved_local_path(path).ok())
        .collect()
}

/// A flake location that is a URL whose transport reads local files, as Nix
/// reads it.
enum LocalUrl<'a> {
    /// No authority or an empty one: the path after it (`git+file:/etc`,
    /// `git+file:///etc`), and `/` for an empty one (`git+file://`).
    Path(&'a str),
    /// An authority (`git+file://../../etc/nixos`, `file://localhost/etc`),
    /// which Nix does not take in a local URL: it reads a file URL with one
    /// as a path relative to the working directory, the whole reference, and
    /// refuses a `path:` reference with one.
    Authority(&'a str),
}

/// `location` as a URL whose transport reads local files; `None` for a path
/// and for any other reference.
fn local_url(location: &str) -> Option<LocalUrl<'_>> {
    if location.starts_with('/') || looks_like_explicit_relative_flake_ref(location) {
        return None;
    }
    let (scheme, rest) = location.split_once(':')?;
    if !reads_local_files(scheme) {
        return None;
    }
    let path = match rest.strip_prefix("//") {
        Some(after) if !after.is_empty() && !after.starts_with('/') => {
            let authority = after.split('/').next().unwrap_or_default();
            return Some(LocalUrl::Authority(authority));
        }
        Some(path) => path,
        None => rest,
    };
    Some(LocalUrl::Path(if path.is_empty() { "/" } else { path }))
}

/// The work tree of a repository whose `.git` directory `path` is, as Nix
/// reads a git URL that names one (`git+file:///etc/nixos/.git` is the
/// repository in `/etc/nixos`, and its `dir` parameter a directory there).
fn work_tree(path: &Path) -> Option<PathBuf> {
    let path = lexical(path);
    if path.file_name()? != ".git" {
        return None;
    }
    path.parent().map(Path::to_path_buf)
}

/// Whether a URL with the scheme `scheme` reads local files, as `path:`
/// does and every scheme whose transport is `file` (`file:`, `git+file:`,
/// `hg+file:`, `tarball+file:`), in any case.
fn reads_local_files(scheme: &str) -> bool {
    let scheme = scheme.to_ascii_lowercase();
    scheme == "path" || scheme == "file" || scheme.ends_with("+file")
}

/// `text` as written, and with its percent-escapes decoded where it holds
/// any.
fn spellings(text: &str) -> Vec<PathBuf> {
    let mut spellings = vec![PathBuf::from(text)];
    if let Some(decoded) = percent_decoded(text) {
        push_new(&mut spellings, decoded);
    }
    spellings
}

/// `text` with its percent-escapes (`%6E`) decoded, as Nix decodes a URL's
/// path and its query; `None` when it holds no escape, or one that is not
/// `%` and two hex digits.
fn percent_decoded(text: &str) -> Option<PathBuf> {
    if !text.contains('%') {
        return None;
    }
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = bytes.get(at + 1..at + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            decoded.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    Some(PathBuf::from(OsString::from_vec(decoded)))
}

/// `path` with its `.` and `..` components applied by the text, as Nix
/// applies them to a path before it looks at the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Add `item` to `items` unless it is there already.
fn push_new<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

fn resolved_local_path(path_ref: PathBuf) -> crate::Result<PathBuf> {
    if path_ref.is_absolute() {
        return Ok(path_ref);
    }

    let cwd = std::env::current_dir().map_err(|err| crate::NailsError::NixOSPreflightError {
        category: "configuration",
        message: format!(
            "could not resolve current working directory for relative flake ref '{}': {}",
            path_ref.display(),
            err
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
