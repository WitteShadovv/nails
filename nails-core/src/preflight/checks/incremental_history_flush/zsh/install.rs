// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the check knows of the zsh a shell runs, beside its startup files:
//! where its `fpath` starts, which its program and its environment tell
//! ([`Install`]), the Nix profiles NixOS's `/etc/zshenv` adds directories of
//! to `fpath` (`NIX_PROFILES`), and the lines of NixOS's generated
//! `/etc/zshrc` that it knows to write nothing ([`known_lines`]).
//!
//! A zsh from the Nix store, as nixpkgs builds it, looks for the functions it
//! autoloads in one directory of its own store path,
//! `share/zsh/<version>/functions`, unless `FPATH` in its environment names
//! others, which zsh then takes instead. The check knows that directory
//! only when the program names it and no other of zsh's, and it holds no
//! directory, so that a zsh built otherwise counts as one it cannot tell. It
//! reads the environment of a shell that runs now; of one that may run later
//! it knows neither.

use super::{GLOB, Reader, Word};
use crate::Filesystem;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// The variables of a shell's environment the check reads: where zsh looks
/// for the functions it autoloads (`FPATH`), and what NixOS's `/etc/zshenv`
/// reads the Nix profiles from (`NIX_PROFILES`, and the `USER` and
/// `XDG_STATE_HOME` its `set-environment` writes them with).
pub(in super::super) const ENVIRONMENT: [&str; 4] =
    ["FPATH", "NIX_PROFILES", "USER", "XDG_STATE_HOME"];

/// How many bytes of a zsh program the check reads for the directories it
/// names: 64 MiB, more than any zsh program holds.
const PROGRAM_LIMIT: u64 = 64 << 20;

/// The characters of the hash of a Nix store path's name.
const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz"; // pragma: allowlist secret

/// What the check knows of the zsh program a shell runs and of the
/// environment it started with, which tell where zsh looks for the functions
/// the files autoload; nothing when the check reads a shell that may not run
/// yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in super::super) struct Install {
    /// The directories zsh's `fpath` starts with: those an `FPATH` in its
    /// environment names, else the one its program was built with; `None`
    /// when the check cannot tell.
    pub fpath: Option<Vec<PathBuf>>,
    /// The version zsh holds in `ZSH_VERSION`, when the check can tell.
    pub version: Option<String>,
    /// What its environment holds of [`ENVIRONMENT`] but `FPATH`, when the
    /// check can tell.
    pub env: Option<Env>,
}

/// What a shell's environment holds of what NixOS's `/etc/zshenv` reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in super::super) struct Env {
    pub nix_profiles: Option<String>,
    pub user: Option<String>,
    pub xdg_state_home: Option<String>,
}

impl Install {
    /// What the check knows of a zsh that runs the program `program` with
    /// the variables `environment` holds of [`ENVIRONMENT`], either of them
    /// `None` when the check cannot tell.
    pub(in super::super) fn of<F: Filesystem>(
        fs: &F,
        program: Option<&Path>,
        environment: Option<&[(String, String)]>,
    ) -> Self {
        let own = program.and_then(|program| nix_functions(fs, program));
        let get = |name: &str| {
            environment?
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let fpath = environment.and_then(|_| match get("FPATH") {
            // Each must be absolute: zsh takes another one from where it
            // runs.
            Some(value) => value
                .split(':')
                .map(|dir| Path::new(dir).is_absolute().then(|| PathBuf::from(dir)))
                .collect(),
            None => own.as_ref().map(|(dir, _)| vec![dir.clone()]),
        });
        Self {
            fpath,
            version: own.map(|(_, version)| version),
            env: environment.map(|_| Env {
                nix_profiles: get("NIX_PROFILES"),
                user: get("USER"),
                xdg_state_home: get("XDG_STATE_HOME"),
            }),
        }
    }
}

/// Whether `name` is the name of a Nix store path of the package `package`:
/// `<hash>-<package>-<version>`, the version digits and dots.
fn store_name<'a>(name: &'a str, package: &str) -> Option<&'a str> {
    let (hash, rest) = name.split_at_checked(32)?;
    let version = rest
        .strip_prefix('-')?
        .strip_prefix(package)?
        .strip_prefix('-')?;
    (hash.chars().all(|c| NIX_BASE32.contains(c))
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())))
    .then_some(version)
}

/// The directories of zsh's own that the zsh program `bytes` names: each run
/// of printable characters in it that names a directory under `share/zsh` or
/// one of the directories zsh may be built to look in beside its own.
fn named_dirs(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| !(0x20..0x7f).contains(byte))
        .filter_map(|run| std::str::from_utf8(run).ok())
        .filter(|run| {
            [
                "/share/zsh",
                "site-functions",
                "vendor-functions",
                "vendor-completions",
            ]
            .iter()
            .any(|part| run.contains(part))
        })
        .map(str::to_string)
        .collect()
}

/// The directory where a zsh from the Nix store looks for the functions it
/// autoloads when its environment names none, and its version: for the
/// program `/nix/store/<hash>-zsh-<version>/bin/zsh`, `share/zsh/<version>/
/// functions` in that store path, when the program names that directory and
/// no other of zsh's, and it holds no directory, as nixpkgs builds zsh.
/// `None` for any other program, or when the check cannot read it.
fn nix_functions<F: Filesystem>(fs: &F, program: &Path) -> Option<(PathBuf, String)> {
    let mut parts = program.strip_prefix("/nix/store").ok()?.components();
    let name = parts.next()?.as_os_str().to_str()?;
    if parts.as_path() != Path::new("bin/zsh") {
        return None;
    }
    let version = store_name(name, "zsh")?;
    let dir = Path::new("/nix/store")
        .join(name)
        .join("share/zsh")
        .join(version)
        .join("functions");
    if fs.file_size(program).ok()? > PROGRAM_LIMIT {
        return None;
    }
    let bytes = fs.read_file_bytes(program).ok()?;
    let mut named = named_dirs(&bytes);
    named.sort();
    named.dedup();
    if named != [dir.to_string_lossy().into_owned()] {
        return None;
    }
    let entries = fs.list_directory(&dir).ok()?;
    (!entries.is_empty()
        && entries
            .iter()
            .all(|entry| matches!(fs.is_directory(entry), Ok(false))))
    .then(|| (dir, version.to_string()))
}

/// The first line of the `/etc/zshrc` that NixOS's `programs.zsh` writes.
const NIXOS_ZSHRC: &str =
    "# /etc/zshrc: DO NOT EDIT -- this file has been generated automatically.";

/// Whether `line` is the one that NixOS's `programs.zsh.enableLsColors`
/// writes in `/etc/zshrc`, as written there:
/// `eval "$(/nix/store/<hash>-coreutils-<version>/bin/dircolors -b)"`, which
/// runs what coreutils' `dircolors` prints, the `LS_COLORS` it sets.
fn dircolors(line: &str) -> bool {
    line.strip_prefix("eval \"$(/nix/store/")
        .and_then(|rest| rest.strip_suffix("/bin/dircolors -b)\""))
        .is_some_and(|name| store_name(name, "coreutils").is_some())
}

/// `text`, the file at `path`, with the lines the check knows to do nothing
/// that writes history left out: in the `/etc/zshrc` NixOS's `programs.zsh`
/// writes, its `eval` of what `dircolors` prints ([`dircolors`]).
pub(super) fn known_lines<'a>(path: &Path, text: &'a str) -> Cow<'a, str> {
    if path != Path::new("/etc/zshrc")
        || text.lines().next() != Some(NIXOS_ZSHRC)
        || !text.lines().any(dircolors)
    {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.split_inclusive('\n')
            .map(|line| {
                if dircolors(line.strip_suffix('\n').unwrap_or(line)) {
                    "\n"
                } else {
                    line
                }
            })
            .collect(),
    )
}

/// Whether `profile` is a Nix profile's path as the check can follow it: an
/// absolute path with nothing zsh expands in it.
pub(super) fn plain_profile(profile: &str) -> bool {
    profile.starts_with('/')
        && !profile.contains(['$', '`', '~', '\\', '\'', '"'])
        && !profile.contains(GLOB)
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note the value `value` a file gives `NIX_PROFILES`: the profiles it
    /// names count beside those it may name already, with `$HOME`, `$USER`
    /// and `$XDG_STATE_HOME` in them as the shell runs with them, as NixOS's
    /// `set-environment` writes them; anything else makes the profiles
    /// unknown.
    pub(super) fn nix_profiles(&mut self, value: &Word) {
        let Some(env) = self.install.env.as_ref() else {
            self.profiles = None;
            return;
        };
        let home = self.home.map(|home| home.to_string_lossy().into_owned());
        let user = env.user.clone().unwrap_or_default();
        let state = env.xdg_state_home.clone().unwrap_or_default();
        let resolved: Option<Vec<String>> = value
            .text
            .split_whitespace()
            .map(|word| {
                let mut word = word.to_string();
                for (pattern, with) in [
                    ("${HOME}", home.clone()),
                    ("$HOME", home.clone()),
                    ("${USER}", Some(user.clone())),
                    ("$USER", Some(user.clone())),
                    ("${XDG_STATE_HOME}", Some(state.clone())),
                    ("$XDG_STATE_HOME", Some(state.clone())),
                ] {
                    if word.contains(pattern) {
                        word = word.replace(pattern, &with?);
                    }
                }
                plain_profile(&word).then_some(word)
            })
            .collect();
        match (resolved, self.profiles.as_mut()) {
            (Some(resolved), Some(profiles)) => {
                for profile in resolved {
                    if !profiles.contains(&profile) {
                        profiles.push(profile);
                    }
                }
            }
            _ => self.profiles = None,
        }
    }

    /// Add to `fpath` the directories the files add under each Nix profile
    /// ([`Event::ProfileFpath`]), with zsh's version in them, when the check
    /// knows the profiles; else each is a directory it cannot follow.
    pub(super) fn profile_dirs(&mut self) {
        let version = self.install.version.clone().filter(|_| !self.version_set);
        if self.profile_vars_set {
            self.profiles = None;
        }
        for (written, rest, first, place) in std::mem::take(&mut self.profile_fpath) {
            let rest = version
                .as_ref()
                .map(|version| rest.replace("$ZSH_VERSION", version))
                .filter(|rest| !rest.contains('$'));
            match (self.profiles.clone(), rest) {
                (Some(profiles), Some(rest)) => {
                    for profile in profiles {
                        let entry = Ok((PathBuf::from(format!("{profile}{rest}")), first));
                        if !self.fpath.contains(&entry) {
                            self.fpath.push(entry);
                        }
                    }
                }
                _ => self.fpath.push(Err(format!(
                    "it cannot follow the directory that {place} adds to fpath as `{written}`, \
                     where zsh looks for the functions the files autoload"
                ))),
            }
        }
    }
}
