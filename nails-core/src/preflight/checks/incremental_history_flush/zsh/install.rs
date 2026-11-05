// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the check knows of the zsh a shell runs, beside its startup files:
//! where its `fpath` starts, which its program and its environment tell
//! ([`Install`]), the Nix profiles NixOS's `/etc/zshenv` adds directories of
//! to `fpath` (`NIX_PROFILES`), and the lines of NixOS's generated
//! `/etc/zshrc` that it knows to write nothing ([`dircolors_split`]).
//!
//! A zsh from the Nix store, as nixpkgs builds it, looks for the functions it
//! autoloads in one directory of its own store path,
//! `share/zsh/<version>/functions`, unless `FPATH` in its environment names
//! others, which zsh then takes instead. The check knows that directory
//! only when every path the program names is one a nixpkgs build of zsh
//! names ([`nix_functions`]), and the directory holds no directory, so that a
//! zsh built otherwise counts as one it cannot tell. It reads the environment
//! of a shell that runs now; of one that may run later it knows neither.

use super::walk::PROMPTS;
use super::{Reader, Word};
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The variables of a shell's environment the check reads: where zsh looks
/// for the functions it autoloads (`FPATH`), what NixOS's `/etc/zshenv`
/// reads the Nix profiles from (`NIX_PROFILES`, and the `USER` and
/// `XDG_STATE_HOME` its `set-environment` writes them with), the directory
/// whose own the stock `compaudit` puts in `fpath` (`_compdir`), where zsh
/// reads the user's startup files (`HOME`, `ZDOTDIR`), the name zsh gives
/// every program it runs (`ARGV0`), the mail messages it expands before a
/// prompt (`MAILPATH`), as `LD_` without a value, whether a variable of
/// the dynamic loader is set (`LD_PRELOAD`), and the prompts zsh takes from
/// its environment and expands as it shows them (`PS1`, `RPROMPT`, ...,
/// [`PROMPTS`]), which run code where `PROMPT_SUBST` is on.
pub(in super::super) const ENVIRONMENT: [&str; 25] = [
    "FPATH",
    "NIX_PROFILES",
    "USER",
    "XDG_STATE_HOME",
    "_compdir",
    "HOME",
    "ZDOTDIR",
    "ARGV0",
    "MAILPATH",
    LOADER,
    "PS1",
    "PROMPT",
    "prompt",
    "RPS1",
    "RPROMPT",
    "PS2",
    "PROMPT2",
    "RPS2",
    "RPROMPT2",
    "PS3",
    "PROMPT3",
    "PS4",
    "PROMPT4",
    "SPROMPT",
    "PROMPT_EOL_MARK",
];

/// Whether the check reads the value of the variable `name` of
/// [`ENVIRONMENT`] only for an expansion in it, as it does `MAILPATH`'s and
/// the prompts' ([`PROMPTS`]), so that what is no UTF-8 in it may be
/// replaced.
pub(in super::super) fn lossy(name: &str) -> bool {
    name == "MAILPATH" || PROMPTS.contains(&name)
}

/// The name the check keeps, without a value, for any variable of the
/// dynamic loader a shell's environment holds (`LD_PRELOAD`,
/// `LD_LIBRARY_PATH`).
pub(in super::super) const LOADER: &str = "LD_";

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

/// What a shell's environment holds of [`ENVIRONMENT`] but `FPATH`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in super::super) struct Env {
    pub nix_profiles: Option<String>,
    pub user: Option<String>,
    pub xdg_state_home: Option<String>,
    pub compdir: Option<String>,
    pub home: Option<String>,
    pub zdotdir: Option<String>,
    pub argv0: Option<String>,
    pub mailpath: Option<String>,
    /// Whether a variable of the dynamic loader is set ([`LOADER`]).
    pub loader: bool,
    /// The prompts it holds ([`PROMPTS`]), each one's name and value.
    pub prompts: Vec<(String, String)>,
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
                compdir: get("_compdir"),
                home: get("HOME"),
                zdotdir: get("ZDOTDIR"),
                argv0: get("ARGV0"),
                mailpath: get("MAILPATH"),
                loader: get(LOADER).is_some(),
                prompts: PROMPTS
                    .iter()
                    .filter_map(|name| get(name).map(|value| ((*name).to_string(), value)))
                    .collect(),
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

/// The paths that the zsh program `bytes` names: each string in it, a run
/// of printable characters between two NUL bytes, that starts with `/`.
fn named_paths(bytes: &[u8]) -> Vec<String> {
    let mut paths: Vec<String> = bytes
        .split(|byte| *byte == 0)
        .filter(|run| {
            run.first() == Some(&b'/') && run.iter().all(|byte| (0x20..0x7f).contains(byte))
        })
        .filter_map(|run| std::str::from_utf8(run).ok())
        .map(str::to_string)
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// The paths a nixpkgs build of zsh 5.9 to 5.9.2 names that are none where
/// it looks for functions: the startup files in `/etc`, devices, its
/// temporary files, the directories of its default `PATH`, and the like.
const NON_FPATH: &[&str] = &[
    "/",
    "/bin/sh",
    "/cur",
    "/dev/",
    "/dev/fd/",
    "/dev/null",
    "/dev/tty",
    "/etc/profile",
    "/etc/suid_profile",
    "/etc/zlogin",
    "/etc/zlogout",
    "/etc/zprofile",
    "/etc/zshrc",
    "/new",
    "/pid-%ld/host-",
    "/proc/self/fd",
    "/run/current-system/sw/bin:/bin:/usr/bin",
    "/run/current-system/sw/bin:/bin:/usr/bin:/nix/var/nix/profiles/default/bin",
    "/tmp",
    "/tmp/zsh",
    "/usr/bin",
    "/usr/local/bin",
    "/usr/ucb",
];

/// Whether `path`, a path the program of the zsh at the store path `own`
/// names, is one a nixpkgs build of zsh names ([`NON_FPATH`]): its own
/// files (`etc/zshenv`, `lib/zsh/<version>` and `dir`, where it looks for
/// functions), the libraries it links (a list of store paths' `lib`
/// directories) or its program interpreter.
fn nixpkgs_path(path: &str, own: &Path, version: &str, dir: &Path) -> bool {
    let own = own.to_string_lossy();
    let store_lib = |part: &str| {
        part.strip_prefix("/nix/store/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(name, rest)| {
                name.len() > 33
                    && name[..32].chars().all(|c| NIX_BASE32.contains(c))
                    && (rest == "lib"
                        || (rest.starts_with("lib/ld-linux") && !rest[4..].contains('/')))
            })
    };
    NON_FPATH.contains(&path)
        || path == format!("{own}/etc/zshenv")
        || path == format!("{own}/lib/zsh/{version}")
        || Path::new(path) == dir
        || path.split(':').all(store_lib)
}

/// The directory where a zsh from the Nix store looks for the functions it
/// autoloads when its environment names none, and its version: for the
/// program `/nix/store/<hash>-zsh-<version>/bin/zsh`, `share/zsh/<version>/
/// functions` in that store path, when the program names that directory and
/// no path a nixpkgs build of zsh does not name ([`nixpkgs_path`]), so that
/// it was built to look in no other (`--enable-site-fndir`,
/// `--enable-additional-fpath`), and the directory holds no directory, as
/// nixpkgs builds zsh. `None` for any other program, or when the check
/// cannot read it.
fn nix_functions<F: Filesystem>(fs: &F, program: &Path) -> Option<(PathBuf, String)> {
    let mut parts = program.strip_prefix("/nix/store").ok()?.components();
    let name = parts.next()?.as_os_str().to_str()?;
    if parts.as_path() != Path::new("bin/zsh") {
        return None;
    }
    let version = store_name(name, "zsh")?;
    let own = Path::new("/nix/store").join(name);
    let dir = own.join("share/zsh").join(version).join("functions");
    if fs.file_size(program).ok()? > PROGRAM_LIMIT {
        return None;
    }
    let bytes = fs.read_file_bytes(program).ok()?;
    let named = named_paths(&bytes);
    // A string of `/` and one byte (`/0`) is a piece of data, unless it
    // names a directory.
    let other = |path: &&String| {
        !nixpkgs_path(path, &own, version, &dir)
            && !(path.len() == 2 && matches!(fs.is_directory(Path::new(path.as_str())), Ok(false)))
    };
    if !named.iter().any(|path| Path::new(path) == dir) || named.iter().any(|path| other(&path)) {
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
/// `eval "$(/nix/store/<hash>-coreutils-<version>/bin/dircolors -b)"`, and
/// the program it names is coreutils' own ([`coreutils_dircolors`]), which
/// prints the `LS_COLORS` it sets.
fn dircolors<F: Filesystem>(fs: &F, line: &str) -> bool {
    line.strip_prefix("eval \"$(/nix/store/")
        .and_then(|rest| rest.strip_suffix("/bin/dircolors -b)\""))
        .is_some_and(|name| {
            store_name(name, "coreutils").is_some() && coreutils_dircolors(fs, name)
        })
}

/// Whether the store path `name` holds coreutils' `dircolors`, as nixpkgs
/// builds it: `bin/dircolors` links to the one `coreutils` program beside
/// it, an ELF program that holds the code GNU dircolors prints for a Bourne
/// shell (`LS_COLORS='...';` and `export LS_COLORS`).
fn coreutils_dircolors<F: Filesystem>(fs: &F, name: &str) -> bool {
    let bin = Path::new("/nix/store").join(name).join("bin");
    let program = bin.join("coreutils");
    let holds = |bytes: &[u8], wanted: &[u8]| bytes.windows(wanted.len()).any(|at| at == wanted);
    fs.canonicalize(&bin.join("dircolors")).ok().as_deref() == Some(program.as_path())
        && matches!(fs.is_regular_file(&program), Ok(true))
        && fs
            .file_size(&program)
            .is_ok_and(|size| size <= PROGRAM_LIMIT)
        && fs.read_file_bytes(&program).is_ok_and(|bytes| {
            bytes.starts_with(b"\x7fELF")
                && holds(&bytes, b"LS_COLORS='")
                && holds(&bytes, b"';\nexport LS_COLORS\n")
        })
}

/// `text`, the file at `path`, parted at the line the check knows to do
/// nothing that writes history but what runs before it may change: in the
/// `/etc/zshrc` NixOS's `programs.zsh` writes, the first `eval` of what
/// `dircolors` prints ([`dircolors`]). The text before the line, the
/// program it runs, and the text after it; `None` for any other file.
pub(super) fn dircolors_split<'a, F: Filesystem>(
    fs: &F,
    path: &Path,
    text: &'a str,
) -> Option<(&'a str, String, &'a str)> {
    if path != Path::new("/etc/zshrc") || text.lines().next() != Some(NIXOS_ZSHRC) {
        return None;
    }
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        if dircolors(fs, bare) {
            let program = bare
                .strip_prefix("eval \"$(")
                .and_then(|rest| rest.strip_suffix(" -b)\""))
                .unwrap_or_default()
                .to_string();
            return Some((&text[..start], program, &text[start + line.len()..]));
        }
        start += line.len();
    }
    None
}

/// Whether `profile` is a Nix profile's path as the check can follow it: an
/// absolute path of letters, digits and `/._+@-` alone, in which zsh expands
/// nothing and its `${(z)...}` splits nothing off (`;`, `&`, `>`).
pub(super) fn plain_profile(profile: &str) -> bool {
    profile.starts_with('/')
        && profile
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '+' | '@' | '-'))
}

/// The Nix profiles `value`, a value of `NIX_PROFILES`, names, as
/// `${(z)NIX_PROFILES}` splits it: at spaces and tabs, each a plain profile
/// ([`plain_profile`]); `None` when it holds anything else, which zsh may
/// split otherwise (a newline, a `;`, a no-break space).
pub(super) fn profile_words(value: &str) -> Option<Vec<String>> {
    value
        .split([' ', '\t'])
        .filter(|word| !word.is_empty())
        .map(|word| plain_profile(word).then(|| word.to_string()))
        .collect()
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
            .split([' ', '\t'])
            .filter(|word| !word.is_empty())
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

#[cfg(test)]
pub(super) mod tests {
    use crate::Filesystem;
    use crate::filesystem::MockFilesystem;
    use std::path::Path;

    /// coreutils at the store path `name` as nixpkgs builds it:
    /// `bin/dircolors` links to `bin/coreutils`, an ELF program that holds
    /// what GNU dircolors prints for a Bourne shell.
    pub(in super::super::super) fn seed_coreutils(fs: &MockFilesystem, name: &str) {
        let bin = format!("/nix/store/{name}/bin");
        fs.mock_set_file_bytes(
            &format!("{bin}/coreutils"),
            b"\x7fELF\0LS_COLORS='\0';\nexport LS_COLORS\n\0",
        );
        fs.create_symlink(
            Path::new("coreutils"),
            Path::new(&format!("{bin}/dircolors")),
        )
        .expect("a link");
    }
}
