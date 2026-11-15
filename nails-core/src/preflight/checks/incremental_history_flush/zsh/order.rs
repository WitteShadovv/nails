// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The startup files of a zsh that runs with one home, read in the order zsh
//! reads them (`zshenv`, `zprofile`, `zshrc`, `zlogin`, each in `/etc` and
//! then the user's), and what the reader judges once they are read.

use super::{
    Candidates, Install, OPTIONS, Reader, Scan, Start, Write, profile_words, reading, walk,
};
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// What zsh's startup files below `/etc` and in `home` turn on, for a zsh
/// that runs with `home`.
pub(super) fn in_home<F: Filesystem>(
    fs: &F,
    home: Option<&Path>,
    start: Start,
    install: &Install,
) -> Scan {
    let env = install.env.as_ref();
    // The profiles the environment names, as `${(z)NIX_PROFILES}` splits
    // them; none the check can tell when the environment holds what zsh
    // splits otherwise.
    let profiles =
        env.and_then(|env| profile_words(env.nix_profiles.as_deref().unwrap_or_default()));
    // Where the user's files are: the ZDOTDIR the environment holds, when it
    // holds one, else the home; and what XDG_CONFIG_HOME it holds, beside
    // its default, or any where the check does not know the environment.
    let mut doubts = Vec::new();
    let zdotdirs: Vec<Option<PathBuf>> = match env.and_then(|env| env.zdotdir.as_deref()) {
        Some(dir) if Path::new(dir).is_absolute() => vec![Some(PathBuf::from(dir))],
        Some(dir) => {
            doubts.push(format!(
                "it cannot follow the ZDOTDIR that the shell's environment holds (`{dir}`)"
            ));
            Vec::new()
        }
        None => vec![None],
    };
    let mut xdg = vec![env.and_then(|env| env.xdg_config_home.clone())];
    if xdg[0].is_some() {
        xdg.push(None);
    }
    let values = Candidates {
        zdotdirs,
        xdg,
        xdg_unknown: env.is_none(),
    };
    let mut reader = Reader {
        fs,
        home,
        options: Default::default(),
        ever: values.clone(),
        values,
        given: Vec::new(),
        late: Vec::new(),
        stack: Vec::new(),
        fpath: install
            .fpath
            .iter()
            .flatten()
            .map(|dir| Ok((dir.clone(), false)))
            .collect(),
        autoloads: Vec::new(),
        fc: Vec::new(),
        hooks: Vec::new(),
        in_functions: Vec::new(),
        ends_in: Vec::new(),
        widgets: Vec::new(),
        edits: Vec::new(),
        jobs: Vec::new(),
        doubts,
        rcs: false,
        sh_mode: false,
        prompt_subst: false,
        prompts: Vec::new(),
        install,
        profiles,
        profile_fpath: Vec::new(),
        version_set: false,
        profile_vars_set: false,
        expanding: Vec::new(),
        devices: Vec::new(),
        global_alias_defs: Vec::new(),
        typed_keys: Vec::new(),
        rebound: None,
        arith: Vec::new(),
        integers: Vec::new(),
        keyed_arrays: Vec::new(),
        unset: Vec::new(),
        missing: Vec::new(),
        read_files: Vec::new(),
        known_files: Vec::new(),
        looked: Vec::new(),
        function_code: false,
        writes: Vec::new(),
        under: Vec::new(),
        top_calls: Vec::new(),
        order: 0,
        computed: Vec::new(),
        fc_aliases: Vec::new(),
        texts: Vec::new(),
        stock_texts: Vec::new(),
        defined: Vec::new(),
        computed_calls: Vec::new(),
        calls: Vec::new(),
        edges: Vec::new(),
        promptinit: false,
        compinit: false,
        compinit_places: Vec::new(),
        changers: Vec::new(),
        dircolors: Vec::new(),
        startup_changers: 0,
        outers: Vec::new(),
        autoloaded_by: Vec::new(),
        word_split: None,
        fpath_splits: Vec::new(),
        keys_splits: Vec::new(),
        reading: reading::Reading::default(),
        disabled: Vec::new(),
        listed: super::reached::Listed::default(),
    };
    // The prompts zsh takes from its environment, which it shows as they
    // are unless a file sets them: code where PROMPT_SUBST may be on.
    for (name, value) in env.map(|env| env.prompts.as_slice()).unwrap_or_default() {
        if walk::expands(value) {
            reader.prompts.push(format!(
                "it cannot follow the code that `{name}` in the shell's environment holds, which \
                 zsh runs as it shows the prompt unless a file sets it, as PROMPT_SUBST may be on"
            ));
        }
    }
    for stage in ["zshenv", "zprofile", "zshrc", "zlogin"] {
        let login_stage = matches!(stage, "zprofile" | "zlogin");
        if login_stage && start.login == Some(false) {
            continue;
        }
        // Without `RCS`, zsh reads /etc's zshenv and nothing after it;
        // without `GLOBAL_RCS`, no other file in /etc; a file read so far
        // may turn them on again.
        if !(start.rcs || reader.rcs) && stage != "zshenv" {
            break;
        }
        // Whether zsh certainly reads the stage's file, as an assignment
        // that is its first command then drops the values from before it
        // ([`paths`]): a login stage's only for a login shell. A file in /etc
        // never, as a zsh reads its stage's file in /etc or in /etc/zsh, as
        // it was built, which the check does not know.
        let certain = !login_stage || start.login == Some(true);
        if start.global_rcs || reader.rcs || stage == "zshenv" {
            for dir in ["/etc", "/etc/zsh"] {
                reader.file(&Path::new(dir).join(stage), false);
            }
            if stage == "zshenv" && !matches!(fs.inode(Path::new("/etc/NIXOS")), Ok(None)) {
                // The zshenv nixpkgs builds into zsh reads, on NixOS,
                // /etc/set-environment when /etc/zshenv is missing, and
                // /etc/zshenv.local after either.
                if matches!(fs.inode(Path::new("/etc/zshenv")), Ok(None)) {
                    reader.file(Path::new("/etc/set-environment"), false);
                }
                reader.file(Path::new("/etc/zshenv.local"), false);
            }
        }
        if !(start.rcs || reader.rcs) {
            break;
        }
        // The user's own, from each place the files read so far may put
        // ZDOTDIR in. Where a file read so far may turn `RCS` off, zsh reads
        // none of them, so they may still be certain; where one may run an
        // `emulate` of sh's mode, zsh may read the home's in their place.
        reader.user_files(stage, certain && !reader.sh_mode);
    }
    reader.startup_changers = reader.changers.len();
    reader.autoloaded();
    reader.edits();
    reader.runs();
    reader.unlisted();
    reader.jobs();
    reader.reading_doubts();
    reader.arithmetic();
    reader.since_start();
    reader.made();
    // A prompt's code runs only when PROMPT_SUBST is on; whether a command
    // line turns it on, the check reads beside the files.
    let mut doubts = reader.doubts;
    let mut prompts = Vec::new();
    if reader.prompt_subst {
        doubts.extend(reader.prompts);
    } else {
        prompts = reader.prompts;
    }
    let mut scan = Scan {
        doubts,
        prompts,
        reopened: reader.rcs && !(start.rcs && start.global_rcs),
        ..Scan::default()
    };
    for ((_, shown, entered), named) in OPTIONS.iter().zip(reader.options) {
        if let Some(named) = named {
            scan.writes.push(Write {
                what: format!("{named} {shown}"),
                entered: *entered,
                option: true,
            });
        }
    }
    // A hook may run it as each line is entered (`preexec`).
    scan.writes.extend(reader.fc.into_iter().map(|what| Write {
        what,
        entered: true,
        option: false,
    }));
    scan
}
