// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a zsh's `fpath` starts, as its program and its environment tell,
//! the stock `promptinit` it finds there and what it reads, a `compinit`
//! zsh may load, and NixOS's generated files.

use super::autoload::unfound;
use super::*;
use crate::filesystem::PathKind;

// What may change what NixOS's dircolors line runs.
#[path = "zsh_dircolors_tests.rs"]
mod dircolors;

// The elements of fpath the check cannot follow where it knows where fpath
// starts, and prompt themes.
#[path = "zsh_fpath_tests.rs"]
mod fpath;

// What zsh may run as you complete a word: a compinit zsh may load,
// `compctl` and bash's `complete`.
#[path = "zsh_completion_tests.rs"]
mod completion;

/// A zsh 5.9.2 from the Nix store.
const ZSH: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2";

/// Its own function directory.
const OWN: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2/share/zsh/5.9.2/functions";

/// A zsh from the Nix store at `ZSH` whose program names `named`, with the
/// files `functions` in its own function directory; a stock function among
/// them holds the text a test takes for its stock code.
fn nix_zsh(fs: &MockFilesystem, named: &[&str], functions: &[&str]) {
    let mut program = b"\x7fELF\0".to_vec();
    for dir in named {
        program.extend_from_slice(dir.as_bytes());
        program.push(0);
    }
    program.extend_from_slice(format!("{ZSH}/etc/zshenv\0").as_bytes());
    fs.mock_set_file_content(
        &format!("{ZSH}/bin/zsh"),
        &String::from_utf8(program).expect("text"),
    );
    fs.mock_set_path_type(OWN, PathKind::Dir);
    let mut entries = Vec::new();
    for name in functions {
        let path = format!("{OWN}/{name}");
        seed(fs, &path, &stock::tests::text(name));
        entries.push(PathBuf::from(path));
    }
    fs.mock_set_directory_contents(Path::new(OWN), entries);
}

/// The environment of a shell with `vars` in it.
fn environment(vars: &[(&str, &str)]) -> Vec<(String, String)> {
    vars.iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

/// What the check knows of the zsh at `ZSH` started with `vars` in its
/// environment.
fn install(fs: &MockFilesystem, vars: &[(&str, &str)]) -> Install {
    Install::of(
        fs,
        Some(Path::new(&format!("{ZSH}/bin/zsh"))),
        Some(&environment(vars)),
    )
}

/// What `fs` sets for a zsh started as `start`, in the home, with `install`.
fn scan_with(fs: &MockFilesystem, start: Start, install: &Install) -> Scan {
    zsh(fs, &[PathBuf::from(HOME)], start, install)
}

#[test]
fn a_nix_zsh_s_fpath_starts_in_its_own_directory_or_where_fpath_names() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    assert_eq!(
        install(&fs, &[("USER", "alice")]),
        Install {
            fpath: Some(vec![PathBuf::from(OWN)]),
            version: Some("5.9.2".to_string()),
            env: Some(super::super::install::Env {
                user: Some("alice".to_string()),
                ..Default::default()
            }),
            started: None,
        }
    );
    // An FPATH in its environment replaces it, as zsh 5.9.2 takes it.
    assert_eq!(
        install(&fs, &[("FPATH", "/a:/b")]).fpath,
        Some(vec![PathBuf::from("/a"), PathBuf::from("/b")])
    );
    // One that names a directory relative to where zsh runs, or nothing, is
    // none the check can tell.
    for fpath in ["rel:/b", "", "/a::/b"] {
        assert_eq!(install(&fs, &[("FPATH", fpath)]).fpath, None, "{fpath}");
    }
    // Without its environment, the check cannot tell where it starts.
    assert_eq!(
        Install::of(&fs, Some(Path::new(&format!("{ZSH}/bin/zsh"))), None),
        Install {
            fpath: None,
            version: Some("5.9.2".to_string()),
            env: None,
            started: None,
        }
    );
}

#[test]
fn a_zsh_the_check_cannot_tell_was_built_as_nixpkgs_builds_it_has_no_known_fpath() {
    let unknown = |fs: &MockFilesystem, program: &str| {
        Install::of(fs, Some(Path::new(program)), Some(&environment(&[]))).fpath
    };
    // A program that names another of zsh's directories beside its own, or
    // not its own, as one built with a site directory would.
    for named in [
        vec![
            OWN,
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2/share/zsh/site-functions",
        ],
        vec![OWN, "/usr/local/share/zsh/site-functions"],
        vec!["/usr/share/zsh/functions"],
        vec![],
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(&fs, &named, &["compinit"]);
        assert_eq!(unknown(&fs, &format!("{ZSH}/bin/zsh")), None, "{named:?}");
    }
    // A directory in its own, as a build with function subdirectories has.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    fs.mock_set_path_type(&format!("{OWN}/Completion"), PathKind::Dir);
    fs.mock_set_directory_contents(
        Path::new(OWN),
        vec![PathBuf::from(format!("{OWN}/Completion"))],
    );
    assert_eq!(unknown(&fs, &format!("{ZSH}/bin/zsh")), None);
    // A program outside the store, or not named as nixpkgs names zsh's.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    for program in [
        "/usr/bin/zsh",
        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2/bin/zsh-5.9.2",
        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.x/bin/zsh",
        "/nix/store/0123456789abcdfghijklmnpqrsvwxye-zsh-5.9.2/bin/zsh",
        "/nix/store/0123456789-zsh-5.9.2/bin/zsh",
    ] {
        assert_eq!(unknown(&fs, program), None, "{program}");
    }
}

#[test]
fn a_function_found_where_the_fpath_starts_is_read_and_an_unfound_one_is_none() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    seed(&fs, &format!("{OWN}/hist_setup"), "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz hist_setup nowhere && hist_setup\n",
    );
    let known = install(&fs, &[]);
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known)
            .writes
            .into_iter()
            .map(|write| write.what)
            .collect::<Vec<_>>(),
        [format!("{OWN}/hist_setup names SHARE_HISTORY")]
    );
    // zsh finds `nowhere` in no directory, so it runs none: no doubt.
    assert_eq!(scan_with(&fs, UNKNOWN, &known).doubts, Vec::<String>::new());
    // Not knowing where it starts, each is a doubt as before.
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [unfound("`hist_setup` and `nowhere`")]
    );
}

#[test]
fn an_fc_alias_counts_as_used_in_a_stock_function_zsh_expands_aliases_in() {
    // Autoloaded without -U, zsh expands the aliases the files define in
    // promptinit's code as it loads it: with this alias, `typeset -A
    // _i_test` there runs `fc -l -A _i_test`, which appends the history to a
    // file.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["promptinit"]);
    let known = install(&fs, &[]);
    let doubt = "it cannot tell what the alias `typeset=fc -l` in /home/alice/.zshrc runs where \
                 it is used, as zsh hands the fc it stands for the words after it";
    for (rc, doubts) in [
        (
            "alias typeset='fc -l'\nautoload promptinit && promptinit\n",
            vec![doubt],
        ),
        (
            "alias typeset='fc -l'\nfunctions -u promptinit && promptinit\n",
            vec![doubt],
        ),
        (
            "alias typeset='fc -l'\nautoload -Uz promptinit && promptinit\n",
            vec![],
        ),
        (
            "alias typeset='fc -l'\nautoload -U +X promptinit && promptinit\n",
            vec![],
        ),
    ] {
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan_with(&fs, UNKNOWN, &known).doubts, doubts, "{rc}");
    }
}

/// The doubt of a `compinit` that zsh may load, which the files at `places`
/// autoload.
pub(super) fn compinit_doubt(places: &str) -> String {
    let verb = if places.contains(" and ") {
        "autoload"
    } else {
        "autoloads"
    };
    format!(
        "it cannot tell what zsh runs as you complete a word, as {places} {verb} compinit, which \
         starts zsh's completion system, whose own functions run what programs print as code, \
         and the programs and settings that may change what they print cannot all be listed"
    )
}

#[test]
fn a_compinit_zsh_may_load_is_a_doubt_whatever_its_bytes() {
    // zsh 5.9 to 5.9.2's own completion functions run what tar prints for
    // a catalog `LANGUAGE` names, and what bash prints with `BASH_ENV`, as
    // code: zsh writes the line with either as Tab completes `tar --zap=` or
    // `bash -o zap=`, so a compinit zsh may load is a doubt, its stock code
    // too.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    let known = install(&fs, &[]);
    for rc in [
        "autoload -Uz compinit && compinit\n",
        "autoload -U compinit\n",
        "autoload -Uz +X compinit\n",
        "functions -u compinit\n",
        "typeset -fu compinit\n",
        "precmd() { autoload -Uz compinit && compinit; unfunction precmd }\n",
    ] {
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known).doubts,
            [compinit_doubt("/home/alice/.zshrc")],
            "{rc}"
        );
    }
    // A changed one, one in a directory the files put in front, and one
    // loaded by its path are doubts too, whatever their code.
    seed(
        &fs,
        &format!("{OWN}/compinit"),
        ": a compinit of another zsh\n",
    );
    seed(&fs, "/home/alice/.zfunc/compinit", ":\n");
    for rc in [
        "autoload -Uz compinit && compinit\n",
        "fpath=(~/.zfunc $fpath)\nautoload -Uz compinit && compinit\n",
        "autoload -Uz ~/.zfunc/compinit && compinit\n",
    ] {
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known).doubts,
            [compinit_doubt("/home/alice/.zshrc")],
            "{rc}"
        );
    }
    // One that no directory holds is none zsh can run: no doubt.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["promptinit"]);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &install(&fs, &[])), Scan::default());
    // Not knowing where fpath starts, one is a doubt as any function is.
    assert_eq!(scan(&fs, UNKNOWN).doubts, [unfound("`compinit`")]);
}

#[test]
fn a_function_add_zsh_hook_or_add_zle_hook_widget_autoloads_is_read() {
    // zsh 5.9.2 runs ~/.zfunc/lines after each command for each of these:
    // add-zsh-hook and add-zle-hook-widget autoload the function they add.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["add-zsh-hook", "add-zle-hook-widget"]);
    seed(&fs, "/home/alice/.zfunc/lines", "fc -AI\n");
    let known = install(&fs, &[]);
    for line in [
        "autoload -Uz add-zsh-hook && add-zsh-hook precmd lines",
        "autoload -Uz add-zsh-hook && add-zsh-hook -Uz precmd lines",
        "autoload -Uz add-zle-hook-widget && add-zle-hook-widget line-finish lines",
    ] {
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("fpath=(~/.zfunc $fpath)\n{line}\n"),
        );
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known)
                .writes
                .into_iter()
                .map(|write| write.what)
                .collect::<Vec<_>>(),
            ["/home/alice/.zfunc/lines names `fc -AI`"],
            "{line}"
        );
    }
    // One that takes a hook away autoloads none.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/.zfunc $fpath)\nautoload -Uz add-zsh-hook && add-zsh-hook -d precmd lines\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
}

#[test]
fn a_prompt_the_shell_s_environment_holds_is_code_where_prompt_subst_may_be_on() {
    // zsh 5.9.2 takes each of these from its environment and, with `setopt
    // prompt_subst` in ~/.zshrc, runs `fc -AI` as it shows the prompt, which
    // appends each command line to HISTFILE.
    let doubt = |name: &str| {
        format!(
            "it cannot follow the code that `{name}` in the shell's environment holds, which zsh \
             runs as it shows the prompt unless a file sets it, as PROMPT_SUBST may be on"
        )
    };
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &[]);
    seed(&fs, "/home/alice/.zshrc", "setopt prompt_subst\n");
    for name in walk::PROMPTS.iter().copied() {
        let known = install(&fs, &[(name, "$(fc -AI)%# ")]);
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known).doubts,
            [doubt(name)],
            "{name}"
        );
        assert!(ENVIRONMENT.contains(&name), "{name}");
    }
    // Where no file may turn PROMPT_SUBST on, it is one the command line may
    // make a doubt.
    seed(&fs, "/home/alice/.zshrc", "");
    let found = scan_with(&fs, UNKNOWN, &install(&fs, &[("PS1", "`fc -AI`")]));
    assert_eq!(found.doubts, Vec::<String>::new());
    assert_eq!(found.prompts, [doubt("PS1")]);
    // One without an expansion, and a `$` that starts none, are none.
    seed(&fs, "/home/alice/.zshrc", "setopt prompt_subst\n");
    for value in ["%n@%m %# ", "[\\u@\\h \\W]\\$ ", "$ "] {
        let known = install(&fs, &[("PS1", value)]);
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{value}");
    }
    // zsh 5.9.2 runs the function `log` the environment's NULLCMD names for
    // `>/dev/null` alone in a hook, and READNULLCMD's for `</dev/null`.
    seed(&fs, "/home/alice/.zshrc", "");
    for name in ["NULLCMD", "READNULLCMD"] {
        let known = install(&fs, &[(name, "log")]);
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known).doubts,
            [format!(
                "it cannot tell what code the command that {name} in the shell's environment \
                 names runs, which zsh runs for a redirection that has none"
            )],
            "{name}"
        );
        assert!(ENVIRONMENT.contains(&name), "{name}");
    }
}

#[test]
fn the_stock_promptinit_runs_the_theme_prompt_names() {
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[OWN],
        &["promptinit", "add-zsh-hook", "add-zle-hook-widget"],
    );
    seed(
        &fs,
        &format!("{OWN}/prompt_suse_setup"),
        "prompt_suse_setup () {\n  PS1=\"%n@%m:%~/ > \"\n  PS2=\"> \"\n  prompt_opts=( cr percent )\n}\n\nprompt_suse_setup \"$@\"\n",
    );
    seed(
        &fs,
        &format!("{OWN}/prompt_evil_setup"),
        "setopt share_history\n",
    );
    let known = install(&fs, &[]);
    let rc = |line: &str| format!("autoload -U promptinit && promptinit && {line}\n");
    // It marks every theme; zsh runs the one `prompt` names.
    for line in [
        "prompt suse",
        "prompt -s suse",
        "prompt -l",
        "prompt -c",
        ":",
    ] {
        seed(&fs, "/home/alice/.zshrc", &rc(line));
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{line}");
    }
    for line in [
        "prompt evil",
        "prompt -h evil",
        "prompt -p evil suse",
        "prompt_evil_setup",
    ] {
        seed(&fs, "/home/alice/.zshrc", &rc(line));
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known)
                .writes
                .into_iter()
                .map(|write| write.what)
                .collect::<Vec<_>>(),
            [format!("{OWN}/prompt_evil_setup names SHARE_HISTORY")],
            "{line}"
        );
    }
    // One it picks itself, or that an expansion names, is a doubt.
    for (line, shown) in [
        ("prompt random", "prompt random"),
        ("prompt -p", "prompt -p"),
        ("prompt $theme", "prompt $theme"),
        ("prompt 'a/b'", "prompt a/b"),
    ] {
        seed(&fs, "/home/alice/.zshrc", &rc(line));
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known).doubts,
            [format!(
                "it cannot tell which prompt theme `{shown}` in /home/alice/.zshrc runs"
            )],
            "{line}"
        );
    }
    // What the code it keeps runs as the theme changes, it cannot follow.
    seed(&fs, "/home/alice/.zshrc", &rc("prompt_cleanup 'print x'"));
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        [
            "it cannot follow the code that `prompt_cleanup` in /home/alice/.zshrc runs, which \
             promptinit defines"
        ]
    );
    // A theme may turn PROMPT_SUBST on, so a prompt's code is a doubt.
    seed(
        &fs,
        "/home/alice/.zshrc",
        &rc("prompt suse\nPS1='$(git_branch) %# '"),
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        [
            "it cannot follow the code that `PS1=$(git_branch) %# ` in /home/alice/.zshrc runs \
             as zsh shows the prompt, as PROMPT_SUBST may be on"
        ]
    );
    // A widget add-zle-hook-widget makes a hook is one.
    seed(
        &fs,
        "/home/alice/.zshrc",
        &rc("w() { print -r -- $BUFFER >> $f }\nadd-zle-hook-widget line-finish w"),
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        [
            "it cannot tell where the output that `w` in /home/alice/.zshrc redirects to `$f` \
             goes, which may be the history file"
        ]
    );
}

/// NixOS's generated `/etc/zshenv`, as `programs.zsh` writes it, sourcing
/// its `set-environment`.
const NIXOS_ZSHENV: &str = "\
# /etc/zshenv: DO NOT EDIT -- this file has been generated automatically.
# This file is read for all shells.

# Only execute this file once per shell.
if [ -n \"${__ETC_ZSHENV_SOURCED-}\" ]; then return; fi
__ETC_ZSHENV_SOURCED=1

if [ -z \"${__NIXOS_SET_ENVIRONMENT_DONE-}\" ]; then
    . /nix/store/i7pr6qxbzs6a7qxim17l8krynfy2r7ll-set-environment
fi

HELPDIR=\"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2/share/zsh/$ZSH_VERSION/help\"

# Tell zsh how to find installed completions.
for p in ${(z)NIX_PROFILES}; do
    fpath=($p/share/zsh/site-functions $p/share/zsh/$ZSH_VERSION/functions $p/share/zsh/vendor-completions $fpath)
done

# Setup custom shell init stuff.




# Read system-wide modifications.
if test -f /etc/zshenv.local; then
    . /etc/zshenv.local
fi
";

/// The lines of NixOS's `set-environment` that name the profiles, and that
/// set `PATH` to each profile's `bin` and put the setuid wrappers in front.
const NIXOS_SET_ENVIRONMENT: &str = "\
# DO NOT EDIT -- this file has been generated automatically.
# Prevent this file from being sourced by child shells.
export __NIXOS_SET_ENVIRONMENT_DONE=1
export LANG=\"en_US.UTF-8\"
export NIX_PROFILES=\"/run/current-system/sw /nix/var/nix/profiles/default /etc/profiles/per-user/$USER $HOME/.local/state/nix/profile ${XDG_STATE_HOME}/nix/profile $HOME/.nix-profile\"
export PATH=\"$HOME/.nix-profile/bin:${XDG_STATE_HOME}/nix/profile/bin:$HOME/.local/state/nix/profile/bin:/etc/profiles/per-user/$USER/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin\"
export TERM=$TERM

# Extra initialisation
export PATH=\"/run/wrappers/bin:$PATH\"
";

/// NixOS's generated `/etc/zshrc` with `programs.zsh.setOptions` without
/// `SHARE_HISTORY`, as nixpkgs 26.05 writes it, its completion on as by
/// default ([`NIXOS_COMPINIT`]).
const NIXOS_ZSHRC: &str = "\
# /etc/zshrc: DO NOT EDIT -- this file has been generated automatically.
# This file is read for interactive shells.

# Only execute this file once per shell.
if [ -n \"$__ETC_ZSHRC_SOURCED\" -o -n \"$NOSYSZSHRC\" ]; then return; fi
__ETC_ZSHRC_SOURCED=1

# Set zsh options.
setopt HIST_IGNORE_DUPS HIST_FCNTL_LOCK


# Determine current fqdn hostname
HOST=$(/nix/store/ik047piv5073d8iyc9bmk3l9l5iq5nwl-hostname-hostname-debian-3.25/bin/hostname --fqdn)

# Setup command line history.
# Don't export these, otherwise other shells (bash) will try to use same HISTFILE.
SAVEHIST=2000
HISTSIZE=2000
HISTFILE=$HOME/.zsh_history

# Configure sane keyboard defaults.
. /etc/zinputrc

# Enable autocompletion.
autoload -U compinit && compinit

# Extra colors for directory listings.
eval \"$(/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin/dircolors -b)\"


# Setup aliases.
alias -- l='ls -alh'
alias -- ll='ls -l'
alias -- ls='ls --color=tty'

# Setup prompt.
autoload -U promptinit && promptinit && prompt suse && setopt prompt_sp


# Disable some features to support TRAMP.
if [ \"$TERM\" = dumb ]; then
    unsetopt zle prompt_cr prompt_subst
    unset RPS1 RPROMPT
    PS1='$ '
    PROMPT='$ '
fi

# Read system-wide modifications.
if test -f /etc/zshrc.local; then
    . /etc/zshrc.local
fi
";

/// The line of [`NIXOS_ZSHRC`] that `programs.zsh.enableCompletion`, on by
/// default, writes.
const NIXOS_COMPINIT: &str = "autoload -U compinit && compinit\n";

/// [`NIXOS_ZSHRC`] as nixpkgs writes it with `programs.zsh.enableCompletion`
/// off, without [`NIXOS_COMPINIT`].
fn nixos_zshrc() -> String {
    assert!(NIXOS_ZSHRC.contains(NIXOS_COMPINIT));
    NIXOS_ZSHRC.replacen(NIXOS_COMPINIT, "", 1)
}

/// A NixOS host as `programs.zsh` sets it up, without `SHARE_HISTORY` and
/// with its completion off ([`nixos_zshrc`]), whose system profile links
/// zsh's own functions and a completion function of another package, and
/// the coreutils its `/etc/zshrc` names.
fn nixos(fs: &MockFilesystem) {
    nixos_without_coreutils(fs);
    seed_coreutils(fs, "2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11");
}

/// A NixOS host as [`nixos`] sets it up, but for the coreutils its
/// `/etc/zshrc` names.
fn nixos_without_coreutils(fs: &MockFilesystem) {
    nix_zsh(
        fs,
        &[OWN],
        &[
            "compinit",
            "compaudit",
            "compdump",
            "promptinit",
            "add-zsh-hook",
            "add-zle-hook-widget",
        ],
    );
    seed(
        fs,
        &format!("{OWN}/prompt_suse_setup"),
        "prompt_suse_setup () {\n  PS1=\"%n@%m:%~/ > \"\n  prompt_opts=( cr percent )\n}\n\
         prompt_suse_setup \"$@\"\n",
    );
    seed(fs, "/etc/zshenv", NIXOS_ZSHENV);
    seed(
        fs,
        "/nix/store/i7pr6qxbzs6a7qxim17l8krynfy2r7ll-set-environment",
        NIXOS_SET_ENVIRONMENT,
    );
    seed(fs, "/etc/zshrc", &nixos_zshrc());
    seed(fs, "/etc/zinputrc", "bindkey '^[[H' beginning-of-line\n");
    let sw = "/run/current-system/sw/share/zsh";
    for name in ["compinit", "compaudit", "compdump", "promptinit"] {
        seed(
            fs,
            &format!("{sw}/5.9.2/functions/{name}"),
            &stock::tests::text(name),
        );
    }
    seed(
        fs,
        &format!("{sw}/site-functions/_systemctl"),
        "#compdef systemctl\neval \"$(systemctl --help)\"\n",
    );
}

/// The environment of a shell in a NixOS session: `set-environment` has
/// run, and named the profiles.
const SESSION: [(&str, &str); 4] = [
    (
        "NIX_PROFILES",
        "/run/current-system/sw /nix/var/nix/profiles/default /etc/profiles/per-user/alice \
         /home/alice/.local/state/nix/profile /home/alice/.nix-profile",
    ),
    ("USER", "alice"),
    ("__NIXOS_SET_ENVIRONMENT_DONE", "1"),
    (
        "PATH",
        "/run/wrappers/bin:/home/alice/.nix-profile/bin:/nix/profile/bin:\
         /home/alice/.local/state/nix/profile/bin:/etc/profiles/per-user/alice/bin:\
         /nix/var/nix/profiles/default/bin:/run/current-system/sw/bin",
    ),
];

#[test]
fn a_nixos_zsh_without_the_options_or_completion_passes() {
    let fs = MockFilesystem::new();
    nixos(&fs);
    // In a session, and from a login on a console, where /etc/zshenv runs
    // set-environment, which names the profiles.
    for vars in [&SESSION[..], &[("USER", "alice")][..]] {
        let known = install(&fs, vars);
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{vars:?}");
    }
    // With an empty ~/.zshrc or one with what most hold but compinit.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "zstyle ':completion:*' menu select\n\
         alias h='fc -l'\nprecmd() { print -Pn '\\e]0;%~\\a' > $TTY }\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)),
        Scan::default()
    );
    // The compinit NixOS writes with its completion on, as by default, and
    // one the user's files run, are doubts.
    seed(&fs, "/etc/zshrc", NIXOS_ZSHRC);
    seed(&fs, "/home/alice/.zshrc", "");
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)).doubts,
        [compinit_doubt("/etc/zshrc")]
    );
    seed(&fs, "/etc/zshrc", &nixos_zshrc());
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)).doubts,
        [compinit_doubt("/home/alice/.zshrc")]
    );
}

#[test]
fn a_nixos_zsh_that_differs_from_what_nixos_writes_does_not_pass() {
    let warns = |fs: &MockFilesystem, vars: &[(&str, &str)]| {
        let found = scan_with(fs, UNKNOWN, &install(fs, vars));
        !found.writes.is_empty() || !found.doubts.is_empty()
    };
    // SHARE_HISTORY in programs.zsh.setOptions, as by default.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(
        &fs,
        "/etc/zshrc",
        &nixos_zshrc().replace(
            "HIST_IGNORE_DUPS HIST_FCNTL_LOCK",
            "HIST_IGNORE_DUPS SHARE_HISTORY",
        ),
    );
    assert!(warns(&fs, &SESSION));
    // A dircolors line that is not the one NixOS writes, or in a file that
    // is not NixOS's.
    for (from, to) in [
        ("dircolors -b)\"", "dircolors -b ~/.dircolors)\""),
        ("dircolors -b)\"", "dircolors -b)\" # x"),
        ("eval \"$(/nix", "  eval \"$(/nix"),
        ("-coreutils-9.11/", "-evil-9.11/"),
        (
            "2gfxiwls9hbgwdwcy43mprchwsq36mg6-",
            "2gfxiwls9hbgwdwcy43mprchwsq36mge-",
        ),
        ("# /etc/zshrc: DO NOT EDIT", "# /etc/zshrc: edited"),
    ] {
        let fs = MockFilesystem::new();
        nixos(&fs);
        assert!(nixos_zshrc().contains(from), "{from}");
        seed(&fs, "/etc/zshrc", &nixos_zshrc().replacen(from, to, 1));
        assert!(warns(&fs, &SESSION), "{to}");
    }
    // A store path named for coreutils whose dircolors is no link to its
    // coreutils program, or whose program is none that prints what GNU
    // dircolors does (a script that prints `setopt share_history`).
    let bin = "/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin";
    for (path, bytes) in [
        ("dircolors", &b"#!/bin/sh\necho setopt share_history\n"[..]),
        ("coreutils", &b"#!/bin/sh\necho setopt share_history\n"[..]),
        ("coreutils", &b"\x7fELF\0setopt share_history\0"[..]),
    ] {
        let fs = MockFilesystem::new();
        nixos(&fs);
        if path == "dircolors" {
            // Its own program, not the link nixpkgs makes.
            let fresh = MockFilesystem::new();
            nixos_without_coreutils(&fresh);
            fresh.mock_set_file_bytes(&format!("{bin}/dircolors"), bytes);
            assert!(warns(&fresh, &SESSION), "{path}");
            continue;
        }
        fs.mock_set_file_bytes(&format!("{bin}/{path}"), bytes);
        assert!(warns(&fs, &SESSION), "{path}");
    }
    let fs = MockFilesystem::new();
    nixos_without_coreutils(&fs);
    assert!(warns(&fs, &SESSION), "no coreutils");
    // The loop over the profiles with more in its body, the profiles named
    // otherwise, ZSH_VERSION set, or an environment the check cannot read.
    for (from, to) in [
        ("    fpath=($p", "    p=/tmp/x\n    fpath=($p"),
        (
            "    fpath=($p/share/zsh/site-functions",
            "    fpath=($p/share/zsh/site-functions $p/x",
        ),
        (
            "for p in ${(z)NIX_PROFILES}; do",
            "for p in ${NIX_PROFILES}; do",
        ),
        ("HELPDIR=", "NIX_PROFILES=$profiles\nHELPDIR="),
        ("HELPDIR=", "read NIX_PROFILES < ~/.profiles\nHELPDIR="),
        ("HELPDIR=", "ZSH_VERSION=x\nHELPDIR="),
    ] {
        let fs = MockFilesystem::new();
        nixos(&fs);
        assert!(NIXOS_ZSHENV.contains(from), "{from}");
        seed(&fs, "/etc/zshenv", &NIXOS_ZSHENV.replacen(from, to, 1));
        assert!(warns(&fs, &SESSION), "{to}");
    }
    let fs = MockFilesystem::new();
    nixos(&fs);
    let found = scan(&fs, UNKNOWN);
    assert!(!found.doubts.is_empty(), "{found:?}");
    // A profile the environment names that zsh would split otherwise.
    assert!(warns(
        &fs,
        &[
            ("NIX_PROFILES", "/run/current-system/sw '/a b'"),
            ("USER", "alice")
        ]
    ));
    // A profile that holds a promptinit of its own: it is read.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(
        &fs,
        "/home/alice/.nix-profile/share/zsh/site-functions/promptinit",
        "setopt share_history\n",
    );
    assert!(warns(&fs, &SESSION));
}

/// Whether `found` is anything but a pass.
fn warned(found: &Scan) -> bool {
    !found.writes.is_empty() || !found.doubts.is_empty()
}

#[test]
fn prompt_restore_runs_prompt_default_setup() {
    // zsh 5.9.2 writes each command line to HISTFILE with a
    // prompt_default_setup that makes a hook, once `prompt` has run.
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[OWN],
        &["promptinit", "add-zsh-hook", "add-zle-hook-widget"],
    );
    seed(
        &fs,
        "/home/alice/zfn/prompt_default_setup",
        "precmd() { fc -AI }\n",
    );
    let known = install(&fs, &[]);
    for line in [
        "prompt restore",
        "prompt suse; prompt restore",
        "prompt -s restore",
    ] {
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("fpath=(~/zfn $fpath)\nautoload -Uz promptinit && promptinit\n{line}\n"),
        );
        assert!(
            scan_with(&fs, UNKNOWN, &known)
                .writes
                .iter()
                .any(|write| write.what.contains("prompt_default_setup names `fc -AI`")),
            "{line}"
        );
    }
    // Without a `prompt`, its code to restore the prompt is none.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/zfn $fpath)\nautoload -Uz promptinit && promptinit\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
}

#[test]
fn a_home_a_file_sets_is_one_the_check_cannot_follow() {
    // zsh 5.9.2 reads ~/alt/.zshrc with HOME set so in ~/.zshenv.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "HOME=/home/alice/alt\n");
    seed(&fs, "/home/alice/alt/.zshrc", "setopt share_history\n");
    assert!(warned(&scan(&fs, UNKNOWN)));
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "HOME=$HOME/alt\n");
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [
            "it cannot follow the HOME that /home/alice/.zshrc may set, which changes where zsh \
             reads the user's startup files"
        ]
    );
}

#[test]
fn what_the_environment_holds_of_where_zsh_reads_its_files_counts() {
    // A ZDOTDIR there is where zsh reads the user's files.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/zd/.zshrc", "setopt share_history\n");
    let found = scan_with(
        &fs,
        UNKNOWN,
        &install(&fs, &[("ZDOTDIR", "/home/alice/zd")]),
    );
    assert_eq!(
        found
            .writes
            .iter()
            .map(|write| write.what.as_str())
            .collect::<Vec<_>>(),
        ["/home/alice/zd/.zshrc names SHARE_HISTORY"]
    );
    assert!(warned(&scan_with(
        &fs,
        UNKNOWN,
        &install(&fs, &[("ZDOTDIR", "zd")])
    )));
    // A HOME there is the one zsh runs with; one not among the homes is a
    // doubt.
    let known = install(&fs, &[("HOME", "/home/alice")]);
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    let found = zsh(
        &fs,
        &[PathBuf::from(HOME)],
        UNKNOWN,
        &install(&fs, &[("HOME", "/srv/other")]),
    );
    assert_eq!(
        found.doubts,
        [
            "it cannot tell what the user's startup files hold, as the shell's environment sets \
             HOME to `/srv/other`, a home the check does not read"
        ]
    );
}

#[test]
fn nix_profiles_are_split_as_zsh_splits_them() {
    use super::super::install::profile_words;
    assert_eq!(
        profile_words("/run/current-system/sw\t/home/alice/.nix-profile  /a+b@c"),
        Some(
            [
                "/run/current-system/sw",
                "/home/alice/.nix-profile",
                "/a+b@c"
            ]
            .map(str::to_string)
            .to_vec()
        )
    );
    // zsh 5.9.2's `${(z)...}` splits `;`, `&` and `>` off as words of their
    // own, and no no-break space.
    for value in [
        "/nonexistent;/home/alice/evil",
        "/a&/b",
        "/a>/b",
        "/a\u{a0}/b",
        "/a\n/b",
        "relative/profile",
        "/a$x",
    ] {
        assert_eq!(profile_words(value), None, "{value:?}");
    }
}

#[test]
fn a_function_loaded_by_its_path_puts_its_directory_in_front_of_fpath() {
    // zsh 5.9.2 finds `helper` beside `init`, which it loads by its path,
    // and a function `-d` names in fpath when its path holds none.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    let known = install(&fs, &[]);
    seed(
        &fs,
        "/home/alice/.zplug/init",
        "autoload -Uz helper; helper\n",
    );
    seed(&fs, "/home/alice/.zplug/helper", "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz ~/.zplug/init; init\n",
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &known)));
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit"]);
    seed(&fs, "/home/alice/zfn/hist_setup", "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/zfn $fpath)\nautoload -Uzd ~/nowhere/hist_setup; hist_setup\n",
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &install(&fs, &[]))));
}

#[test]
fn an_fpath_whose_elements_an_expansion_changes_is_one_the_check_cannot_follow() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["promptinit"]);
    let known = install(&fs, &[]);
    // zsh 5.9.2 looks for the functions the files autoload (compinit, as it
    // was seen) in directories relative to where it runs with the first two.
    for set in [
        "fpath=(${(s:/:)fpath})",
        "fpath=($FPATH[2,10] $fpath)",
        "fpath=(${fpath[(I)x]})",
        "fpath=(${(L)fpath})",
        "fpath=($fpath:h)",
    ] {
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{set}\nautoload -Uz promptinit && promptinit\n"),
        );
        assert!(warned(&scan_with(&fs, UNKNOWN, &known)), "{set}");
    }
    // Elements kept as they are, or some of them, are none.
    for set in [
        "fpath=(${(u)fpath})",
        "fpath=(${fpath[2,-1]} $fpath[1])",
        "fpath=(${(@)fpath} ${fpath[@]})",
        "fpath=(${fpath:#/nix/store/x})",
    ] {
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{set}\nautoload -Uz promptinit && promptinit\n"),
        );
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{set}");
    }
}

#[test]
fn a_nix_zsh_built_to_look_in_another_directory_has_no_known_fpath() {
    // As `--enable-site-fndir` or `--enable-additional-fpath` builds it.
    for extra in [
        "/etc/zsh/functions",
        "/opt/zfuncs",
        "/usr/share/zsh/site-functions",
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(&fs, &[OWN, extra], &["compinit"]);
        assert_eq!(install(&fs, &[]).fpath, None, "{extra}");
    }
    // The paths a nixpkgs build names beside its own are none, and a string
    // of `/` and a byte is data unless it names a directory.
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[
            OWN,
            "/etc/zshrc",
            "/dev/tty",
            "/tmp/zsh",
            "/0",
            "/run/current-system/sw/bin:/bin:/usr/bin:/nix/var/nix/profiles/default/bin",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-glibc-2.42/lib/ld-linux-x86-64.so.2",
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-ncurses-6.6/lib",
        ],
        &["compinit"],
    );
    assert_eq!(install(&fs, &[]).fpath, Some(vec![PathBuf::from(OWN)]));
    fs.mock_set_path_type("/0", PathKind::Dir);
    assert_eq!(install(&fs, &[]).fpath, None);
}

#[test]
fn the_zshenv_of_nixpkgs_zsh_reads_zshenv_local_on_nixos() {
    // zsh 5.9.2 from nixpkgs, started with -f, turns SHARE_HISTORY on with
    // these files.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/NIXOS", "");
    seed(&fs, "/etc/zshenv.local", "setopt share_history\n");
    let bare = Start {
        login: Some(false),
        rcs: false,
        global_rcs: true,
    };
    assert!(warned(&scan(&fs, bare)));
    // With no /etc/zshenv, it reads /etc/set-environment.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/NIXOS", "");
    seed(&fs, "/etc/set-environment", "setopt share_history\n");
    assert!(warned(&scan(&fs, bare)));
    // Not on NixOS, it reads neither.
    let fs = MockFilesystem::new();
    seed(&fs, "/etc/zshenv.local", "setopt share_history\n");
    seed(&fs, "/etc/set-environment", "setopt share_history\n");
    assert_eq!(scan(&fs, bare), Scan::default());
}

#[test]
fn a_word_prompt_may_expand_into_others_is_a_doubt() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["promptinit"]);
    let known = install(&fs, &[]);
    // zsh 5.9.2 expands each word before prompt reads it, which may name
    // another theme.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz promptinit && promptinit && prompt {suse,x}\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        ["it cannot tell which prompt theme `prompt {suse,x}` in /home/alice/.zshrc runs"]
    );
}
