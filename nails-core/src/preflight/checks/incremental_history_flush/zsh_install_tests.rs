// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a zsh's `fpath` starts, as its program and its environment tell,
//! the stock `compinit` and `promptinit` it finds there and what they read,
//! and NixOS's generated files.

use super::autoload::unfound;
use super::*;
use crate::filesystem::PathKind;

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
fn the_stock_compinit_is_read_for_the_dump_file_it_sources() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    let known = install(&fs, &[]);
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // A dump file as compdump writes it holds data and marks alone.
    seed(&fs, "/home/alice/.zcompdump", dump::tests::DUMP);
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // One with any other line is read as code.
    seed(
        &fs,
        "/home/alice/.zcompdump",
        &format!("{}setopt share_history\n", dump::tests::DUMP),
    );
    assert!(
        scan_with(&fs, UNKNOWN, &known)
            .writes
            .iter()
            .any(|write| write.what == "/home/alice/.zcompdump names SHARE_HISTORY"),
        "{:?}",
        scan_with(&fs, UNKNOWN, &known)
    );
    // zsh may run compiled code in place of it.
    seed(&fs, "/home/alice/.zcompdump", dump::tests::DUMP);
    seed(&fs, "/home/alice/.zcompdump.zwc", "");
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        ["it cannot read the compiled code in /home/alice/.zcompdump.zwc that zsh may run"]
    );
    // The one `-d` names, in the ZDOTDIR a file sets too.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(&fs, "/home/alice/.zshenv", "ZDOTDIR=~/.config/zsh\n");
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "autoload -Uz compinit && compinit -i -d ~/.cache/zcompdump\n",
    );
    seed(
        &fs,
        "/home/alice/.cache/zcompdump",
        "setopt share_history\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/.zcompdump",
        "setopt inc_append_history\n",
    );
    let names: Vec<String> = scan_with(&fs, UNKNOWN, &known)
        .writes
        .into_iter()
        .map(|write| write.what)
        .collect();
    assert_eq!(
        names,
        [
            "/home/alice/.config/zsh/.zcompdump names INC_APPEND_HISTORY",
            "/home/alice/.cache/zcompdump names SHARE_HISTORY",
        ]
    );
    // One whose path the check cannot follow is a doubt.
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "autoload -Uz compinit && compinit -d $XDG_CACHE_HOME/zcompdump\n",
    );
    assert!(
        scan_with(&fs, UNKNOWN, &known).doubts.contains(
            &"it cannot follow the dump file that `compinit -d $XDG_CACHE_HOME/zcompdump` in \
              /home/alice/.config/zsh/.zshrc sources"
                .to_string()
        ),
        "{:?}",
        scan_with(&fs, UNKNOWN, &known)
    );
}

#[test]
fn an_fc_alias_counts_as_used_in_a_stock_function_zsh_expands_aliases_in() {
    // Autoloaded without -U, zsh expands the aliases the files define in
    // compinit's code as it loads it: with this alias, `typeset -A _i_test`
    // there runs `fc -l -A _i_test`, which appends the history to a file.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    let known = install(&fs, &[]);
    let doubt = "it cannot tell what the alias `typeset=fc -l` in /home/alice/.zshrc runs where \
                 it is used, as zsh hands the fc it stands for the words after it";
    for (rc, doubts) in [
        (
            "alias typeset='fc -l'\nautoload compinit && compinit\n",
            vec![doubt],
        ),
        (
            "alias typeset='fc -l'\nfunctions -u compinit && compinit\n",
            vec![doubt],
        ),
        (
            "alias typeset='fc -l'\nautoload -Uz compinit && compinit\n",
            vec![],
        ),
        (
            "alias typeset='fc -l'\nautoload -U +X compinit && compinit\n",
            vec![],
        ),
    ] {
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan_with(&fs, UNKNOWN, &known).doubts, doubts, "{rc}");
    }
}

#[test]
fn a_changed_compinit_or_one_found_first_elsewhere_is_read_as_code() {
    // A compinit whose bytes are no stock one is any function.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compaudit"]);
    seed(&fs, &format!("{OWN}/compinit"), "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    let known = install(&fs, &[]);
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known)
            .writes
            .into_iter()
            .map(|write| write.what)
            .collect::<Vec<_>>(),
        [format!("{OWN}/compinit names SHARE_HISTORY")]
    );
    // One in a directory the files put in front is read, beside the stock
    // one zsh's own holds.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/.zfunc $fpath)\nautoload -Uz compinit && compinit\n",
    );
    seed(&fs, "/home/alice/.zfunc/compinit", "fc -AI\n");
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known)
            .writes
            .into_iter()
            .map(|write| write.what)
            .collect::<Vec<_>>(),
        ["/home/alice/.zfunc/compinit names `fc -AI`"]
    );
    // So is the compaudit compinit runs, when it is no stock one.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compdump"]);
    seed(&fs, &format!("{OWN}/compaudit"), "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).writes.len(),
        1,
        "{:?}",
        scan_with(&fs, UNKNOWN, &known)
    );
}

#[test]
fn a_completion_function_compinit_marks_is_read_where_the_files_run_it() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(&fs, "/home/alice/.zfunc/_lines", "#compdef lines\nfc -AI\n");
    let known = install(&fs, &[]);
    let base = "fpath=(~/.zfunc $fpath)\nautoload -Uz compinit && compinit\n";
    // zsh runs it only as completion runs: compinit marks it, the check
    // does not read it.
    seed(&fs, "/home/alice/.zshrc", base);
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // Run by name, as a hook or in a command substitution, it is read.
    for line in [
        "_lines",
        "precmd_functions+=(_lines)",
        "add-zsh-hook precmd _lines",
        "precmd() { : $(_lines) }",
        "functions[precmd]='_lines'",
        "trap '_lines' DEBUG",
    ] {
        seed(&fs, "/home/alice/.zshrc", &format!("{base}{line}\n"));
        assert_eq!(
            scan_with(&fs, UNKNOWN, &known)
                .writes
                .into_iter()
                .map(|write| write.what)
                .collect::<Vec<_>>(),
            ["/home/alice/.zfunc/_lines names `fc -AI`"],
            "{line}"
        );
    }
    // A function the dump file marks is read the same way.
    let dump = dump::tests::DUMP.replace("_zypper\n", "_zypper _evil\n");
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(&fs, "/home/alice/.zcompdump", &dump);
    seed(&fs, &format!("{OWN}/_evil"), "setopt share_history\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\nzle -N zle-line-init _evil\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known).writes.len(), 1);
}

#[test]
fn a_function_add_zsh_hook_or_compdef_a_autoloads_is_read() {
    // zsh 5.9.2 runs ~/.zfunc/lines after each command for each of these:
    // add-zsh-hook and add-zle-hook-widget autoload the function they add,
    // and so does compdef -a.
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[OWN],
        &[
            "compinit",
            "compaudit",
            "compdump",
            "add-zsh-hook",
            "add-zle-hook-widget",
        ],
    );
    seed(&fs, "/home/alice/.zfunc/lines", "fc -AI\n");
    let known = install(&fs, &[]);
    for line in [
        "autoload -Uz add-zsh-hook && add-zsh-hook precmd lines",
        "autoload -Uz add-zsh-hook && add-zsh-hook -Uz precmd lines",
        "autoload -Uz add-zle-hook-widget && add-zle-hook-widget line-finish lines",
        "autoload -Uz compinit && compinit && compdef -a lines cmd && lines",
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
    // One that takes a hook away autoloads none, and a compdef without -a
    // names a function completion runs.
    for line in [
        "autoload -Uz add-zsh-hook && add-zsh-hook -d precmd lines",
        "autoload -Uz compinit && compinit && compdef lines cmd",
    ] {
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("fpath=(~/.zfunc $fpath)\n{line}\n"),
        );
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{line}");
    }
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit && compdef -a $f cmd\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        ["it cannot tell which function `compdef -a $f cmd` in /home/alice/.zshrc autoloads"]
    );
}

#[test]
fn what_compaudit_may_put_in_fpath_is_read_too() {
    // A directory laid out as zsh's sources are, with Base in it.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    fs.mock_set_path_type("/home/alice/comp", PathKind::Dir);
    fs.mock_set_path_type("/home/alice/comp/Base", PathKind::Dir);
    fs.mock_set_path_type("/home/alice/comp/Unix", PathKind::Dir);
    fs.mock_set_directory_contents(
        Path::new("/home/alice/comp"),
        vec![
            PathBuf::from("/home/alice/comp/Base"),
            PathBuf::from("/home/alice/comp/Unix"),
        ],
    );
    seed(
        &fs,
        "/home/alice/comp/Unix/hist_setup",
        "setopt share_history\n",
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/comp $fpath)\nautoload -Uz compinit && compinit\nautoload -Uz hist_setup\n",
    );
    let known = install(&fs, &[]);
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known)
            .writes
            .into_iter()
            .map(|write| write.what)
            .collect::<Vec<_>>(),
        ["/home/alice/comp/Unix/hist_setup names SHARE_HISTORY"]
    );
    // A `_compdir` a file sets picks the directory: a doubt.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "_compdir=~/comp\nautoload -Uz compinit && compinit\n",
    );
    assert!(
        scan_with(&fs, UNKNOWN, &known).doubts.contains(
            &"it cannot tell which directories compaudit, which compinit runs, puts in fpath, \
              as /home/alice/.zshrc names _compdir"
                .to_string()
        ),
        "{:?}",
        scan_with(&fs, UNKNOWN, &known)
    );
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

/// The lines of NixOS's `set-environment` that name the profiles.
const NIXOS_SET_ENVIRONMENT: &str = "\
# DO NOT EDIT -- this file has been generated automatically.
# Prevent this file from being sourced by child shells.
export __NIXOS_SET_ENVIRONMENT_DONE=1
export LANG=\"en_US.UTF-8\"
export NIX_PROFILES=\"/run/current-system/sw /nix/var/nix/profiles/default /etc/profiles/per-user/$USER $HOME/.local/state/nix/profile ${XDG_STATE_HOME}/nix/profile $HOME/.nix-profile\"
export TERM=$TERM
";

/// NixOS's generated `/etc/zshrc` with `programs.zsh.setOptions` without
/// `SHARE_HISTORY`, as nixpkgs 26.05 writes it.
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

/// A NixOS host as `programs.zsh` sets it up, without `SHARE_HISTORY`,
/// whose system profile links zsh's own functions and a completion function
/// of another package.
fn nixos(fs: &MockFilesystem) {
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
    seed(fs, "/etc/zshrc", NIXOS_ZSHRC);
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
const SESSION: [(&str, &str); 3] = [
    (
        "NIX_PROFILES",
        "/run/current-system/sw /nix/var/nix/profiles/default /etc/profiles/per-user/alice \
         /home/alice/.local/state/nix/profile /home/alice/.nix-profile",
    ),
    ("USER", "alice"),
    ("__NIXOS_SET_ENVIRONMENT_DONE", "1"),
];

#[test]
fn a_nixos_zsh_without_the_options_passes() {
    let fs = MockFilesystem::new();
    nixos(&fs);
    // In a session, and from a login on a console, where /etc/zshenv runs
    // set-environment, which names the profiles.
    for vars in [&SESSION[..], &[("USER", "alice")][..]] {
        let known = install(&fs, vars);
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{vars:?}");
    }
    // With an empty ~/.zshrc or one with what most hold.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\nzstyle ':completion:*' menu select\n\
         alias h='fc -l'\nprecmd() { print -Pn '\\e]0;%~\\a' > $TTY }\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)),
        Scan::default()
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
        &NIXOS_ZSHRC.replace(
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
        assert!(NIXOS_ZSHRC.contains(from), "{from}");
        seed(&fs, "/etc/zshrc", &NIXOS_ZSHRC.replacen(from, to, 1));
        assert!(warns(&fs, &SESSION), "{to}");
    }
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
    // A profile that holds a compinit of its own: it is read.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(
        &fs,
        "/home/alice/.nix-profile/share/zsh/site-functions/compinit",
        "setopt share_history\n",
    );
    assert!(warns(&fs, &SESSION));
}
