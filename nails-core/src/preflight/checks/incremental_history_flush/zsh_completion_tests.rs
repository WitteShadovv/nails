// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What zsh may run as you complete a word that is no code of zsh's own,
//! where the files run its stock `compinit`: completion functions in a
//! directory of `fpath` that is neither zsh's own nor a Nix profile's, a
//! completer, a completion widget's or a `compdef`'s function that is no
//! function of zsh's own, a function the files define named like a
//! completion function, the parameters of the completion system, and
//! `compctl` and bash's `complete`.

use super::*;

/// The stock functions and the completion functions of zsh's own that the
/// tests give zsh's own function directory.
const STOCK: [&str; 7] = [
    "compinit",
    "compaudit",
    "compdump",
    "_complete",
    "_main_complete",
    "_files",
    "_gnu_generic",
];

/// The `.zshrc` lines that run the stock `compinit`.
const COMPINIT: &str = "autoload -Uz compinit && compinit -D\n";

/// What a typed Nix zsh with [`STOCK`] in its own directory finds with `rc`
/// as `.zshrc`, and `fs` with what a test seeds besides.
fn found_with(fs: &MockFilesystem, rc: &str) -> Scan {
    nix_zsh(fs, &[OWN], &STOCK);
    seed(fs, "/home/alice/.zshrc", rc);
    scan_with(fs, UNKNOWN, &install(fs, &[]))
}

/// What [`found_with`] finds in a filesystem of its own.
fn found(rc: &str) -> Scan {
    found_with(&MockFilesystem::new(), rc)
}

/// Seed the files `names` in the directory `dir`, which lists them.
fn listed(fs: &MockFilesystem, dir: &str, names: &[&str]) {
    let mut entries = Vec::new();
    for name in names {
        let path = format!("{dir}/{name}");
        seed(
            fs,
            &path,
            "#compdef git\nprint -r -- \"$BUFFER\" >> ~/.zl\n",
        );
        entries.push(PathBuf::from(path));
    }
    fs.mock_set_path_type(dir, PathKind::Dir);
    fs.mock_set_directory_contents(Path::new(dir), entries);
}

#[test]
fn completion_functions_in_a_directory_the_files_add_to_fpath_are_a_doubt() {
    // zsh 5.9.2 runs `_w` as Tab completes a word with each, which appends
    // the line to the history file.
    for setter in [
        "fpath=(~/zc $fpath)",
        "fpath+=(~/zc)",
        "fpath[1,0]=~/zc",
        "FPATH=~/zc:$FPATH",
    ] {
        let fs = MockFilesystem::new();
        listed(&fs, "/home/alice/zc", &["_w"]);
        let got = found_with(&fs, &format!("{setter}\n{COMPINIT}"));
        assert_eq!(
            got.doubts,
            [
                "it cannot tell what the completion functions in /home/alice/zc write (`_w`), \
                 which zsh runs as you complete a word once compinit marks them, as that directory \
                 of fpath is neither zsh's own nor a Nix profile's"
            ],
            "{setter}"
        );
    }
    // One named like one of zsh's own runs in its place; a compiled one
    // counts too, and the doubt names three of them and how many more.
    let fs = MockFilesystem::new();
    listed(
        &fs,
        "/home/alice/zc",
        &["_complete", "_x.zwc", "_a", "_b", "lines"],
    );
    let got = found_with(&fs, &format!("fpath=(~/zc $fpath)\n{COMPINIT}"));
    assert!(
        got.doubts.iter().any(|doubt| doubt.contains(
            "in /home/alice/zc write (`_a`, `_b`, `_complete` and 1 more), which zsh runs"
        )),
        "{got:?}"
    );
    // A directory without one, or none there, holds no function compinit
    // marks; and without compinit, zsh marks none.
    let fs = MockFilesystem::new();
    listed(&fs, "/home/alice/zc", &["lines", "w"]);
    assert_eq!(
        found_with(&fs, &format!("fpath=(~/zc $fpath)\n{COMPINIT}")),
        Scan::default()
    );
    assert_eq!(
        found(&format!("fpath=(~/zc $fpath)\n{COMPINIT}")),
        Scan::default()
    );
    let fs = MockFilesystem::new();
    listed(&fs, "/home/alice/zc", &["_w"]);
    assert_eq!(
        found_with(
            &fs,
            "fpath=(~/zc $fpath)\nzstyle ':completion:*' menu select\n"
        ),
        Scan::default()
    );
}

#[test]
fn completion_functions_of_zsh_s_own_and_of_a_nix_profile_in_the_store_are_none() {
    // zsh's own directory, and NixOS's loop over the profiles, whose
    // directories lead into the Nix store, as packages fill them.
    let fs = MockFilesystem::new();
    nixos(&fs);
    let store = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-system-path/share/zsh/site-functions";
    fs.create_symlink(
        Path::new(store),
        Path::new("/run/current-system/sw/share/zsh/site-functions"),
    )
    .expect("a link");
    listed(
        &fs,
        "/run/current-system/sw/share/zsh/site-functions",
        &["_docker"],
    );
    listed(&fs, store, &["_docker"]);
    let known = install(&fs, &SESSION);
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // The same directory put in fpath by the files is a profile's too.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(/run/current-system/sw/share/zsh/site-functions $fpath)\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // A profile that leads elsewhere than into the store holds functions of
    // the files' own: zsh 5.9.2 runs a `_w` there as Tab completes a word.
    seed(&fs, "/home/alice/.zshrc", "");
    listed(
        &fs,
        "/home/alice/.nix-profile/share/zsh/site-functions",
        &["_w"],
    );
    let got = scan_with(&fs, UNKNOWN, &known);
    assert_eq!(
        got.doubts,
        ["it cannot tell what the completion functions in \
             /home/alice/.nix-profile/share/zsh/site-functions write (`_w`), which zsh runs as you \
             complete a word once compinit marks them, as that directory of fpath is neither \
             zsh's own nor a Nix profile's"]
    );
}

#[test]
fn a_function_the_completion_system_is_given_to_run_is_one_of_zsh_s_own() {
    // zsh 5.9.2 runs each of these as Tab completes a word, a function that
    // appends the line to the history file among them.
    for line in [
        "zstyle ':completion:*' completer _w _complete",
        "zstyle ':completion:*' completer _complete _w:tag",
        "zstyle -- ':completion:*' completer _w",
        "zstyle -e ':completion:*' completer 'reply=(_complete)'",
        "zstyle ':completion:*' completer $c",
        "zstyle ':completion:*' cache-policy _stale",
        "zstyle ':completion:*' user-expand _mine",
        "compdef _w print",
        "compdef -a _w print",
        "compdef -an _w print",
        "compdef -p _w 'pri*'",
        "compdef -P _w 'zz*'",
        "compdef -k _w complete-word '^I'",
        "compdef -K _w w complete-word '^I'",
        "compdef 'print -r -- \"$BUFFER\" >> ~/.zl' print",
        "compdef -e 'x=y' print",
        "compdef +d _w print",
        "compdef -- -d print",
        "zle -C w complete-word _w",
        "zle -C w complete-word $f",
    ] {
        let got = found(&format!("{COMPINIT}{line}\n"));
        assert!(warned(&got), "{line}");
    }
    // zsh's own, by its name or past a tag, and one of a deletion or of a
    // command's completion given to another, run nothing of the files'.
    for line in [
        "zstyle ':completion:*' completer _complete _files",
        "zstyle ':completion:*' completer _complete:tag",
        "zstyle ':completion:*' menu select",
        "zstyle -s ':completion:*' completer c",
        "compdef _gnu_generic print",
        "compdef -d print",
        "compdef print=git",
        "zle -C w complete-word _main_complete",
        "zstyle ':completion:*' command 'ps -e'",
    ] {
        assert_eq!(
            found(&format!("{COMPINIT}{line}\n")),
            Scan::default(),
            "{line}"
        );
    }
    // A function of zsh's own that a file defines in its place is the
    // file's.
    let got = found(&format!(
        "{COMPINIT}_complete() {{ :; }}\nzstyle ':completion:*' completer _complete\n"
    ));
    assert_eq!(
        got.doubts,
        [
            "it cannot tell what `_complete`, which `zstyle :completion:* completer _complete` in \
             /home/alice/.zshrc makes zsh run as you complete a word, writes, as it is no \
             completion function of zsh's own"
        ]
    );
    // Without compinit, no completer or compdef runs.
    for line in ["zstyle ':completion:*' completer _w", "compdef _w print"] {
        assert_eq!(found_plain(line), Scan::default(), "{line}");
    }
}

/// What a typed Nix zsh with [`STOCK`] finds with `line` alone as `.zshrc`.
fn found_plain(line: &str) -> Scan {
    found(&format!("{line}\n"))
}

#[test]
fn the_code_a_command_style_gives_is_read_as_a_hook_s() {
    // zsh 5.9.2 runs it as `_call_program` runs a command for a completion
    // (`kill <Tab>`), which appends the line to the history file.
    for line in [
        "zstyle ':completion:*' command 'print -r -- \"$BUFFER\" >> ~/.zl; ps'",
        "zstyle ':completion:*' command '-print -r -- \"$BUFFER\" >> ~/.zl'",
        "zstyle ':completion:*' command $c",
        "zstyle -e ':completion:*' command 'reply=(ps)'",
    ] {
        let got = found(&format!("{COMPINIT}{line}\n"));
        assert!(warned(&got), "{line}");
    }
}

#[test]
fn a_function_the_files_define_named_like_a_completion_function_is_a_hook() {
    // zsh 5.9.2 runs `_print` in place of its own as Tab completes a word of
    // `print`, which appends the line to the history file.
    for rc in [
        "_print() { print -r -- \"$BUFFER\" >> ~/.zl }\n",
        "functions[_print]='print -r -- \"$BUFFER\" >> ~/.zl'\n",
        "_mine() { print -r -- \"$BUFFER\" >> ~/.zl }\n",
    ] {
        let got = found(&format!("{COMPINIT}{rc}"));
        assert!(warned(&got), "{rc}");
        // Without compinit, nothing runs it.
        assert_eq!(found_plain(rc.trim_end()), Scan::default(), "{rc}");
    }
    // One that writes nothing is no doubt.
    assert_eq!(
        found(&format!("{COMPINIT}_mine() {{ _files }}\n")),
        Scan::default()
    );
}

#[test]
fn a_parameter_the_completion_system_runs_code_from_is_a_doubt() {
    // zsh 5.9.2 runs each as Tab completes a word, which appends the line to
    // the history file.
    for line in [
        "_comps[print]=_w",
        "_comps[print]='print -r -- \"$BUFFER\" >> ~/.zl'",
        "_patcomps[pri*]=_w",
        "_postpatcomps[zz*]=_w",
        "typeset -gA _comps",
        "_services[print]=git",
        "precmd() { comppostfuncs=(_w) }",
        "precmd() { compprefuncs+=(_w) }",
        "_comp_setup+=$'\\n_w'",
        "_compautos[_w]=+X",
    ] {
        let got = found(&format!("{COMPINIT}{line}\n"));
        let ours = |found: &Scan| {
            found
                .doubts
                .iter()
                .any(|doubt| doubt.contains("which zsh's completion system runs code or"))
        };
        assert!(ours(&got), "{line}: {got:?}");
        // Without compinit, no completion runs them (an element's key is
        // arithmetic then, a doubt of its own).
        assert!(!ours(&found_plain(line)), "{line}");
    }
    // Reading one sets none.
    assert_eq!(
        found(&format!(
            "{COMPINIT}print -r -- $#_comps ${{(k)_comps}} $comppostfuncs\n"
        )),
        Scan::default()
    );
}

#[test]
fn compctl_and_complete_are_a_doubt_with_compinit_or_without() {
    // zsh 5.9.2 runs `w2` as Tab completes a word of `print` with compctl's
    // completion, which needs no compinit, and `_w` with bashcompinit's.
    for line in [
        "compctl -K w2 print",
        "complete -F _w print",
        "complete -C logger print",
    ] {
        assert!(warned(&found_plain(line)), "{line}");
        assert!(warned(&found(&format!("{COMPINIT}{line}\n"))), "{line}");
    }
}

#[test]
fn a_dump_file_whose_completion_is_code_is_read_as_code() {
    // zsh 5.9.2's `_dispatch` runs the value of `_comps` for the command with
    // `eval`: with this dump file compinit -C sources, `print <Tab>` appends
    // the line to the history file.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zcompdump",
        &dump::tests::DUMP.replace(
            "'eval' '_precommand'",
            "'print' 'print -r -- \"$BUFFER\" >> ~/.zl'",
        ),
    );
    assert!(warned(&found_with(
        &fs,
        "autoload -Uz compinit && compinit -C\n"
    )));
    // As compdump writes them, the names of completion functions, a
    // pattern's after a service, are data.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zcompdump",
        &dump::tests::DUMP.replace("'*/(init|rc[0-9S]#).d/*' '_init_d'", "'x*' '=svc=_init_d'"),
    );
    assert_eq!(
        found_with(&fs, "autoload -Uz compinit && compinit -C\n"),
        Scan::default()
    );
}
