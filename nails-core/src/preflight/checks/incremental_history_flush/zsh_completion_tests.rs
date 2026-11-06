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

#[test]
fn a_function_of_the_files_own_is_a_hook_where_compinit_runs() {
    // zsh 5.9.2's `_ls` runs `ls --help` as Tab completes a word of `ls`, so
    // a function named `ls` runs there, which appends the line to the
    // history file; zsh's own completion functions run other commands by
    // name too (`locale`, `ps`, `getent`).
    let writes = "print -r -- \"$BUFFER\" >> ~/.zl";
    for rc in [
        format!("ls() {{ {writes}; command ls \"$@\" }}\n"),
        format!("function locale {{ {writes} }}\n"),
        format!("functions[ps]='{writes}'\n"),
        format!("eval 'getent() {{ {writes} }}'\n"),
    ] {
        let got = found(&format!("{COMPINIT}{rc}"));
        assert!(warned(&got), "{rc}");
        // Without compinit, it runs where it is typed, which the check does
        // not read.
        assert_eq!(found_plain(rc.trim_end()), Scan::default(), "{rc}");
    }
    // One the files autoload from a directory of their own is theirs too.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/zf/ls", &format!("{writes}\n"));
    let got = found_with(
        &fs,
        &format!("fpath=(~/zf $fpath)\nautoload -Uz ls\n{COMPINIT}"),
    );
    assert!(warned(&got), "{got:?}");
    // One of zsh's own, autoloaded from its directory, and one of the
    // files' that writes nothing, are no doubt.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &[&STOCK[..], &["zmv"]].concat());
    seed(&fs, &format!("{OWN}/zmv"), "mv -- \"$1\" \"$2\"\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("{COMPINIT}autoload -Uz zmv\n"),
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &install(&fs, &[])), Scan::default());
    assert_eq!(
        found(&format!("{COMPINIT}hello() {{ print -r -- hi }}\n")),
        Scan::default()
    );
    // A helper that hands its words to a program warns again: the check
    // cannot tell that the program writes no file they name.
    assert!(warned(&found(&format!(
        "{COMPINIT}mkcd() {{ mkdir -p -- \"$1\" && cd -- \"$1\" }}\n"
    ))));
}

#[test]
fn a_file_named_like_a_function_of_zsh_s_own_in_a_directory_the_files_add_is_a_doubt() {
    // compinit autoloads compinstall, and zsh 5.9.2 runs `~/zf/compinstall`
    // in place of zsh's own as the completer it is given, which appends the
    // line to the history file.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &[&STOCK[..], &["compinstall"]].concat());
    listed(&fs, "/home/alice/zf", &["compinstall", "mytool"]);
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("fpath=(~/zf $fpath)\n{COMPINIT}zstyle ':completion:*' completer compinstall\n"),
    );
    let got = scan_with(&fs, UNKNOWN, &install(&fs, &[]));
    assert_eq!(
        got.doubts,
        [
            "it cannot tell what the functions in /home/alice/zf write (`compinstall`), which zsh \
             may run in place of zsh's own of their names where its own code runs one by name, \
             as that directory of fpath is neither zsh's own nor a Nix profile's"
        ]
    );
    // A function the files autoload by its path is theirs where a completer
    // or a compdef names it.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &[&STOCK[..], &["compinstall"]].concat());
    seed(&fs, "/home/alice/zf/compinstall", ":\n");
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("{COMPINIT}autoload -Uz ~/zf/compinstall\ncompdef compinstall print\n"),
    );
    let got = scan_with(&fs, UNKNOWN, &install(&fs, &[]));
    assert!(
        got.doubts.iter().any(|doubt| doubt
            .starts_with("it cannot tell what `compinstall`, which `compdef compinstall print`")),
        "{got:?}"
    );
}

#[test]
fn a_completion_style_whose_value_zsh_s_own_code_may_run_is_a_doubt() {
    // zsh 5.9.2 runs the backquote in `_files`'s `eval` of file-patterns,
    // the subscript in `_main_complete`'s arithmetic on menu's number,
    // `_history`'s on range, complist's on MENUSCROLL and `zformat`'s on a
    // `%(`'s test, and `_retrieve_cache` sources the cache files where
    // use-cache is on: each may append the line to the history file.
    for line in [
        "zstyle ':completion:*' file-patterns '`logit`*:all-files'",
        "zstyle ':completion:*' file-patterns \"$p\"",
        "zstyle ':completion:*' menu 'select=1+pipestatus[$(logit)1]'",
        "zstyle ':completion:*' menu 'yes=1+x'",
        "zstyle ':completion:*' menu \"select=$n\"",
        "zstyle ':completion:*' range 'pipestatus[$(logit)1]'",
        "zstyle ':completion:*' range 5:x",
        "zstyle ':completion:*' select-scroll x",
        "zstyle ':completion:*:descriptions' format '%(d.%d.)'",
        "zstyle ':completion:*:warnings' format '%5(D.a.b)'",
        "zstyle ':completion:*' tag-order 'files:f:%(d.x.y)'",
        "zstyle ':completion:*' use-cache on",
        "zstyle ':completion:*' use-cache $c",
        "zstyle ':completion:*' cache-path ~/.zcache",
        "zstyle ':completion:*' environ 'LISTMAX=x'",
        "zstyle ':completion:*:git:*' max-verbose 'pipestatus[$(logit)1]'",
        "zstyle ':completion:*' something-new x",
        "zstyle -e ':completion:*' menu 'reply=(select=1+x)'",
        "zstyle '*' menu 'select=1+x'",
        "zstyle -- \"$ctx\" menu 'select=1+x'",
    ] {
        let ours = |found: &Scan| {
            found.doubts.iter().any(|doubt| {
                doubt.starts_with(
                    "it cannot tell what code zsh's own completion functions run as you \
                     complete a word with `zstyle ",
                )
            })
        };
        let got = found(&format!("{COMPINIT}{line}\n"));
        assert!(ours(&got), "{line}: {got:?}");
        // Without compinit, no completion function reads it.
        assert!(!ours(&found_plain(line)), "{line}");
    }
    // The common lines, values zsh's own code reads as data or as a plain
    // number, and a context of no completion pass.
    for line in [
        "zstyle ':completion:*' menu select",
        "zstyle ':completion:*' menu select=2",
        "zstyle ':completion:*' menu select=long-list",
        "zstyle ':completion:*:*:kill:*' menu yes select",
        "zstyle ':completion:*' matcher-list 'm:{a-z}={A-Za-z}' 'r:|=*' 'l:|=* r:|=*'",
        "zstyle ':completion:*' list-colors \"${(s.:.)LS_COLORS}\"",
        "zstyle ':completion:*' group-name ''",
        "zstyle ':completion:*:descriptions' format '%F{yellow}-- %d --%f'",
        "zstyle ':completion:*' verbose yes",
        "zstyle ':completion:*' rehash true",
        "zstyle ':completion:*' special-dirs true",
        "zstyle ':completion:*' squeeze-slashes true",
        "zstyle ':completion:*' accept-exact '*(N)'",
        "zstyle ':completion:*' insert-tab pending=2",
        "zstyle ':completion:*' max-errors 2 numeric",
        "zstyle ':completion:*' range 20:5",
        "zstyle ':completion:*' select-scroll -2",
        "zstyle ':completion:*' file-patterns '*(-/):directories' '*.txt:text'",
        "zstyle ':completion:*' use-cache off",
        "zstyle ':completion:*' tag-order local-directories directory-stack",
        "zstyle -e ':completion:*' verbose 'reply=(yes)'",
        "zstyle ':chpwd:*' menu 'select=1+x'",
        "zstyle :compinstall filename ~/.zshrc",
    ] {
        assert_eq!(
            found(&format!("{COMPINIT}{line}\n")),
            Scan::default(),
            "{line}"
        );
    }
}

#[test]
fn a_parameter_that_gives_the_completion_system_code_or_options_is_a_doubt() {
    // zsh 5.9.2 runs compcontext's action with `eval`, `_sort_tags` by its
    // name, and with `aliases` among `_comp_options` a global alias named
    // like the completion function it runs (`alias -g _ls=logit`).
    for line in [
        "compcontext='x:y:{logit}'",
        "typeset -g compcontext='x:y: logit'",
        "_sort_tags=logit",
        "_comp_options+=(aliases)",
        "_comp_options=(${_comp_options:#NO_aliases})",
        "_comp_options+=(globdots) # dotfiles",
    ] {
        let got = found(&format!("{COMPINIT}{line}\n"));
        let what = if line.starts_with("_comp_options") {
            "which zsh's completion system takes the options it completes with from"
        } else {
            "which zsh's completion system runs code or"
        };
        assert!(
            got.doubts.iter().any(|doubt| doubt.contains(what)),
            "{line}: {got:?}"
        );
    }
    // GLOB_DOTS alone makes it complete the files whose names start with a
    // dot, which runs nothing.
    for line in ["_comp_options+=(globdots)", "_comp_options+=( GLOB_DOTS )"] {
        assert_eq!(
            found(&format!("{COMPINIT}{line}\n")),
            Scan::default(),
            "{line}"
        );
    }
}

#[test]
fn what_the_check_cannot_read_where_compinit_runs_is_a_doubt() {
    // An fpath directory it cannot list may hold completion functions.
    let fs = MockFilesystem::new();
    fs.mock_set_unreadable_dir("/home/alice/zc");
    let got = found_with(&fs, &format!("fpath=(~/zc $fpath)\n{COMPINIT}"));
    assert!(
        got.doubts
            .iter()
            .any(|doubt| doubt
                .starts_with("it could not read the directory /home/alice/zc of fpath")),
        "{got:?}"
    );
    // Where it cannot list zsh's own directory as it reads the files, no
    // completer is one of its own.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &STOCK);
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("{COMPINIT}zstyle ':completion:*' completer _complete\n"),
    );
    let known = install(&fs, &[]);
    fs.mock_set_unreadable_dir(OWN);
    let got = scan_with(&fs, UNKNOWN, &known);
    assert!(
        got.doubts
            .iter()
            .any(|doubt| doubt.starts_with("it cannot tell what `_complete`")),
        "{got:?}"
    );
    // A Nix profile's directory named with zsh's version is one of the
    // profiles' only while no file sets ZSH_VERSION, which may name
    // another.
    let fs = MockFilesystem::new();
    nixos(&fs);
    let profile = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-profile"; // pragma: allowlist secret
    let dir = format!("{profile}/share/zsh/5.9.2/functions");
    listed(&fs, &dir, &["_w"]);
    let known = install(
        &fs,
        &[
            ("NIX_PROFILES", profile),
            ("USER", "alice"),
            ("__NIXOS_SET_ENVIRONMENT_DONE", "1"),
        ],
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("fpath=({dir} $fpath)\n"),
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("ZSH_VERSION=x\nfpath=({dir} $fpath)\n"),
    );
    let got = scan_with(&fs, UNKNOWN, &known);
    let doubt = format!("it cannot tell what the completion functions in {dir} write");
    assert!(
        got.doubts.iter().any(|found| found.starts_with(&doubt)),
        "{got:?}"
    );
}

#[test]
fn files_in_the_completion_cache_s_directory_are_a_doubt_where_compinit_runs() {
    // zsh 5.9.2's `_retrieve_cache` sources a file of
    // `${ZDOTDIR:-$HOME}/.zcompcache` where use-cache is on, and its
    // `_composer`, `_zypper` and `_luarocks` source one there whatever the
    // files set: one that appends the line to the history file writes it.
    let fs = MockFilesystem::new();
    listed(&fs, "/home/alice/.zcompcache", &["command-descriptions"]);
    let got = found_with(&fs, COMPINIT);
    assert_eq!(
        got.doubts,
        [
            "it cannot tell what the files of the completion cache in /home/alice/.zcompcache run \
             (`command-descriptions`), which zsh's own completion functions source as you complete \
             some commands (`composer`, `zypper`, `luarocks`) or a word where `use-cache` is on"
        ]
    );
    // In the ZDOTDIR a file sets too.
    let fs = MockFilesystem::new();
    listed(&fs, "/home/alice/z/.zcompcache", &["x"]);
    seed(&fs, "/home/alice/.zshenv", "ZDOTDIR=/home/alice/z\n");
    let got = found_with(&fs, "");
    seed(&fs, "/home/alice/z/.zshrc", COMPINIT);
    let got_rc = scan_with(&fs, UNKNOWN, &install(&fs, &[]));
    assert_eq!(got, Scan::default());
    assert!(
        got_rc
            .doubts
            .iter()
            .any(|doubt| doubt.contains("in /home/alice/z/.zcompcache run")),
        "{got_rc:?}"
    );
    // None, an empty one, and one without compinit, are no doubt.
    assert_eq!(found(COMPINIT), Scan::default());
    let fs = MockFilesystem::new();
    listed(&fs, "/home/alice/.zcompcache", &[]);
    assert_eq!(found_with(&fs, COMPINIT), Scan::default());
    let fs = MockFilesystem::new();
    listed(&fs, "/home/alice/.zcompcache", &["command-descriptions"]);
    assert_eq!(found_with(&fs, "HISTSIZE=100\n"), Scan::default());
}

#[test]
fn an_unlistable_completion_cache_directory_is_a_doubt_where_compinit_runs() {
    // zsh's own completion functions may source its files.
    let fs = MockFilesystem::new();
    fs.mock_set_unreadable_dir("/home/alice/.zcompcache");
    let got = found_with(&fs, COMPINIT);
    assert!(
        got.doubts.iter().any(|doubt| doubt.starts_with(
            "it could not read the directory /home/alice/.zcompcache (permission denied), whose \
             files zsh's own completion functions may source as you complete a word"
        )),
        "{got:?}"
    );
    let fs = MockFilesystem::new();
    fs.mock_set_unreadable_dir("/home/alice/.zcompcache");
    assert_eq!(found_with(&fs, "HISTSIZE=100\n"), Scan::default());
}

/// The words of a doubt of a parameter whose name zsh's own completion
/// functions may keep code by, set as `name`.
fn code_parameter(name: &str) -> String {
    format!(
        "as it sets `{name}`, a parameter by whose name zsh's own completion functions may keep \
         code they run"
    )
}

#[test]
fn a_parameter_zsh_s_own_completion_functions_keep_code_in_is_a_doubt_where_compinit_runs() {
    // zsh 5.9.2 runs the action of the specification `_patch` takes from
    // `_patch_args` as `patch --zz=<Tab>` completes, and so `_telnet`,
    // `_finger`, `_arguments`' cache by the command's name, `_valgrind`'s
    // `args_<tool>` and `_baz`'s `cmd_<subcommand>`: each may append the
    // line to the history file.
    for (set, name) in [
        (
            "_patch_args=( '--zz=[x]:y:{print -r -- \"$BUFFER\" >> ~/.zl}' )",
            "_patch_args",
        ),
        (
            "typeset -ga _patch_args=( '--zz=[x]:y:{w}' )",
            "_patch_args",
        ),
        ("_args_cache_curl=( '--zz=[x]:y:{w}' )", "_args_cache_curl"),
        ("export _telnet_args='-zz[x]:y:{w}'", "_telnet_args"),
        ("f() { _finger_args=(x) }", "_finger_args"),
        ("_whois_arguments+=(x)", "_whois_arguments"),
        ("cmd_foo=( ':x:{w}' )", "cmd_foo"),
        ("args_foo=( '--zz=[x]:y:{w}' )", "args_foo"),
        ("__x=1", "__x"),
        ("typeset -A _x\n_x[k]=v", "_x"),
        ("eval '_x=1'", "_x"),
        ("alias s='_x=1 true'\ns", "_x"),
        ("print -v _patch_args x", "_patch_args"),
        ("read -r _patch_args < ~/.spec", "_patch_args"),
        ("zstyle -s ':x' y _patch_args", "_patch_args"),
        ("for _patch_args in x; do :; done", "_patch_args"),
        ("set -A _patch_args x", "_patch_args"),
        ("zparseopts -A _patch_args", "_patch_args"),
        ("local _x=1", "_x"),
        ("typeset -T X _patch_args\nX=y", "_patch_args"),
    ] {
        let got = found(&format!("{COMPINIT}{set}\n"));
        assert!(
            got.doubts
                .iter()
                .any(|doubt| doubt.contains(&code_parameter(name))),
            "{set}: {got:?}"
        );
        assert_eq!(found_plain(set), Scan::default(), "{set}");
    }
    // One a line sets in a form the walk does not read.
    for set in [": ${_patch_args::=x}", ": ${(A)_x::=y}", ": ${_x:=y}"] {
        let got = found(&format!("{COMPINIT}{set}\n"));
        assert!(
            got.doubts.iter().any(|doubt| doubt.contains(
                "as it may set a parameter whose name starts with `_`, `cmd_` or `args_` in a way \
                 the check does not read"
            )),
            "{set}: {got:?}"
        );
    }
    // `debug_fd`, which `_call_program` reads as arithmetic, and
    // `MODULEPATH`, which `_module` expands once more, in any form.
    for (set, what) in [
        (
            "debug_fd='pipestatus[$(w)1]'",
            "`_call_program` reads as arithmetic",
        ),
        ("dbg=x\ndebug_fd=dbg", "`_call_program` reads as arithmetic"),
        (
            "typeset -g debug_fd=x",
            "`_call_program` reads as arithmetic",
        ),
        (": ${debug_fd::=x}", "`_call_program` reads as arithmetic"),
        ("MODULEPATH='$(w)'", "`_module` expands once more"),
    ] {
        let got = found(&format!("{COMPINIT}{set}\n"));
        assert!(
            got.doubts.iter().any(|doubt| doubt.contains(what)),
            "{set}: {got:?}"
        );
    }
    // A function's own, one whose name has an upper-case letter past its
    // `_`, a declaration without a value, the names compinstall and compdef
    // give functions, and the same lines without compinit pass.
    for rc in [
        format!("{COMPINIT}f() {{ local _patch_args=(x); typeset -a _y=(z); local -a _z=(w) }}\n"),
        format!("{COMPINIT}_ZSH_AUTOSUGGEST_X=1\n__NIXOS_DONE=1\n"),
        format!("{COMPINIT}typeset -ga _patch_args\n"),
        format!("{COMPINIT}zstyle ':completion:*' completer _complete\ncompdef _gnu_generic foo\n"),
        "_patch_args=(x)\ndebug_fd=x\n: ${_x::=y}\n".to_string(),
    ] {
        assert_eq!(found(&rc), Scan::default(), "{rc}");
    }
}

#[test]
fn a_parameter_zsh_s_own_completion_functions_may_read_as_code_in_the_environment_is_a_doubt() {
    // zsh takes the shell's environment as parameters it sets: an
    // `_patch_args` there is as one a file sets.
    for (vars, doubts) in [
        (vec![("_patch_args", "--zz=[x]:y:{w}")], true),
        (vec![("_args_cache_curl", "--zz=[x]:y:{w}")], true),
        (vec![("debug_fd", "pipestatus[$(w)1]")], true),
        (vec![("compprefuncs", "w")], true),
        (vec![("MODULEPATH", "$(w)")], true),
        (vec![("debug_fd", "3")], false),
        (vec![("MODULEPATH", "/usr/share/modulefiles")], false),
        (
            vec![
                ("__NIXOS_SET_ENVIRONMENT_DONE", "1"),
                ("_JAVA_OPTIONS", "-Dx=y"),
                ("__GL_SYNC_TO_VBLANK", "0"),
            ],
            false,
        ),
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(&fs, &[OWN], &STOCK);
        seed(&fs, "/home/alice/.zshrc", COMPINIT);
        let known = install(&fs, &vars);
        let got = scan_with(&fs, UNKNOWN, &known);
        let ours = got.doubts.iter().any(|doubt| {
            doubt.starts_with(
                "it cannot tell what the shell's environment makes zsh run as you complete a word",
            )
        });
        assert_eq!(ours, doubts, "{vars:?}: {got:?}");
        // Without compinit, nothing reads them.
        seed(&fs, "/home/alice/.zshrc", "HISTSIZE=100\n");
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{vars:?}");
    }
    // The check keeps them from a shell's environment.
    for name in [
        "_patch_args",
        "debug_fd",
        "MODULEPATH",
        "compcontext",
        "cmd_x",
    ] {
        assert!(super::super::kept(name), "{name}");
    }
    for name in [
        "__NIXOS_SET_ENVIRONMENT_DONE",
        "_JAVA_OPTIONS",
        "EDITOR",
        "_",
    ] {
        assert!(!super::super::kept(name), "{name}");
    }
}

#[test]
fn a_style_whose_pattern_may_match_a_completion_context_by_its_options_is_read() {
    // zsh 5.9.2 compiles a zstyle pattern with the options on as zstyle
    // runs: `@(:completion):*` matches a completion context under KSH_GLOB,
    // `x#:completion:*` under EXTENDED_GLOB and `x|:completion:*` under
    // none, so `_main_complete` reads menu's value as arithmetic.
    for pattern in [
        "@(:completion):*",
        "+(:completion:)*",
        "!(x)",
        "x#:completion:*",
        "x(#c0,1):completion:*",
        ":completionx#:*",
        "x|:completion:*",
        "(x|:completion:*)",
        "(#i):COMPLETION:*",
    ] {
        for style in ["menu 'select=1+x'", "max-verbose 5", "cache-path ~/cc"] {
            let line = format!("zstyle '{pattern}' {style}");
            let got = found(&format!("{COMPINIT}{line}\n"));
            assert!(
                got.doubts.iter().any(|doubt| doubt.starts_with(
                    "it cannot tell what code zsh's own completion functions run as you complete \
                     a word with `zstyle "
                )),
                "{line}: {got:?}"
            );
        }
    }
    // One whose literal start no option makes match none.
    for pattern in [
        ":vcs_info:*",
        ":zle:*",
        ":complexion:*",
        ":COMPLETION(#i):*",
    ] {
        assert_eq!(
            found(&format!("{COMPINIT}zstyle '{pattern}' menu 'select=1+x'\n")),
            Scan::default(),
            "{pattern}"
        );
    }
}

#[test]
fn a_compiled_digest_an_element_of_fpath_names_is_a_doubt() {
    // zsh 5.9.2 loads the functions in `~/zc.zwc` from the digest itself
    // (`fpath=(~/zc.zwc $fpath)`), `_files` or `compinit` among them, whose
    // code the check cannot read.
    for setter in [
        "fpath=(~/zc.zwc $fpath)",
        "FPATH=~/zc.zwc:$FPATH",
        "fpath=(~/.zwc $fpath)",
    ] {
        let fs = MockFilesystem::new();
        let digest = if setter.contains("/.zwc") {
            "/home/alice/.zwc"
        } else {
            "/home/alice/zc.zwc"
        };
        fs.mock_set_file_bytes(digest, b"\x07\x06\x05\x04zwc");
        let got = found_with(&fs, &format!("{setter}\n{COMPINIT}"));
        assert!(
            got.doubts.contains(&format!(
                "it cannot read the compiled code in {digest} that zsh may run"
            )),
            "{setter}: {got:?}"
        );
    }
    // One that is not there is none.
    assert_eq!(
        found(&format!("fpath=(~/zc.zwc $fpath)\n{COMPINIT}")),
        Scan::default()
    );
}
