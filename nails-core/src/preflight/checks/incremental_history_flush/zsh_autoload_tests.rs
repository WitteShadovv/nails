// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions zsh's startup files autoload, the directories they add to
//! `fpath`, and the compiled code and expanded paths zsh may run.

use super::*;

/// A file whose code turns `SHARE_HISTORY` on.
const SETS: &str = "setopt share_history\n";

/// What a doubt about the functions the files autoload that no directory in
/// front of `fpath` holds, `names`, says.
pub(super) fn unfound(names: &str) -> String {
    format!(
        "it cannot read the functions the files autoload that no directory they put in front of \
         fpath holds ({names}), which zsh then finds in one it was built with or one FPATH names"
    )
}

/// What a doubt about the function that `line`, an `autoload -X` in
/// `.zshrc`, loads says.
fn x_doubt(line: &str) -> String {
    format!(
        "it cannot tell which function `{line}` in /home/alice/.zshrc loads, as -X loads the one \
         whose code runs it, from the directory a word after it names or from fpath"
    )
}

/// What a doubt about the `fpath` directory that `.zshrc` adds as `dir`
/// says.
fn dir_doubt(dir: &str) -> String {
    format!(
        "it cannot follow the directory that /home/alice/.zshrc adds to fpath as `{dir}`, where \
         zsh looks for the functions the files autoload"
    )
}

#[test]
fn a_function_the_files_autoload_is_read_where_they_add_to_fpath() {
    // zsh 5.9.1 runs each of these with SHARE_HISTORY on once the function
    // has run, as it reads the function from ~/.zfunc.
    for rc in [
        "fpath=(~/.zfunc $fpath)\nautoload -Uz hist_setup\nhist_setup\n",
        "fpath=(\"$HOME/.zfunc\" \"${fpath[@]}\")\nautoload -U +X hist_setup\n",
        "FPATH=$HOME/.zfunc:$FPATH\nautoload -Uz hist_setup\n",
        "fpath[1,0]=~/.zfunc\nbuiltin autoload -Uz hist_setup\n",
        "typeset -ga fpath=(~/.zfunc $fpath)\nautoload -Uz hist_setup\n",
        "for dir in ~/.zfunc; do fpath=($dir $fpath); done\nautoload -Uz hist_setup\n",
        // Marked before the directory is added, under a condition, or by
        // the other builtins that mark it.
        "autoload -Uz hist_setup\nfpath=(~/.zfunc $fpath)\n",
        "[[ -d ~/.zfunc ]] && fpath=(~/.zfunc $fpath)\nif true; then autoload hist_setup; fi\n",
        "functions -u hist_setup\nfpath=(~/.zfunc $fpath)\n",
        "functions -U hist_setup\nfpath=(~/.zfunc $fpath)\n",
        "typeset -fu hist_setup\nfpath=(~/.zfunc $fpath)\n",
        "eval 'fpath=(~/.zfunc $fpath); autoload -Uz hist_setup'\n",
        // By the path of its file.
        "autoload -Uz ~/.zfunc/hist_setup\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
        assert_eq!(
            on(&fs, UNKNOWN),
            ["/home/alice/.zfunc/hist_setup names SHARE_HISTORY"],
            "{rc}"
        );
        assert_eq!(scan(&fs, UNKNOWN).doubts, Vec::<String>::new(), "{rc}");
    }
    // One in a directory put behind the others zsh may find first in one of
    // its own, which the check does not read.
    for rc in [
        "fpath+=(~/.zfunc)\nautoload -Uz hist_setup\n",
        "fpath+=~/.zfunc\nautoload hist_setup\n",
        "fpath=($fpath ~/.zfunc)\nautoload hist_setup\n",
        "FPATH=$FPATH:$HOME/.zfunc\nautoload hist_setup\n",
        "fpath[3]=~/.zfunc\nautoload hist_setup\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
        let found = scan(&fs, UNKNOWN);
        assert_eq!(
            found.writes.len(),
            1,
            "{rc}: the file is read all the same: {found:?}"
        );
        assert_eq!(found.doubts, [unfound("`hist_setup`")], "{rc}");
    }
    // A function's file that adds a directory and autoloads from it.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "ZDOTDIR=~/.config/zsh\n");
    seed(
        &fs,
        "/home/alice/.config/zsh/.zshrc",
        "fpath=(${ZDOTDIR:-$HOME}/functions $fpath)\nautoload -Uz setup && setup\n",
    );
    seed(
        &fs,
        "/home/alice/.config/zsh/functions/setup",
        "fpath+=(~/.zfunc)\nautoload -Uz hist_setup\nhist_setup\n",
    );
    seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
    assert_eq!(
        on(&fs, UNKNOWN),
        ["/home/alice/.zfunc/hist_setup names SHARE_HISTORY"]
    );
    // A function the files do not autoload is not read, and one they
    // autoload that the directories they add do not hold is a doubt: zsh
    // finds it in one of its own.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "typeset -U path fpath\nfpath=(~/.zfunc ${fpath:#/nowhere})\n\
         autoload -Uz compinit colors && compinit\n",
    );
    seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
    assert_eq!(
        scan(&fs, UNKNOWN),
        Scan {
            doubts: vec![unfound("`compinit` and `colors`")],
            ..Scan::default()
        }
    );
}

#[test]
fn an_autoloaded_function_the_check_cannot_find_is_a_doubt() {
    for (rc, doubt) in [
        (
            "fpath=($plugin/functions $fpath)\nautoload -Uz hist\n",
            dir_doubt("$plugin/functions"),
        ),
        (
            "fpath=(functions $fpath)\nautoload -Uz hist\n",
            dir_doubt("functions"),
        ),
        (
            "fpath=(~/.zsh/*/functions $fpath)\nautoload -Uz hist\n",
            dir_doubt("~/.zsh/*/functions"),
        ),
        (
            "fpath=(${fpath[1]}/sub $fpath)\nautoload -Uz hist\n",
            dir_doubt("${fpath[1]}/sub"),
        ),
        (
            "set -A fpath ~/.zfunc $fpath\nautoload -Uz hist\n",
            "it cannot follow what a line of /home/alice/.zshrc may add to fpath, where zsh \
             looks for the functions the files autoload"
                .to_string(),
        ),
        (
            "fpath=(~/.zfunc $fpath)\nautoload -Uz $name\n",
            "it cannot tell which function `$name` in /home/alice/.zshrc autoloads".to_string(),
        ),
        (
            "autoload -Uz ~/.zfunc/*(.:t)\n",
            "it cannot follow the function file that /home/alice/.zshrc autoloads as \
             `~/.zfunc/*(.:t)`"
                .to_string(),
        ),
        (
            "autoload -Uz $plugin/hist\n",
            "it cannot follow the function file that /home/alice/.zshrc autoloads as \
             `$plugin/hist`"
                .to_string(),
        ),
        (
            "fpath=(~/.zfunc $fpath)\nautoload -Uzm 'h*'\n",
            "it cannot tell which functions `autoload -Uzm h*` in /home/alice/.zshrc loads"
                .to_string(),
        ),
        (
            "fpath=(~/.zfunc $fpath)\nhist() { autoload -X }\nhist\n",
            x_doubt("autoload -X"),
        ),
        // zsh 5.9 to 5.9.2 load the function `-X` runs in from the
        // directory the word names, and with `-d` from fpath where that does
        // not hold it: the stock compinit, or a file that turns the option on
        // (`~/.zfunc/hist`), though the word names no such directory or
        // function.
        (
            "compinit() { autoload -dX ~/.nope }\ncompinit -D\n",
            x_doubt("autoload -dX ~/.nope"),
        ),
        (
            "compinit() { autoload -X zfn }\ncompinit -D\n",
            x_doubt("autoload -X zfn"),
        ),
        (
            "fpath=(~/.zfunc $fpath)\nhist() { autoload -dX ~/.nope }\nhist\n",
            x_doubt("autoload -dX ~/.nope"),
        ),
        (
            "fpath=(~/.zfunc $fpath)\nhist() { builtin autoload -X -d nope }\nhist\n",
            x_doubt("autoload -X -d nope"),
        ),
        (
            "fpath=(~/.zfunc $fpath)\nhist() { autoload -X ~/.zfunc }\nhist\n",
            x_doubt("autoload -X ~/.zfunc"),
        ),
        (
            "alias al='autoload -Uz'\n",
            "it cannot tell what the alias `al=autoload -Uz` in /home/alice/.zshrc runs where it \
             is used"
                .to_string(),
        ),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.zfunc/hist", SETS);
        let mut expected = vec![doubt];
        if rc.contains("autoload -Uz hist") {
            expected.push(unfound("`hist`"));
        }
        assert_eq!(scan(&fs, UNKNOWN).doubts, expected, "{rc}");
    }
}

#[test]
fn a_directory_added_to_fpath_matters_once_a_function_is_autoloaded() {
    // NixOS's /etc/zshenv adds the profiles' directories, which the check
    // cannot follow, and its /etc/zshrc autoloads compinit.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/etc/zshenv",
        "for p in ${(z)NIX_PROFILES}; do\n    \
         fpath=($p/share/zsh/site-functions $p/share/zsh/$ZSH_VERSION/functions $fpath)\n\
         done\n",
    );
    seed(&fs, "/etc/zshrc", "autoload -U compinit && compinit\n");
    // A zsh started with -f reads /etc/zshenv alone, which autoloads none.
    let bare = Start {
        rcs: false,
        ..UNKNOWN
    };
    assert_eq!(scan(&fs, bare), Scan::default());
    // Any other may find compinit where the check cannot look.
    let dir = |dir: &str| {
        format!(
            "it cannot follow the directory that /etc/zshenv adds to fpath as `{dir}`, where zsh \
             looks for the functions the files autoload"
        )
    };
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [
            dir("$p/share/zsh/site-functions"),
            dir("$p/share/zsh/$ZSH_VERSION/functions"),
            unfound("`compinit`"),
        ]
    );
}

#[test]
fn compiled_code_zsh_may_run_in_place_of_a_file_is_a_doubt() {
    // zsh 5.9.1 runs a file's .zwc in its place when it is newer or when the
    // file is missing, and a function from the .zwc of an fpath directory.
    let autoloads = "fpath=(~/.zfunc $fpath)\nautoload -Uz hist\n";
    for (files, compiled) in [
        (vec![], "/home/alice/.zshrc.zwc"),
        (
            vec![("/home/alice/.zshrc", "true\n")],
            "/home/alice/.zshrc.zwc",
        ),
        (vec![], "/etc/zshenv.zwc"),
        (
            vec![("/home/alice/.zshrc", "source ~/.zsh/history.zsh\n")],
            "/home/alice/.zsh/history.zsh.zwc",
        ),
        (
            vec![("/home/alice/.zshrc", autoloads)],
            "/home/alice/.zfunc.zwc",
        ),
        (
            vec![
                ("/home/alice/.zshrc", autoloads),
                ("/home/alice/.zfunc/hist", "true\n"),
            ],
            "/home/alice/.zfunc/hist.zwc",
        ),
    ] {
        let fs = MockFilesystem::new();
        for (path, text) in files {
            seed(&fs, path, text);
        }
        seed(&fs, compiled, "");
        let mut expected = vec![format!(
            "it cannot read the compiled code in {compiled} that zsh may run"
        )];
        if compiled == "/home/alice/.zfunc.zwc" {
            // No file holds the function: zsh finds it in the digest, or in
            // one of its own directories.
            expected.push(unfound("`hist`"));
        }
        assert_eq!(scan(&fs, UNKNOWN).doubts, expected, "{compiled}");
    }
    // zsh 5.9 to 5.9.2 run a function autoloaded by its path from the
    // digest of its file's directory when that is newer than the file, here
    // the stock compinit as `ci`, or code that turns the option on, while
    // the file holds `:`; and from a directory whose name ends in `.zwc`.
    for (rc, compiled) in [
        ("autoload -Uz ~/zfn/so && so\n", "/home/alice/zfn.zwc"),
        ("autoload +X -Uz ~/zfn/so\n", "/home/alice/zfn.zwc"),
        (
            "autoload -Uz ~/zfn/logit\nprecmd_functions+=(logit)\n",
            "/home/alice/zfn.zwc",
        ),
        ("autoload -Uz ~/zfn/ci && ci -D\n", "/home/alice/zfn.zwc"),
        ("autoload -Uz ~/zc.zwc/so && so\n", "/home/alice/zc.zwc"),
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", rc);
        for name in ["so", "logit", "ci"] {
            seed(&fs, &format!("/home/alice/zfn/{name}"), ":\n");
        }
        seed(&fs, compiled, "");
        let found = scan(&fs, UNKNOWN);
        assert!(
            found.doubts.contains(&format!(
                "it cannot read the compiled code in {compiled} that zsh may run"
            )),
            "{rc}: {found:?}"
        );
    }
}

#[test]
fn a_path_zsh_expands_into_others_is_a_doubt() {
    // zsh 5.9.1 sources the first file that a glob or a brace expansion
    // makes of the path.
    for path in [
        "~/.zsh/*.zsh",
        "~/.zsh/{history,none}.zsh",
        "~/.zsh/history.zsh(N)",
        "~/.zsh/histor?.zsh",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("source {path}\n"));
        seed(&fs, "/home/alice/.zsh/history.zsh", SETS);
        assert_eq!(
            scan(&fs, UNKNOWN).doubts,
            [format!(
                "it cannot follow the file /home/alice/.zshrc sources as `{path}`"
            )],
            "{path}"
        );
    }
}

#[test]
fn a_function_is_autoloaded_by_the_options_zsh_reads_as_it_does() {
    // zsh 5.9 to 5.9.2 mark `hist_setup` to be autoloaded with each of
    // these (`whence -w` gives `function`), with the options of either sign
    // up to the first other word, an `-x` of `functions` or a number of
    // `typeset` taking the word after it.
    for marks in [
        "functions +t -u",
        "functions +U -u",
        "functions -x 2 -u",
        "functions -x2 -u",
        "functions -ux 3",
        "functions -u --",
        "typeset +f -u",
        "typeset -u +f",
        "typeset +t -fu",
        "typeset -p 1 -fu",
        "typeset -fL 3 -u",
        "typeset -i 3 -fu",
        "typeset --fu",
        // A number as the word after its letter: zsh takes it and reads no
        // more letters of that word.
        "typeset -fLt 3 -u",
        "typeset -fLq 3 -u",
        "declare -fRx 2 -u",
        "readonly -fZt 4 -u",
        "typeset -fpz 1 -u",
        "typeset -uLt 3 -f",
        "typeset -Lt 3 -fu",
        "declare +f -U",
        "declare +g -fu",
        "readonly -fu",
        "readonly -fU",
        "readonly -f -u",
        "readonly +f -u",
        "builtin readonly -fu",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("fpath=(~/.zfunc $fpath)\n{marks} hist_setup\n"),
        );
        seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
        assert_eq!(
            scan(&fs, UNKNOWN),
            Scan {
                writes: vec![Write {
                    what: "/home/alice/.zfunc/hist_setup names SHARE_HISTORY".to_string(),
                    entered: true,
                    option: true,
                }],
                ..Scan::default()
            },
            "{marks}"
        );
    }
    // These mark none: zsh 5.9 to 5.9.2 refuse them, read the `-u` as a
    // name, or mark no function.
    for marks in [
        "typeset -f",
        "typeset +u -f",
        "typeset -f +u",
        "functions +u",
        "functions -2 -u",
        "functions - -u",
        "typeset -f -- -u",
        "readonly -u",
        // `readonly`'s `p` takes no number, and `local` no `-f`.
        "readonly -fp 1 -u",
        "local -fu",
        "export -fu",
        "integer -fu",
        "float -fu",
        "private -fu",
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("fpath=(~/.zfunc $fpath)\n{marks} hist_setup\n"),
        );
        seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
        assert_eq!(scan(&fs, UNKNOWN).writes, [], "{marks}");
    }
    // With no word for `-x`, zsh 5.9 to 5.9.2 print `argument expected: -x`
    // and run nothing.
    for line in ["functions -ux", "functions -u -x", "functions -Ux"] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{line}");
    }
}

#[test]
fn options_an_expansion_may_make_of_a_marking_builtin_are_a_doubt() {
    for (line, word) in [
        ("functions $o hist_setup", "$o"),
        ("functions -x 2 $o hist_setup", "$o"),
        // An array may give `-x` its number and then options (`a=(2 -u)`).
        ("functions -x $a hist_setup", "$a"),
        ("functions -ux $a hist_setup", "$a"),
        ("typeset -$o hist_setup", "-$o"),
        ("typeset -f $o hist_setup", "$o"),
        ("readonly -p $n -fu hist_setup", "$n"),
        ("declare {-fu,+x} hist_setup", "{-fu,+x}"),
    ] {
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("fpath=(~/.zfunc $fpath)\n{line}\n"),
        );
        seed(&fs, "/home/alice/.zfunc/hist_setup", SETS);
        let found = scan(&fs, UNKNOWN);
        let (command, args) = line.split_once(' ').unwrap();
        let doubt = format!(
            "it cannot tell what `{command} {args}` in /home/alice/.zshrc does, as zsh may expand \
             `{word}` into any of its options"
        );
        assert!(found.doubts.contains(&doubt), "{line}: {found:?}");
    }
}

#[test]
fn a_function_a_signed_typeset_autoloads_counts_for_the_fc_alias_cut() {
    // zsh 5.9.2 runs the hook `hk`, which `typeset +f -u` marks, and it uses
    // the alias as `fc -l -A`, which writes the history file.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias h='fc -l'\nfpath=(~/zfn $fpath)\ntypeset +f -u hk\nprecmd_functions+=(hk)\n",
    );
    seed(&fs, "/home/alice/zfn/hk", "h -A\n");
    assert_eq!(
        scan(&fs, UNKNOWN).doubts,
        [
            "it cannot tell what the alias `h=fc -l` in /home/alice/.zshrc runs where it is used, \
             as zsh hands the fc it stands for the words after it"
        ]
    );
}
