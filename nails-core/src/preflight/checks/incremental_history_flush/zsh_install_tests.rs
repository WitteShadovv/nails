// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a zsh's `fpath` starts, as its program and its environment tell,
//! the stock `compinit` and `promptinit` it finds there and what they read,
//! and NixOS's generated files.

use super::autoload::unfound;
use super::*;
use crate::filesystem::PathKind;

// What may change what NixOS's dircolors line runs.
#[path = "zsh_dircolors_tests.rs"]
mod dircolors;

// The elements of fpath the check cannot follow where it knows where fpath
// starts, prompt themes and completion functions as hooks.
#[path = "zsh_fpath_tests.rs"]
mod fpath;

// What zsh may run as you complete a word that is no code of zsh's own.
#[path = "zsh_completion_tests.rs"]
mod completion;

// Where zsh finds the programs its own completion functions run.
#[path = "zsh_programs_tests.rs"]
mod programs;

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

/// The `PATH` of a NixOS session: its setuid wrappers and the system
/// profile, the directories of the system's own programs.
const SYSTEM_PATH: &str = "/run/wrappers/bin:/run/current-system/sw/bin";

/// The environment of a shell with `vars` in it, and [`SYSTEM_PATH`] unless
/// `vars` names a `PATH`, as a session's environment holds one.
fn environment(vars: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut environment: Vec<(String, String)> = vars
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    if !vars.iter().any(|(name, _)| *name == "PATH") {
        environment.push(("PATH".to_string(), SYSTEM_PATH.to_string()));
    }
    environment
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
            functions: Some(PathBuf::from(OWN)),
            version: Some("5.9.2".to_string()),
            env: Some(super::super::install::Env {
                user: Some("alice".to_string()),
                path: Some(SYSTEM_PATH.to_string()),
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
            functions: Some(PathBuf::from(OWN)),
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
fn the_dump_file_compinit_is_given_is_no_file_the_code_makes_first() {
    // compinit makes the dump file only once it has read it or found none,
    // so one that is not there now is none the code makes before zsh reads
    // it: zsh 5.9.2 writes nothing with these, the stock compinit's own
    // name of it aside.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    let known = install(&fs, &[]);
    for rc in [
        "autoload -Uz compinit && compinit -d ~/.cache/zcd\n",
        "autoload -Uz compinit && compinit -d \"$HOME/.cache/zcd\"\n",
        "alias h='fc -l'\nautoload compinit && compinit\n",
    ] {
        seed(&fs, "/home/alice/.zshrc", rc);
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{rc}");
    }
    // A command that names it beyond compinit may make it first.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "mkdump ~/.cache/zcd\nautoload -Uz compinit && compinit -d ~/.cache/zcd\n",
    );
    assert!(
        scan_with(&fs, UNKNOWN, &known)
            .doubts
            .iter()
            .any(|doubt| doubt.contains("/home/alice/.cache/zcd, which is not there now")),
        "{:?}",
        scan_with(&fs, UNKNOWN, &known)
    );
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
    // One that takes a hook away autoloads none.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/.zfunc $fpath)\nautoload -Uz add-zsh-hook && add-zsh-hook -d precmd lines\n",
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // A compdef without -a names a function completion runs, which is no
    // completion function of zsh's own.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/.zfunc $fpath)\nautoload -Uz compinit && compinit && compdef lines cmd\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        [
            "it cannot tell what `lines`, which `compdef lines cmd` in /home/alice/.zshrc makes \
             zsh run as you complete a word, writes, as it is no completion function of zsh's own"
        ]
    );
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit && compdef -a $f cmd\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &known).doubts,
        [
            "it cannot tell which function `compdef -a $f cmd` in /home/alice/.zshrc autoloads",
            "it cannot tell which function `compdef -a $f cmd` in /home/alice/.zshrc makes zsh \
             run as you complete a word, as zsh may expand `$f` into other words"
        ]
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
/// of another package, and the coreutils its `/etc/zshrc` names.
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
fn compinit_sources_a_dump_file_in_each_zdotdir_and_home_it_may_run_with() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(&fs, "/home/alice/.zcompdump", "precmd() { fc -AI }\n");
    let known = install(&fs, &[]);
    // zsh 5.9.2 sources ~/.zcompdump with a ZDOTDIR set after compinit, and
    // ~/alt/.zcompdump with HOME set before it.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit -C\nZDOTDIR=$HOME/other\n",
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &known)));
    seed(
        &fs,
        "/home/alice/.zshrc",
        "HOME=$HOME/alt\nautoload -Uz compinit && compinit -C\n",
    );
    assert!(
        scan_with(&fs, UNKNOWN, &known).doubts.contains(
            &"it cannot follow the HOME that /home/alice/.zshrc may set, which changes where zsh \
              reads the user's startup files and the dump file compinit sources"
                .to_string()
        ),
        "{:?}",
        scan_with(&fs, UNKNOWN, &known)
    );
    // zsh 5.9.2 reads ~/alt/.zshrc with HOME set so in ~/.zshenv.
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshenv", "HOME=/home/alice/alt\n");
    seed(&fs, "/home/alice/alt/.zshrc", "setopt share_history\n");
    assert!(warned(&scan(&fs, UNKNOWN)));
}

#[test]
fn a_stock_dump_holds_data_in_which_zsh_expands_no_alias() {
    // Its `'history' '_fc'` names no use of `alias history='fc -l 1'`, and
    // zsh 5.9.2 writes nothing with them.
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    let known = install(&fs, &[]);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias history='fc -l 1'\nautoload -Uz compinit && compinit\n",
    );
    seed(
        &fs,
        "/home/alice/.zcompdump",
        &dump::tests::DUMP.replace("'eval' '_precommand'", "'history' '_fc'"),
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // An alias named like a command of its lines is used.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias zle='fc -l'\nautoload -Uz compinit && compinit\n",
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &known)));
}

/// A Nix profile in the store, whose completion functions the check reads
/// as those a package put there.
const PROFILE: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-profile"; // pragma: allowlist secret

/// Its directory of completion functions.
const PROFILE_COMP: &str =
    "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-profile/share/zsh/site-functions";

/// What the check knows of the zsh at `ZSH` started with `PROFILE` in its
/// `NIX_PROFILES`.
fn profiled(fs: &MockFilesystem) -> Install {
    install(fs, &[("NIX_PROFILES", PROFILE)])
}

#[test]
fn compinit_s_marks_by_the_first_line_of_a_completion_function_are_read() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    let known = profiled(&fs);
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("fpath=({PROFILE_COMP} $fpath)\nautoload -Uz compinit && compinit -D\n"),
    );
    // zsh 5.9.2 marks the functions of a compiled file with `-w`, a hook
    // among them, which runs after each command.
    for line in [
        "#autoload -w",
        "#autoload precmd",
        "#autoload +X -w",
        "#autoload\t-m",
    ] {
        seed(&fs, &format!("{PROFILE_COMP}/_b"), &format!("{line}\n:\n"));
        fs.mock_set_directory_contents(
            Path::new(PROFILE_COMP),
            vec![PathBuf::from(format!("{PROFILE_COMP}/_b"))],
        );
        assert!(warned(&scan_with(&fs, UNKNOWN, &known)), "{line}");
    }
    for line in [
        "#autoload",
        "#autoload +X",
        "#compdef git",
        "#compdef -p 'git-*'",
        "#compdef -Pn '*'",
        "#compdef -value-,PATH,-default- -k",
        "#compdef git -K x",
        // Only the first word binds keys: zsh 5.9.2 makes `-k` a command
        // name here, and Enter stays accept-line.
        "#compdef git -k complete-word ^M",
    ] {
        seed(&fs, &format!("{PROFILE_COMP}/_b"), &format!("{line}\n:\n"));
        assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default(), "{line}");
    }
    // In a directory of the files' own, any completion function is a doubt,
    // whatever its first line says.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/zcomp $fpath)\nautoload -Uz compinit && compinit -D\n",
    );
    seed(&fs, "/home/alice/zcomp/_b", "#compdef git\n:\n");
    fs.mock_set_directory_contents(
        Path::new("/home/alice/zcomp"),
        vec![PathBuf::from("/home/alice/zcomp/_b")],
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &known)));
    // Keys a first line binds the function to are zsh's own, in its own
    // function, or a doubt: compinit binds a key that has no widget, which a
    // file may make Space or Enter (`bindkey -r ' '`).
    let rc = format!("fpath=({PROFILE_COMP} $fpath)\nautoload -Uz compinit && compinit -D\n");
    for (name, line) in [
        ("_b", "#compdef -k complete-word \\C-xt"),
        ("_complete_tag", "#compdef -k complete-word \\C-xa"),
        ("_complete_tag", "#compdef -k complete-word \\C-xt x"),
        ("_complete_tag", "#compdef -k complete-word \\C-xt "),
        ("_b", "#compdef -K _b complete-word ' '"),
        // compinit takes `-kn` and `-Kn` as it takes `-k` and `-K`, whose `n`
        // binds only a key with no widget: zsh 5.9.2 runs `_x` as `ma` is
        // typed in `marker`.
        ("_b", "#compdef -kn complete-word ma"),
        ("_b", "#compdef -Kn _xw complete-word ma"),
        ("_complete_tag", "#compdef -kn complete-word \\C-xt"),
        ("_b", "#compdef\t-kn complete-word \\x20"),
        ("_b", "  #compdef -kx complete-word ma"),
        // A control character, which the check may split otherwise.
        ("_b", "#compdef\x0b-k complete-word ma"),
        ("_b", "#compdef git\r"),
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
        let path = format!("{PROFILE_COMP}/{name}");
        seed(&fs, "/home/alice/.zshrc", &rc);
        seed(&fs, &path, &format!("{line}\n:\n"));
        fs.mock_set_directory_contents(Path::new(PROFILE_COMP), vec![PathBuf::from(&path)]);
        let known = profiled(&fs);
        assert!(warned(&scan_with(&fs, UNKNOWN, &known)), "{name}: {line}");
    }
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    let known = profiled(&fs);
    seed(&fs, "/home/alice/.zshrc", &rc);
    seed(
        &fs,
        &format!("{PROFILE_COMP}/_complete_tag"),
        "#compdef -k complete-word \\C-xt\n:\n",
    );
    fs.mock_set_directory_contents(
        Path::new(PROFILE_COMP),
        vec![PathBuf::from(format!("{PROFILE_COMP}/_complete_tag"))],
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &known), Scan::default());
    // A dump file that marks with `-w` is read as code, a doubt.
    seed(&fs, &format!("{PROFILE_COMP}/_b"), "#autoload\n:\n");
    seed(
        &fs,
        "/home/alice/.zcompdump",
        "#files: 1\tversion: 5.9.2\n\nautoload -Uz -w _b\n",
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &known)));
}

#[test]
fn what_the_environment_holds_of_where_zsh_reads_its_files_counts() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "autoload -Uz compinit && compinit\nautoload -Uz myfn && myfn\n",
    );
    seed(&fs, "/home/alice/evil/x/myfn", "setopt share_history\n");
    fs.mock_set_path_type("/home/alice/evil/Base", PathKind::Dir);
    // zsh 5.9.2's compaudit puts the directories under a `_compdir` from the
    // environment in fpath, and myfn then turns SHARE_HISTORY on.
    let found = scan_with(
        &fs,
        UNKNOWN,
        &install(&fs, &[("_compdir", "/home/alice/evil")]),
    );
    assert!(
        found.doubts.contains(
            &"it cannot tell which directories compaudit, which compinit runs, puts in fpath, \
              as the shell's environment names _compdir"
                .to_string()
        ),
        "{found:?}"
    );
    assert_eq!(scan_with(&fs, UNKNOWN, &install(&fs, &[])), Scan::default());
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
    nix_zsh(&fs, &[OWN], &["compinit"]);
    let known = install(&fs, &[]);
    // zsh 5.9.2 looks for compinit in directories relative to where it
    // runs with the first two.
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
            &format!("{set}\nautoload -Uz compinit && compinit\n"),
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
            &format!("{set}\nautoload -Uz compinit && compinit\n"),
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
fn the_count_of_a_dump_file_s_first_line_is_arithmetic() {
    // compinit 5.9.2 reads the second word of the dump file's first line as
    // arithmetic (`$_i_line[2] -eq $#_i_files`), which sets TTY with this
    // one, so a hook's output to $TTY goes to the history file.
    let rc = "autoload -Uz compinit && compinit\nprecmd() { print -Pn '%~' > $TTY }\n";
    for header in [
        "#files: TTY=5\tversion: 5.9.2",
        "#files: n\tversion: 5.9.2",
        "#files: 5\r\tversion: 5.9.2",
    ] {
        let fs = MockFilesystem::new();
        nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
        seed(&fs, "/home/alice/.zshrc", rc);
        seed(&fs, "/home/alice/.zcompdump", &format!("{header}\n"));
        assert!(
            warned(&scan_with(&fs, UNKNOWN, &install(&fs, &[]))),
            "{header}"
        );
    }
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(&fs, "/home/alice/.zshrc", rc);
    seed(&fs, "/home/alice/.zcompdump", "#files: 5\tversion: 5.9.2\n");
    assert_eq!(scan_with(&fs, UNKNOWN, &install(&fs, &[])), Scan::default());
}

#[test]
fn a_word_compdef_compinit_or_prompt_may_expand_into_others_is_a_doubt() {
    let fs = MockFilesystem::new();
    nix_zsh(
        &fs,
        &[OWN],
        &["compinit", "compaudit", "compdump", "promptinit"],
    );
    let known = install(&fs, &[]);
    // zsh 5.9.2 expands each word before compdef, compinit or prompt reads
    // it, which may make it a flag that binds keys to a function or names
    // another dump file, or name another theme.
    for (line, doubt) in [
        (
            "autoload -Uz compinit && compinit && compdef {-k,lines} complete-word '^M'",
            "it cannot tell which function `compdef {-k,lines} complete-word ^M` in \
             /home/alice/.zshrc autoloads",
        ),
        (
            "autoload -Uz compinit && compinit {-d,~/.zd}",
            "it cannot tell which dump file `compinit {-d,~/.zd}` in /home/alice/.zshrc sources",
        ),
        (
            "autoload -Uz promptinit && promptinit && prompt {suse,x}",
            "it cannot tell which prompt theme `prompt {suse,x}` in /home/alice/.zshrc runs",
        ),
    ] {
        seed(&fs, "/home/alice/.zshrc", &format!("{line}\n"));
        assert!(
            scan_with(&fs, UNKNOWN, &known)
                .doubts
                .contains(&doubt.to_string()),
            "{line}: {:?}",
            scan_with(&fs, UNKNOWN, &known)
        );
    }
}
