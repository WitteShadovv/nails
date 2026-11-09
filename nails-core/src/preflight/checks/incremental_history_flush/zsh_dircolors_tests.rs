// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may change what NixOS's dircolors line in `/etc/zshrc` runs, which
//! the check reads as harmless only while nothing that runs before it may.

use super::*;

/// The program the dircolors line of [`nixos_zshrc`] runs.
const DIRCOLORS: &str = "/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin/dircolors";

/// What a NixOS host as [`nixos`] sets up finds, with `zshenv` as
/// `~/.zshenv`, `before` in `/etc/zshrc` above the dircolors line, where
/// `programs.zsh.interactiveShellInit` puts its lines, `after` below it,
/// where the aliases go, and the files `extra`.
fn nixos_with(zshenv: &str, before: &str, after: &str, extra: &[(&str, &str)]) -> Scan {
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(&fs, "/home/alice/.zshenv", zshenv);
    let colors = "# Extra colors for directory listings.\n";
    let aliases = "# Setup aliases.\n";
    let zshrc = nixos_zshrc();
    assert!(zshrc.contains(colors) && zshrc.contains(aliases));
    let zshrc = zshrc
        .replacen(colors, &format!("{before}{colors}"), 1)
        .replacen(aliases, &format!("{aliases}{after}"), 1);
    seed(&fs, "/etc/zshrc", &zshrc);
    for (path, text) in extra {
        seed(&fs, path, text);
    }
    scan_with(&fs, UNKNOWN, &install(&fs, &SESSION))
}

/// What the doubt about the dircolors line says, as `what` comes before it.
fn changed(what: &str) -> String {
    format!(
        "it cannot tell what the `eval` of what dircolors prints in /etc/zshrc runs, as {what} \
         before it, which may change what it runs"
    )
}

#[test]
fn what_runs_before_the_dircolors_line_may_change_what_it_runs() {
    // zsh 5.9.2 runs `setopt sharehistory` in the line's `eval` after each
    // in ~/.zshenv: a function or an alias named like its program, a global
    // alias for its `-b`, a DEBUG trap, which runs in its command
    // substitution and prints into it.
    let prints = "printf 'setopt %s%s\\n' share history";
    for (zshenv, what) in [
        (
            format!("function {DIRCOLORS} {{ {prints} }}\n"),
            format!("/home/alice/.zshenv defines the function `{DIRCOLORS}`"),
        ),
        (
            format!("alias {DIRCOLORS}=\"{prints}; :\"\n"),
            "/home/alice/.zshenv defines an alias".to_string(),
        ),
        (
            format!("alias -g -- -b=\"-b; {prints}; :\"\n"),
            "/home/alice/.zshenv defines an alias".to_string(),
        ),
        (
            format!("TRAPDEBUG() {{ {prints} }}\n"),
            "/home/alice/.zshenv defines the function `TRAPDEBUG`".to_string(),
        ),
        (
            format!("trap \"{prints}\" DEBUG\n"),
            "/home/alice/.zshenv names `trap`".to_string(),
        ),
    ] {
        let found = nixos_with(&zshenv, "", "", &[]);
        assert_eq!(found.doubts, [changed(&what)], "{zshenv}");
    }
    // Each of these may change it too, as the check reads it: `eval` or
    // `export`, which it runs, as functions, `eval` disabled, a function
    // whose name an expansion makes, a TRAP function autoloaded, an alias by
    // the parameters that hold them, a variable of the dynamic loader, which
    // may make the program print other code.
    for zshenv in [
        "eval() { builtin eval \"$@\" }\n".to_string(),
        "export() { :; }\n".to_string(),
        "disable eval\n".to_string(),
        format!("n={DIRCOLORS}\nfunction $n {{ :; }}\n"),
        "autoload -Uz TRAPDEBUG\n".to_string(),
        "autoload -Uz ~/fn/eval\n".to_string(),
        "aliases[x]=y\n".to_string(),
        "g''aliases[-b]='-b; :'\n".to_string(),
        "export LD_PRELOAD=$HOME/.x.so\n".to_string(),
        "LD_LIBRARY_PATH=~/lib; export LD_LIBRARY_PATH\n".to_string(),
        // On a line that starts with `#` inside a quote.
        "x='\n#'; alias -g -- -b='-b; :'\n".to_string(),
        "x='\n#'; trap : DEBUG\n".to_string(),
    ] {
        assert!(warned(&nixos_with(&zshenv, "", "", &[])), "{zshenv}");
    }
    // In NixOS's /etc/zshenv (`programs.zsh.shellInit`), and above the line
    // in /etc/zshrc (`programs.zsh.interactiveShellInit`), alike.
    let galias = format!("alias -g -- -b=\"-b; {prints}; :\"\n");
    assert_eq!(
        nixos_with("", &galias, "", &[]).doubts,
        [changed("/etc/zshrc defines an alias")]
    );
    let fs = MockFilesystem::new();
    nixos(&fs);
    let local = "# Read system-wide modifications.\n";
    seed(
        &fs,
        "/etc/zshenv",
        &NIXOS_ZSHENV.replacen(
            local,
            &format!("function {DIRCOLORS} {{ {prints} }}\n{local}"),
            1,
        ),
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &install(&fs, &SESSION))));
    // A function the files autoload and run before the line runs its code
    // there, and so does one it autoloads in turn.
    let fpath = "fpath=(~/zfn $fpath)\nautoload -Uz myinit\nmyinit\n";
    for (path, text) in [
        ("/home/alice/zfn/myinit", "alias -g -- -b='-b; :'\n"),
        ("/home/alice/zfn/myinit", "autoload -Uz more\nmore\n"),
    ] {
        let more = ("/home/alice/zfn/more", "alias -g -- -b='-b; :'\n");
        assert!(
            warned(&nixos_with(fpath, "", "", &[(path, text), more])),
            "{text}"
        );
    }
}

#[test]
fn what_comes_after_the_dircolors_line_or_names_none_of_its_words_leaves_it_known() {
    // An alias of any kind after the line, as NixOS's shellAliases and
    // shellGlobalAliases put them there, and in ~/.zshrc: zsh has run the
    // line before it reads the alias.
    for after in ["alias -g -- -b='-b; :'\n", "alias -- l='ls -alh'\n"] {
        assert_eq!(nixos_with("", "", after, &[]), Scan::default(), "{after}");
    }
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias -g G='| grep'\nTRAPDEBUG() { :; }\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)),
        Scan::default()
    );
    // A variable of the dynamic loader after it leaves it known too.
    seed(
        &fs,
        "/home/alice/.zshrc",
        "alias -g G='| grep'\nexport LD_LIBRARY_PATH=~/lib\n",
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)),
        Scan::default()
    );
    // A function named otherwise than its program, as zsh runs it by its
    // name alone.
    let zshenv = format!("function {DIRCOLORS}x {{ :; }}\n");
    assert_eq!(nixos_with(&zshenv, "", "", &[]), Scan::default());
    // A function autoloaded after the line, which runs after it.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(
        &fs,
        "/home/alice/.zshrc",
        "fpath=(~/zfn $fpath)\nautoload -Uz myfn\nmyfn\n",
    );
    seed(&fs, "/home/alice/zfn/myfn", "alias -g -- G='-b; :'\n");
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)),
        Scan::default()
    );
    // A line inside a structure, which the check reads whole: its `eval` is
    // one it cannot follow.
    let fs = MockFilesystem::new();
    nixos(&fs);
    let line =
        "eval \"$(/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin/dircolors -b)\"\n";
    assert!(nixos_zshrc().contains(line));
    seed(
        &fs,
        "/etc/zshrc",
        &nixos_zshrc().replacen(line, &format!("if true; then\n{line}fi\n"), 1),
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &install(&fs, &SESSION))));
}

#[test]
fn what_the_environment_or_a_file_gives_every_program_may_change_the_dircolors_line() {
    // zsh 5.9.2 gives an exported ARGV0 to every program it runs as its
    // name, which makes the multi-call coreutils run `ls -b` in the line, so
    // its `eval` runs a file named `$(<.x)`; set in ~/.zshenv, in
    // ~/.zprofile or in the shell's environment, it turns SHARE_HISTORY on.
    for zshenv in [
        "export ARGV0=ls\n",
        "typeset -x ARGV0=ls\n",
        "AR''GV0=ls; export ARGV0\n",
        ": ${ARGV0::=ls}\n",
    ] {
        let found = nixos_with(zshenv, "", "", &[]);
        assert_eq!(
            found.doubts,
            [changed(
                "/home/alice/.zshenv sets ARGV0, the name zsh gives every program it runs"
            )],
            "{zshenv}"
        );
    }
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(&fs, "/home/alice/.zprofile", "export ARGV0=ls\n");
    assert!(warned(&scan_with(&fs, LOGIN, &install(&fs, &SESSION))));
    // ARGV0 or a variable of the dynamic loader in the shell's environment,
    // and an environment the check does not know, alike.
    for (vars, why) in [
        (
            &[("ARGV0", "ls")][..],
            "the shell's environment sets ARGV0, which names the program coreutils runs",
        ),
        (
            &[(LOADER, "")][..],
            "the shell's environment sets a variable of the dynamic loader (`LD_...`)",
        ),
    ] {
        let fs = MockFilesystem::new();
        nixos(&fs);
        let mut all = SESSION.to_vec();
        all.extend_from_slice(vars);
        let found = scan_with(&fs, UNKNOWN, &install(&fs, &all));
        assert!(
            found.doubts.contains(&format!(
                "it cannot tell what the `eval` of what dircolors prints in /etc/zshrc runs, as \
                 {why}"
            )),
            "{found:?}"
        );
    }
    let fs = MockFilesystem::new();
    nixos(&fs);
    let unknown = Install::of(
        &fs,
        Some(Path::new(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-zsh-5.9.2/bin/zsh",
        )),
        None,
    );
    assert!(warned(&scan_with(&fs, UNKNOWN, &unknown)));
    // ARGV0 set after the line, as in ~/.zshrc, runs after it, and one read
    // changes nothing.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(&fs, "/home/alice/.zshrc", "export ARGV0=ls\n");
    seed(&fs, "/home/alice/.zshenv", "print -r -- $ARGV0\n");
    assert_eq!(
        scan_with(&fs, UNKNOWN, &install(&fs, &SESSION)),
        Scan::default()
    );
}

#[test]
fn a_function_named_like_the_dircolors_program_in_any_form_zsh_reads_changes_it() {
    // zsh 5.9.2 defines the program's name or TRAPDEBUG with each, as zsh
    // reads every name of a definition and expands braces, globs and `=`
    // in them, and the line's `eval` turns SHARE_HISTORY on.
    let body = "{ printf 'setopt %s%s\\n' share history }";
    for zshenv in [
        format!("function {{{DIRCOLORS},x}} {body}"),
        format!("function x {DIRCOLORS} {body}"),
        format!("x {DIRCOLORS} () {body}"),
        format!("function /nix/store/*-coreutils-*/bin/dircolor[s] {body}"),
        format!("p={DIRCOLORS}; PATH=${{p%/*}}:$PATH\nfunction =dircolors {body}"),
        format!("function {{TRAPDEBUG,x}} {body}"),
        format!("function x TRAPDEBUG {body}"),
    ] {
        let found = nixos_with(&format!("{zshenv}\n"), "", "", &[]);
        assert!(warned(&found), "{zshenv}");
    }
    // Two names that are neither, of a function no hook runs.
    for zshenv in [
        "function x y { print -r -- done }\n".to_string(),
        format!("function x y {body}\n"),
    ] {
        assert_eq!(
            nixos_with(&zshenv, "", "", &[]),
            Scan::default(),
            "{zshenv}"
        );
    }
}

#[test]
fn a_global_alias_after_the_dircolors_line_that_no_code_uses_leaves_it_known() {
    // As NixOS's shellGlobalAliases writes one below the line.
    assert_eq!(
        nixos_with("", "", "alias -g -- G='| grep'\n", &[]),
        Scan::default()
    );
}
