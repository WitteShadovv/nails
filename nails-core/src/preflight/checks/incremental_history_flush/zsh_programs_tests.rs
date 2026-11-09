// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where zsh finds the programs its own completion functions run, where the
//! files run its stock `compinit`: a directory of `PATH` of the operator's
//! own that holds one, from the shell's environment or put there by the
//! files, one named relative to where zsh runs, a change of `PATH` the check
//! cannot follow, and a program a `hash` or `commands` names for a command.

use super::*;

/// The `.zshrc` lines that run the stock `compinit`.
const COMPINIT: &str = "autoload -Uz compinit && compinit -D\n";

/// What a typed Nix zsh finds with `rc` as `.zshrc` and `vars` in its
/// environment, and `fs` with what a test seeds besides.
fn found_with(fs: &MockFilesystem, rc: &str, vars: &[(&str, &str)]) -> Scan {
    nix_zsh(fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(fs, "/home/alice/.zshrc", rc);
    scan_with(fs, UNKNOWN, &install(fs, vars))
}

/// Seed the programs `names` in the directory `dir`, which lists them: a
/// `locale` that prints an `LC_CTYPE` line `_comp_locale` runs as code.
fn programs(fs: &MockFilesystem, dir: &str, names: &[&str]) {
    let mut entries = Vec::new();
    for name in names {
        let path = format!("{dir}/{name}");
        seed(
            fs,
            &path,
            "#!/bin/sh\necho 'LC_CTYPE=$(print -s -- \"$BUFFER\"; fc -W)'\n",
        );
        entries.push(PathBuf::from(path));
    }
    fs.mock_set_path_type(dir, PathKind::Dir);
    fs.mock_set_directory_contents(Path::new(dir), entries);
}

/// The doubt for the programs `names` (as listed) in the directory `dir`.
fn own(dir: &str, names: &str) -> String {
    format!(
        "it cannot tell what the programs in {dir} print ({names}), as that directory of PATH is \
         neither a system directory nor one that leads into the Nix store, and zsh's own \
         completion functions may run them as you complete a word, reading what some print as \
         code (`_comp_locale` reads what `locale` prints)"
    )
}

/// What the doubts end with that name where zsh looks for programs.
const RUN: &str = "whose programs zsh's own completion functions may run as you complete a \
                   word, reading what some print as code (`_comp_locale` reads what `locale` \
                   prints)";

#[test]
fn a_program_in_a_directory_of_path_of_the_operator_s_own_is_a_doubt_where_compinit_runs() {
    // zsh 5.9.2 ran a ~/bin/locale that prints `LC_CTYPE=$(...)` as Tab
    // completed `ls marker-one `, through `_ls`, `_pick_variant`,
    // `_call_program` and `_comp_locale`'s `eval export $ctype`, and so wrote
    // the line.
    let fs = MockFilesystem::new();
    programs(&fs, "/home/alice/bin", &["locale"]);
    let path = [("PATH", "/home/alice/bin:/run/current-system/sw/bin")];
    assert_eq!(
        found_with(&fs, COMPINIT, &path).doubts,
        [own("/home/alice/bin", "`locale`")]
    );
    // Any program counts, by any name, three of them named and how many more.
    let fs = MockFilesystem::new();
    programs(
        &fs,
        "/home/alice/.local/bin",
        &["npm", "apt-config", "zz", "a", "b"],
    );
    assert_eq!(
        found_with(
            &fs,
            COMPINIT,
            &[("PATH", "/usr/bin:/home/alice/.local/bin")]
        )
        .doubts,
        [own(
            "/home/alice/.local/bin",
            "`a`, `apt-config`, `b` and 2 more"
        )]
    );
    // Without compinit, no completion function of zsh's own runs them.
    let fs = MockFilesystem::new();
    programs(&fs, "/home/alice/bin", &["locale"]);
    assert_eq!(found_with(&fs, "", &path), Scan::default());
    // A directory that holds no program, only directories, or that is not
    // there, holds none zsh runs.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/home/alice/bin", PathKind::Dir);
    fs.mock_set_directory_contents(Path::new("/home/alice/bin"), Vec::new());
    programs(&fs, "/home/alice/go/bin", &[]);
    fs.mock_set_path_type("/home/alice/.cargo/bin/sub", PathKind::Dir);
    fs.mock_set_directory_contents(
        Path::new("/home/alice/.cargo/bin"),
        vec![PathBuf::from("/home/alice/.cargo/bin/sub")],
    );
    assert_eq!(
        found_with(
            &fs,
            COMPINIT,
            &[(
                "PATH",
                "/home/alice/bin:/home/alice/go/bin:/home/alice/.cargo/bin:/home/alice/none"
            )]
        ),
        Scan::default()
    );
    // One the check cannot read is a doubt.
    let fs = MockFilesystem::new();
    fs.mock_set_path_type("/home/alice/bin", PathKind::Dir);
    fs.mock_set_unreadable_dir("/home/alice/bin");
    assert_eq!(
        found_with(&fs, COMPINIT, &path).doubts,
        [format!(
            "it could not read the directory /home/alice/bin of PATH (permission denied), {RUN}"
        )]
    );
}

#[test]
fn a_system_directory_and_one_that_leads_into_the_nix_store_hold_none_of_the_operator_s_own() {
    let fs = MockFilesystem::new();
    for dir in [
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/run/wrappers/wrappers.Qu8VZgD8Lg",
        "/usr/local/bin",
        "/home/alice/bin",
    ] {
        programs(&fs, dir, &["locale"]);
    }
    let system = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-system-path"; // pragma: allowlist secret
    programs(&fs, &format!("{system}/bin"), &["locale"]);
    for (target, link) in [
        (system, "/run/current-system/sw"),
        // NixOS's wrappers, which it makes anew at each activation.
        ("/run/wrappers/wrappers.Qu8VZgD8Lg", "/run/wrappers/bin"),
        // A link of the operator's own into the store, or to a system
        // directory.
        (system, "/home/alice/.nix-profile"),
        ("/usr/bin", "/home/alice/sys"),
    ] {
        fs.create_symlink(Path::new(target), Path::new(link))
            .expect("a link");
    }
    for value in [
        "/usr/bin:/bin:/usr/sbin:/sbin",
        "/run/wrappers/bin",
        "/usr/bin/://usr//sbin:/usr/./bin",
        "/run/current-system/sw/bin",
        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-system-path/bin", // pragma: allowlist secret
        "/home/alice/.nix-profile/bin",
        "/home/alice/sys",
    ] {
        assert_eq!(
            found_with(&fs, COMPINIT, &[("PATH", value)]),
            Scan::default(),
            "{value}"
        );
    }
    // Any other directory, /usr/local/bin among them, is the operator's: a
    // link that leads into one of the operator's own, and a `..` that may
    // lead anywhere, too.
    fs.create_symlink(Path::new("/home/alice/bin"), Path::new("/home/alice/b"))
        .expect("a link");
    programs(&fs, "/usr/bin/../local/bin", &["locale"]);
    for (value, dir) in [
        ("/usr/local/bin:/usr/bin", "/usr/local/bin"),
        ("/home/alice/b", "/home/alice/b"),
        ("/usr/bin/../local/bin", "/usr/bin/../local/bin"),
    ] {
        assert_eq!(
            found_with(&fs, COMPINIT, &[("PATH", value)]).doubts,
            [own(dir, "`locale`")],
            "{value}"
        );
    }
}

#[test]
fn a_directory_the_files_put_in_path_is_read_in_each_form_zsh_sets_it_in() {
    // zsh 5.9.2 looks in ~/bin first after each of these, and a `locale`
    // there makes it write the line as Tab completes `ls marker-one `.
    for line in [
        "path=(~/bin $path)",
        "path+=(~/bin)",
        "path+=~/bin",
        "path[1,0]=~/bin",
        "path[1]=~/bin",
        "path=(\"$HOME/bin\" \"${path[@]}\")",
        "typeset path=(~/bin $path)",
        "PATH=~/bin:$PATH",
        "PATH=$PATH:~/bin",
        "PATH+=:$HOME/bin",
        "export PATH=\"$HOME/bin:$PATH\"",
        "typeset -x PATH=${HOME}/bin:$PATH",
        "builtin export PATH=~/bin:$PATH",
        "eval 'path=(~/bin $path)'",
        "f() { local path=(~/bin $path) }",
        "for d in ~/bin; do path+=($d); done",
        "PATH=~/bin:$PATH ls",
    ] {
        let fs = MockFilesystem::new();
        programs(&fs, "/home/alice/bin", &["locale"]);
        let got = found_with(&fs, &format!("{line}\n{COMPINIT}"), &[]);
        assert_eq!(got.doubts, [own("/home/alice/bin", "`locale`")], "{line}");
    }
    // A directory they put there that holds no program, or one of the
    // system's, and a declaration or an unset, which add none, pass.
    for line in [
        "path=(~/bin /usr/bin $path)",
        "typeset -U path PATH",
        "export PATH",
        "unset path",
        "f() { local path }",
        "print -r -- $PATH ~/path/x $path[1]",
        "PATH=/run/wrappers/bin:$PATH",
    ] {
        let fs = MockFilesystem::new();
        programs(&fs, "/usr/bin", &["locale"]);
        assert_eq!(
            found_with(&fs, &format!("{line}\n{COMPINIT}"), &[]),
            Scan::default(),
            "{line}"
        );
    }
}

#[test]
fn a_directory_of_path_named_relative_to_where_zsh_runs_is_a_doubt() {
    // zsh 5.9.2 runs a program in the directory it runs in by an empty
    // element, `.` or `bin`, and by a `~` a quote keeps as written.
    for (value, what) in [
        (
            ":/usr/bin",
            "an empty element, which names the directory zsh runs in",
        ),
        (
            "/usr/bin:",
            "an empty element, which names the directory zsh runs in",
        ),
        (
            ".:/usr/bin",
            "`.`, a directory relative to the one zsh runs in",
        ),
        (
            "/usr/bin:bin",
            "`bin`, a directory relative to the one zsh runs in",
        ),
        (
            "~/bin",
            "`~/bin`, a directory relative to the one zsh runs in",
        ),
        (
            "/home/alice/b\u{fffd}n:/usr/bin",
            "a directory whose name is no UTF-8 (`/home/alice/b\u{fffd}n`)",
        ),
    ] {
        let fs = MockFilesystem::new();
        assert_eq!(
            found_with(&fs, COMPINIT, &[("PATH", value)]).doubts,
            [format!(
                "it cannot tell which programs zsh finds by PATH in the shell's environment, as \
                 it holds {what}, {RUN}"
            )],
            "{value}"
        );
    }
    for (line, dir) in [
        ("PATH=$PATH:", ""),
        ("path+=('')", ""),
        ("path=($path .)", "."),
        ("path=(bin $path)", "bin"),
        ("PATH=\"~/bin:$PATH\"", "~/bin"),
        ("path=(\"~/bin\" $path)", "~/bin"),
        ("path=(\\~/bin $path)", "~/bin"),
        ("path=(~+/bin $path)", "~+/bin"),
    ] {
        let fs = MockFilesystem::new();
        assert_eq!(
            found_with(&fs, &format!("{line}\n{COMPINIT}"), &[]).doubts,
            [format!(
                "it cannot follow the directory that /home/alice/.zshrc puts in PATH as \
                 `{dir}`, {RUN}"
            )],
            "{line}"
        );
    }
}

#[test]
fn a_change_of_path_the_check_cannot_follow_is_a_doubt_where_compinit_runs() {
    // Each of these may put ~/bin in PATH as zsh runs, which the check does
    // not follow.
    for line in [
        "PATH+=/x",
        "PATH[1,0]=~/bin:",
        "path=($dir $path)",
        "PATH=$(print ~/bin):$PATH",
        "PATH=${PATH:+$PATH:}~/bin",
        "path=(~/bin(N) $path)",
        "path=(~/b{in,in2} $path)",
        "read -A path < ~/.p",
        "set -A path ~/bin $path",
        "for path in ~/bin; do :; done",
        "print -v PATH ~/bin",
        ": ${PATH::=~/bin}",
        ": ${(A)path::=~/bin}",
        "typeset -T PATH path",
        "PATH=(~/bin)",
        "vared path",
    ] {
        let fs = MockFilesystem::new();
        let got = found_with(&fs, &format!("{line}\n{COMPINIT}"), &[]);
        assert!(
            got.doubts.iter().any(|doubt| doubt.contains("PATH")),
            "{line}: {got:?}"
        );
    }
    // Without compinit none of them is a doubt of this rule.
    for line in ["PATH+=/x", "read -A path < ~/.p"] {
        let fs = MockFilesystem::new();
        assert_eq!(found_with(&fs, line, &[]), Scan::default(), "{line}");
    }
    // An element that holds what `path` held may split under SH_WORD_SPLIT.
    let fs = MockFilesystem::new();
    let got = found_with(
        &fs,
        &format!("setopt sh_word_split\npath=(~/x $path)\n{COMPINIT}"),
        &[],
    );
    assert_eq!(
        got.doubts,
        [format!(
            "it cannot follow the directories that `$path` gives PATH in /home/alice/.zshrc, as \
             /home/alice/.zshrc may turn SH_WORD_SPLIT or KSH_ARRAYS on, which split them or keep \
             the first, {RUN}"
        )]
    );
}

#[test]
fn a_program_a_hash_or_commands_names_for_a_command_is_a_doubt_where_compinit_runs() {
    // zsh 5.9.2 runs the program each of these names for `locale`, wherever
    // it is.
    for line in [
        "hash locale=~/bin/locale",
        "hash -- locale=/x",
        "builtin hash locale=/x",
        "hash $x",
        "commands[locale]=~/bin/locale",
        "commands+=(locale ~/bin/locale)",
        "read -A commands < ~/.c",
        "set -A commands locale ~/bin/locale",
        "print -v 'commands[locale]' ~/bin/locale",
        ": ${commands[locale]::=~/bin/locale}",
        ": ${(AA)commands::=locale ~/bin/locale}",
    ] {
        let fs = MockFilesystem::new();
        let got = found_with(&fs, &format!("{line}\n{COMPINIT}"), &[]);
        assert!(warned(&got), "{line}");
    }
    // Named directories, a table emptied or filled from PATH, and a test of
    // what it holds name no program.
    for line in [
        "hash -d src=~/src",
        "hash -r",
        "rehash",
        "unhash -m 'x*'",
        "print -r -- $commands[ls]",
        "(( $+commands[fzf] ))",
    ] {
        let fs = MockFilesystem::new();
        assert_eq!(
            found_with(&fs, &format!("{line}\n{COMPINIT}"), &[]),
            Scan::default(),
            "{line}"
        );
    }
}

#[test]
fn an_environment_without_path_or_one_the_check_cannot_read_is_a_doubt_where_compinit_runs() {
    let fs = MockFilesystem::new();
    nix_zsh(&fs, &[OWN], &["compinit", "compaudit", "compdump"]);
    seed(&fs, "/home/alice/.zshrc", COMPINIT);
    let program = PathBuf::from(format!("{ZSH}/bin/zsh"));
    let without = Install::of(
        &fs,
        Some(&program),
        Some(&[("USER".to_string(), "alice".to_string())]),
    );
    assert_eq!(
        scan_with(&fs, UNKNOWN, &without).doubts,
        [format!(
            "it cannot tell which directories PATH names, as the shell's environment holds none \
             and zsh then takes the one it was built with, {RUN}"
        )]
    );
    // Where the check does not know the environment, compinit is found only
    // in a directory the files put in front of fpath.
    seed(
        &fs,
        "/home/alice/.zshrc",
        &format!("fpath=({OWN} $fpath)\n{COMPINIT}"),
    );
    let unknown = Install::of(&fs, Some(&program), None);
    let got = scan_with(&fs, UNKNOWN, &unknown);
    assert!(
        got.doubts.contains(&format!(
            "it cannot tell which directories PATH names, as it does not know the shell's \
             environment, {RUN}"
        )),
        "{got:?}"
    );
}

#[test]
fn nixos_s_path_holds_none_of_the_operator_s_own_until_a_directory_of_it_does() {
    // set-environment puts each profile's `bin` in PATH, behind the setuid
    // wrappers; those of the store hold none of the operator's own.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(&fs, "/home/alice/.zshrc", COMPINIT);
    let system = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-system-path/bin"; // pragma: allowlist secret
    programs(&fs, system, &["locale"]);
    fs.create_symlink(Path::new(system), Path::new("/run/current-system/sw/bin"))
        .expect("a link");
    for vars in [&SESSION[..], &[("USER", "alice")][..]] {
        assert_eq!(
            scan_with(&fs, UNKNOWN, &install(&fs, vars)),
            Scan::default(),
            "{vars:?}"
        );
    }
    // A profile in the home that leads elsewhere than into the store holds
    // programs of the operator's own, as set-environment puts it in PATH
    // whether the environment names it or not.
    programs(&fs, "/home/alice/.nix-profile/bin", &["locale"]);
    for vars in [&SESSION[..], &[("USER", "alice")][..]] {
        assert_eq!(
            scan_with(&fs, UNKNOWN, &install(&fs, vars)).doubts,
            [own("/home/alice/.nix-profile/bin", "`locale`")],
            "{vars:?}"
        );
    }
    // A user the check cannot follow, which names the per-user profile.
    let fs = MockFilesystem::new();
    nixos(&fs);
    seed(&fs, "/home/alice/.zshenv", "USER=bob\n");
    seed(&fs, "/home/alice/.zshrc", COMPINIT);
    let got = scan_with(&fs, UNKNOWN, &install(&fs, &[("USER", "alice")]));
    assert!(
        got.doubts.contains(&format!(
            "it cannot follow the directory that \
             /nix/store/i7pr6qxbzs6a7qxim17l8krynfy2r7ll-set-environment puts in PATH as \
             `/etc/profiles/per-user/$USER/bin`, {RUN}"
        )),
        "{got:?}"
    );
}
