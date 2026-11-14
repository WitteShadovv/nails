// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The values `ZDOTDIR` and `XDG_CONFIG_HOME` may hold where zsh need not
//! read the file that sets them, or need not set them as the walk reads it:
//! a file in `/etc`, a login stage's, a conditional `source`, a builtin that a
//! function, an alias, a `disable` or `command` runs something else in place
//! of, and an `emulate` of sh's mode, in which zsh reads the user's files in
//! the home.

use super::*;

/// What the check names as written for `fs`, for a zsh started as `start`.
fn writes(fs: &MockFilesystem, start: Start) -> Vec<String> {
    on(fs, start)
}

/// A home whose `.zshrc` turns `SHARE_HISTORY` on and whose `~/.zd/.zshrc`,
/// where a `ZDOTDIR=~/.zd` puts the user's files, turns nothing on.
fn moved_home() -> MockFilesystem {
    let fs = MockFilesystem::new();
    seed(&fs, "/home/alice/.zshrc", "setopt share_history\n");
    seed(&fs, "/home/alice/.zd/.zshrc", "true\n");
    fs
}

const HOME_RC: &str = "/home/alice/.zshrc names SHARE_HISTORY";

#[test]
fn a_zdotdir_set_first_in_a_file_zsh_need_not_read_keeps_the_one_before() {
    // A zsh reads its stage's file in /etc or in /etc/zsh as it was built,
    // so one built for the other reads none of these, and ~/.zshrc then.
    for path in ["/etc/zshenv", "/etc/zsh/zshenv"] {
        let fs = moved_home();
        seed(&fs, path, "export ZDOTDIR=$HOME/.zd\n");
        assert_eq!(writes(&fs, NOT_LOGIN), [HOME_RC], "{path}");
    }
    // A login stage's file, for a shell that need not be a login shell.
    let fs = moved_home();
    seed(&fs, "/home/alice/.zprofile", "export ZDOTDIR=~/.zd\n");
    assert_eq!(writes(&fs, UNKNOWN), [HOME_RC]);
    assert!(writes(&fs, LOGIN).is_empty());
    // A file sourced under a condition, which zsh need not read.
    for zshenv in [
        "[[ -r ~/.zd.zsh ]] && source ~/.zd.zsh\n",
        "if [[ -r ~/.zd.zsh ]]; then source ~/.zd.zsh; fi\n",
    ] {
        let fs = moved_home();
        seed(&fs, "/home/alice/.zshenv", zshenv);
        seed(&fs, "/home/alice/.zd.zsh", "export ZDOTDIR=~/.zd\n");
        assert_eq!(writes(&fs, NOT_LOGIN), [HOME_RC], "{zshenv}");
    }
    // The user's .zshenv, which zsh reads, set first: the one value. Where
    // a file may turn RCS off, zsh reads no user's file at all.
    for etc in ["", "[[ -n $NORC ]] && unsetopt rcs\n"] {
        let fs = moved_home();
        seed(&fs, "/etc/zshenv", etc);
        seed(&fs, "/home/alice/.zshenv", "export ZDOTDIR=~/.zd\n");
        assert!(writes(&fs, NOT_LOGIN).is_empty(), "{etc}");
    }
}

#[test]
fn a_builtin_a_function_an_alias_or_a_disable_runs_something_else_in_place_of_is_a_doubt() {
    // zsh 5.9 to 5.9.2 set no ZDOTDIR after `alias export=:`, read ~/.zshrc
    // and write each line; a function runs in place of `unset` and
    // `source`, and in place of `export` once `disable -r` takes the
    // reserved word away.
    let shadowed = |name: &str, place: &str| {
        format!(
            "it cannot tell what the files set where they run `{name}`, as {place} defines a \
             function or an alias `{name}`, which zsh runs in place of the builtin of that name"
        )
    };
    for (zshenv, name) in [
        ("alias export=:\n", "export"),
        ("alias typeset=true\n", "typeset"),
        ("unset() { : }\n", "unset"),
        ("source() { : }\n", "source"),
        ("disable -r export\nexport() { : }\n", "export"),
        ("functions[local]=:\n", "local"),
        ("n=unset\nfunction $n { : }\n", "$n"),
    ] {
        let fs = moved_home();
        seed(&fs, "/etc/zshenv", zshenv);
        seed(&fs, "/home/alice/.zshenv", "export ZDOTDIR=~/.zd\n");
        let found = zsh(&fs, &[PathBuf::from(HOME)], NOT_LOGIN, &Install::default());
        assert!(
            found.doubts.contains(&shadowed(name, "/etc/zshenv")),
            "{zshenv}: {found:?}"
        );
    }
    // After a `disable`, zsh runs what PATH finds by the name.
    for disable in [
        "disable unset",
        "disable -m 'un*'",
        "disable -- source",
        "disable $b",
    ] {
        let fs = moved_home();
        seed(&fs, "/etc/zshenv", &format!("{disable}\n"));
        let found = zsh(&fs, &[PathBuf::from(HOME)], NOT_LOGIN, &Install::default());
        assert!(
            found.doubts.iter().any(|doubt| doubt.contains(
                "as a `disable` in /etc/zshenv may take that builtin away, after which zsh runs \
                 what PATH finds by its name"
            )),
            "{disable}: {found:?}"
        );
    }
    // A reserved word `disable -r` takes away leaves the builtin, and other
    // names and kinds are none.
    for zshenv in [
        "disable -r export\n",
        "disable -a ll\n",
        "disable -f precmd\n",
        "alias ls='ls --color=auto'\n",
        "exporter() { : }\n",
    ] {
        let fs = moved_home();
        seed(&fs, "/etc/zshenv", zshenv);
        seed(&fs, "/home/alice/.zshenv", "export ZDOTDIR=~/.zd\n");
        assert_eq!(
            zsh(&fs, &[PathBuf::from(HOME)], NOT_LOGIN, &Install::default()),
            Scan::default(),
            "{zshenv}"
        );
    }
}

#[test]
fn what_a_builtin_after_command_sets_it_may_set_and_need_not() {
    // `command` runs the program PATH finds unless POSIX_BUILTINS is on: zsh
    // 5.9 to 5.9.2 find no `export`, so ZDOTDIR stays unset and they read
    // ~/.zshrc.
    let fs = moved_home();
    seed(&fs, "/home/alice/.zshenv", "command export ZDOTDIR=~/.zd\n");
    assert_eq!(writes(&fs, NOT_LOGIN), [HOME_RC]);
    // An XDG_CONFIG_HOME of the environment `command unset` need not take
    // away.
    let fs = MockFilesystem::new();
    seed(
        &fs,
        "/home/alice/.zshenv",
        "command unset XDG_CONFIG_HOME\nexport ZDOTDIR=\"${XDG_CONFIG_HOME:-$HOME/.config}/zsh\"\n",
    );
    seed(&fs, "/home/alice/.cfg/zsh/.zshrc", "setopt share_history\n");
    seed(&fs, "/home/alice/.config/zsh/.zshrc", "true\n");
    let found = zsh(
        &fs,
        &[PathBuf::from(HOME)],
        NOT_LOGIN,
        &super::installed::install(&fs, &[("XDG_CONFIG_HOME", "/home/alice/.cfg")]),
    );
    assert!(
        found
            .writes
            .iter()
            .any(|write| write.what == "/home/alice/.cfg/zsh/.zshrc names SHARE_HISTORY"),
        "{found:?}"
    );
}

#[test]
fn an_emulate_of_sh_or_ksh_that_lasts_reads_the_user_files_in_the_home() {
    // zsh 5.9 to 5.9.2 read ~/.zshrc after these, whatever ZDOTDIR holds.
    for zshenv in [
        "export ZDOTDIR=~/.zd\nemulate sh\n",
        "export ZDOTDIR=~/.zd\nemulate bash\n",
        "export ZDOTDIR=~/.zd\nemulate -R rksh\n",
        "export ZDOTDIR=~/.zd\nf() { emulate sh }\nf\n",
        "export ZDOTDIR=~/.zd\nemulate -L sh\n",
        "export ZDOTDIR=~/.zd\neval 'emulate sh'\n",
    ] {
        let fs = moved_home();
        seed(&fs, "/home/alice/.zshenv", zshenv);
        assert_eq!(writes(&fs, NOT_LOGIN), [HOME_RC], "{zshenv}");
    }
    // A ZDOTDIR of the shell's environment, in whose .zshenv it runs.
    let fs = moved_home();
    seed(&fs, "/home/alice/.zd/.zshenv", "emulate sh\n");
    let found = zsh(
        &fs,
        &[PathBuf::from(HOME)],
        NOT_LOGIN,
        &super::installed::install(&fs, &[("ZDOTDIR", "/home/alice/.zd")]),
    );
    assert!(
        found.writes.iter().any(|write| write.what == HOME_RC),
        "{found:?}"
    );
    // One that runs only its code in the mode, one a function restores as it
    // returns, one in a subshell, and csh's, keep ZDOTDIR.
    for zshenv in [
        "export ZDOTDIR=~/.zd\nemulate sh -c 'true'\n",
        "export ZDOTDIR=~/.zd\nf() { emulate -L sh }\nf\n",
        "export ZDOTDIR=~/.zd\n: $(emulate sh)\n",
        "export ZDOTDIR=~/.zd\nemulate csh\n",
        "export ZDOTDIR=~/.zd\nemulate -R zsh\n",
    ] {
        let fs = moved_home();
        seed(&fs, "/home/alice/.zshenv", zshenv);
        assert!(writes(&fs, NOT_LOGIN).is_empty(), "{zshenv}");
    }
}
