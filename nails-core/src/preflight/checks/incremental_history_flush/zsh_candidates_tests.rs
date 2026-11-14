// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The values `ZDOTDIR` and `XDG_CONFIG_HOME` may hold where zsh need not
//! read the file that sets them: a file in `/etc`, a login stage's, a
//! conditional `source`.

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
