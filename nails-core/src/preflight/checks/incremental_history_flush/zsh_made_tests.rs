// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A startup file zsh reads next, which the code before it may write.

use super::*;

/// Whether the check warns for `fs`.
fn warns(fs: &MockFilesystem) -> bool {
    scan(fs, UNKNOWN) != Scan::default()
}

#[test]
fn a_write_of_the_next_startup_file_as_the_last_command_before_it_is_a_doubt() {
    // zsh 5.9 to 5.9.2 read the ~/.zshrc each of these writes as the last
    // command of ~/.zshenv, and write each line, while ~/.zshrc as the check
    // reads it names no option.
    for zshenv in [
        "cp ~/.src ~/.zshrc\n",
        "cp ~/p/.zshrc ~/\n",
        "cp ~/p/.zshrc ~\n",
        "cp ~/p/.zshrc ~/.zshrc\n",
        "cp -t ~ ~/p/.zshrc\n",
        "mv ~/p/.zshrc ~/\n",
        "install -m 644 ~/p/.zshrc ~/\n",
        "ln -sf ~/p/.zshrc ~/\n",
        "tee ~/.zshrc < ~/.src >/dev/null\n",
        "sed -i 's/^#S//' ~/.zshrc\n",
        "ZDOTDIR=~/.zd\ncp ~/.src ~/.zd/.zshrc\n",
        "f() { cp ~/.src ~/.zshrc }\nf\n",
        // Followed by a command, as before.
        "cp ~/.src ~/.zshrc\n:\n",
        "cat ~/.src > ~/.zshrc\n",
    ] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshenv", zshenv);
        seed(
            &fs,
            "/home/alice/.zshrc",
            "HISTSIZE=100\n#Ssetopt share_history\n",
        );
        seed(&fs, "/home/alice/.zd/.zshrc", "HISTSIZE=100\n");
        seed(&fs, "/home/alice/.src", "setopt share_history\n");
        seed(&fs, "/home/alice/p/.zshrc", "setopt share_history\n");
        assert!(warns(&fs), "{zshenv}");
    }
    // A write of another file, or of one zsh read before, is none.
    for zshenv in ["cp ~/.src ~/.other\n", "cp ~/.src ~/.zshenv.bak\n"] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshenv", zshenv);
        seed(&fs, "/home/alice/.zshrc", "HISTSIZE=100\n");
        seed(&fs, "/home/alice/.src", "setopt share_history\n");
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{zshenv}");
    }
}
