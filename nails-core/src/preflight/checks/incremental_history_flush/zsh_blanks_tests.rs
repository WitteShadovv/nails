// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where zsh parts words: at a space or a tab alone, so that any other white
//! space stays in the word, a `#` after it starts no comment and a value that
//! ends in it names another path.

use super::*;

/// The white space zsh keeps in a word: a vertical tab, a form feed, a
/// carriage return, a no-break space, a next line, a line separator and an
/// em space.
const KEPT_SPACES: [char; 7] = [
    '\u{b}', '\u{c}', '\r', '\u{a0}', '\u{85}', '\u{2028}', '\u{2003}',
];

/// The texts of the words of `text`.
fn words(text: &str) -> Vec<String> {
    tokens(text)
        .into_iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.text),
            _ => None,
        })
        .collect()
}

#[test]
fn a_word_parts_at_a_space_or_a_tab_alone() {
    for c in KEPT_SPACES {
        assert_eq!(
            words(&format!(":{c}# x\ty z")),
            [
                format!(":{c}#"),
                "x".to_string(),
                "y".to_string(),
                "z".to_string()
            ],
            "{c:?}"
        );
        // In a command substitution, an array and a here-document's
        // delimiter too.
        let text = format!("a=(x{c}y z)\nprint $(:{c}# )\ncat <<E{c}\nE\nb\nE{c}\nc\n");
        let found = tokens(&text);
        assert!(
            found.contains(&Token::Array(
                "a".to_string(),
                vec![
                    Word {
                        text: format!("x{c}y"),
                        ..Word::default()
                    },
                    Word {
                        text: "z".to_string(),
                        ..Word::default()
                    },
                ]
            )),
            "{c:?}: {found:?}"
        );
        assert!(
            found.contains(&Token::Text("E\nb\n".to_string())),
            "{c:?}: {found:?}"
        );
        assert!(words(&text).contains(&"c".to_string()), "{c:?}: {found:?}");
        assert!(
            words(&text).contains(&format!("$(:{c}# )")),
            "{c:?}: {found:?}"
        );
    }
    // A brace that stands alone is one before a space, a tab or a line end.
    assert_eq!(words("{ :; }\n{\u{b}:; }"), ["{", ":", "}", "{\u{b}:", "}"]);
}

#[test]
fn a_hash_after_other_white_space_starts_no_comment() {
    // zsh 5.9 to 5.9.2 run what follows such a `#` on the line, and write
    // each line typed into the file this hook names.
    let hook = " ; preexec() { print -r -- \"$1\" >> ~/.zl }\n";
    for c in KEPT_SPACES {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!(":{c}#{hook}"));
        let found = scan(&fs, UNKNOWN);
        assert!(
            found
                .doubts
                .iter()
                .any(|doubt| doubt.contains("`~/.zl`, which `preexec`")),
            "{c:?}: {found:?}"
        );
        // A line that starts with it is no comment either.
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshrc",
            &format!("{c}# ; setopt share_history\n"),
        );
        assert_eq!(
            on(&fs, UNKNOWN),
            ["/home/alice/.zshrc names SHARE_HISTORY"],
            "{c:?}"
        );
    }
    // After a space or a tab, it does.
    for c in [' ', '\t'] {
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!(":{c}#{hook}"));
        assert_eq!(scan(&fs, UNKNOWN), Scan::default(), "{c:?}");
    }
}

#[test]
fn a_path_that_ends_in_other_white_space_is_another_path() {
    for c in KEPT_SPACES {
        // `ZDOTDIR=~/.third` and a Windows line end: zsh 5.9 to 5.9.2 read
        // `~/.third\r/.zshrc`.
        let fs = MockFilesystem::new();
        seed(
            &fs,
            "/home/alice/.zshenv",
            &format!(":\nZDOTDIR=~/.third{c}\n"),
        );
        seed(&fs, "/home/alice/.third/.zshrc", "HISTSIZE=100\n");
        seed(
            &fs,
            &format!("/home/alice/.third{c}/.zshrc"),
            "setopt share_history\n",
        );
        assert_eq!(
            on(&fs, NOT_LOGIN),
            [format!("/home/alice/.third{c}/.zshrc names SHARE_HISTORY")],
            "{c:?}"
        );
        let fs = MockFilesystem::new();
        seed(&fs, "/home/alice/.zshrc", &format!("source ~/.zs{c}\n"));
        seed(
            &fs,
            &format!("/home/alice/.zs{c}"),
            "setopt share_history\n",
        );
        assert_eq!(
            on(&fs, NOT_LOGIN),
            [format!("/home/alice/.zs{c} names SHARE_HISTORY")],
            "{c:?}"
        );
    }
}

#[test]
fn a_file_with_bytes_that_are_no_utf8_is_a_doubt() {
    // zsh 5.9.2 reads `~/.th\xffird/.zshrc` after this, a path the check
    // cannot name as it reads the file.
    let fs = MockFilesystem::new();
    fs.mock_set_file_bytes("/home/alice/.zshenv", b"ZDOTDIR=~/.th\xffird\n");
    assert!(
        scan(&fs, NOT_LOGIN).doubts.contains(
            &"it cannot read /home/alice/.zshenv as zsh does, as it holds bytes that are no UTF-8 \
          text"
                .to_string()
        )
    );
}
