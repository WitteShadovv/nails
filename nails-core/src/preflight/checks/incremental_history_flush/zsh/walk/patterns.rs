// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether a pattern that zsh matches against the names of the parameters
//! (`unset -m`) may match a name, as zsh compiles it (Src/pattern.c), or
//! more: `*` and `?` match any characters and any one, a `[...]` any one, a
//! `\` keeps the character after it as it is, and a group `(...)` and the
//! alternatives `|` parts are followed; `x~y`, which matches what `x` does
//! but `y` with `EXTENDED_GLOB`, counts as `x`. Any other operator zsh may
//! read in a pattern (`#`, `^`, `<1-9>`, a group's flags `(#i)`, ksh's
//! `@(...)`), and one that does not close, may match any name. Letters match
//! in either case.

/// A piece of a pattern.
#[derive(Debug)]
enum Piece {
    /// The character, in either case.
    Char(char),
    /// Any one character.
    One,
    /// Any characters, or none.
    Any,
    /// Any of the alternatives, each a run of pieces.
    Group(Vec<Vec<Piece>>),
}

/// The alternatives of `chars` from `at`, each a run of pieces, up to the
/// `)` that closes the group they are in (`nested`) or the end; `None` where
/// they hold what the check does not follow, which may match any name.
fn alternatives(chars: &[char], at: &mut usize, nested: bool) -> Option<Vec<Vec<Piece>>> {
    let mut found = vec![Vec::new()];
    while let Some(&c) = chars.get(*at) {
        *at += 1;
        let next = chars.get(*at).copied();
        let piece = match c {
            '\\' => {
                *at += 1;
                Piece::Char(next.unwrap_or('\\'))
            }
            '*' | '?' | '+' | '@' | '!' if next == Some('(') => return None,
            '*' => Piece::Any,
            '?' => Piece::One,
            '[' => {
                // A class: `]` first stands for itself, after a `!` or `^`.
                let mut end = *at;
                if matches!(chars.get(end), Some('!' | '^')) {
                    end += 1;
                }
                if chars.get(end) == Some(&']') {
                    end += 1;
                }
                while chars.get(end).is_some_and(|&c| c != ']') {
                    if chars[end] == '[' && chars.get(end + 1) == Some(&':') {
                        // `[:alpha:]`.
                        let close = chars[end..]
                            .windows(2)
                            .position(|pair| pair == [':', ']'])?;
                        end += close + 2;
                    } else {
                        end += 1;
                    }
                }
                chars.get(end)?;
                *at = end + 1;
                Piece::One
            }
            '(' if next == Some('#') => return None,
            '(' => Piece::Group(alternatives(chars, at, true)?),
            ')' if nested => return Some(found),
            '|' => {
                found.push(Vec::new());
                continue;
            }
            '~' => {
                // What it excludes, up to the next alternative or the end of
                // the group, need not be matched.
                let mut depth = 0usize;
                while let Some(&c) = chars.get(*at) {
                    match c {
                        '\\' => *at += 1,
                        '(' => depth += 1,
                        ')' if depth == 0 => break,
                        ')' => depth -= 1,
                        '|' if depth == 0 => break,
                        _ => {}
                    }
                    *at += 1;
                }
                continue;
            }
            '#' | '^' | '<' | ')' => return None,
            c => Piece::Char(c),
        };
        found.last_mut().expect("an alternative").push(piece);
    }
    (!nested).then_some(found)
}

/// Whether `pieces` match all of `name`.
fn run_matches(pieces: &[Piece], name: &[char]) -> bool {
    match pieces.split_first() {
        None => name.is_empty(),
        Some((Piece::Char(c), rest)) => {
            name.first().is_some_and(|n| n.eq_ignore_ascii_case(c)) && run_matches(rest, &name[1..])
        }
        Some((Piece::One, rest)) => !name.is_empty() && run_matches(rest, &name[1..]),
        Some((Piece::Any, rest)) => (0..=name.len()).any(|at| run_matches(rest, &name[at..])),
        Some((Piece::Group(alternatives), rest)) => (0..=name.len()).any(|at| {
            alternatives
                .iter()
                .any(|alternative| run_matches(alternative, &name[..at]))
                && run_matches(rest, &name[at..])
        }),
    }
}

/// Whether zsh may match the pattern `pattern`, as a builtin is given it,
/// against `name` ([the module](self)).
pub(in super::super) fn may_match(pattern: &str, name: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let mut at = 0;
    alternatives(&chars, &mut at, false).is_none_or(|alternatives| {
        alternatives
            .iter()
            .any(|alternative| run_matches(alternative, &name))
    })
}

#[cfg(test)]
mod tests {
    use super::may_match;

    #[test]
    fn a_pattern_matches_a_name_as_zsh_may_match_it() {
        for (pattern, name) in [
            ("ZDOTDI?", "ZDOTDIR"),
            ("XDG_CONFIG_HOM?", "XDG_CONFIG_HOME"),
            ("ZDOT*", "ZDOTDIR"),
            ("*", "HOME"),
            ("[Z]DOTDIR", "ZDOTDIR"),
            ("[!a]DOTDIR", "ZDOTDIR"),
            ("[]Z]DOTDIR", "ZDOTDIR"),
            ("[[:upper:]]DOTDIR", "ZDOTDIR"),
            ("(ZDOTDIR|x)", "ZDOTDIR"),
            ("(x|ZDOT(DIR|x))", "ZDOTDIR"),
            ("x|ZDOTDIR", "ZDOTDIR"),
            ("Z\\DOTDIR", "ZDOTDIR"),
            ("zdotdir", "ZDOTDIR"),
            ("ZDOTDIR~ZDOTDIR", "ZDOTDIR"),
            ("(ZDOTDIR~x|y)", "ZDOTDIR"),
            // What the check does not follow may match any name.
            ("x#", "ZDOTDIR"),
            ("^x", "ZDOTDIR"),
            ("<1-9>", "ZDOTDIR"),
            ("(#i)x", "ZDOTDIR"),
            ("@(x)", "ZDOTDIR"),
            ("*(x)", "ZDOTDIR"),
            ("(x", "ZDOTDIR"),
            ("x)", "ZDOTDIR"),
            ("[x", "ZDOTDIR"),
        ] {
            assert!(may_match(pattern, name), "{pattern} {name}");
        }
        for (pattern, name) in [
            ("POWERLEVEL9K_*", "ZDOTDIR"),
            (
                "(POWERLEVEL9K_*|DEFAULT_USER)~POWERLEVEL9K_GITSTATUS_DIR",
                "HOME",
            ),
            ("ZDOTDI?", "ZDOTDIR2"),
            ("?", "HOME"),
            ("(x|y)", "x|y"),
            ("_p9k_*", "fpath"),
        ] {
            assert!(!may_match(pattern, name), "{pattern} {name}");
        }
    }
}
