// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The parameters a builtin sets by a name among its words, as zsh reads
//! its options: `print -v`'s, `read`'s, `zstyle -s`'s, `strftime -s`'s and
//! the like. An option that takes an argument takes the rest of its word,
//! or the word after it (`print -vPS1`, `print -rv PS1`, `strftime -sPS1`).
//! A name, or a word where the options may stand, that an expansion, brace
//! expansion or a glob may make is one the check cannot read
//! ([`names_parameter`]).

use super::super::lexer::Word;
use super::declare::starts_computed;

/// Whether `word`, a word of zsh code, holds an expansion.
pub(super) fn computed(word: &Word) -> bool {
    word.expands || word.text.contains(['$', '`'])
}

/// The builtins that take the names of the parameters they set among
/// words the check does not tell apart from their others, so that an
/// expansion in any word of them may make such a name.
const ANY_WORD: &[&str] = &[
    "vared",
    "zparseopts",
    "sysread",
    "sysopen",
    "zselect",
    "pcre_match",
    "zregexparse",
    "zsystem",
    "getln",
    "ztie",
    "zcurses",
];

/// The arguments that the options of `wanted` take among `args`, the words
/// after a builtin whose options that take an argument are `takes`, as zsh
/// reads them: each word that starts with `-` holds options up to the first
/// word that does not (`-` and `--` end them), and an option that takes an
/// argument takes the rest of its word, or the word after it when nothing
/// follows it in its word. A word of options that an expansion makes may
/// hold any, so its rest and the word after it count too.
pub(super) fn option_arguments(args: &[Word], takes: &str, wanted: &str) -> Vec<Word> {
    let mut found = Vec::new();
    let mut words = args.iter().peekable();
    while let Some(word) = words.next() {
        let Some(flags) = word.text.strip_prefix('-') else {
            break;
        };
        if flags.is_empty() || flags == "-" {
            break;
        }
        if computed(word) || word.bare {
            found.push(Word {
                text: flags.to_string(),
                expands: true,
                quoted: false,
                bare: word.bare,
            });
            found.extend(words.peek().map(|next| (*next).clone()));
            continue;
        }
        for (at, letter) in flags.char_indices() {
            if !takes.contains(letter) {
                continue;
            }
            let rest = &flags[at + letter.len_utf8()..];
            let argument = if rest.is_empty() {
                words.next().cloned()
            } else {
                Some(Word {
                    text: rest.to_string(),
                    expands: false,
                    quoted: false,
                    bare: false,
                })
            };
            if wanted.contains(letter) {
                found.extend(argument);
            }
            break;
        }
    }
    found
}

/// Each word among `args` that is no option, and each rest of a word of
/// options past one of its letters, which an option may take as its
/// argument (`-aarray`): more than the names a builtin of [`ANY_WORD`] sets.
fn every_name(args: &[Word]) -> Vec<Word> {
    let mut found = Vec::new();
    for word in args {
        match word.text.strip_prefix('-') {
            Some(flags) => {
                for (at, letter) in flags.char_indices() {
                    let rest = &flags[at + letter.len_utf8()..];
                    if !rest.is_empty() {
                        found.push(Word {
                            text: rest.to_string(),
                            expands: computed(word) || word.bare,
                            quoted: false,
                            bare: word.bare,
                        });
                    }
                }
            }
            None => found.push(word.clone()),
        }
    }
    found
}

/// The words among `args`, the words after the builtin `command`, that name a
/// parameter it sets, as zsh reads its options: `print -v`'s (`-vname`,
/// `-rv name`), `printf -v`'s, `read`'s, `getln`'s and `vared`'s names,
/// `getopts`'s second word, `zstyle -s`'s, `-a`'s, `-b`'s and `-g`'s,
/// `zformat -f`'s and `-a`'s, `strftime -s`'s, `syswrite -c`'s,
/// `syserror -e`'s, `stat -A`'s and `-H`'s, `zgetattr`'s third word,
/// `zlistattr`'s second, the one `zpty -r` reads into, and, of a builtin of
/// [`ANY_WORD`], every word that may be one.
pub(super) fn targets(command: &str, args: &[Word]) -> Vec<Word> {
    let at = |index: usize| args.get(index).cloned().into_iter().collect();
    // The words past the options a builtin takes alone (`zgetattr -h`).
    let positional = |index: usize| {
        args.iter()
            .skip_while(|word| word.text.starts_with('-') && word.text.len() > 1)
            .nth(index)
            .cloned()
            .into_iter()
            .collect()
    };
    match command {
        "print" => option_arguments(args, "CfuvxX", "v"),
        // printf takes `-v` as a word of its own only.
        "printf" => match args.first() {
            Some(flag) if flag.text == "-v" => at(1),
            Some(flag) if flag.text.starts_with('-') && computed(flag) => {
                args.iter().take(2).cloned().collect()
            }
            _ => Vec::new(),
        },
        "read" => every_name(args),
        "getopts" => at(1),
        "zstyle" => match args.first().map(|flag| flag.text.as_str()) {
            Some("-s" | "-a" | "-b") => at(3),
            Some("-g") => at(1),
            _ => Vec::new(),
        },
        "zformat" => match args.first().map(|flag| flag.text.as_str()) {
            Some("-f" | "-a") => at(1),
            _ => Vec::new(),
        },
        "strftime" => option_arguments(args, "s", "s"),
        "syswrite" => option_arguments(args, "co", "c"),
        "syserror" => option_arguments(args, "ep", "e"),
        "stat" | "zstat" => option_arguments(args, "AHfF", "AH"),
        "zgetattr" => positional(2),
        "zlistattr" => positional(1),
        "zpty" => {
            // `zpty -r [-mt] name [param]`.
            let Some(read) = args
                .iter()
                .position(|word| word.text.starts_with('-') && word.text.contains('r'))
            else {
                return Vec::new();
            };
            args[read + 1..]
                .iter()
                .position(|word| !word.text.starts_with('-'))
                .and_then(|name| args.get(read + 1 + name + 1))
                .cloned()
                .into_iter()
                .collect()
        }
        command if ANY_WORD.contains(&command) => every_name(args),
        _ => Vec::new(),
    }
}

/// The letters of the options that take an argument of each builtin that
/// sets a parameter by an option or past its options, as zsh reads them
/// itself or as the builtin does (`zstyle -s`); `None` for any other.
fn option_letters(command: &str) -> Option<&'static str> {
    Some(match command {
        "print" => "CfuvxX",
        "printf" => "v",
        "strftime" => "s",
        "syswrite" => "co",
        "syserror" => "ep",
        "stat" | "zstat" => "AHfF",
        "zstyle" | "zformat" | "zpty" | "zgetattr" | "zlistattr" => "",
        _ => return None,
    })
}

/// The first word among `args`, the words after a builtin whose options that
/// take an argument are `takes`, that stands where its options may and that
/// an expansion, brace expansion or a glob may make any options of (`$o`,
/// `-$o`, `{-v,x}`): the options run up to the first word that starts
/// otherwise than with a `-` or with what an expansion may give it, a `-` or
/// `--` alone, or a `-` and a digit, each argument of an option passed over
/// (`print -f "$f" $x` reads `$x` as options).
fn unread_option<'a>(args: &'a [Word], takes: &str) -> Option<&'a Word> {
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if starts_computed(word) {
            return Some(word);
        }
        let flags = word.text.strip_prefix('-')?;
        if flags.is_empty() || flags == "-" || flags.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        if computed(word) || word.bare {
            return Some(word);
        }
        if let Some((at, letter)) = flags
            .char_indices()
            .find(|(_, letter)| takes.contains(*letter))
            && flags[at + letter.len_utf8()..].is_empty()
        {
            words.next();
        }
    }
    None
}

/// A word among `args`, the words after the builtin `command`, in which an
/// expansion, brace expansion or a glob makes the name of a parameter it
/// sets ([`targets`]), or that stands where its options may and such a word
/// may make any options of ([`unread_option`]), or, for a builtin of
/// [`ANY_WORD`], any word they make; `None` when there is none. Where a word
/// before a name the builtin takes by its place may make no word or several
/// (an expansion or a glob outside quotes, `getopts $x a ${n}`), any such
/// word after it may stand in that place.
pub(super) fn names_parameter(command: &str, args: &[Word]) -> Option<Word> {
    if ANY_WORD.contains(&command) {
        return args
            .iter()
            .find(|word| computed(word) || word.bare)
            .cloned();
    }
    if let Some(word) = option_letters(command).and_then(|takes| unread_option(args, takes)) {
        return Some(word.clone());
    }
    let targets = targets(command, args);
    let place = targets
        .iter()
        .filter_map(|target| args.iter().position(|word| word == target))
        .max();
    if let Some(place) = place
        && let Some(at) = args[..place].iter().position(|word| word.bare)
        && let Some(word) = args[at + 1..]
            .iter()
            .find(|word| computed(word) || word.bare)
    {
        return Some(word.clone());
    }
    targets
        .into_iter()
        .find(|word| (computed(word) || word.bare) && !word.text.starts_with(['-', '+']))
}
