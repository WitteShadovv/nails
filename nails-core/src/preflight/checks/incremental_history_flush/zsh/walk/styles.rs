// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The styles of zsh's completion system whose values may make zsh's own
//! completion functions run code as you complete a word, as their code reads
//! each: the check takes a value of a style they only test or read as data
//! for harmless, judges a value they read as arithmetic, as a `zformat`
//! format, with `eval` or as parameters to set, and doubts any style whose
//! uses it has not read ([`style_doubt`]).

use super::super::arith::plain_number;
use super::super::lexer::Word;
use super::strings::computed;

/// The styles of zsh's completion system whose values zsh 5.9 to 5.9.2's
/// own completion functions only test for a true value (`zstyle -t`, `-T`)
/// or read as data, any value they hold: words they compare, patterns they
/// match, words they add as matches or show, and what the builtins they hand
/// them to (`compadd`, `compfiles`, `compdescribe`) read as such, as their
/// code reads each where it looks it up. The check takes the others for
/// styles whose values may make them run code: `completer`, `cache-policy`
/// and `user-expand`, which name functions they run, and `command`, which
/// `_call_program` runs, which the walk reads where it reads a `zstyle`;
/// `menu`, `select-scroll` and `range`, which they read as arithmetic;
/// `format` and `tag-order`, in which `zformat` reads a `%(` as arithmetic;
/// `file-patterns`, which `_files` reads with `eval`; `environ`, which
/// `_sudo` sets parameters by; `use-cache`, which makes them source the cache
/// files, and `cache-path`, which names their directory, whose files
/// `_luarocks` sources whatever `use-cache` says; and any style the check has
/// not read.
const DATA_STYLES: [&str; 69] = [
    "accept-exact",
    "accept-exact-dirs",
    "add-space",
    "ambiguous",
    "auto-description",
    "avoid-completer",
    "call-command",
    "complete-options",
    "condition",
    "domains",
    "expand",
    "extra-verbose",
    "file-sort",
    "force-list",
    "glob",
    "global",
    "group-name",
    "group-order",
    "groups",
    "hidden",
    "hosts",
    "ignore-line",
    "ignore-parents",
    "ignored-patterns",
    "insert-ids",
    "insert-tab",
    "insert-unambiguous",
    "keep-prefix",
    "last-prompt",
    "list-colors",
    "list-dirs-first",
    "list-grouped",
    "list-packed",
    "list-prompt",
    "list-rows-first",
    "list-separator",
    "list-suffixes",
    "matcher",
    "matcher-list",
    "max-errors",
    "max-matches-width",
    "old-list",
    "old-matches",
    "old-menu",
    "original",
    "path-completion",
    "ports",
    "prefix-hidden",
    "prefix-needed",
    "preserve-prefix",
    "rehash",
    "remote-access",
    "remove-all-dups",
    "select-prompt",
    "separate-sections",
    "show-completer",
    "single-ignored",
    "sort",
    "special-dirs",
    "squeeze-slashes",
    "subst-globs-only",
    "substitute",
    "suffix",
    "try-to-use-pminst",
    "urls",
    "use-ip",
    "users",
    "verbose",
    "word",
];

/// Whether `pattern`, a `zstyle`'s pattern as written, may match a context
/// zsh's own completion functions look a style up in, which starts with
/// `:completion:`: one an expansion, brace expansion or a glob may make, or
/// whose part before its first pattern character neither starts with
/// `:completion:` nor is the start of it (`:prompt:*`, `:vcs_info:*` match
/// none).
pub(super) fn completion_context(pattern: &Word) -> bool {
    if computed(pattern) || pattern.bare {
        return true;
    }
    let literal: String = pattern
        .text
        .chars()
        .take_while(|c| !"*?[<(|#^~\\".contains(*c))
        .collect();
    ":completion:".starts_with(&literal) || literal.starts_with(":completion:")
}

/// Whether `text`, a value of the `menu` style, is one `_main_complete`
/// reads as arithmetic without running code: one with no `=` before a digit,
/// or digits alone past its first `=` (`select=2`, `select=long`).
fn menu_value(text: &str) -> bool {
    let counted = text
        .match_indices('=')
        .any(|(at, _)| text[at + 1..].starts_with(|c: char| c.is_ascii_digit()));
    !counted
        || text
            .split_once('=')
            .is_some_and(|(_, number)| number.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `text`, a value of the `range` style, is one `_history` reads as
/// arithmetic without running code: digits, or two runs of them parted by a
/// `:` (`20:5`).
fn range_value(text: &str) -> bool {
    let digits = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit());
    match text.split_once(':') {
        Some((max, slice)) => digits(max) && digits(slice),
        None => digits(text),
    }
}

/// Whether `text`, a format, holds a `zformat` ternary, `%` and `(` with a
/// width between (`%(d.a.b)`, `%5(d.a.b)`), whose test `zformat -f` reads
/// as arithmetic.
fn ternary(text: &str) -> bool {
    text.match_indices('%').any(|(at, _)| {
        text[at + 1..]
            .trim_start_matches(|c: char| c == '-' || c == '.' || c.is_ascii_digit())
            .starts_with('(')
    })
}

/// How zsh's own completion functions read the value of the completion
/// style `style` that a `zstyle` gives with `values`, or with `-e` (`eval`)
/// code that makes them, where that may make them run code as you complete
/// a word, as a doubt names it; `None` for a style whose values they only
/// test or read as data ([`DATA_STYLES`]), for one that names their
/// functions or code, which the walk reads as such, and for a value that
/// runs nothing as they read it.
pub(super) fn style_doubt(style: &str, values: &[Word], eval: bool) -> Option<String> {
    if DATA_STYLES.contains(&style)
        || matches!(
            style,
            "completer" | "cache-policy" | "user-expand" | "command"
        )
    {
        return None;
    }
    let unread = |value: &&Word| eval || computed(value) || value.bare;
    let how = match style {
        "menu" | "select-scroll" | "range" => {
            let plain = |value: &Word| match style {
                "menu" => menu_value(&value.text),
                "range" => range_value(&value.text),
                _ => plain_number(&value.text),
            };
            if !values.iter().any(|value| unread(&value) || !plain(value)) {
                return None;
            }
            format!("they read the value of `{style}` as arithmetic")
        }
        "format" | "tag-order" => {
            if !values
                .iter()
                .any(|value| unread(&value) || ternary(&value.text))
            {
                return None;
            }
            format!("`zformat` reads a `%(` in the value of `{style}` as arithmetic")
        }
        "file-patterns" => {
            if !values.iter().any(|value| unread(&value)) {
                return None;
            }
            "`_files` reads the value of `file-patterns` with `eval`".to_string()
        }
        "use-cache" => {
            let on = |value: &Word| matches!(value.text.as_str(), "true" | "yes" | "on" | "1");
            if !values.iter().any(|value| unread(&value)) && !values.first().is_some_and(on) {
                return None;
            }
            "it may turn `use-cache` on, with which they source the files of the completion \
             cache, which the check does not read"
                .to_string()
        }
        "cache-path" => "they source the files of the directory `cache-path` names where \
                         `use-cache` is on, and `_luarocks` whatever it says"
            .to_string(),
        "environ" => "`_sudo` sets the parameters the value of `environ` names".to_string(),
        _ => format!("the check does not know how they read the `{style}` style"),
    };
    Some(how)
}
