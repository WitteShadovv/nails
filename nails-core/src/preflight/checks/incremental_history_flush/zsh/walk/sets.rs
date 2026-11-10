// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a command tests and what a function sets, as the walk reads them:
//! the files a test asks about (`[[ -f file ]]`, `test -r file`), which a
//! `source` of a file that is not there now may follow, and, in a function,
//! a parameter set to what an expansion makes, which zsh gives every program
//! a hook runs in its environment once it is exported, which it may be
//! anywhere ([`Event::Computed`]).

use super::super::arith::NUMERIC;
use super::super::lexer::Word;
use super::declare::options;
use super::names::{computed, targets};
use super::{Event, Walker};

/// Whether `value`, a value assigned as written, may carry the command line:
/// an expansion makes it, but for one of a parameter zsh keeps a number in
/// (`$SECONDS`, `${EPOCHSECONDS}` aside) or of `$?`, `$#` or `$$` alone.
fn carries(value: &str) -> bool {
    let mut rest = value;
    while let Some(at) = rest.find(['$', '`']) {
        let after = &rest[at + 1..];
        if rest[at..].starts_with('`') {
            return true;
        }
        let (name, len) = match after.strip_prefix('{') {
            Some(braced) => match braced.split_once('}') {
                Some((name, _)) => (name, name.len() + 2),
                None => return true,
            },
            None => {
                let end = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                match &after[..end] {
                    "" => (after.get(..1).unwrap_or_default(), 1),
                    name => (name, end),
                }
            }
        };
        if !(NUMERIC.contains(&name) || matches!(name, "?" | "#" | "$")) {
            return true;
        }
        rest = &after[len.min(after.len())..];
    }
    false
}

/// The operators of a test that ask about a file.
const FILE_TESTS: &[&str] = &[
    "-a", "-b", "-c", "-d", "-e", "-f", "-g", "-h", "-k", "-L", "-N", "-O", "-G", "-p", "-r", "-s",
    "-S", "-u", "-w", "-x",
];

impl Walker<'_> {
    /// Note the files that a test, `command` with `args`, asks about
    /// ([`Event::Tested`]).
    pub(super) fn tested(&mut self, command: &str, args: &[Word]) {
        if !matches!(command, "[[" | "[" | "test") {
            return;
        }
        for pair in args.windows(2) {
            if FILE_TESTS.contains(&pair[0].text.as_str()) {
                self.events.push(Event::Tested(pair[1].text.clone()));
            }
        }
    }

    /// In a function, note each parameter `command` with `args` sets to what
    /// an expansion makes, or to what it reads (`read`), and whether it is
    /// local to the function ([`Event::Computed`]): `local`, and `typeset`,
    /// `declare`, `private`, `integer` and `float` without `-g` or `-x`, make
    /// one local.
    pub(super) fn computed_sets(&mut self, command: &str, args: &[Word]) {
        let Some(function) = self.function() else {
            return;
        };
        let declares = matches!(
            command,
            "local"
                | "typeset"
                | "declare"
                | "private"
                | "integer"
                | "float"
                | "export"
                | "readonly"
        );
        if declares {
            // Its options read as zsh reads them, past a number (`local -L 3
            // -x LINE=$1` exports it).
            let options = options(command, args);
            let local = command != "export" && !options.has('g') && !options.has('x');
            for arg in args {
                if let Some((target, value)) = arg.text.split_once('=')
                    && computed(arg)
                    && carries(value)
                {
                    self.events.push(Event::Computed {
                        function: function.clone(),
                        name: target.to_string(),
                        local,
                    });
                }
            }
            return;
        }
        for target in targets(command, args) {
            self.events.push(Event::Computed {
                function: function.clone(),
                name: target.text,
                local: false,
            });
        }
    }

    /// In a function, note each assignment among `words`, which a command
    /// has none after, that sets a parameter to what an expansion makes
    /// ([`Walker::computed_sets`]).
    pub(super) fn computed_assignments(&mut self, words: &[Word]) {
        let Some(function) = self.function() else {
            return;
        };
        for word in words.iter().filter(|word| computed(word)) {
            if let Some((target, value)) = word.text.split_once('=')
                && carries(value)
            {
                self.events.push(Event::Computed {
                    function: function.clone(),
                    name: target.to_string(),
                    local: false,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::carries;

    #[test]
    fn a_value_of_numbers_zsh_keeps_carries_no_command_line() {
        for value in ["$SECONDS", "${SECONDS}", "$?:$#:$$", "x$HISTCMD"] {
            assert!(!carries(value), "{value}");
        }
        for value in [
            "$1",
            "${1}",
            "$BUFFER",
            "${SECONDS:-$1}",
            "`fc -ln -1`",
            "$(fc -ln -1)",
            "$",
        ] {
            assert!(carries(value), "{value}");
        }
    }
}
