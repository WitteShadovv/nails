// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The commands the files run that the list of those the check knows to be
//! harmless does not hold ([`super::known`], [`super::walk::Event::Unlisted`]),
//! judged once every file is read: each is a doubt where zsh may run it, that
//! is where it stands outside a function, as the startup files run, or in a
//! function zsh runs. That is one the startup files run by name, one zsh
//! runs as a hook, a widget or a trap, one named like the command a NAILS
//! command is typed with, and each one such a function runs
//! ([`Reader::is_hook`]).
//!
//! A command by a name that is no builtin of zsh's ([`super::known::Verdict::Named`])
//! runs the function or the alias of that name the files define or autoload,
//! whose code the check reads in its place, only where the code it stands in
//! certainly defines one before it: earlier in the same reading of its file,
//! or of a file that sources that one, at that file's top level where
//! nothing may keep the definition from running (an `if`, `&&`, a loop, a
//! subshell, the background), or earlier in its chain of commands joined by
//! `&&` alone for what a command defines as it runs. Then the definition has
//! run wherever the command runs: zsh stops reading a file at a `return` or
//! at an error (a glob that matches nothing, a parameter `NO_UNSET`
//! refuses), which stops it before both. A definition in another file (a
//! file the code sources, another startup file, another reading of the same
//! file), or after the code that runs the name (a helper a hook runs that
//! the file defines after the hook), counts for nothing, as such a stop may
//! come before it: zsh 5.9 to 5.9.2 then run the outside program PATH finds
//! by that name, which is a doubt. An alias counts the same way, as zsh puts
//! its value in place of the name as it reads the code, but only for a name
//! with no quote or backslash in it past no precommand that is a builtin:
//! zsh puts none in place of `\name`, `"name"` or `noglob name`. One whose
//! value hands the words it is used with to a command the list does not
//! hold with any words ([`super::known::TAKES_ANY_WORDS`]) is a doubt where
//! it is used with words (`alias k=kill`, then `k -HUP $$`). The stock
//! `promptinit` defines `prompt` and the functions it runs, and marks the
//! prompt themes, as it runs ([`super::stock`]).

use super::Reader;
use super::known::{ZLE_PARAMETERS, arithmetic_parameter, outside_program};
use super::walk::Event;
use crate::Filesystem;

/// A function or a regular alias the files define, or a function they
/// autoload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Def {
    pub(super) name: String,
    /// How many events were applied before it, in the order zsh runs them.
    pub(super) order: usize,
    /// It certainly runs where the code it stands in runs to it, at that
    /// code's top level, as the walk followed its structure.
    pub(super) here: bool,
    /// The readings of the files being followed as it is defined, outermost
    /// first ([`Listed::within`]).
    pub(super) within: Vec<usize>,
    /// For a regular alias, whether its value's last command takes whatever
    /// words it is used with harmlessly.
    pub(super) alias: Option<bool>,
    /// For what a command defines as it runs, the piece of code and the
    /// chain of commands joined by `&&` alone in it that it is in
    /// ([`super::walk::Event::Unlisted`]).
    pub(super) chain: Option<(usize, usize)>,
}

/// A command the list does not hold ([`super::walk::Event::Unlisted`]), and
/// where and when the files run it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Unlisted {
    pub(super) function: Option<String>,
    pub(super) shown: String,
    pub(super) name: Option<String>,
    pub(super) words: bool,
    pub(super) certain: bool,
    pub(super) chain: Option<(usize, usize)>,
    pub(super) alias: bool,
    pub(super) why: String,
    pub(super) order: usize,
    pub(super) place: String,
    /// The readings of the files being followed as it is read, outermost
    /// first ([`Listed::within`]).
    pub(super) within: Vec<usize>,
}

/// What the reader keeps for the list of the commands the check knows to be
/// harmless ([the module](self)).
#[derive(Debug, Default)]
pub(super) struct Listed {
    /// The functions and regular aliases the files define and the functions
    /// they autoload, and the commands they run that the list does not hold.
    pub(super) defs: Vec<Def>,
    pub(super) unlisted: Vec<Unlisted>,
    /// Whether the walk lost track of the structure of the piece of code
    /// being followed, which then certainly runs nothing where it stands.
    pub(super) confused: bool,
    /// The readings of the files being followed, outermost first, each by a
    /// number of its own: a file read twice (sourced twice, or in two
    /// places) is read twice, and what one reading defines is not certainly
    /// there for the other, which zsh may have stopped at an error before
    /// the definition; the two pieces NixOS's `/etc/zshrc` is read in are
    /// one reading.
    pub(super) within: Vec<usize>,
    /// How many readings and how many pieces of code were followed so far,
    /// and the number of the piece being followed.
    pub(super) readings: usize,
    pub(super) pieces: usize,
    pub(super) piece: usize,
}

/// The functions the stock `promptinit` defines as it runs.
const PROMPTINIT_DEFINES: &[&str] = &[
    "prompt",
    "prompt_cleanup",
    "prompt_preview_safely",
    "prompt_preview_theme",
    "set_prompt",
];

/// How many of a file's commands a doubt names, past which it counts them.
const NAMED: usize = 3;

impl<F: Filesystem> Reader<'_, F> {
    /// Note the command the list does not hold that `event`, an
    /// [`Event::Unlisted`] of the file at `place`, gives, to judge once every
    /// file is read.
    pub(super) fn unlisted_at(&mut self, event: Event, place: &str) {
        let Event::Unlisted {
            function,
            shown,
            name,
            words,
            certain,
            chain,
            alias,
            why,
        } = event
        else {
            return;
        };
        let confused = self.listed.confused;
        let piece = self.listed.piece;
        let unlisted = Unlisted {
            function,
            shown,
            name,
            words,
            certain: certain && !confused,
            chain: chain.filter(|_| !confused).map(|chain| (piece, chain)),
            alias,
            why,
            order: self.order,
            place: place.to_string(),
            within: self.listed.within.clone(),
        };
        self.listed.unlisted.push(unlisted);
    }

    /// Note the definition of `name`, a function or a regular alias (with
    /// whether its value takes any words, `alias`), or the autoload of a
    /// function; `here` where it certainly runs where the code it stands in
    /// runs to it, at that code's top level, as the walk followed its
    /// structure.
    pub(super) fn defined_at(&mut self, name: &str, here: bool, alias: Option<bool>) {
        self.listed.defs.push(Def {
            name: name.to_string(),
            order: self.order,
            here,
            within: self.listed.within.clone(),
            alias,
            chain: None,
        });
    }

    /// Whether the code `unlisted`, a command that runs by the name `name`,
    /// stands in certainly defines or autoloads a function or an alias of that
    /// name before it ([the module](self)): an alias only where zsh may put
    /// one in place of the name.
    fn certainly_defined(&self, name: &str, unlisted: &Unlisted) -> bool {
        self.listed.defs.iter().any(|def| {
            def.name == name
                && (def.alias.is_none() || unlisted.alias)
                && def.order < unlisted.order
                && unlisted.within.starts_with(&def.within)
                && (def.here || (def.chain.is_some() && def.chain == unlisted.chain))
        })
    }

    /// Note a doubt for each command the list does not hold that zsh may run
    /// ([the module](self)), each file's in one doubt; and for arithmetic
    /// that names a parameter of the line editor (`(( HISTNO = 1 ))`).
    pub(super) fn unlisted(&mut self) {
        // The functions zsh runs as the startup files run: one a file runs by
        // name where no function does, and each such a function runs.
        let mut early: Vec<String> = Vec::new();
        for (name, _) in &self.top_calls {
            if !early.contains(name) {
                early.push(name.clone());
            }
        }
        let mut hooked = self.hooks.clone();
        loop {
            let before = (early.len(), hooked.len());
            for (caller, callee) in &self.edges {
                if early.contains(caller) && !early.contains(callee) {
                    early.push(callee.clone());
                }
                if Self::is_hook(caller, &hooked) && !Self::is_hook(callee, &hooked) {
                    hooked.push(callee.clone());
                }
            }
            if (early.len(), hooked.len()) == before {
                break;
            }
        }
        // What the stock promptinit defines and marks once it runs, for the
        // code after it where it certainly runs, and in its chain of commands
        // joined by `&&` alone.
        if self.promptinit {
            let marked: Vec<String> = PROMPTINIT_DEFINES
                .iter()
                .map(|name| (*name).to_string())
                .chain(
                    self.autoloaded_by
                        .iter()
                        .filter(|(by, _)| by == "promptinit" || by == "prompt")
                        .map(|(_, name)| name.clone()),
                )
                .chain(
                    self.autoloads
                        .iter()
                        .filter(|name| name.starts_with("prompt_") && name.ends_with("_setup"))
                        .cloned(),
                )
                .collect();
            let runs: Vec<Def> = self
                .listed
                .unlisted
                .iter()
                .filter(|unlisted| unlisted.name.as_deref() == Some("promptinit"))
                .flat_map(|unlisted| {
                    marked.iter().map(|name| Def {
                        name: name.clone(),
                        order: unlisted.order,
                        here: unlisted.certain,
                        within: unlisted.within.clone(),
                        alias: None,
                        chain: unlisted.chain,
                    })
                })
                .collect();
            self.listed.defs.extend(runs);
        }
        let mut found: Vec<(String, String)> = Vec::new();
        for unlisted in std::mem::take(&mut self.listed.unlisted) {
            let reached = match unlisted.function.as_deref() {
                None => true,
                Some(function) => {
                    early.iter().any(|known| known == function) || Self::is_hook(function, &hooked)
                }
            };
            if !reached {
                continue;
            }
            let why = match unlisted.name.as_deref() {
                None => Some(unlisted.why.clone()),
                Some(name) if !self.certainly_defined(name, &unlisted) => {
                    Some(outside_program(name))
                }
                Some(name)
                    if unlisted.words
                        && unlisted.alias
                        && self
                            .listed
                            .defs
                            .iter()
                            .any(|def| def.name == name && def.alias == Some(false)) =>
                {
                    Some(format!(
                        "`{name}` is an alias whose value hands the words it is used with to a \
                         command the check does not read with them"
                    ))
                }
                Some(_) => None,
            };
            if let Some(why) = why {
                let item = format!("`{}`, as {why}", unlisted.shown.trim());
                let entry = (unlisted.place, item);
                if !found.contains(&entry) {
                    found.push(entry);
                }
            }
        }
        // The arithmetic that names a parameter of the line editor, or
        // assigns one of zsh's own the list does not let be there
        // (`(( STTY = 0 ))`, `let FPATH=1`).
        for (expr, _, place) in &self.arith {
            let zle = super::arith::pieces(expr)
                .into_iter()
                .find_map(|piece| match piece {
                    super::arith::Piece::Name(name) if ZLE_PARAMETERS.contains(&name.as_str()) => {
                        Some(name)
                    }
                    _ => None,
                })
                .map(|name| {
                    format!(
                        "`{name}` is a parameter of the line editor, which a widget that sets it \
                         may make run another line than the one typed"
                    )
                });
            let own = super::arith::assigned(expr)
                .into_iter()
                .find_map(arithmetic_parameter);
            if let Some(why) = zle.or(own) {
                let entry = (place.clone(), format!("`(( {} ))`, as {why}", expr.trim()));
                if !found.contains(&entry) {
                    found.push(entry);
                }
            }
        }
        let mut places: Vec<String> = Vec::new();
        for (place, _) in &found {
            if !places.contains(place) {
                places.push(place.clone());
            }
        }
        for place in places {
            let items: Vec<&str> = found
                .iter()
                .filter(|(at, _)| *at == place)
                .map(|(_, item)| item.as_str())
                .collect();
            let more = items.len().saturating_sub(NAMED);
            let mut text = items[..items.len().min(NAMED)].join("; ");
            if more > 0 {
                text.push_str(&format!("; and {more} more"));
            }
            self.doubt(format!(
                "it cannot tell what {place} runs past the commands it knows to be harmless: \
                 {text}"
            ));
        }
    }
}
