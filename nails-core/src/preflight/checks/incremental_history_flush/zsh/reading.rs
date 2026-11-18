// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may make zsh read the files' code otherwise than the check reads it:
//! a `histchars` set, whose third character starts a comment in place of `#`
//! (none, when it has no third), so that a line the check leaves out as a
//! comment may run; `RC_QUOTES` and csh's quotes (`CSH_JUNKIE_QUOTES`, which
//! `emulate csh` turns on), which change what a quote holds and so the code
//! an `eval` or an alias's value runs; `IGNORE_BRACES` and
//! `IGNORE_CLOSE_BRACES` (`set -I`, `NO_BRACE_EXPAND`, `emulate sh`), with
//! which a `}` after a command's words is a word of it, so that a function's
//! body ends at a later `}` and holds the code after it; and `ALIAS_FUNC_DEF`
//! (`emulate sh` and `emulate ksh` too), with which zsh puts an alias's
//! value in place of the name of a function defined as `name ()`, which may
//! then be a hook's. An `emulate` of sh's, ksh's or csh's mode turns
//! `GLOB_SUBST` on, with which zsh expands a value as a pattern, so that a
//! glob qualifier in it runs code (`*(e:...:)`) where qualifiers are on,
//! which in sh's and ksh's mode takes `SH_GLOB` off and `BARE_GLOB_QUAL` or
//! `EXTENDED_GLOB` on: where a file runs such an `emulate` and one names
//! those options, that is a doubt. Each option counts where a file names it, in either
//! form and in any spelling zsh reads as its name (quotes and backslashes
//! taken off), or runs an `emulate` of a mode that turns it on
//! ([`super::option_words::emulates`]), as the three the check asks about do, and
//! where none does, zsh reads the code as the check does.

use super::Reader;
use super::backstop::Forms;
use super::walk::Event;
use crate::Filesystem;

/// What the files read may change of how zsh reads code, and what that
/// may then read otherwise ([`super::reading`]).
#[derive(Debug, Default)]
pub(super) struct Reading {
    /// Where a file read may turn `IGNORE_BRACES` or `IGNORE_CLOSE_BRACES`
    /// on, and each command whose words a `}` follows, as written, and
    /// where ([`Event::WordBrace`]).
    braces: Option<String>,
    word_braces: Vec<(String, String)>,
    /// Where a file read may turn `ALIAS_FUNC_DEF` on, each function defined
    /// as `name ()` and where ([`Event::NamedBody`]), and the regular aliases
    /// the files define.
    alias_func_def: Option<String>,
    named_bodies: Vec<(String, String)>,
    regular_aliases: Vec<String>,
    /// Where a file read may run an `emulate` of sh's, ksh's or csh's mode,
    /// which turns `GLOB_SUBST` on, and whether one may run csh's, whether a
    /// file names `SH_GLOB`, and whether one names `BARE_GLOB_QUAL` or
    /// `EXTENDED_GLOB`, which turn glob qualifiers on.
    glob_subst: Option<String>,
    csh: bool,
    sh_glob: bool,
    qualifiers: bool,
}

impl<F: Filesystem> Reader<'_, F> {
    /// Note what `text`, the code of the file at `place`, in its forms
    /// `forms`, may change of how zsh reads code ([`super::reading`]): a
    /// `histchars` it sets, and the `RC_QUOTES` and csh's quotes it names,
    /// are doubts at once; where it may turn `IGNORE_BRACES`,
    /// `IGNORE_CLOSE_BRACES` or `ALIAS_FUNC_DEF` on is noted for
    /// [`Reader::reading_doubts`].
    pub(super) fn reading(&mut self, forms: &Forms, place: &str) {
        if ["histchars", "HISTCHARS"]
            .iter()
            .any(|name| forms.writes(name) > 0)
        {
            self.doubt(format!(
                "it cannot tell which lines of the files zsh runs, as {place} sets histchars, \
                 whose third character starts a comment in place of `#`"
            ));
        }
        if forms.names_any(&["rcquotes", "cshjunkiequotes"]) || forms.emulates(&['c']) {
            self.doubt(format!(
                "it cannot read the quotes of the files as zsh may, as {place} may turn \
                 RC_QUOTES or CSH_JUNKIE_QUOTES on, which change what a quote holds"
            ));
        }
        if self.reading.braces.is_none()
            && (forms.names_any(&["ignorebraces", "ignoreclosebraces", "braceexpand"])
                || forms.sets_letter('I')
                || forms.emulates(&['s', 'b']))
        {
            self.reading.braces = Some(place.to_string());
        }
        if self.reading.alias_func_def.is_none()
            && (forms.names_any(&["aliasfuncdef"]) || forms.emulates(&['s', 'b', 'k']))
        {
            self.reading.alias_func_def = Some(place.to_string());
        }
        if self.reading.glob_subst.is_none() && forms.emulates(&['s', 'b', 'k', 'c']) {
            self.reading.glob_subst = Some(place.to_string());
        }
        self.reading.csh |= forms.emulates(&['c']);
        self.reading.sh_glob |= forms.names_any(&["shglob"]);
        self.reading.qualifiers |= forms.names_any(&["bareglobqual", "extendedglob"]);
    }

    /// Note an event of the file at `place` that zsh may read otherwise
    /// ([`Event::WordBrace`], [`Event::NamedBody`], [`Event::RegularAlias`]).
    pub(super) fn reading_event(&mut self, event: Event, place: &str) {
        let reading = &mut self.reading;
        match event {
            Event::WordBrace(command) => {
                let entry = (command, place.to_string());
                if !reading.word_braces.contains(&entry) {
                    reading.word_braces.push(entry);
                }
            }
            Event::NamedBody(name) => reading.named_bodies.push((name, place.to_string())),
            Event::RegularAlias(name) if !reading.regular_aliases.contains(&name) => {
                reading.regular_aliases.push(name);
            }
            _ => {}
        }
    }

    /// Note the doubts of what zsh may read otherwise, once every file is
    /// read: each `}` after a command's words where a file may turn
    /// `IGNORE_BRACES` or `IGNORE_CLOSE_BRACES` on, and each function defined
    /// as `name ()` where an alias of that name is defined and a file may turn
    /// `ALIAS_FUNC_DEF` on. Of zsh's own functions the check reads by their
    /// bytes only `add-zle-hook-widget` holds such a `}`, and zsh 5.9.2 then
    /// cannot load it (a parse error), so that it makes no hook.
    pub(super) fn reading_doubts(&mut self) {
        let reading = std::mem::take(&mut self.reading);
        if let Some(place) = &reading.glob_subst
            && reading.qualifiers
            && (reading.sh_glob || reading.csh)
        {
            self.doubt(format!(
                "it cannot tell what code zsh runs from the values it expands as patterns, as \
                 {place} may run an `emulate` of sh's, ksh's or csh's mode, which turns \
                 GLOB_SUBST on, and the files name the options that turn glob qualifiers on \
                 there (SH_GLOB, and BARE_GLOB_QUAL or EXTENDED_GLOB), with which a glob \
                 qualifier in a value runs"
            ));
        }
        if let Some(set) = &reading.braces {
            for (command, place) in &reading.word_braces {
                self.doubt(format!(
                    "it cannot tell where the code that `{command}` in {place} ends with its `}}` \
                     ends, as {set} may turn IGNORE_BRACES or IGNORE_CLOSE_BRACES on, with which \
                     that `}}` is a word of the command"
                ));
            }
        }
        if let Some(set) = &reading.alias_func_def {
            for (name, place) in &reading.named_bodies {
                if reading.regular_aliases.contains(name) {
                    self.doubt(format!(
                        "it cannot tell which function `{name} ()` in {place} defines, as {set} \
                         may turn ALIAS_FUNC_DEF on, with which zsh puts the value of the alias \
                         `{name}` in place of its name"
                    ));
                }
            }
        }
    }
}
