// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The line a widget gives zsh to run, as the walk reads it. zsh runs what
//! the line editor holds as a widget accepts the line, so code that a widget
//! runs and that sets it (`BUFFER=exit` in a wrapper of `accept-line`, in
//! `zle-line-init` or in `zle-line-finish`), or that runs a widget of zsh's
//! own that puts other text in it (one that fetches a line from the history
//! or the kill ring, or edits the line), gives zsh a line to run, as a typed
//! line, which may end the shell: zsh 5.9 to 5.9.2 then write the lines typed
//! before it. A value given `BUFFER` as written is read as such a line
//! ([`Walker::hooked`]), but one zsh may expand history in; any other value
//! and any other way to set one of [`BUFFERS`] (`LBUFFER=exit`,
//! `BUFFER+=x`, `read BUFFER`) is a doubt, should a widget run the function
//! it is in ([`Event::HookDoubt`]), and so is such a widget run there
//! ([`Event::Edits`]): any but those that leave the text as it is
//! ([`STRICT_WIDGETS`]), those that put no other text in it than typing does
//! ([`COMPLETING_WIDGETS`]) where no file sets the line as written, and one
//! of the name of a widget the files make, whose code the check reads. A line
//! beyond those the walk read that sets one of [`BUFFERS`] is a doubt too
//! ([`beyond`]).

use super::super::backstop::Forms;
use super::super::lexer::{Word, blank};
use super::{Event, Walker};

/// The parameters that hold the line zsh's line editor edits: all of it,
/// and what stands before and after the cursor.
const BUFFERS: &[&str] = &["BUFFER", "LBUFFER", "RBUFFER"];

/// The widgets of zsh 5.9 to 5.9.2's own that leave the text of the line as
/// it is, run by their names or with a `.` before them: those that accept
/// it, redraw it, list completions, beep, drop the line, move the cursor or
/// switch how keys type.
pub(in super::super) const STRICT_WIDGETS: &[&str] = &[
    "accept-line",
    "accept-and-hold",
    "redisplay",
    "reset-prompt",
    "clear-screen",
    "beep",
    "send-break",
    "list-choices",
    "list-expand",
    "beginning-of-line",
    "end-of-line",
    "forward-char",
    "backward-char",
    "forward-word",
    "backward-word",
    "emacs-forward-word",
    "emacs-backward-word",
    "vi-beginning-of-line",
    "vi-end-of-line",
    "vi-first-non-blank",
    "vi-forward-char",
    "vi-backward-char",
    "vi-forward-word",
    "vi-backward-word",
    "vi-forward-blank-word",
    "vi-backward-blank-word",
    "vi-cmd-mode",
    "vi-insert",
    "vi-insert-bol",
    "vi-add-next",
    "vi-add-eol",
    "vi-replace",
    "overwrite-mode",
];

/// The widgets of zsh's own that put in the line only the keys typed, a
/// completion or an expansion of the word at the cursor, or the line with
/// its history expanded, as typing does: no other text than the line holds
/// or the keys give it, so that a line typed stays one typed. Of a line a
/// file sets as written (`BUFFER=exi`), they may make another
/// (`zle expand-or-complete` makes `exit` of it).
pub(in super::super) const COMPLETING_WIDGETS: &[&str] = &[
    "self-insert",
    "self-insert-unmeta",
    "magic-space",
    "expand-history",
    "complete-word",
    "expand-or-complete",
    "expand-or-complete-prefix",
    "expand-word",
    "menu-complete",
    "reverse-menu-complete",
    "menu-expand-or-complete",
    "menu-select",
];

/// Whether `text`, a line as typed, holds what zsh's history expansion may
/// put the text of another line in place of, with zsh's default
/// `histchars`: a `!` anywhere, or a `^` that starts a line (`^old^new`).
pub(super) fn expands_history(text: &str) -> bool {
    text.contains('!')
        || text
            .split('\n')
            .any(|line| line.trim_start_matches(blank).starts_with('^'))
}

/// The doubt for a line of the file at `place` that sets one of [`BUFFERS`]
/// beyond the `walked` the walk read, in `text`, its code, in any form zsh
/// may read its words in ([`Forms`]).
pub(super) fn beyond(text: &str, walked: usize, place: &str) -> Option<Event> {
    let forms = Forms::of(text);
    let named: usize = BUFFERS.iter().map(|name| forms.writes(name)).sum();
    (named > walked).then(|| {
        Event::Doubt(format!(
            "it cannot tell what line a line of {place} may give the line editor (BUFFER, \
             LBUFFER, RBUFFER), which zsh runs as a widget accepts it"
        ))
    })
}

impl Walker<'_> {
    /// Note what setting `target`, a parameter an assignment or a builtin
    /// sets (`BUFFER`, `LBUFFER[1]`, `BUFFER+`), as `shown` writes it, to
    /// `value` where an assignment gives one, does where it is one of
    /// [`BUFFERS`] ([the module](self)).
    pub(super) fn buffer(&mut self, target: &str, value: Option<&Word>, shown: &str) {
        let name = target.strip_suffix('+').unwrap_or(target);
        let name = name.split_once('[').map_or(name, |(name, _)| name);
        if !BUFFERS.contains(&name) {
            return;
        }
        self.buffers += 1;
        // Outside a function, no widget runs it: the line editor is idle as
        // the startup files run.
        let Some(function) = self.function() else {
            return;
        };
        match value {
            Some(value)
                if target == "BUFFER"
                    && !value.expands
                    && !value.bare
                    && !expands_history(&value.text) =>
            {
                self.events.push(Event::Typed {
                    text: value.text.clone(),
                    keys: false,
                });
                self.hooked(&value.text, false, format!("BUFFER={}", value.text));
            }
            _ => self.events.push(Event::HookDoubt {
                doubt: format!(
                    "it cannot tell what line `{shown}` in `{function}` in {} makes zsh run, \
                     should a widget run it",
                    self.place
                ),
                function,
            }),
        }
    }

    /// Note a widget `widget` that a `zle` runs by its name in the code
    /// being walked, which may change the line zsh runs as the widget that
    /// runs it accepts the line ([`Event::Edits`]).
    pub(super) fn runs_widget(&mut self, widget: &Word) {
        if let Some(function) = self.function() {
            self.events.push(Event::Edits {
                function,
                widget: widget.text.clone(),
            });
        }
    }
}
