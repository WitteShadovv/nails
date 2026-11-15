// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The widgets the files' functions run by their names ([`walk::Event::Edits`]),
//! judged once the files are read: one of zsh's own that may put other text
//! in the line than it holds (`up-history`, `yank`, `kill-word`) may change
//! the line zsh runs as a widget accepts it, so the function that runs it is
//! a doubt should a widget run it. One that leaves the text as it is
//! ([`walk::STRICT_WIDGETS`]), with a `.` before its name too, one that puts
//! no other text in it than typing does ([`walk::COMPLETING_WIDGETS`]) where
//! no file sets the line as written (`BUFFER=exi`, which a completion may
//! make `exit`), and one the files make (`zle -N name`), whose code the check
//! reads as a hook's, are none here; a widget the files make, and a `zle` that
//! runs one, are doubts of the list of the commands the check knows to be
//! harmless besides ([`super::known`]).

use super::{Reader, walk};
use crate::Filesystem;

impl<F: Filesystem> Reader<'_, F> {
    /// Note, as what the function holds that counts where a widget runs it,
    /// each widget a function runs that may change the line ([the
    /// module](self)).
    pub(super) fn edits(&mut self) {
        // A line a file sets as written is read as typed ([`walk::widgets`]).
        let written = self.hooks.iter().any(|hook| hook.starts_with("BUFFER="));
        for (function, widget, place) in std::mem::take(&mut self.edits) {
            let own = widget.strip_prefix('.').unwrap_or(&widget);
            let made = !widget.starts_with('.') && self.widgets.contains(&widget);
            if walk::STRICT_WIDGETS.contains(&own)
                || (!written && walk::COMPLETING_WIDGETS.contains(&own))
                || made
            {
                continue;
            }
            self.in_functions.push((
                function.clone(),
                Err(format!(
                    "it cannot tell what line `zle {widget}` in `{function}` in {place} leaves zsh \
                     to run, as that widget may put text from the history, the kill ring or the \
                     keys pressed in the line"
                )),
            ));
        }
    }
}
