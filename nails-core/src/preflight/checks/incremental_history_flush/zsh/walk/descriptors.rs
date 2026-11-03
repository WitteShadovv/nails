// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The descriptors a file's code keeps open, as the walk reads them: a
//! `sysopen` to write keeps one open on a file, which a hook may write each
//! command line to.

use super::super::lexer::Word;
use super::{Event, Walker};

impl Walker<'_> {
    /// The events of a `sysopen` of `args` (zsh/system): one that opens its
    /// file to write (`-w`, `-a`) keeps the descriptor open as `exec 3>>file`
    /// does, which a hook may write each command line to.
    pub(super) fn sysopen(&mut self, args: &[Word]) {
        let mut writes = false;
        let mut words = args.iter();
        let mut file = None;
        while let Some(word) = words.next() {
            match word.text.strip_prefix('-') {
                Some(flags) if !flags.is_empty() && !word.expands => {
                    writes |= flags.contains(['w', 'a']);
                    // `-u`, `-o` and `-m` take the word after them, unless
                    // the rest of theirs.
                    if let Some(at) = flags.find(['u', 'o', 'm'])
                        && at + 1 == flags.len()
                    {
                        words.next();
                    }
                }
                Some(_) => writes = true,
                None => file = Some(word),
            }
            if word.expands {
                writes = true;
            }
        }
        if let Some(file) = file.filter(|_| writes) {
            self.events.push(Event::Redirect {
                computed: file.expands || file.text.contains(['$', '`']),
                function: self.function(),
                target: file.text.clone(),
                kept: true,
            });
        }
    }
}
