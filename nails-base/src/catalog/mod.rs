// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The message catalogue: every user-facing string in one place.
//!
//! One catalogue serves the CLI, the window and the docs. Each entry is a
//! [`Message`] with a stable catalogue [`id`](Message::id), the English
//! [`text`](Message::text), a [`note`](Message::note) for translators, the
//! named [`placeholders`](Message::placeholders) the text carries, and the
//! [`surface`](Message::surface) it is shown on. The surface decides which
//! words are refused there: the copy lint (`nails-base/tests/copy_lint.rs`),
//! driven by the rules file `copy-lint.toml`, forbids a different set on a
//! screen the person opened than on a surface someone else may see.
//!
//! Translations come later; the IDs, notes and named placeholders are in place
//! from the first day, so a string is never assembled from fragments and never
//! split across entries. A front end renders a message with [`Message::render`],
//! which substitutes the placeholders, so the CLI and the window show the same
//! words for the same situation.
//!
//! Strings move in over the CLI work: this first set is the stable guidance
//! prose; the per-command messages and the help follow as each surface is
//! reworked. Once a string is here, the copy lint keeps it here.

mod entries;

pub use entries::*;

/// Where a message is shown. The copy lint refuses a different set of words on
/// each surface (see `copy-lint.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The CLI's own human output: a screen the person opened. The vocabulary
    /// is plain; no internal word, no storage name.
    Cli,
    /// A `--json` envelope field a person reads (`message`, `fix`). Same
    /// vocabulary as [`Cli`](Surface::Cli).
    Json,
    /// `--help` and the man-page body a person reads. Same vocabulary as
    /// [`Cli`](Surface::Cli).
    Help,
    /// A desktop alert. A neutral surface others may see, so it names nothing
    /// about the tool or the storage.
    Alert,
    /// A unit, app, menu, process or inhibitor name, or a window title. A
    /// neutral surface, held to the same neutral words as an alert.
    Neutral,
    /// The reference: man-page syntax lines and the glossary, where an internal
    /// word or a storage name is defined for the reader. Those words are
    /// allowed here and nowhere else on screen.
    Reference,
}

impl Surface {
    /// The lint token for this surface, as `copy-lint.toml`'s `forbid-on` lists
    /// it.
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Cli => "cli",
            Surface::Json => "json",
            Surface::Help => "help",
            Surface::Alert => "alert",
            Surface::Neutral => "neutral",
            Surface::Reference => "reference",
        }
    }
}

/// One catalogue entry.
///
/// Every field is `'static`: the catalogue is data baked into the binary, so no
/// file is read at run time and a missing entry cannot happen after a build.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// The stable catalogue ID, lowercase dotted-kebab (`rehearse.guide.done`).
    /// It never changes once shipped, so a translation keeps pointing at it.
    pub id: &'static str,
    /// The English source text, with placeholders written `{name}`.
    pub text: &'static str,
    /// A note for whoever translates the text: the context and what each
    /// placeholder stands for. Never shown to the person.
    pub note: &'static str,
    /// The placeholder names the text carries, each also written `{name}` in
    /// [`text`](Message::text). The lint pairs the two: every name used is
    /// declared and every name declared is used.
    pub placeholders: &'static [&'static str],
    /// Where the message is shown, which decides the words refused there.
    pub surface: Surface,
}

impl Message {
    /// Render the message, replacing each `{name}` with the value paired to it.
    ///
    /// A debug build asserts that the supplied names are exactly the declared
    /// placeholders, so a caller that forgets one or passes an unknown name is
    /// caught in the tests rather than shipping a stray `{name}`.
    pub fn render(&self, args: &[(&str, &str)]) -> String {
        debug_assert!(
            self.placeholders
                .iter()
                .all(|ph| args.iter().any(|&(name, _)| name == *ph)),
            "catalogue message {:?}: a declared placeholder was not supplied",
            self.id
        );
        debug_assert!(
            args.iter()
                .all(|&(name, _)| self.placeholders.contains(&name)),
            "catalogue message {:?}: an unknown placeholder was supplied",
            self.id
        );
        let mut out = self.text.to_string();
        for (name, value) in args {
            out = out.replace(&format!("{{{name}}}"), value);
        }
        out
    }
}

/// The message with this ID, if the catalogue has it.
pub fn find(id: &str) -> Option<&'static Message> {
    CATALOG.iter().find(|message| message.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_named_placeholders() {
        let rendered =
            REHEARSE_GUIDE_SCAN_NOW.render(&[("command", "sudo /mnt/data/nails rehearse scan")]);
        assert_eq!(
            rendered,
            "Step 3 of 3: run `sudo /mnt/data/nails rehearse scan`."
        );
        assert!(!rendered.contains('{'), "no placeholder left: {rendered}");
    }

    #[test]
    fn find_resolves_a_known_id_and_rejects_an_unknown_one() {
        assert_eq!(
            find("rehearse.guide.done").map(|m| m.id),
            Some("rehearse.guide.done")
        );
        assert!(find("no.such.message").is_none());
    }

    #[test]
    fn every_id_is_unique() {
        let mut ids: Vec<&str> = CATALOG.iter().map(|m| m.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(count, ids.len(), "a catalogue ID is not unique");
    }
}
