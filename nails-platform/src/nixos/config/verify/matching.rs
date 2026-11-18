// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines of a `.nix` file matched against the markers.

use super::escapes::{Decoded, Escape};
use super::nix_text::{Context, Shell};
use super::scan::{Place, Scanner};
use super::{BaseConfigReference, Marker, Markers, ReferenceKind};
use nails_base::hidden_root::separation::counts_as_system_folder;
use std::ops::Range;
use std::path::Path;

/// A line as the markers are matched against it: lowercased, as the file
/// spells it or with the escapes of its strings decoded, and what it holds.
struct View {
    text: Vec<u8>,
    context: Context,
    /// For the decoded line, where its bytes come from.
    decoded: Option<Decoded>,
}

impl View {
    /// The range of the line as the file spells it that `range`, a range of
    /// this view, stands for.
    fn raw(&self, range: Range<usize>) -> Range<usize> {
        match &self.decoded {
            Some(decoded) => decoded.raw(&range),
            None => range,
        }
    }

    /// The text with the decoy's own places for the names let be blanked
    /// out ([`decoys_own_place`]).
    fn outside_own_places(&self, root: &Path) -> Vec<u8> {
        let mut text = self.text.clone();
        for place in &self.context.places {
            if decoys_own_place(place, root) {
                text[place.range.clone()].fill(b' ');
            }
        }
        text
    }
}

/// The first marker of `markers` that matches one of `lines` (a text and
/// the view it is of), with the range of the line it matched as the file
/// spells it.
fn first(markers: &[Marker], lines: &[(&[u8], &View)]) -> Option<(ReferenceKind, Range<usize>)> {
    markers.iter().find_map(|marker| {
        lines.iter().find_map(|(text, view)| {
            marker
                .pattern
                .find(text, &view.context)
                .map(|range| (marker.kind, view.raw(range)))
        })
    })
}

/// Each line of `content` that matches a marker that counts, for the first
/// one it matches, or a name let be outside the decoy's own places for it,
/// for the first such name, and each other line that matches one of the
/// names let be, for the first of those. Each line is matched as the file
/// spells it and, when its strings hold an escape, again as Nix reads them.
/// With a filesystem the flag accepted, a line with a string in a place of
/// the decoy's own that the scan cannot read whole counts as well
/// ([`unread_own_place`]).
pub(super) fn references_in(
    file: &Path,
    content: &str,
    markers: &Markers,
) -> (Vec<BaseConfigReference>, Vec<BaseConfigReference>) {
    let original = content.as_bytes();
    let text = original.to_ascii_lowercase();
    let mut scanner = Scanner::default();
    let mut shell = Shell::default();

    // Every line is read before any is matched: the `+` that joins a string
    // to something can stand on a later line.
    let mut lines: Vec<(Range<usize>, Context, Vec<Escape>)> = Vec::new();
    let mut start = 0;
    for line in text.split(|&byte| byte == b'\n') {
        let span = start..start + line.len();
        start = span.end + 1;
        // The scanner reads the line as the file spells it, so the attribute
        // names of the places keep their case.
        let names = scanner.line(&original[span.clone()]);
        let context = Context {
            names,
            arguments: shell.line(line),
            places: scanner.places(),
            joined: Vec::new(),
        };
        lines.push((span, context, scanner.escapes()));
    }
    for joined in scanner.joined() {
        lines[joined.line]
            .1
            .joined
            .push((joined.text.clone(), joined.continued));
    }

    let mut found = Vec::new();
    let mut let_be = Vec::new();
    for (index, (span, context, escapes)) in lines.into_iter().enumerate() {
        let raw = &original[span.clone()];
        let reference = |kind, range: Range<usize>| BaseConfigReference {
            file: file.to_path_buf(),
            line: index + 1,
            text: String::from_utf8_lossy(&raw[range]).into_owned(),
            kind,
        };
        let mut views = Vec::with_capacity(2);
        if !escapes.is_empty() {
            let decoded = Decoded::of(raw, &escapes);
            views.push(View {
                text: decoded.text.clone(),
                context: decoded.context(&context),
                decoded: Some(decoded),
            });
        }
        views.insert(
            0,
            View {
                text: text[span].to_vec(),
                context,
                decoded: None,
            },
        );
        let whole: Vec<(&[u8], &View)> = views.iter().map(|v| (&v.text[..], v)).collect();
        if let Some((kind, range)) = first(&markers.counted, &whole) {
            found.push(reference(kind, range));
        } else if let Some(range) = markers
            .allowing
            .then(|| unread_own_place(&views[0], raw, &markers.root))
            .flatten()
        {
            found.push(reference(ReferenceKind::RootPlace, range));
        } else if let Some((kind, range)) = first(&markers.let_be, &whole) {
            // The line with the decoy's own places blanked out: a name of
            // the filesystem's devices that it still holds stands elsewhere.
            let outside: Vec<Vec<u8>> = views
                .iter()
                .map(|view| view.outside_own_places(&markers.root))
                .collect();
            let elsewhere: Vec<(&[u8], &View)> = outside
                .iter()
                .zip(&views)
                .map(|(text, view)| (&text[..], view))
                .collect();
            match first(&markers.let_be, &elsewhere) {
                Some((kind, range)) => found.push(reference(kind, range)),
                None => let_be.push(reference(kind, range)),
            }
        }
    }
    (found, let_be)
}

/// A string in a place of the decoy's own ([`decoys_own_place`]) on the
/// line `raw` that the scan cannot read whole: it holds an interpolation
/// (`"${dev}"`), a `+` joins it to something before or after it
/// (`"/srv/@va" + "ult"`), or it goes on over the next line. The range to
/// show of it.
fn unread_own_place(view: &View, raw: &[u8], root: &Path) -> Option<Range<usize>> {
    let context = &view.context;
    context
        .places
        .iter()
        .find(|place| {
            !place.attribute
                && decoys_own_place(place, root)
                && (!place.whole
                    || raw[place.range.clone()].windows(2).any(|w| w == b"${")
                    || context.joined.iter().any(|(text, _)| *text == place.range))
        })
        .map(|place| {
            // An empty string shows with its quotes.
            let range = place.range.clone();
            if !range.is_empty() {
                return range;
            }
            let quotes = if raw[..range.start].ends_with(b"''") {
                2
            } else {
                1
            };
            range.start.saturating_sub(quotes)..(range.end + quotes).min(raw.len())
        })
}

/// Whether `place` is one where the decoy's configuration names the devices
/// of its own mounts, so a name of a device of the filesystem the root lies
/// on is let be there: a string that is the `device` or `label` of a
/// `fileSystems` entry for `/` or a system folder, other than the hidden
/// root at `root` and the folders inside it ([`counts_as_system_folder`]),
/// the name of a `boot.initrd.luks.devices` entry, or a string that is the
/// `device` of one. The attribute path is the one the file defines, wherever
/// it stands (inside a service's settings too), read with its case.
pub(super) fn decoys_own_place(place: &Place, root: &Path) -> bool {
    let path: Vec<&str> = place.path.iter().map(String::as_str).collect();
    if place.attribute {
        return matches!(path.as_slice(), [.., "initrd", "luks", "devices", _]);
    }
    match path.as_slice() {
        [.., "fileSystems", at, "device" | "label"] => counts_as_system_folder(Path::new(at), root),
        [.., "initrd", "luks", "devices", _, "device"] => true,
        _ => false,
    }
}
