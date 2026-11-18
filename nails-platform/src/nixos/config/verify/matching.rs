// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines of a `.nix` file matched against the markers.

use super::escapes::Decoded;
use super::nix_text::{Context, Shell};
use super::scan::{Place, Scanner, Unplain};
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
/// With a filesystem the flag accepted, a line with a part that is no plain
/// literal in an entry of the decoy's own counts as well
/// ([`unplain_in_own_entry`]).
pub(super) fn references_in(
    file: &Path,
    content: &str,
    markers: &Markers,
) -> (Vec<BaseConfigReference>, Vec<BaseConfigReference>) {
    let original = content.as_bytes();
    let text = original.to_ascii_lowercase();
    let mut scanner = Scanner::default();
    let mut shell = Shell::default();

    let mut lines = Vec::new();
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
        };
        lines.push((span, context, scanner.escapes(), scanner.unplain()));
    }

    let mut found = Vec::new();
    let mut let_be = Vec::new();
    for (index, (span, context, escapes, unplain)) in lines.into_iter().enumerate() {
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
            .then(|| unplain_in_own_entry(&unplain, &markers.root))
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

/// The first part of `unplain`, the parts of a line that are no plain
/// literal ([`Unplain`]), that stands in an entry of the decoy's own
/// ([`own_entry`]): the scan cannot tell what Nix makes of that entry, so
/// the names it lets be there could stand for something else.
fn unplain_in_own_entry(unplain: &[Unplain], root: &Path) -> Option<Range<usize>> {
    unplain
        .iter()
        .find(|part| own_entry(&part.path, root))
        .map(|part| part.range.clone())
}

/// Whether `path` is in an entry where the decoy's own places stand
/// ([`decoys_own_place`]): in a `fileSystems` entry for `/` or a system
/// folder other than the hidden root at `root` and the folders inside it, or
/// in a `boot.initrd.luks.devices` entry, or is the set of such entries
/// itself (`fileSystems`, `boot.initrd.luks.devices`), whose value could
/// change them. Like the places, the path counts wherever it stands.
fn own_entry(path: &[String], root: &Path) -> bool {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    let set = matches!(
        path.as_slice(),
        [.., "fileSystems"] | [.., "initrd", "luks", "devices"]
    );
    set || (1..=path.len()).any(|end| match &path[..end] {
        [.., "fileSystems", at] => counts_as_system_folder(Path::new(at), root),
        [.., "initrd", "luks", "devices", _] => true,
        _ => false,
    })
}

/// Whether `place` is one where the decoy's configuration names the devices
/// of its own mounts, so a name of a device of the filesystem the root lies
/// on is let be there: a string that is the `device` or `label` of a
/// `fileSystems` entry for `/` or a system folder, other than the hidden
/// root at `root` and the folders inside it ([`counts_as_system_folder`]),
/// the name of a `boot.initrd.luks.devices` entry, or a string that is the
/// `device` of one. The attribute path is the one the file defines, wherever
/// it stands (inside a service's settings too), read with its case, and only
/// a definition in code outside a `let` block counts ([`Place::option`]):
/// not a comment and not a binding.
pub(super) fn decoys_own_place(place: &Place, root: &Path) -> bool {
    if !place.option {
        return false;
    }
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
