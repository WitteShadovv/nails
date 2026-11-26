// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines of a `.nix` file matched against the markers.

use super::escapes::{self, Decoded};
use super::nix_text::{Context, Shell};
use super::scan::{Reading, Scanner};
use super::{BaseConfigReference, Marker, ReferenceKind};
use std::ops::Range;
use std::path::Path;

/// A line as the markers are matched against it: lowercased, as the file
/// spells it or with the escapes of its strings decoded, and fstab's octal
/// escapes decoded on top of either, and what it holds.
struct View {
    text: Vec<u8>,
    context: Context,
    /// The decodings that made `text` from the line, in the order they were
    /// made, each with where its bytes come from.
    layers: Vec<Decoded>,
}

impl View {
    /// The range of the line as the file spells it that `range`, a range of
    /// this view, stands for.
    fn raw(&self, range: Range<usize>) -> Range<usize> {
        self.layers
            .iter()
            .rev()
            .fold(range, |range, layer| layer.raw(&range))
    }

    /// This view with fstab's octal escapes decoded ([`escapes::fstab`]), as
    /// libmount reads a `fileSystems` value that NixOS wrote into
    /// `/etc/fstab`; `None` when it holds none.
    fn fstab(&self) -> Option<View> {
        let found = escapes::fstab(&self.text);
        if found.is_empty() {
            return None;
        }
        let decoded = Decoded::of(&self.text, &found);
        let text = decoded.text.clone();
        let context = decoded.context(&self.context);
        let mut layers = self.layers.clone();
        layers.push(decoded);
        Some(View {
            text,
            context,
            layers,
        })
    }
}

/// The first marker of `markers` that matches one of `views`, with the
/// range of the line it matched as the file spells it.
fn first(markers: &[Marker], views: &[View]) -> Option<(ReferenceKind, Range<usize>)> {
    markers.iter().find_map(|marker| {
        views.iter().find_map(|view| {
            marker
                .pattern
                .find(&view.text, &view.context)
                .map(|range| (marker.kind, view.raw(range)))
        })
    })
}

/// Each line of `content` that matches a marker, for the first one it
/// matches. Each line is matched as the file spells it and, when its strings
/// hold an escape, again as Nix reads them, with what the scanner finds in
/// it read by quotes and brackets alone ([`Reading::Quotes`]); a line that
/// matches no marker that way is matched again with what it finds as Nix's
/// lexer reads the file ([`Reading::Nix`]). Only a line that matches no
/// marker in these views is matched again with fstab's octal escapes decoded
/// in each. So a line reports what it reported before the later views
/// counted, and a name that one reading of comments and tokens finds counts
/// whatever the other finds.
pub(super) fn references_in(
    file: &Path,
    content: &str,
    markers: &[Marker],
) -> Vec<BaseConfigReference> {
    let original = content.as_bytes();
    let text = original.to_ascii_lowercase();
    let mut scanners = [Reading::Quotes, Reading::Nix].map(Scanner::reading);
    let mut shell = Shell::default();

    let mut found = Vec::new();
    let mut start = 0;
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        let span = start..start + line.len();
        start = span.end + 1;
        let raw = &original[span];
        let arguments = shell.line(line);
        let readings: Vec<Vec<View>> = scanners
            .iter_mut()
            .map(|scanner| views(scanner, raw, line, arguments.clone()))
            .collect();
        let matched = readings
            .iter()
            .find_map(|views| first(markers, views))
            .or_else(|| {
                let fstab: Vec<View> = readings.iter().flatten().filter_map(View::fstab).collect();
                first(markers, &fstab)
            });
        if let Some((kind, range)) = matched {
            found.push(BaseConfigReference {
                file: file.to_path_buf(),
                line: index + 1,
                text: String::from_utf8_lossy(&raw[range]).into_owned(),
                kind,
            });
        }
    }
    found
}

/// The views of `raw`, a line as the file spells it, and `line`, the same
/// lowercased, with what `scanner` finds in it and the `arguments` of
/// `cryptsetup` commands: as the file spells it and, when its strings hold
/// an escape, as Nix reads them.
fn views(
    scanner: &mut Scanner,
    raw: &[u8],
    line: &[u8],
    arguments: Vec<Range<usize>>,
) -> Vec<View> {
    // The scanner reads the line as the file spells it: an escape such as
    // `\N` is no `\n`.
    let names = scanner.line(raw);
    let context = Context {
        names,
        arguments,
        defined: scanner.defined(),
    };
    let escapes = scanner.escapes();
    let mut views = vec![View {
        text: line.to_vec(),
        context,
        layers: Vec::new(),
    }];
    if !escapes.is_empty() {
        let decoded = Decoded::of(raw, &escapes);
        let context = decoded.context(&views[0].context);
        views.push(View {
            text: decoded.text.clone(),
            context,
            layers: vec![decoded],
        });
    }
    views
}
