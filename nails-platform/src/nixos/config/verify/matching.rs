// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines of a `.nix` file matched against the markers.

use super::escapes::Decoded;
use super::nix_text::{Context, Shell};
use super::scan::Scanner;
use super::{BaseConfigReference, Marker, ReferenceKind};
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
/// hold an escape, again as Nix reads them.
pub(super) fn references_in(
    file: &Path,
    content: &str,
    markers: &[Marker],
) -> Vec<BaseConfigReference> {
    let original = content.as_bytes();
    let text = original.to_ascii_lowercase();
    let mut scanner = Scanner::default();
    let mut shell = Shell::default();

    let mut found = Vec::new();
    let mut start = 0;
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        let span = start..start + line.len();
        start = span.end + 1;
        let raw = &original[span];
        // The scanner reads the line as the file spells it: an escape such
        // as `\N` is no `\n`.
        let names = scanner.line(raw);
        let context = Context {
            names,
            arguments: shell.line(line),
            defined: scanner.defined(),
        };
        let escapes = scanner.escapes();
        let mut views = vec![View {
            text: line.to_vec(),
            context,
            decoded: None,
        }];
        if !escapes.is_empty() {
            let decoded = Decoded::of(raw, &escapes);
            let context = decoded.context(&views[0].context);
            views.push(View {
                text: decoded.text.clone(),
                context,
                decoded: Some(decoded),
            });
        }
        if let Some((kind, range)) = first(markers, &views) {
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
