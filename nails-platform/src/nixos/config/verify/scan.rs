// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The attribute paths a `.nix` file defines, line by line.
//!
//! A mapping name or a filesystem label is often an ordinary word (`data`),
//! so the reference check counts one only where the file defines it as one
//! ([`Named`]). [`Scanner`] reads the file a line at a time and follows what
//! Nix makes of it: attribute sets and the paths they define, lists, `let`
//! blocks, `with` clauses, strings and interpolations. A bracket inside a
//! string does not count, so a shell prompt or a script in a string does not
//! throw it off.
//!
//! Comments count too: a block commented out line by line names an entry as
//! plainly as a live one. A comment is read as code, on a copy of the brackets
//! open around it, so it never changes how the code after it is read.
//! Consecutive comment lines share the copy, so a commented-out block that
//! spans lines is followed. A bracket a comment line opened is closed again at
//! the next comment line indented no deeper, and a string in a comment ends
//! with its line: prose such as `# keep [ for later` or `# a 5" disk` does not
//! hide a block commented out below it. A comment line that starts by closing
//! a bracket closes that one itself, and two exceptions keep a block that a
//! tool commented out whole: a comment line with no text (`#` alone, as
//! editors comment out a blank line) closes nothing, and a block a
//! definition's value opened (`x = {`, `x = [`) stays open over the lines
//! indented exactly as deep as the line that opened it, as in a block whose
//! lines keep no indentation of their own. A block whose lines are indented
//! less than its first is not followed. Parentheses are not followed.
//!
//! In code, the scanner also notes each part of a value that is no plain
//! literal ([`Unplain`]), so the check can tell an entry Nix may read
//! otherwise than its text from one written out in full.

use super::escapes::{self, Escape};
use std::ops::Range;

/// A range of a line that the file defines something at: an attribute name
/// being defined, or the text of a string in the value of a definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Place {
    /// The range, without quotes.
    pub(super) range: Range<usize>,
    /// For an attribute name, the attribute path it ends
    /// (`boot.initrd.luks.devices."root"` for `"root"`); for a string, the
    /// path of the definition whose value holds it
    /// (`fileSystems."/".device`), as the file spells it.
    pub(super) path: Vec<String>,
    /// An attribute name, not a string.
    pub(super) attribute: bool,
    /// Defined in code, outside a `let` block: a definition of the
    /// configuration, not a comment or a binding.
    pub(super) option: bool,
}

/// A part of a value, read in code, that is no plain literal, and the path
/// it stands in: the definition whose value holds it, or the set or list
/// whose attributes or elements it stands among. Plain are a `"…"` string
/// that ends on its line and holds no interpolation (its escapes are
/// plain), the brackets of a set or a list, the `;` that ends a
/// definition, the attribute names being defined and, as the whole value
/// of a definition other than a `device` or a `label`, `true`, `false` or
/// a number. Everything else is noted: a name that refers to something, a
/// function call, an operator, a parenthesis, an interpolation, a path, a
/// `''…''` string, a string that goes on over the next line, a keyword
/// (`let`, `if`, `with`, `inherit`, `rec`). Only the parts in a path below a
/// `fileSystems` or `luks.devices` attribute are noted, outside a `let`
/// block ([`Scanner::unplain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Unplain {
    /// The range of the line.
    pub(super) range: Range<usize>,
    /// The path, as the file spells it.
    pub(super) path: Vec<String>,
}

/// What a range of a line names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Named {
    /// A device-mapper mapping: the name of a `luks.devices` or
    /// `clevis.devices` entry, or the value of an option that names one
    /// (`encrypted.label`, a `luks.devices` entry's `name`, `name` in the
    /// list form of `luks.devices`).
    Mapping,
    /// A filesystem label: the value of a `fileSystems` or `swapDevices`
    /// entry's `label`.
    Label,
}

/// An attribute set, or a `let` block.
#[derive(Debug, Clone, Default)]
struct Attrs {
    /// The path its attributes are defined below.
    path: Vec<String>,
    /// The full path of the definition whose value is being read, from its
    /// `=` to its `;`: a `{` or `[` in that value opens a block of it.
    value: Option<Vec<String>>,
    /// The indentation of the line that set `value`.
    value_indent: usize,
    /// `with …;` clauses read in that value: their `;` does not end it.
    withs: usize,
    /// That value is a list itself (`= [`), not a call such as
    /// `lib.mkMerge [`: its attribute sets are elements, not attributes.
    list_value: bool,
    /// An element of such a list, as in the old list form of `luks.devices`.
    in_list: bool,
    /// A `let` block, which `in` ends.
    binding: bool,
}

/// One open bracket or string.
#[derive(Debug, Clone)]
enum Frame {
    Attrs(Attrs),
    /// A list in the value of a path. In `lib.mkMerge [ { … } { … } ]`
    /// each attribute set in it is a value of that path too; when the list
    /// is the value itself (`elements`), each is an element.
    List {
        path: Vec<String>,
        elements: bool,
    },
    /// An interpolation, `${ … }`.
    Interpolation,
    /// A string: `''…''` when `indented`, else `"…"`. `opened`, for a
    /// string the line being read opened: where its text starts, the path
    /// of the definition whose value holds it, and whether that is a
    /// definition of the configuration ([`Place::option`]).
    Str {
        indented: bool,
        opened: Option<(usize, Vec<String>, bool)>,
    },
}

impl Frame {
    /// A block a definition's value opened (`x = {`, `x = [`, or a set in
    /// such a list), as opposed to a bracket in prose.
    fn is_value(&self) -> bool {
        match self {
            Frame::Attrs(attrs) => !attrs.path.is_empty(),
            Frame::List { path, .. } => !path.is_empty(),
            Frame::Interpolation | Frame::Str { .. } => false,
        }
    }
}

/// The open frames, the file's top level first, each with the indentation of
/// the line that opened it.
#[derive(Debug, Clone)]
struct Stack(Vec<(Frame, usize)>);

impl Default for Stack {
    fn default() -> Self {
        Self(vec![(Frame::Attrs(Attrs::default()), 0)])
    }
}

/// The copy of the code's frames that comments read.
#[derive(Debug, Clone)]
struct Comment {
    stack: Stack,
    /// How many frames were copied from the code.
    base: usize,
    /// Made for a comment after code on its line: it ends with the line.
    trailing: bool,
}

/// Reads a file line by line; see the module docs.
#[derive(Debug, Default)]
pub(super) struct Scanner {
    code: Stack,
    comment: Option<Comment>,
    /// Inside a `/* … */` comment.
    in_block_comment: bool,
    /// The places of the line read last ([`Scanner::places`]).
    places: Vec<Place>,
    /// The escapes in the strings of the line read last
    /// ([`Scanner::escapes`]).
    escapes: Vec<Escape>,
    /// The parts of the line read last that are no plain literal
    /// ([`Scanner::unplain`]).
    unplain: Vec<Unplain>,
}

impl Scanner {
    /// The places of the line [`Scanner::line`] read last: each attribute
    /// name it defines and each string it holds whole in the value of a
    /// definition ([`Place`]).
    pub(super) fn places(&mut self) -> Vec<Place> {
        std::mem::take(&mut self.places)
    }

    /// The escapes in the strings of the line [`Scanner::line`] read last,
    /// in the order of the line ([`escapes`]). The text of a quoted
    /// attribute name is a string too.
    pub(super) fn escapes(&mut self) -> Vec<Escape> {
        std::mem::take(&mut self.escapes)
    }

    /// The parts of the line [`Scanner::line`] read last that are no plain
    /// literal ([`Unplain`]), in code, where the path they stand in is below
    /// a `fileSystems` attribute or a `luks.devices` attribute (or is one):
    /// one for each run of such parts in the same path.
    pub(super) fn unplain(&mut self) -> Vec<Unplain> {
        std::mem::take(&mut self.unplain)
    }

    /// Note `range`, a part of the code that is no plain literal, in the
    /// path the code's frames stand in, unless that is in a `let` block.
    fn note(&mut self, range: Range<usize>) {
        let path = context(&self.code.0);
        if below_entries(path)
            && !self.code.bound()
            && self.unplain.last().is_none_or(|last| last.path != path)
        {
            self.unplain.push(Unplain {
                range,
                path: path.to_vec(),
            });
        }
    }

    /// The ranges of `line` that name something ([`Named`]). `line` is read
    /// as the file spells it: a keyword and an attribute name that leads to
    /// a mapping are compared with any case, and [`Scanner::places`] keeps
    /// the spelling.
    pub(super) fn line(&mut self, line: &[u8]) -> Vec<(Range<usize>, Named)> {
        let mut names = Vec::new();
        let mut places = Vec::new();
        let mut escaped = Vec::new();
        self.unplain.clear();
        let in_string = matches!(self.code.top(), Some(Frame::Str { .. }));
        let first = skip_blanks(line, 0);
        let indent = comment_text(line, first);
        if self.in_block_comment
            || (!in_string && (line[first..].starts_with(b"#") || line[first..].starts_with(b"/*")))
        {
            let comment = self.comment.get_or_insert_with(|| Comment {
                stack: self.code.clone(),
                base: self.code.0.len(),
                trailing: false,
            });
            comment.trailing = false;
            if line.get(indent).is_some_and(|b| !matches!(b, b'}' | b']')) {
                comment.recover(indent);
            }
        }
        let mut in_comment = self.in_block_comment;
        let mut attribute = self.stack(in_comment).expects_attribute();
        let mut i = 0;
        while i < line.len() {
            if let Some(Frame::Str { indented, .. }) = self.stack(in_comment).top() {
                let indented = *indented;
                if !in_comment && line[i..].starts_with(b"${") {
                    self.note(i..i + 2);
                }
                let (next, closed) = self.stack(in_comment).string(line, i, indented);
                let raw = i..next.min(line.len());
                if let Some(text) = escapes::decode(&line[raw.clone()], indented) {
                    escaped.push(Escape { raw, text });
                }
                places.extend(closed);
                i = next;
                continue;
            }
            if !in_comment && (line[i] == b'#' || line[i..].starts_with(b"/*")) {
                let block = line[i] == b'/';
                self.in_block_comment = block;
                if self.comment.is_none() {
                    self.comment = Some(Comment {
                        stack: self.code.clone(),
                        base: self.code.0.len(),
                        trailing: true,
                    });
                }
                in_comment = true;
                if i <= first {
                    attribute = self.stack(true).expects_attribute();
                }
                i += if block { 2 } else { 1 };
                continue;
            }
            if in_comment && self.in_block_comment && line[i..].starts_with(b"*/") {
                self.in_block_comment = false;
                in_comment = false;
                attribute = self.code.expects_attribute();
                i += 2;
                continue;
            }
            if !in_comment && !is_blank(line[i]) {
                self.comment = None;
            }
            if attribute {
                if is_blank(line[i]) || (in_comment && matches!(line[i], b'#' | b'*')) {
                    i += 1;
                    continue;
                }
                attribute = false;
                let defined = places.len();
                let stack = self.stack(in_comment);
                let option = !in_comment && !stack.bound();
                if let Some((next, inherits)) =
                    stack.definition(line, i, (indent, option), &mut names, &mut places)
                {
                    for place in &places[defined..] {
                        if place.range.start > 0 && line[place.range.start - 1] == b'"' {
                            escaped.extend(quoted_escapes(line, place.range.clone()));
                        }
                    }
                    if inherits && !in_comment {
                        self.note(i..i + b"inherit".len());
                    }
                    i = next;
                    continue;
                }
            }
            if is_token_start(line, i) {
                let end = token_end(line, i);
                if !in_comment && !self.code.plain_word(&line[i..end]) {
                    self.note(i..end);
                }
                attribute = self.stack(in_comment).keyword(&line[i..end], indent);
                i = end;
                continue;
            }
            let step = if line[i..].starts_with(b"${") || line[i..].starts_with(b"''") {
                2
            } else {
                1
            };
            if !in_comment && (step == 2 || !b"{}[];\" \t\r".contains(&line[i])) {
                self.note(i..i + step);
            }
            attribute = self
                .stack(in_comment)
                .punctuation(line, i, indent, !in_comment);
            i += step;
        }
        let ends = self
            .comment
            .as_ref()
            .is_some_and(|comment| comment.trailing && !self.in_block_comment);
        if ends {
            self.comment = None;
        } else if let Some(comment) = &mut self.comment {
            comment.stack.end_strings(comment.base);
        }
        // A string the next line goes on with is no plain literal, noted on
        // the line that opened it, and a place on that line up to its end.
        for (at, (frame, _)) in self.code.0.iter().enumerate() {
            if let Frame::Str {
                opened: Some((start, ..)),
                ..
            } = frame
            {
                let path = context(&self.code.0[..at]);
                if below_entries(path) && !self.code.bound() {
                    self.unplain.push(Unplain {
                        range: *start..line.len(),
                        path: path.to_vec(),
                    });
                }
            }
        }
        places.extend(self.code.forget_openings(line.len()));
        if let Some(comment) = &mut self.comment {
            places.extend(comment.stack.forget_openings(line.len()));
        }
        escaped.sort_by_key(|escape| escape.raw.start);
        self.places = places;
        self.escapes = escaped;
        names
    }

    /// The frames that code, or a comment (`in_comment`), reads.
    fn stack(&mut self, in_comment: bool) -> &mut Stack {
        match &mut self.comment {
            Some(comment) if in_comment => &mut comment.stack,
            _ => &mut self.code,
        }
    }
}

impl Comment {
    /// Close what earlier comment lines opened at `indent` or deeper, except
    /// a block a definition's value opened at `indent` itself, and end a
    /// definition such a line left without its `;`.
    fn recover(&mut self, indent: usize) {
        while self.stack.0.len() > self.base
            && self
                .stack
                .0
                .last()
                .is_some_and(|(frame, at)| *at > indent || (*at == indent && !frame.is_value()))
        {
            self.stack.0.pop();
        }
        if let Some(attrs) = self.stack.attrs_mut()
            && attrs.value.is_some()
            && attrs.value_indent >= indent
        {
            attrs.value = None;
            attrs.withs = 0;
        }
    }
}

impl Stack {
    fn top(&self) -> Option<&Frame> {
        self.0.last().map(|(frame, _)| frame)
    }

    fn attrs_mut(&mut self) -> Option<&mut Attrs> {
        match self.0.last_mut() {
            Some((Frame::Attrs(attrs), _)) => Some(attrs),
            _ => None,
        }
    }

    /// Whether a `let` block is open: what is defined now is a binding.
    fn bound(&self) -> bool {
        self.0
            .iter()
            .any(|(frame, _)| matches!(frame, Frame::Attrs(Attrs { binding: true, .. })))
    }

    /// Whether the token `word`, read in code here, is a plain literal
    /// ([`Unplain`]): `true`, `false` or a number as the whole value of a
    /// definition other than a `device` or a `label`.
    fn plain_word(&self, word: &[u8]) -> bool {
        let literal = word == b"true" || word == b"false" || word.iter().all(u8::is_ascii_digit);
        literal
            && matches!(
                self.top(),
                Some(Frame::Attrs(Attrs { value: Some(path), .. }))
                    if !path.last().is_some_and(|last| last == "device" || last == "label")
            )
    }

    /// Whether the innermost frame waits for an attribute.
    fn expects_attribute(&self) -> bool {
        matches!(self.top(), Some(Frame::Attrs(Attrs { value: None, .. })))
    }

    /// The path a block opened here defines below: the definition whose
    /// value is being read, or the list's path; none elsewhere.
    fn block_path(&self) -> Vec<String> {
        match self.top() {
            Some(Frame::Attrs(Attrs {
                value: Some(path), ..
            }))
            | Some(Frame::List { path, .. }) => path.clone(),
            _ => Vec::new(),
        }
    }

    /// One step inside the string that holds `i`: past an escape, into an
    /// interpolation, or out of the string. Returns where to go on, and the
    /// place of a string that ends here, where this line opened it.
    fn string(&mut self, line: &[u8], i: usize, indented: bool) -> (usize, Option<Place>) {
        let rest = &line[i..];
        if rest.starts_with(b"$$") {
            return (i + 2, None);
        }
        if rest.starts_with(b"${") {
            self.0.push((Frame::Interpolation, usize::MAX));
            return (i + 2, None);
        }
        if indented {
            if rest.starts_with(b"'''") || rest.starts_with(b"''$") {
                return (i + 3, None);
            }
            if rest.starts_with(b"''\\") {
                return (i + 4, None);
            }
            if rest.starts_with(b"''") {
                return (i + 2, self.close_string(i));
            }
        } else if rest[0] == b'\\' {
            return (i + 2, None);
        } else if rest[0] == b'"' {
            return (i + 1, self.close_string(i));
        }
        (i + 1, None)
    }

    /// Close the string on top, which ends at `end`: its place, where this
    /// line opened it.
    fn close_string(&mut self, end: usize) -> Option<Place> {
        let (Frame::Str { opened, .. }, _) = self.0.pop()? else {
            return None;
        };
        opened.map(|(start, path, option)| Place {
            range: start..end,
            path,
            attribute: false,
            option,
        })
    }

    /// Forget where the open strings started, at the end of a line that is
    /// `end` long: the next line goes on with them. Returns the place of
    /// each one this line opened, up to the end of the line.
    fn forget_openings(&mut self, end: usize) -> Vec<Place> {
        let mut places = Vec::new();
        for (frame, _) in &mut self.0 {
            if let Frame::Str { opened, .. } = frame
                && let Some((start, path, option)) = opened.take()
            {
                places.push(Place {
                    range: start..end,
                    path,
                    attribute: false,
                    option,
                });
            }
        }
        places
    }

    /// The byte at `i` outside a string and a token, read in code when
    /// `code`: a bracket, a string's opening, a `;` or anything else.
    /// Returns whether an attribute may start after it.
    fn punctuation(&mut self, line: &[u8], i: usize, indent: usize, code: bool) -> bool {
        let rest = &line[i..];
        if rest.starts_with(b"${") {
            self.0.push((Frame::Interpolation, indent));
            return false;
        }
        let option = code && !self.bound();
        if rest.starts_with(b"''") {
            let opened = Some((i + 2, self.block_path(), option));
            let indented = true;
            self.0.push((Frame::Str { indented, opened }, indent));
            return false;
        }
        match rest[0] {
            b'"' => {
                let opened = Some((i + 1, self.block_path(), option));
                let indented = false;
                self.0.push((Frame::Str { indented, opened }, indent));
            }
            b'{' => {
                let attrs = Attrs {
                    path: self.block_path(),
                    in_list: matches!(self.top(), Some(Frame::List { elements: true, .. })),
                    ..Attrs::default()
                };
                self.0.push((Frame::Attrs(attrs), indent));
                return true;
            }
            b'[' => {
                let path = self.block_path();
                let elements = matches!(
                    self.top(),
                    Some(Frame::Attrs(Attrs {
                        list_value: true,
                        value: Some(_),
                        ..
                    }))
                );
                self.0.push((Frame::List { path, elements }, indent));
            }
            b']' => self.close(|frame| matches!(frame, Frame::List { .. })),
            b'}' => self.close(|frame| matches!(frame, Frame::Attrs(_) | Frame::Interpolation)),
            b';' => {
                if let Some(attrs) = self.attrs_mut() {
                    if attrs.withs > 0 {
                        attrs.withs -= 1;
                    } else {
                        attrs.value = None;
                    }
                }
                return self.expects_attribute();
            }
            _ => {}
        }
        false
    }

    /// Close the innermost frame `closes` takes, and every frame above it.
    /// Nothing closes when a string, an interpolation or the top level comes
    /// first.
    fn close(&mut self, closes: impl Fn(&Frame) -> bool) {
        for at in (1..self.0.len()).rev() {
            let frame = &self.0[at].0;
            if closes(frame) {
                self.0.truncate(at);
                return;
            }
            if matches!(frame, Frame::Str { .. } | Frame::Interpolation) {
                return;
            }
        }
    }

    /// The token `word`, which may be a keyword: `let` opens a block of
    /// bindings, which `in` closes, and `with` makes the next `;` part of the
    /// value being read. Returns whether a binding may start after it. A
    /// keyword is read in any case (`LET`, `With`), as in a comment that
    /// writes one so.
    fn keyword(&mut self, word: &[u8], indent: usize) -> bool {
        match word.to_ascii_lowercase().as_slice() {
            b"let" => {
                let attrs = Attrs {
                    binding: true,
                    ..Attrs::default()
                };
                self.0.push((Frame::Attrs(attrs), indent));
                true
            }
            b"in" => {
                if let Some(Frame::Attrs(Attrs { binding: true, .. })) = self.top() {
                    self.0.pop();
                }
                false
            }
            b"with" => {
                if let Some(attrs) = self.attrs_mut()
                    && attrs.value.is_some()
                {
                    attrs.withs += 1;
                }
                false
            }
            _ => false,
        }
    }

    /// End every string a comment left open, and what is open inside it.
    fn end_strings(&mut self, base: usize) {
        if let Some(at) = self
            .0
            .iter()
            .skip(base)
            .position(|(frame, _)| matches!(frame, Frame::Str { .. }))
        {
            self.0.truncate(base + at);
        }
    }

    /// Read the definition that may start at `start` on a line indented by
    /// `indent`: `inherit …;` or an attribute path and its `=`, whose places
    /// are definitions of the configuration when `option`. Pushes what it
    /// names to `names` and returns where to go on and whether it is an
    /// `inherit`, or `None` when no definition starts there.
    fn definition(
        &mut self,
        line: &[u8],
        start: usize,
        (indent, option): (usize, bool),
        names: &mut Vec<(Range<usize>, Named)>,
        places: &mut Vec<Place>,
    ) -> Option<(usize, bool)> {
        let attrs = self.attrs_mut()?;
        // The old list form's elements are no entries: `name` names one.
        let entries = !(attrs.in_list && names_entry(&attrs.path));
        // `inherit` in any case, as a keyword is read.
        if line[start..]
            .get(..b"inherit".len())
            .is_some_and(|word| word.eq_ignore_ascii_case(b"inherit"))
            && !line
                .get(start + b"inherit".len())
                .copied()
                .is_some_and(is_identifier_byte)
        {
            let entries = entries && names_entry(&attrs.path);
            return Some((
                inherit(entries, line, start + b"inherit".len(), names),
                true,
            ));
        }
        let (components, end) = attribute_path(line, start)?;
        let next = skip_blanks(line, end);
        if line.get(next) != Some(&b'=') || line.get(next + 1) == Some(&b'=') {
            return None;
        }
        let mut full: Vec<String> = attrs.path.clone();
        let offset = full.len();
        full.extend(
            components
                .iter()
                .map(|(text, _)| String::from_utf8_lossy(text).into_owned()),
        );
        for (index, (_, range)) in components.into_iter().enumerate() {
            if entries && names_entry(&full[..offset + index]) {
                names.push((range.clone(), Named::Mapping));
            }
            places.push(Place {
                range,
                path: full[..=offset + index].to_vec(),
                attribute: true,
                option,
            });
        }
        let value = skip_blanks(line, next + 1);
        if let Some(named) = value_names(&full, attrs.in_list)
            && let Some(range) = quoted(line, value)
        {
            names.push((range, named));
        }
        attrs.value = Some(full);
        attrs.value_indent = indent;
        attrs.withs = 0;
        attrs.list_value = line.get(value) == Some(&b'[');
        Some((next + 1, false))
    }
}

/// The path that code read on top of `frames` stands in: the definition
/// whose value is being read, or the set or list it is in.
fn context(frames: &[(Frame, usize)]) -> &[String] {
    frames
        .iter()
        .rev()
        .find_map(|(frame, _)| match frame {
            Frame::Attrs(attrs) => Some(attrs.value.as_deref().unwrap_or(&attrs.path)),
            Frame::List { path, .. } => Some(path.as_slice()),
            Frame::Interpolation | Frame::Str { .. } => None,
        })
        .unwrap_or(&[])
}

/// Whether `path` is below a `fileSystems` attribute or a `luks.devices`
/// attribute, or is one: where an entry of the decoy's own may stand.
fn below_entries(path: &[String]) -> bool {
    path.iter().any(|part| part == "fileSystems")
        || path
            .windows(2)
            .any(|pair| pair[0] == "luks" && pair[1] == "devices")
}

/// Read an `inherit` (`inherit data;`, `inherit (cfg) data;`) from `from`
/// to its `;`, which is left for the caller: the names it defines are
/// entries when `entries`.
fn inherit(
    entries: bool,
    line: &[u8],
    from: usize,
    names: &mut Vec<(Range<usize>, Named)>,
) -> usize {
    let mut i = from;
    let mut depth = 0usize;
    while i < line.len() && line[i] != b';' {
        match line[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                if let Some(((_, range), end)) = component(line, i) {
                    if entries {
                        names.push((range, Named::Mapping));
                    }
                    i = end;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

/// Whether an attribute right below `path` is an entry of `luks.devices` or
/// `clevis.devices`, which names a mapping.
fn names_entry(path: &[String]) -> bool {
    path.len() >= 2
        && path[path.len() - 1].eq_ignore_ascii_case("devices")
        && ["luks", "clevis"]
            .iter()
            .any(|name| path[path.len() - 2].eq_ignore_ascii_case(name))
}

/// What the string value of the definition at `full` names, if anything:
/// `encrypted.label` and the `name` of a `luks.devices` entry name a
/// mapping, the `label` of a `fileSystems` or `swapDevices` entry a
/// filesystem label.
fn value_names(full: &[String], in_list: bool) -> Option<Named> {
    let (last, parent) = full.split_last()?;
    let is = |text: &str, word: &str| text.eq_ignore_ascii_case(word);
    if is(last, "label") && parent.last().is_some_and(|p| is(p, "encrypted")) {
        Some(Named::Mapping)
    } else if is(last, "label")
        && parent
            .iter()
            .any(|c| is(c, "filesystems") || is(c, "swapdevices"))
    {
        Some(Named::Label)
    } else if is(last, "name")
        && ((in_list && names_entry(parent))
            || parent.split_last().is_some_and(|(_, up)| names_entry(up)))
    {
        Some(Named::Mapping)
    } else {
        None
    }
}

/// The text of a `"…"` string that starts at `at` and ends on its line,
/// escapes as the file spells them.
fn quoted(line: &[u8], at: usize) -> Option<Range<usize>> {
    if line.get(at) != Some(&b'"') {
        return None;
    }
    Some(at + 1..string_end(line, at + 1)?)
}

/// The closing quote of the `"…"` string whose text starts at `from`, past
/// its escapes.
fn string_end(line: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while at < line.len() {
        match line[at] {
            b'"' => return Some(at),
            b'\\' => at += 2,
            _ => at += 1,
        }
    }
    None
}

/// The escapes in `range`, the text of a quoted attribute name.
fn quoted_escapes(line: &[u8], range: Range<usize>) -> Vec<Escape> {
    let mut found = Vec::new();
    let mut at = range.start;
    while at < range.end {
        if line[at] == b'\\' {
            let raw = at..(at + 2).min(range.end);
            if let Some(text) = escapes::decode(&line[raw.clone()], false) {
                found.push(Escape { raw, text });
            }
            at += 2;
        } else {
            at += 1;
        }
    }
    found
}

/// One component of an attribute path being read: its text and its range.
type Component = (Vec<u8>, Range<usize>);

/// The attribute path at `start` (`a.b."c"`, blanks allowed around each
/// dot): its components and where it ends.
fn attribute_path(line: &[u8], start: usize) -> Option<(Vec<Component>, usize)> {
    let mut components = Vec::new();
    let (first, mut end) = component(line, start)?;
    components.push(first);
    loop {
        let dot = skip_blanks(line, end);
        if line.get(dot) != Some(&b'.') {
            break;
        }
        let Some((next, after)) = component(line, skip_blanks(line, dot + 1)) else {
            break;
        };
        components.push(next);
        end = after;
    }
    Some((components, end))
}

/// One attribute name at `start` (`data` or `"data"`): its text and range
/// without quotes, and where it ends.
fn component(line: &[u8], start: usize) -> Option<(Component, usize)> {
    if line.get(start) == Some(&b'"') {
        let close = string_end(line, start + 1)?;
        let range = start + 1..close;
        return Some(((line[range.clone()].to_vec(), range), close + 1));
    }
    let len = line
        .get(start..)?
        .iter()
        .take_while(|&&b| is_identifier_byte(b) || b == b'\'')
        .count();
    if len == 0 {
        return None;
    }
    let range = start..start + len;
    Some(((line[range.clone()].to_vec(), range), start + len))
}

/// Where the text of a comment line starts, past blanks, comment markers and
/// the carriage return of a CRLF line: its column is the line's indentation.
fn comment_text(line: &[u8], from: usize) -> usize {
    from + line[from..]
        .iter()
        .take_while(|&&b| matches!(b, b' ' | b'\t' | b'\r' | b'#' | b'*' | b'/'))
        .count()
}

pub(super) fn skip_blanks(line: &[u8], from: usize) -> usize {
    from + line.get(from..).map_or(0, |rest| {
        rest.iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count()
    })
}

fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// The start of a token (a word, a path, a URL or a number), not the inside
/// of one.
fn is_token_start(line: &[u8], i: usize) -> bool {
    is_identifier_byte(line[i]) && (i == 0 || !is_token_byte(line[i - 1]))
}

fn token_end(line: &[u8], i: usize) -> usize {
    i + line[i..].iter().take_while(|&&b| is_token_byte(b)).count()
}

/// A byte of a token: a Nix identifier, or a path, URL or number. A keyword
/// is a whole token, so `./let/in.nix` holds none.
fn is_token_byte(byte: u8) -> bool {
    is_identifier_byte(byte) || matches!(byte, b'.' | b'/' | b'~' | b'+' | b'@' | b':')
}

pub(super) fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
