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
//! Comments and tokens end where Nix's lexer ends them. A block comment ends
//! at its first `*/`, whatever quotes it holds (`/* a 5" disk */`), and
//! starts at a `/*` right after a word too (`true/* … */`); a `#` comment
//! ends at a carriage return as well as at the end of the line, and what
//! follows the carriage return is code. A `'` continues an identifier
//! (`a''` is a name, not the start of a string), and a URI holds every byte
//! Nix allows in one, `'` and `*` among them (`http://example.org/a''`). A
//! scanner made with [`Reading::Quotes`] reads them by quotes and brackets
//! alone instead, and the check counts what either reading finds.
//!
//! The scanner also records the escapes of the strings and quoted attribute
//! names it reads, in code and in comments ([`Scanner::escapes`]), and the
//! attribute names each line defines ([`Scanner::defined`]).

use super::escapes::{self, Escape};
use std::ops::Range;

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
    /// A string: `''…''` when `indented`, else `"…"`.
    Str {
        indented: bool,
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

/// How a [`Scanner`] reads comments and tokens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Reading {
    /// As Nix's lexer reads them; see the module docs.
    #[default]
    Nix,
    /// By quotes and brackets alone: a quote opens a string in a comment as
    /// in code, and the string runs on past the comment's end; a `#` comment
    /// runs to the end of the line; a token is a run of the bytes of words,
    /// paths and URLs, with no `'` and no URI of Nix's own. Where it parts
    /// from Nix it reads text as code, a string or a comment that Nix does
    /// not, and the check counts the names either reading finds.
    Quotes,
}

/// Reads a file line by line; see the module docs.
#[derive(Debug, Default)]
pub(super) struct Scanner {
    reading: Reading,
    code: Stack,
    comment: Option<Comment>,
    /// Inside a `/* … */` comment.
    in_block_comment: bool,
    /// The attribute names the line read last defines
    /// ([`Scanner::defined`]).
    defined: Vec<Range<usize>>,
    /// The escapes in the strings of the line read last
    /// ([`Scanner::escapes`]).
    escapes: Vec<Escape>,
}

impl Scanner {
    /// A scanner that reads comments and tokens as `reading` says.
    pub(super) fn reading(reading: Reading) -> Self {
        Self {
            reading,
            ..Self::default()
        }
    }

    /// The attribute names the line [`Scanner::line`] read last defines,
    /// without quotes, in code and in comments, `let` bindings among them.
    pub(super) fn defined(&mut self) -> Vec<Range<usize>> {
        std::mem::take(&mut self.defined)
    }

    /// The escapes in the strings of the line [`Scanner::line`] read last,
    /// in the order of the line ([`escapes`]). The text of a quoted
    /// attribute name is a string too.
    pub(super) fn escapes(&mut self) -> Vec<Escape> {
        std::mem::take(&mut self.escapes)
    }

    /// The ranges of `line` that name something ([`Named`]). `line` is read
    /// as the file spells it, so an escape keeps its case (`\N` is no `\n`),
    /// and a keyword and an attribute name that leads to a mapping are
    /// compared in any case.
    pub(super) fn line(&mut self, line: &[u8]) -> Vec<(Range<usize>, Named)> {
        let mut names = Vec::new();
        let mut defined = Vec::new();
        let mut escaped = Vec::new();
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
        let nix = self.reading == Reading::Nix;
        let mut in_comment = self.in_block_comment;
        let mut attribute = self.stack(in_comment).expects_attribute();
        // Where the comment the line is in ends on it.
        let mut close = comment_end(line, 0, in_comment);
        let full = line;
        let mut i = 0;
        while i < full.len() {
            // A comment ends where Nix's lexer ends it, whatever the copy of
            // the frames it is read on holds: a block comment at its first
            // `*/`, also inside a quote the comment holds, and a `#` comment
            // at a carriage return as well as at the end of the line. What
            // it holds is read up to there, a string in it ends with it, and
            // what follows is code.
            if nix && in_comment && i >= close {
                i = close + if self.in_block_comment { 2 } else { 1 };
                self.in_block_comment = false;
                in_comment = false;
                attribute = self.code.expects_attribute();
                if let Some(comment) = &mut self.comment {
                    comment.stack.end_strings(comment.base);
                }
                continue;
            }
            let line = if nix && in_comment {
                &full[..close]
            } else {
                full
            };
            if let Some(Frame::Str { indented }) = self.stack(in_comment).top() {
                let indented = *indented;
                let next = self.stack(in_comment).string(line, i, indented);
                let raw = i..next.min(line.len());
                if let Some(text) = escapes::decode(&line[raw.clone()], indented) {
                    escaped.push(Escape { raw, text });
                }
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
                close = comment_end(full, i, block);
                continue;
            }
            if !nix && in_comment && self.in_block_comment && line[i..].starts_with(b"*/") {
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
                let (attributes, named) = (defined.len(), names.len());
                if let Some(next) =
                    self.stack(in_comment)
                        .definition(line, i, indent, &mut names, &mut defined)
                {
                    // The escapes of the quoted names it defines or names.
                    let quoted = defined[attributes..]
                        .iter()
                        .chain(names[named..].iter().map(|(range, _)| range))
                        .filter(|range| range.start > 0 && line[range.start - 1] == b'"');
                    let mut ranges: Vec<Range<usize>> = quoted.cloned().collect();
                    ranges.sort_by_key(|range| range.start);
                    ranges.dedup();
                    for range in ranges {
                        escaped.extend(quoted_escapes(line, range));
                    }
                    i = next;
                    continue;
                }
            }
            if is_token_start(line, i, nix) {
                let end = if nix {
                    token_end(line, i)
                } else {
                    i + line[i..].iter().take_while(|&&b| is_token_byte(b)).count()
                };
                attribute = self.stack(in_comment).keyword(&line[i..end], indent);
                i = end;
                continue;
            }
            attribute = self.stack(in_comment).punctuation(line, i, indent);
            i += if line[i..].starts_with(b"${") || line[i..].starts_with(b"''") {
                2
            } else {
                1
            };
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
        escaped.sort_by_key(|escape| escape.raw.start);
        self.defined = defined;
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
    /// interpolation, or out of the string. Returns where to go on.
    fn string(&mut self, line: &[u8], i: usize, indented: bool) -> usize {
        let rest = &line[i..];
        if rest.starts_with(b"$$") {
            return i + 2;
        }
        if rest.starts_with(b"${") {
            self.0.push((Frame::Interpolation, usize::MAX));
            return i + 2;
        }
        if indented {
            if rest.starts_with(b"'''") || rest.starts_with(b"''$") {
                return i + 3;
            }
            if rest.starts_with(b"''\\") {
                return i + 4;
            }
            if rest.starts_with(b"''") {
                self.0.pop();
                return i + 2;
            }
        } else if rest[0] == b'\\' {
            return i + 2;
        } else if rest[0] == b'"' {
            self.0.pop();
        }
        i + 1
    }

    /// The byte at `i` outside a string and a token: a bracket, a string's
    /// opening, a `;` or anything else. Returns whether an attribute may
    /// start after it.
    fn punctuation(&mut self, line: &[u8], i: usize, indent: usize) -> bool {
        let rest = &line[i..];
        if rest.starts_with(b"${") {
            self.0.push((Frame::Interpolation, indent));
            return false;
        }
        if rest.starts_with(b"''") {
            self.0.push((Frame::Str { indented: true }, indent));
            return false;
        }
        match rest[0] {
            b'"' => self.0.push((Frame::Str { indented: false }, indent)),
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
    /// `indent`: `inherit …;` or an attribute path and its `=`. Pushes what
    /// it names to `names` and the attribute names it defines to `defined`,
    /// and returns where to go on, or `None` when no definition starts
    /// there.
    fn definition(
        &mut self,
        line: &[u8],
        start: usize,
        indent: usize,
        names: &mut Vec<(Range<usize>, Named)>,
        defined: &mut Vec<Range<usize>>,
    ) -> Option<usize> {
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
            return Some(inherit(entries, line, start + b"inherit".len(), names));
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
            defined.push(range);
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
        Some(next + 1)
    }
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

/// Where a comment that holds `from` ends in `line`: a block comment
/// (`block`) at its first `*/`, a `#` comment at a carriage return; the end
/// of the line when it does not end on it.
fn comment_end(line: &[u8], from: usize, block: bool) -> usize {
    let end: &[u8] = if block { b"*/" } else { b"\r" };
    line.get(from..)
        .and_then(|rest| rest.windows(end.len()).position(|window| window == end))
        .map_or(line.len(), |at| from + at)
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
/// of one. As Nix reads it (`nix`), a word right after the `.` that selects
/// an attribute of a value in brackets or a string starts one too
/// (`{ a'' = 1; }.a''`).
fn is_token_start(line: &[u8], i: usize, nix: bool) -> bool {
    let not_in_token = |at: usize| !is_token_byte(line[at]);
    is_identifier_byte(line[i])
        && (i == 0
            || not_in_token(i - 1)
            || (nix && line[i - 1] == b'.' && (i == 1 || not_in_token(i - 2))))
}

/// Where the token that starts at `i` ends, as Nix's lexer reads it. A URI
/// (`http://example.org/a''`) takes every byte Nix allows in one, `'` and
/// `*` among them. Elsewhere `/*` starts a comment, also right after a word
/// (`true/* a 5" disk */`), and `'` continues an identifier (`a''`), but not
/// a path (`./a''` is a path and a string).
fn token_end(line: &[u8], i: usize) -> usize {
    if let Some(end) = uri_end(line, i) {
        return end;
    }
    let mut at = i;
    let mut path = false;
    while let Some(&byte) = line.get(at) {
        let continues = match byte {
            b'/' => {
                path = true;
                line.get(at + 1) != Some(&b'*')
            }
            b'\'' => !path && ends_identifier(&line[i..at]),
            _ => is_token_byte(byte),
        };
        if !continues {
            break;
        }
        at += 1;
    }
    at
}

/// Whether `text`, the token read so far, ends in an identifier, which a `'`
/// continues: its last part, after the last byte no identifier holds, has a
/// letter or `_`, from which on Nix reads it as one (`1a` is `1` and `a`).
fn ends_identifier(text: &[u8]) -> bool {
    let start = text
        .iter()
        .rposition(|&b| !(is_identifier_byte(b) || b == b'\''))
        .map_or(0, |at| at + 1);
    text[start..]
        .iter()
        .any(|&b| b.is_ascii_alphabetic() || b == b'_')
}

/// The end of the URI that starts at `i`, if one does, as Nix's lexer reads
/// one: a scheme (a letter, then letters, digits, `+`, `-` or `.`), a `:`
/// and at least one byte of the URI's own.
fn uri_end(line: &[u8], i: usize) -> Option<usize> {
    if !line.get(i)?.is_ascii_alphabetic() {
        return None;
    }
    let scheme = line[i..]
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    let colon = i + scheme;
    if line.get(colon) != Some(&b':') {
        return None;
    }
    let rest = line[colon + 1..]
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b"%/?:@&=+$,-_.!~*'".contains(&b))
        .count();
    (rest > 0).then_some(colon + 1 + rest)
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
