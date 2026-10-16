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

/// Reads a file line by line; see the module docs.
#[derive(Debug, Default)]
pub(super) struct Scanner {
    code: Stack,
    comment: Option<Comment>,
    /// Inside a `/* … */` comment.
    in_block_comment: bool,
}

impl Scanner {
    /// The ranges of `line` that name something ([`Named`]).
    pub(super) fn line(&mut self, line: &[u8]) -> Vec<(Range<usize>, Named)> {
        let mut names = Vec::new();
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
            if let Some(Frame::Str { indented }) = self.stack(in_comment).top() {
                let indented = *indented;
                i = self.stack(in_comment).string(line, i, indented);
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
                if let Some(next) = self
                    .stack(in_comment)
                    .definition(line, i, indent, &mut names)
                {
                    i = next;
                    continue;
                }
            }
            if is_token_start(line, i) {
                let end = token_end(line, i);
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
    /// value being read. Returns whether a binding may start after it.
    fn keyword(&mut self, word: &[u8], indent: usize) -> bool {
        match word {
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

    /// Read the definition that may start at `start`: `inherit …;` or an
    /// attribute path and its `=`. Pushes what it names to `names` and
    /// returns where to go on, or `None` when no definition starts there.
    fn definition(
        &mut self,
        line: &[u8],
        start: usize,
        indent: usize,
        names: &mut Vec<(Range<usize>, Named)>,
    ) -> Option<usize> {
        let attrs = self.attrs_mut()?;
        // The old list form's elements are no entries: `name` names one.
        let entries = !(attrs.in_list && names_entry(&attrs.path));
        if let Some(rest) = line[start..].strip_prefix(b"inherit")
            && !rest.first().copied().is_some_and(is_identifier_byte)
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
                names.push((range, Named::Mapping));
            }
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
        && path[path.len() - 1] == "devices"
        && matches!(path[path.len() - 2].as_str(), "luks" | "clevis")
}

/// What the string value of the definition at `full` names, if anything:
/// `encrypted.label` and the `name` of a `luks.devices` entry name a
/// mapping, the `label` of a `fileSystems` or `swapDevices` entry a
/// filesystem label.
fn value_names(full: &[String], in_list: bool) -> Option<Named> {
    let (last, parent) = full.split_last()?;
    match last.as_str() {
        "label" if parent.last().is_some_and(|p| p == "encrypted") => Some(Named::Mapping),
        "label"
            if parent
                .iter()
                .any(|c| c == "filesystems" || c == "swapdevices") =>
        {
            Some(Named::Label)
        }
        "name"
            if (in_list && names_entry(parent))
                || parent.split_last().is_some_and(|(_, up)| names_entry(up)) =>
        {
            Some(Named::Mapping)
        }
        _ => None,
    }
}

/// The text of a `"…"` string that starts at `at`, when it holds no escape.
fn quoted(line: &[u8], at: usize) -> Option<Range<usize>> {
    if line.get(at) != Some(&b'"') {
        return None;
    }
    let len = line[at + 1..]
        .iter()
        .position(|&b| b == b'"' || b == b'\\')?;
    (line[at + 1 + len] == b'"').then_some(at + 1..at + 1 + len)
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
        let close = start + 1 + line[start + 1..].iter().position(|&b| b == b'"')?;
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
