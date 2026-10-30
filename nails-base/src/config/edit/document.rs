// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The edits on the TOML document: where a new value goes, what a replaced
//! value keeps, and where the comments of a removed key go.
//!
//! The document is written in this order: the keys at the top, then every
//! table by the position it was read at, then the text after the last item.
//! Comments live in the text before a key, before a table header, after a
//! value on its line, inside a list or an inline table, and at the end. An
//! edit moves comment text between those places but never drops it.

use toml_edit::{
    DocumentMut, InlineTable, Item, Key, RawString, Table, TableLike, Value as TomlValue,
};

use super::{Change, Edit, EditError, Setting, Value};

/// Make `edit` on `doc` and say what it changed.
pub(super) fn make(doc: &mut DocumentMut, edit: &Edit) -> Result<Change, EditError> {
    let setting = edit.setting();
    let before = match find(doc, setting) {
        Found::Value(value) => Some(value.clone()),
        Found::Absent => None,
        // Nothing of the setting is in a file whose table is something else.
        Found::NotATable(_) if matches!(edit, Edit::Unset(_)) => None,
        Found::NotATable(found) => {
            let at = setting.table().unwrap_or(setting.key);
            return Err(blocked(setting, at, found));
        }
        Found::NotAValue(found) => return Err(blocked(setting, setting.key, found)),
    };
    match edit {
        Edit::Set(_, value) => match &before {
            // Already so: keep the file's own spelling of it.
            Some(old) if shown(old) == value.to_toml() => {}
            Some(_) => replace(doc, setting, edit_value(value)),
            None => insert(doc, setting, edit_value(value)),
        },
        Edit::Unset(_) if before.is_some() => super::removal::remove(doc, setting),
        Edit::Unset(_) => {}
    }
    let after = match find(doc, setting) {
        Found::Value(value) => Some(shown(value)),
        _ => None,
    };
    Ok(Change {
        key: setting.key,
        before: before.as_ref().map(shown),
        after,
    })
}

fn blocked(setting: &Setting, at: &'static str, found: &str) -> EditError {
    let article = if found.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    EditError::Blocked {
        key: setting.key,
        at,
        found: format!("{article} {found}"),
    }
}

/// What the file holds where a setting goes.
enum Found<'a> {
    /// Its value.
    Value(&'a TomlValue),
    /// Nothing.
    Absent,
    /// Its table is something else in the file (named by its type).
    NotATable(&'static str),
    /// Its key holds a table, not a value (named by its type).
    NotAValue(&'static str),
}

fn find<'a>(doc: &'a DocumentMut, setting: &Setting) -> Found<'a> {
    let root: &dyn TableLike = doc.as_table();
    let holder = match setting.table() {
        None => root,
        Some(table) => match root.get(table) {
            None => return Found::Absent,
            Some(item) => match item.as_table_like() {
                Some(holder) => holder,
                None => return Found::NotATable(item.type_name()),
            },
        },
    };
    match holder.get(setting.name()) {
        None => Found::Absent,
        Some(Item::Value(value)) => Found::Value(value),
        Some(item) => Found::NotAValue(item.type_name()),
    }
}

/// The value as TOML, without the spacing and comments around it.
fn shown(value: &TomlValue) -> toml::Value {
    let mut bare = value.clone();
    bare.decor_mut().clear();
    let text = bare.to_string();
    text.parse::<toml::Value>()
        .unwrap_or(toml::Value::String(text))
}

/// A new document value for `value`.
fn edit_value(value: &Value) -> TomlValue {
    match value {
        Value::Bool(value) => TomlValue::from(*value),
        Value::Integer(value) => TomlValue::from(i64::try_from(*value).unwrap_or(i64::MAX)),
        Value::Text(text) => TomlValue::from(text.as_str()),
        Value::Names(names) => TomlValue::Array(names.iter().map(String::as_str).collect()),
    }
}

/// The table the setting's key sits in: the top of the file, its table, or
/// its inline table.
fn holder_mut<'a>(doc: &'a mut DocumentMut, setting: &Setting) -> Option<&'a mut dyn TableLike> {
    let root = doc.as_table_mut();
    match setting.table() {
        None => Some(root as &mut dyn TableLike),
        Some(table) => root.get_mut(table)?.as_table_like_mut(),
    }
}

/// Replace the setting's value where it stands. The new value keeps the old
/// one's spacing and the comment at the end of its line; comments inside the
/// old value (a list written over several lines) move to the lines above the
/// key.
fn replace(doc: &mut DocumentMut, setting: &Setting, mut value: TomlValue) {
    let Some(holder) = holder_mut(doc, setting) else {
        return;
    };
    let Some((mut key, item)) = holder.get_key_value_mut(setting.name()) else {
        return;
    };
    let Some(old) = item.as_value() else {
        return;
    };
    *value.decor_mut() = old.decor().clone();
    let mut inner = Vec::new();
    inner_comments(old, &mut inner);
    if !inner.is_empty() {
        let prefix = raw(key.leaf_decor().prefix());
        key.leaf_decor_mut()
            .set_prefix(with_lines_above(&prefix, &inner));
    }
    *item = Item::Value(value);
}

/// `prefix`, the text before a key, with `lines` added just above the key, at
/// the key's indentation.
fn with_lines_above(prefix: &str, lines: &[String]) -> String {
    let (above, indent) = split_indent(prefix);
    let mut text = above.to_string();
    for line in lines {
        text.push_str(indent);
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(indent);
    text
}

/// The text before a key, split into the lines above it and the key line's
/// own indentation.
pub(super) fn split_indent(prefix: &str) -> (&str, &str) {
    match prefix.rfind('\n') {
        Some(at) => prefix.split_at(at + 1),
        None => ("", prefix),
    }
}

/// Add the setting, which the file does not set, after the keys of its table,
/// or in a new table at the end.
fn insert(doc: &mut DocumentMut, setting: &Setting, value: TomlValue) {
    let name = setting.name();
    let Some(table) = setting.table() else {
        insert_at_top(doc, name, value);
        return;
    };
    match doc.as_table_mut().get_mut(table) {
        Some(Item::Value(TomlValue::InlineTable(inline))) => insert_inline(inline, name, value),
        Some(Item::Table(holder)) => {
            holder.insert(name, Item::Value(value));
        }
        _ => insert_table(doc, table, name, value),
    }
}

/// Add a key at the end of an inline table. The space before the closing
/// brace belongs to the last value, so it goes on to the new last one.
fn insert_inline(inline: &mut InlineTable, name: &str, mut value: TomlValue) {
    if let Some((_, last)) = inline.iter_mut().last() {
        let suffix = raw(last.decor().suffix());
        if suffix.trim().is_empty() {
            last.decor_mut().set_suffix("");
            value.decor_mut().set_suffix(suffix);
        }
    }
    inline.insert(name, value);
}

/// Add a key at the top of the file, after the keys already there.
///
/// A file with no key above its tables would get the new key above its
/// opening comments. So the comments before the first table that a blank line
/// sets apart from its header go above the new key, and in a file of comments
/// alone (the template `nails init` writes) the key goes below all of them.
fn insert_at_top(doc: &mut DocumentMut, name: &str, value: TomlValue) {
    let mut key = Key::new(name);
    if doc.as_table().get_values().is_empty() {
        match first_header(doc) {
            First::Table(path) => {
                if let Some(table) = table_at_mut(doc, path.as_slice()) {
                    let prefix = raw(table.decor().prefix());
                    let (opening, own) = split_at_blank_line(&prefix);
                    let own = if opening.contains('#') {
                        key.leaf_decor_mut().set_prefix(opening);
                        own
                    } else {
                        prefix.as_str()
                    };
                    let own = blank_line_before(own);
                    table.decor_mut().set_prefix(own);
                }
            }
            First::NoTable => {
                let trailing = raw(Some(doc.trailing()));
                if trailing.contains('#') {
                    key.leaf_decor_mut().set_prefix(blank_line_after(&trailing));
                    doc.set_trailing("");
                }
            }
            First::Other => {}
        }
    }
    doc.as_table_mut()
        .insert_formatted(&key, Item::Value(value));
}

/// Add `[table]` holding the one key after every other table. The comments
/// that end the file stay above it, so it is written last.
fn insert_table(doc: &mut DocumentMut, table: &str, name: &str, value: TomlValue) {
    let mut new = Table::new();
    new.insert(name, Item::Value(value));
    new.set_position(Some(next_position(doc)));
    let trailing = raw(Some(doc.trailing()));
    if trailing.contains('#') {
        new.decor_mut().set_prefix(blank_line_after(&trailing));
        doc.set_trailing("");
    }
    doc.as_table_mut().insert(table, Item::Table(new));
}

/// The position after that of every table, so a new table is written last.
fn next_position(doc: &DocumentMut) -> isize {
    fn walk(table: &Table, last: &mut isize) {
        if let Some(position) = table.position() {
            *last = (*last).max(position);
        }
        for (_, item) in table.iter() {
            match item {
                Item::Table(child) => walk(child, last),
                Item::ArrayOfTables(array) => array.iter().for_each(|child| walk(child, last)),
                _ => {}
            }
        }
    }
    let mut last = 0;
    walk(doc.as_table(), &mut last);
    last.saturating_add(1)
}

pub(super) fn table_at<'a, S: AsRef<str>>(doc: &'a DocumentMut, path: &[S]) -> Option<&'a Table> {
    let mut table = doc.as_table();
    for key in path {
        table = table.get(key.as_ref())?.as_table()?;
    }
    Some(table)
}

pub(super) fn table_at_mut<'a, S: AsRef<str>>(
    doc: &'a mut DocumentMut,
    path: &[S],
) -> Option<&'a mut Table> {
    let mut table = doc.as_table_mut();
    for key in path {
        table = table.get_mut(key.as_ref())?.as_table_mut()?;
    }
    Some(table)
}

/// A table as the document writes it.
pub(super) struct Rendered {
    /// The keys from the top to it.
    pub(super) path: Vec<String>,
    /// The position it is written at.
    pub(super) position: isize,
    /// Whether it has a header: an implicit table with no value has none.
    pub(super) visible: bool,
    /// Whether it is one table of an array of tables.
    pub(super) in_array: bool,
}

/// Every table in the order the document writes them, the top first: by
/// position, a table without one after the table visited before it.
pub(super) fn rendered_tables(doc: &DocumentMut) -> Vec<Rendered> {
    fn collect(
        table: &Table,
        path: &mut Vec<String>,
        in_array: bool,
        last: &mut isize,
        out: &mut Vec<Rendered>,
    ) {
        if !table.is_dotted() {
            if let Some(position) = table.position() {
                *last = position;
            }
            out.push(Rendered {
                path: path.clone(),
                position: *last,
                visible: !(table.is_implicit() && table.get_values().is_empty()),
                in_array,
            });
        }
        for (key, item) in table.iter() {
            match item {
                Item::Table(child) => {
                    path.push(key.to_string());
                    collect(child, path, false, last, out);
                    path.pop();
                }
                Item::ArrayOfTables(array) => {
                    for child in array.iter() {
                        path.push(key.to_string());
                        collect(child, path, true, last, out);
                        path.pop();
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    collect(doc.as_table(), &mut Vec::new(), false, &mut 0, &mut out);
    out.sort_by_key(|rendered| (!rendered.path.is_empty(), rendered.position));
    out
}

/// The first table header the document writes.
enum First {
    /// There is none.
    NoTable,
    /// The table at this path.
    Table(Vec<String>),
    /// One table of an array of tables.
    Other,
}

fn first_header(doc: &DocumentMut) -> First {
    let first = rendered_tables(doc)
        .into_iter()
        .find(|rendered| !rendered.path.is_empty() && rendered.visible);
    match first {
        None => First::NoTable,
        Some(rendered) if rendered.in_array => First::Other,
        Some(rendered) => First::Table(rendered.path),
    }
}

/// `text` split after its last blank line.
fn split_at_blank_line(text: &str) -> (&str, &str) {
    let mut offset = 0;
    let mut split = 0;
    for line in text.split_inclusive('\n') {
        offset += line.len();
        if line.ends_with('\n') && line.trim().is_empty() {
            split = offset;
        }
    }
    text.split_at(split)
}

/// `text` starting with a blank line.
fn blank_line_before(text: &str) -> String {
    let first = text.split_inclusive('\n').next().unwrap_or("");
    if first.ends_with('\n') && first.trim().is_empty() {
        text.to_string()
    } else {
        format!("\n{text}")
    }
}

/// `text` ending with a blank line.
fn blank_line_after(text: &str) -> String {
    let mut text = text.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let body = &text[..text.len() - 1];
    let last = body.rsplit('\n').next().unwrap_or("");
    if !last.trim().is_empty() {
        text.push('\n');
    }
    text
}

pub(super) fn raw(text: Option<&RawString>) -> String {
    raw_or(text, "")
}

pub(super) fn raw_or(text: Option<&RawString>, default: &str) -> String {
    text.and_then(RawString::as_str)
        .unwrap_or(default)
        .to_string()
}

/// The comments in the text around a key, a value or a table.
pub(super) fn raw_comments(text: Option<&RawString>, out: &mut Vec<String>) {
    let Some(text) = text.and_then(RawString::as_str) else {
        return;
    };
    for line in text.split('\n') {
        if let Some(at) = line.find('#') {
            out.push(line[at..].trim_end_matches('\r').to_string());
        }
    }
}

fn decor_comments(decor: &toml_edit::Decor, out: &mut Vec<String>) {
    raw_comments(decor.prefix(), out);
    raw_comments(decor.suffix(), out);
}

/// The comments inside a list or an inline table, in the order they are
/// written; none for any other value.
pub(super) fn inner_comments(value: &TomlValue, out: &mut Vec<String>) {
    match value {
        TomlValue::Array(array) => {
            for element in array.iter() {
                raw_comments(element.decor().prefix(), out);
                inner_comments(element, out);
                raw_comments(element.decor().suffix(), out);
            }
            raw_comments(Some(array.trailing()), out);
        }
        TomlValue::InlineTable(table) => {
            for (path, element) in table.get_values() {
                for key in &path {
                    raw_comments(key.leaf_decor().prefix(), out);
                    decor_comments(key.dotted_decor(), out);
                    raw_comments(key.leaf_decor().suffix(), out);
                }
                raw_comments(element.decor().prefix(), out);
                inner_comments(element, out);
                raw_comments(element.decor().suffix(), out);
            }
            raw_comments(Some(table.trailing()), out);
        }
        _ => {}
    }
}

/// Every comment of the document.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn comments(doc: &DocumentMut) -> Vec<String> {
    fn table_comments(table: &Table, out: &mut Vec<String>) {
        decor_comments(table.decor(), out);
        for (name, item) in table.iter() {
            if let Some(key) = table.key(name) {
                decor_comments(key.leaf_decor(), out);
                decor_comments(key.dotted_decor(), out);
            }
            match item {
                Item::Value(value) => {
                    decor_comments(value.decor(), out);
                    inner_comments(value, out);
                }
                Item::Table(child) => table_comments(child, out),
                Item::ArrayOfTables(array) => {
                    array.iter().for_each(|child| table_comments(child, out));
                }
                Item::None => {}
            }
        }
    }
    let mut out = Vec::new();
    table_comments(doc.as_table(), &mut out);
    raw_comments(Some(doc.trailing()), &mut out);
    out
}
