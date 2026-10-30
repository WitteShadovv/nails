// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Removing a key from the document without losing its comments.
//!
//! The comments above a removed key, inside its value and at the end of its
//! line move to where the next thing the document writes starts: the next key
//! of the same body, the next table's header, or the text at the end of the
//! file.

use toml_edit::{DocumentMut, Item, Key, KeyMut, Value as TomlValue};

use super::Setting;
use super::document::{
    inner_comments, raw, raw_comments, raw_or, rendered_tables, split_indent, table_at,
    table_at_mut,
};

/// Remove the setting's key and value, keeping their comments on the lines
/// where what follows them starts.
pub(super) fn remove(doc: &mut DocumentMut, setting: &Setting) {
    let name = setting.name();
    let Some(table) = setting.table() else {
        remove_value(doc, &[], &[name]);
        return;
    };
    enum Written {
        Header,
        Dotted,
        Inline,
        Elsewhere,
    }
    let written = match doc.as_table().get(table) {
        Some(Item::Table(holder)) if holder.is_dotted() => Written::Dotted,
        Some(Item::Table(_)) => Written::Header,
        Some(Item::Value(TomlValue::InlineTable(_))) => Written::Inline,
        _ => Written::Elsewhere,
    };
    match written {
        Written::Header => remove_value(doc, &[table], &[name]),
        Written::Dotted => remove_value(doc, &[], &[table, name]),
        Written::Inline => remove_inline(doc, table, name),
        Written::Elsewhere => {}
    }
}

/// Remove the value at `keys` (a dotted path within the body) from the body
/// of the table at `table`.
fn remove_value(doc: &mut DocumentMut, table: &[&str], keys: &[&str]) {
    let next = next_slot(doc, table, keys);
    let Some((leaf, parents)) = keys.split_last() else {
        return;
    };
    let Some(mut holder) = table_at_mut(doc, table) else {
        return;
    };
    for parent in parents {
        let Some(child) = holder.get_mut(parent).and_then(Item::as_table_mut) else {
            return;
        };
        holder = child;
    }
    let Some((key, item)) = holder.remove_entry(leaf) else {
        return;
    };
    let moved = removed_comments(&key, &item);
    if !moved.is_empty() {
        prepend(doc, &next, &moved);
    }
}

/// Remove `name` from the inline table at the top-level key `table`. Its
/// comments go before the next key, or before the closing brace.
fn remove_inline(doc: &mut DocumentMut, table: &str, name: &str) {
    let Some(inline) = doc
        .as_table_mut()
        .get_mut(table)
        .and_then(Item::as_inline_table_mut)
    else {
        return;
    };
    let keys: Vec<String> = inline.iter().map(|(key, _)| key.to_string()).collect();
    let next = keys
        .iter()
        .position(|key| key == name)
        .and_then(|at| keys.get(at + 1))
        .cloned();
    let Some((key, value)) = inline.remove_entry(name) else {
        return;
    };
    if next.is_none()
        && let Some((_, last)) = inline.iter_mut().last()
        && !raw(last.decor().suffix()).contains('#')
    {
        // The new last value takes the space before the closing brace; a
        // comment there moves with the removed key's comments below.
        let suffix = raw(value.decor().suffix());
        let suffix = if suffix.contains('#') {
            " ".to_string()
        } else {
            suffix
        };
        last.decor_mut().set_suffix(suffix);
    }
    let moved = removed_comments(&key, &Item::Value(value));
    if moved.is_empty() {
        return;
    }
    match next.as_deref().and_then(|next| inline.key_mut(next)) {
        Some(mut key) => {
            let old = raw_or(key.leaf_decor().prefix(), " ");
            key.leaf_decor_mut().set_prefix(format!("{moved}{old}"));
        }
        None => {
            let old = raw(Some(inline.trailing()));
            inline.set_trailing(format!("{moved}{old}"));
        }
    }
}

/// The comments of a removed key and value, as whole lines: the lines above
/// the key as they were, blank ones included, then the comments inside the
/// value and the one at the end of its line, each on a line of its own at the
/// key's indentation. Empty when none of it is a comment.
fn removed_comments(key: &Key, item: &Item) -> String {
    let prefix = raw(key.leaf_decor().prefix());
    let (above, indent) = split_indent(&prefix);
    let mut lines = Vec::new();
    if let Some(value) = item.as_value() {
        inner_comments(value, &mut lines);
        raw_comments(value.decor().suffix(), &mut lines);
    }
    if lines.is_empty() && !above.contains('#') {
        return String::new();
    }
    let mut text = above.to_string();
    for line in lines {
        text.push_str(indent);
        text.push_str(&line);
        text.push('\n');
    }
    text
}

/// Where the text after a removed key and value is written: before the next
/// value of the same body, before the next table header, or at the end.
enum Slot {
    Value {
        table: Vec<String>,
        keys: Vec<String>,
    },
    Header(Vec<String>),
    Trailing,
}

fn next_slot(doc: &DocumentMut, table: &[&str], keys: &[&str]) -> Slot {
    if let Some(body) = table_at(doc, table) {
        let values = body.get_values();
        let at = values.iter().position(|(path, _)| {
            path.len() == keys.len() && path.iter().zip(keys).all(|(key, want)| key.get() == *want)
        });
        if let Some((path, _)) = at.and_then(|at| values.get(at + 1)) {
            return Slot::Value {
                table: table.iter().map(|key| (*key).to_string()).collect(),
                keys: path.iter().map(|key| key.get().to_string()).collect(),
            };
        }
    }
    let tables = rendered_tables(doc);
    let here = tables.iter().position(|rendered| {
        !rendered.in_array
            && rendered
                .path
                .iter()
                .map(String::as_str)
                .eq(table.iter().copied())
    });
    let Some(here) = here else {
        return Slot::Trailing;
    };
    match tables[here + 1..].iter().find(|rendered| rendered.visible) {
        Some(next) if !next.in_array => Slot::Header(next.path.clone()),
        _ => Slot::Trailing,
    }
}

/// Write `text` before what is at `slot`.
fn prepend(doc: &mut DocumentMut, slot: &Slot, text: &str) {
    match slot {
        Slot::Value { table, keys } => {
            if let Some(mut key) = value_key_mut(doc, table, keys) {
                let old = raw(key.leaf_decor().prefix());
                key.leaf_decor_mut().set_prefix(format!("{text}{old}"));
                return;
            }
        }
        Slot::Header(path) => {
            if let Some(table) = table_at_mut(doc, path.as_slice()) {
                let old = raw_or(table.decor().prefix(), "\n");
                table.decor_mut().set_prefix(format!("{text}{old}"));
                return;
            }
        }
        Slot::Trailing => {}
    }
    let old = raw(Some(doc.trailing()));
    doc.set_trailing(format!("{text}{old}"));
}

fn value_key_mut<'a>(
    doc: &'a mut DocumentMut,
    table: &[String],
    keys: &[String],
) -> Option<KeyMut<'a>> {
    let (leaf, parents) = keys.split_last()?;
    let mut holder = table_at_mut(doc, table)?;
    for parent in parents {
        holder = holder.get_mut(parent)?.as_table_mut()?;
    }
    holder.key_mut(leaf)
}
