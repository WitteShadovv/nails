// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Changing settings in `nails.toml` without rewriting the rest of the file.
//!
//! An operator's `nails.toml` carries their own comments, their order and the
//! commented template `nails init` wrote. A setting changed through the tool
//! must leave all of that as it was, so the file is edited as a TOML document,
//! never parsed into a [`Config`](super::Config) and written out again:
//!
//! - a value that changes is replaced where it stands, with the comment on its
//!   line, and a value that is already what was asked for keeps its spelling;
//! - a key the file lacks goes after the keys of its table, or into a new
//!   table at the end; in a file of comments alone, such as the template, it
//!   goes below them;
//! - a key that is removed leaves its comments in the file, on the lines where
//!   the next key or table starts;
//! - every other key, known or not, stays as it was.
//!
//! [`SETTINGS`] lists every key a value can be set for, with what it holds.
//! [`Setting::parse`] reads a value from the words of a command line and
//! [`Setting::check`] checks one a window sends. [`apply`] makes the edits on
//! the text and says what each one changed. It judges nothing but the shape of
//! the document: the caller checks the result with the loader every command
//! reads the file with ([`LoadedConfig::parse`](super::LoadedConfig::parse))
//! before anything is written.

mod document;
mod removal;
#[cfg(test)]
mod tests;

/// The largest integer TOML can hold, which bounds every integer setting.
pub const MAX_INTEGER: u64 = i64::MAX as u64;

/// What a setting holds, which decides how a value for it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `true` or `false`.
    Bool,
    /// A whole number from 0 to [`MAX_INTEGER`].
    Integer,
    /// A path. The loader's path rules decide whether it is accepted.
    Path,
    /// A string, such as a flake reference.
    Text,
    /// One of a fixed set of strings.
    Choice(&'static [&'static str]),
    /// A list of entry names, or `*`.
    Names,
}

/// A key of `nails.toml` a value can be set for.
#[derive(Debug, PartialEq, Eq)]
pub struct Setting {
    /// The key as docs/configuration.md writes it: `persona.mode` is the
    /// `mode` key of the `[persona]` table.
    pub key: &'static str,
    /// What it holds.
    pub kind: Kind,
}

/// The spellings `persona.mode` takes.
const PERSONA_MODES: &[&str] = &["shared-home", "fresh-home"];

/// The spellings `sleep_policy.mode` takes.
const SLEEP_MODES: &[&str] = &["warn", "block", "teardown"];

/// Every key a value can be set for, in the order of the reference's key
/// table. A unit test keeps it in step with the fields of
/// [`Config`](super::Config).
pub const SETTINGS: &[Setting] = &[
    Setting {
        key: "hidden_volume_root",
        kind: Kind::Path,
    },
    Setting {
        key: "state_file_path",
        kind: Kind::Path,
    },
    Setting {
        key: "log_path",
        kind: Kind::Path,
    },
    Setting {
        key: "minimum_space_mb",
        kind: Kind::Integer,
    },
    Setting {
        key: "rebuild_space_mb",
        kind: Kind::Integer,
    },
    Setting {
        key: "show_opsec_reminders",
        kind: Kind::Bool,
    },
    Setting {
        key: "nixos_flake",
        kind: Kind::Text,
    },
    Setting {
        key: "persona.mask_inherited",
        kind: Kind::Names,
    },
    Setting {
        key: "persona.mode",
        kind: Kind::Choice(PERSONA_MODES),
    },
    Setting {
        key: "backend_watch.auto_emergency",
        kind: Kind::Bool,
    },
    Setting {
        key: "backend_watch.debounce_secs",
        kind: Kind::Integer,
    },
    Setting {
        key: "backend_watch.enabled",
        kind: Kind::Bool,
    },
    Setting {
        key: "backend_watch.poll_interval_secs",
        kind: Kind::Integer,
    },
    Setting {
        key: "session_mounts.alert",
        kind: Kind::Bool,
    },
    Setting {
        key: "session_mounts.read_only",
        kind: Kind::Bool,
    },
    Setting {
        key: "sleep_policy.mode",
        kind: Kind::Choice(SLEEP_MODES),
    },
];

/// The setting `key` names, if it is one.
pub fn setting(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|setting| setting.key == key)
}

/// The sentence for a key that is not a setting, with the closest one when
/// the key looks like a typo of it.
pub fn unknown_key(key: &str) -> String {
    let keys: Vec<&str> = SETTINGS.iter().map(|setting| setting.key).collect();
    match super::suggest::closest(key, &keys) {
        Some(close) => format!("unknown key `{key}` (did you mean `{close}`?)"),
        None => format!(
            "unknown key `{key}`: docs/configuration.md in the nails source lists every key"
        ),
    }
}

/// A value for a setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// For a [`Kind::Bool`] setting.
    Bool(bool),
    /// For a [`Kind::Integer`] setting.
    Integer(u64),
    /// For a [`Kind::Path`], [`Kind::Text`] or [`Kind::Choice`] setting.
    Text(String),
    /// For a [`Kind::Names`] setting.
    Names(Vec<String>),
}

impl Value {
    /// The value as TOML.
    pub fn to_toml(&self) -> toml::Value {
        match self {
            Value::Bool(value) => toml::Value::Boolean(*value),
            Value::Integer(value) => {
                toml::Value::Integer(i64::try_from(*value).unwrap_or(i64::MAX))
            }
            Value::Text(value) => toml::Value::String(value.clone()),
            Value::Names(names) => toml::Value::Array(
                names
                    .iter()
                    .map(|name| toml::Value::String(name.clone()))
                    .collect(),
            ),
        }
    }
}

impl Setting {
    /// The table the key sits in (`persona` for `persona.mode`), or `None` for
    /// a key at the top of the file.
    pub fn table(&self) -> Option<&'static str> {
        self.key.split_once('.').map(|(table, _)| table)
    }

    /// The key's own name in its table (`mode` for `persona.mode`).
    pub fn name(&self) -> &'static str {
        self.key.split_once('.').map_or(self.key, |(_, name)| name)
    }

    /// What a value of this setting is, completing "`<key>` takes …".
    pub fn expects(&self) -> String {
        match self.kind {
            Kind::Bool => "true or false".to_string(),
            Kind::Integer => format!("a whole number from 0 to {MAX_INTEGER}"),
            Kind::Path => "one absolute path".to_string(),
            Kind::Text => "one string that is not empty".to_string(),
            Kind::Choice(choices) => format!("one of {}", quoted_list(choices)),
            Kind::Names => "one or more entry names, or `*` for all".to_string(),
        }
    }

    /// Read a value for this setting from the words of a command line: one
    /// word, or for a list one word per entry.
    ///
    /// # Errors
    ///
    /// The sentence that says what the setting takes, when the words are not
    /// a value of its kind.
    pub fn parse(&self, words: &[String]) -> Result<Value, String> {
        let value = match (self.kind, words) {
            (Kind::Names, []) => return Err(self.takes()),
            (Kind::Names, names) => Value::Names(names.to_vec()),
            (_, [word]) => self.parse_word(word)?,
            _ => return Err(self.takes()),
        };
        self.check(&value)?;
        Ok(value)
    }

    fn parse_word(&self, word: &str) -> Result<Value, String> {
        match self.kind {
            Kind::Bool => match word {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                _ => Err(self.not(word)),
            },
            Kind::Integer if !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()) => word
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= MAX_INTEGER)
                .map(Value::Integer)
                .ok_or_else(|| self.not(word)),
            Kind::Integer => Err(self.not(word)),
            Kind::Path | Kind::Text | Kind::Choice(_) => Ok(Value::Text(word.to_string())),
            Kind::Names => Ok(Value::Names(vec![word.to_string()])),
        }
    }

    /// Check that `value` is of this setting's kind, as a window sends it.
    ///
    /// # Errors
    ///
    /// The sentence that says what the setting takes.
    pub fn check(&self, value: &Value) -> Result<(), String> {
        let fits = match (self.kind, value) {
            (Kind::Bool, Value::Bool(_)) => true,
            (Kind::Integer, Value::Integer(number)) => *number <= MAX_INTEGER,
            (Kind::Path | Kind::Text, Value::Text(text)) => !text.is_empty(),
            (Kind::Choice(choices), Value::Text(text)) => choices.contains(&text.as_str()),
            (Kind::Names, Value::Names(_)) => true,
            _ => false,
        };
        if fits {
            return Ok(());
        }
        Err(match value {
            Value::Text(text) => self.not(text),
            _ => self.takes(),
        })
    }

    fn takes(&self) -> String {
        format!("`{}` takes {}", self.key, self.expects())
    }

    fn not(&self, word: &str) -> String {
        format!("`{}` takes {}, not {word:?}", self.key, self.expects())
    }
}

/// `a`, `b` or `c`, each in backticks.
fn quoted_list(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("`{item}`")).collect();
    match quoted.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    }
}

/// One change to the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Give the setting this value.
    Set(&'static Setting, Value),
    /// Remove the setting from the file, so its default applies.
    Unset(&'static Setting),
}

impl Edit {
    /// The setting this edit changes.
    pub fn setting(&self) -> &'static Setting {
        match self {
            Edit::Set(setting, _) | Edit::Unset(setting) => setting,
        }
    }
}

/// What one edit changed, as the file writes the value: `None` where the file
/// does not set the key.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    /// The setting's key.
    pub key: &'static str,
    /// The value the file held.
    pub before: Option<toml::Value>,
    /// The value the file holds after the edit.
    pub after: Option<toml::Value>,
}

impl Change {
    /// Whether the edit changed the value.
    pub fn changed(&self) -> bool {
        self.before != self.after
    }
}

/// The file after the edits.
#[derive(Debug, Clone, PartialEq)]
pub struct Edited {
    /// The new text; the text as it was when no edit changed anything.
    pub text: String,
    /// What each edit changed, in the order of the edits.
    pub changes: Vec<Change>,
}

/// Why the edits could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    /// The text is not TOML. Carries the parser's message.
    #[error("{0}")]
    Syntax(String),
    /// A value does not fit its setting.
    #[error("{0}")]
    Value(String),
    /// One request names a setting twice, so one edit would undo the other.
    #[error("`{0}` is named twice")]
    Repeated(&'static str),
    /// The file holds something else where the setting goes: a table the
    /// setting's table is not (`persona = 5`), or a table where its value is.
    #[error("`{key}` cannot be changed: `{at}` is {found} in the file")]
    Blocked {
        /// The setting.
        key: &'static str,
        /// The key in the file that is in the way.
        at: &'static str,
        /// What it is, with its article ("an integer").
        found: String,
    },
}

/// Make `edits` on the text of a `nails.toml`, in order.
///
/// The text that comes back is the text as it was when no edit changes a
/// value, byte for byte, so a caller writes nothing then.
///
/// # Errors
///
/// [`EditError`] when the text is not TOML, a value does not fit its setting,
/// a setting is named twice, or the file holds something else where a value
/// goes.
pub fn apply(text: &str, edits: &[Edit]) -> Result<Edited, EditError> {
    for (index, edit) in edits.iter().enumerate() {
        let key = edit.setting().key;
        if edits[..index].iter().any(|seen| seen.setting().key == key) {
            return Err(EditError::Repeated(key));
        }
        if let Edit::Set(setting, value) = edit {
            setting.check(value).map_err(EditError::Value)?;
        }
    }
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|error: toml_edit::TomlError| EditError::Syntax(error.message().to_string()))?;
    let mut changes = Vec::with_capacity(edits.len());
    for edit in edits {
        changes.push(document::make(&mut doc, edit)?);
    }
    let text = if changes.iter().any(Change::changed) {
        doc.to_string()
    } else {
        text.to_string()
    };
    Ok(Edited { text, changes })
}

/// Every comment of a TOML document, in the order it is written, for the tests
/// and the fuzz target that check an edit loses none.
#[cfg(any(test, feature = "test-support"))]
pub fn comments(text: &str) -> Option<Vec<String>> {
    let doc: toml_edit::DocumentMut = text.parse().ok()?;
    Some(document::comments(&doc))
}
