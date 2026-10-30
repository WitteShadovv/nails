// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! Settings: every setting of `nails.toml` from `nails config show`, and a
//! change of one through `config set` or `config unset`, as a plan, its
//! token and its apply.
//!
//! The page lists each key the engine can set ([`nails_api::settings`]), its
//! value and where the value comes from; a row opens the key's page. There a
//! switch's two states or a choice's options are rows to pick, and a number,
//! a path, a flake or a list of names is a field to type, with Save…; Use
//! the Default… removes a key the file sets. Every change goes to the
//! engine's plan first, whose answer the question shows, each key from its
//! value before to its value after; only Save sends the apply, with the
//! plan's token. A saved change, or a file that changed before the apply
//! (`plan_stale`), reads the settings again.
//!
//! What the window offers, and what it does with an answer it does not
//! expect:
//!
//! - In a hidden session the hidden volume and the record cannot move: the
//!   engine refuses that, so their pages say why and offer no change. Once
//!   the engine refused such a change anywhere else (an entry under way or
//!   left behind), their pages say its words and offer none either.
//! - A value is sent only once it has the shape its kind takes (a whole
//!   number, a full path, a flake, one name or more) and fits in a request;
//!   the engine checks the rest, such as where a path may lie, and says what
//!   is wrong before anything is written.
//! - Use the Default… is offered only for a key the settings file sets
//!   itself, as `config show` names the source of each key.
//! - A plan whose changes are not the ones asked for is withdrawn. Any other
//!   answer the window cannot read changes nothing more and has the settings
//!   read again; settings that cannot be read leave nothing to offer but
//!   reading them again.

use nails_api::protocol::{
    ConfigEditArgs, ConfigEditPlanData, MAX_LIST_ENTRIES, MAX_SETTING_BYTES, SettingArg,
    SettingValue,
};
use nails_api::settings::{self as keys, Kind as KeyKind, SESSION_KEYS, SETTINGS};
use serde_json::Value;

use super::{Context, ToolKind, error_of, tool_page};
use crate::client::{Answer, Plan};
use crate::envelope::{self, ConfigEditData, ConfigShowData};
use crate::model::{Choice, Field, Page, Question};
use crate::text;
use crate::worker::{Ask, Kind};

/// What Settings knows.
#[derive(Debug, Clone, Default)]
pub(crate) struct Settings {
    /// What `config show` said last.
    shown: Option<ConfigShowData>,
    /// Why the settings could not be read, when they could not.
    unreadable: Option<String>,
    /// The key whose page is open, by its place in [`SETTINGS`].
    editing: Option<usize>,
    /// What is typed in that page's field.
    typed: String,
    /// The change the last plan was asked for, to check its answer against.
    asked: Option<ConfigEditArgs>,
    /// What the last change did, or why it did not.
    notice: Option<String>,
    /// The engine's refusal of a change of the hidden volume or the record
    /// for a session it sees, once it came: from then on neither changes
    /// here.
    held: Option<String>,
}

impl Settings {
    /// A Settings page that opens, and the read it asks for first.
    pub(crate) fn open() -> (Self, Ask) {
        (Self::default(), Ask::ConfigShow)
    }

    /// Back from a key's page to the list: true when the page took it.
    pub(crate) fn back(&mut self) -> bool {
        let took = self.editing.take().is_some();
        if took {
            self.notice = None;
        }
        took
    }

    /// The field changed to `typed`.
    pub(crate) fn edited(&mut self, typed: &str) {
        typed.clone_into(&mut self.typed);
    }

    /// The ask for the page's action `label`, in a hidden session when
    /// `hidden`.
    pub(crate) fn action(&mut self, label: &str, hidden: bool) -> Option<Ask> {
        match label {
            text::READ_AGAIN => Some(Ask::ConfigShow),
            text::SAVE_ACTION => {
                let setting = self.editable(hidden)?;
                let value = typed_value(setting, &self.typed)?;
                Some(self.plan_set(setting.key, value))
            }
            text::USE_DEFAULT => {
                let setting = self.editable(hidden)?;
                if self.source(setting) != "file" {
                    // Offered only where the file sets the key itself.
                    return None;
                }
                Some(self.plan(ConfigEditArgs {
                    set: Vec::new(),
                    unset: vec![setting.key.to_string()],
                }))
            }
            _ => None,
        }
    }

    /// The person picked row `index`: on the list, a key's page; on a key's
    /// page, a state or an option, whose plan it asks for.
    pub(crate) fn choose(&mut self, index: usize, hidden: bool) -> Option<Ask> {
        if self.editing.is_none() {
            if self.shown.is_none() || index >= SETTINGS.len() {
                return None;
            }
            self.editing = Some(index);
            self.notice = None;
            self.typed = self.field_text(&SETTINGS[index]);
            return None;
        }
        let setting = self.editable(hidden)?;
        let value = match setting.kind {
            KeyKind::Bool => SettingValue::Bool(index == 0),
            KeyKind::Choice(options) => SettingValue::Text((*options.get(index)?).to_string()),
            _ => return None,
        };
        if Some(json_of(&value)) == self.value(setting) {
            // Already so: nothing to change.
            return None;
        }
        Some(self.plan_set(setting.key, value))
    }

    /// The setting whose page is open, when it can change here.
    fn editable(&self, hidden: bool) -> Option<&'static keys::Setting> {
        let setting = &SETTINGS[self.editing?];
        (self.shown.is_some() && self.fixed(setting, hidden).is_none()).then_some(setting)
    }

    /// Why `setting` cannot change here, in a hidden session when `hidden`:
    /// the hidden volume and the record stay where a session recorded them.
    fn fixed(&self, setting: &keys::Setting, hidden: bool) -> Option<String> {
        if !SESSION_KEYS.contains(&setting.key) {
            return None;
        }
        if hidden {
            Some(text::SESSION_KEY_FIXED.to_string())
        } else {
            self.held.clone()
        }
    }

    fn plan_set(&mut self, key: &str, value: SettingValue) -> Ask {
        self.plan(ConfigEditArgs {
            set: vec![SettingArg {
                key: key.to_string(),
                value,
            }],
            unset: Vec::new(),
        })
    }

    fn plan(&mut self, args: ConfigEditArgs) -> Ask {
        self.asked = Some(args.clone());
        self.notice = None;
        Ask::Plan(Plan::ConfigEdit(args))
    }

    /// The question of the plan `data`, or `None` when its changes are not
    /// the ones asked for: the window then withdraws it.
    pub(crate) fn question(&self, data: &ConfigEditPlanData) -> Option<Question> {
        let asked = self.asked.as_ref()?;
        let named: Vec<&str> = asked
            .set
            .iter()
            .map(|setting| setting.key.as_str())
            .chain(asked.unset.iter().map(String::as_str))
            .collect();
        let answered: Vec<&str> = data
            .changes
            .iter()
            .map(|change| change.key.as_str())
            .collect();
        if named != answered {
            return None;
        }
        let mut lines: Vec<String> = data
            .changes
            .iter()
            .map(|change| {
                let setting = keys::setting(&change.key);
                text::change_line(
                    text::setting(&change.key).0,
                    &shown_or_default(setting, change.before.as_ref()),
                    &shown_or_default(setting, change.after.as_ref()),
                )
            })
            .collect();
        lines.push(text::SETTINGS_WHEN.to_string());
        lines.push(text::saved_in(&data.path));
        Some(Question {
            heading: text::SAVE_QUESTION.to_string(),
            body: lines.join("\n"),
            confirm: text::SAVE.to_string(),
            destructive: false,
            prompt: None,
            locked: false,
            alternative: None,
        })
    }

    /// Take in the answer of `kind`: a read, a plan that settled, or the
    /// apply. Returns what follows.
    pub(crate) fn answered(&mut self, kind: Kind, answer: &Answer) -> Vec<Ask> {
        if kind == Kind::Config {
            self.read(answer);
            return Vec::new();
        }
        let applied = kind == Kind::Apply;
        match envelope::read::<ConfigEditData>(&answer.envelope, "config") {
            Ok(read) => match (read.data, error_of(&answer.envelope)) {
                (Some(data), _) if !data.written => {
                    // The page may have shown another value: read it again.
                    self.notice = Some(text::ALREADY_SAID.to_string());
                    vec![Ask::ConfigShow]
                }
                (Some(_), _) if applied => {
                    self.notice = Some(text::SAVED.to_string());
                    // Back to the list, which the read brings up to date.
                    self.editing = None;
                    vec![Ask::ConfigShow]
                }
                // A plan that wrote without an apply is no answer the window
                // expects.
                (Some(_), _) => self.unexpected(),
                (None, Some((code, message))) => match code.as_str() {
                    "plan_stale" => {
                        self.notice = Some(text::STALE.to_string());
                        vec![Ask::ConfigShow]
                    }
                    "session_paths" => {
                        // The engine sees a session the window did not: the
                        // two keys hold still from now on, in its words.
                        self.held = Some(message.clone());
                        self.notice = Some(message);
                        Vec::new()
                    }
                    _ => {
                        self.notice = Some(message);
                        Vec::new()
                    }
                },
                (None, None) => self.unexpected(),
            },
            Err(_) => self.unexpected(),
        }
    }

    /// An answer the window did not expect: it changes nothing more and
    /// reads the settings again, which says where things stand.
    fn unexpected(&mut self) -> Vec<Ask> {
        self.notice = Some(text::UNEXPECTED_SETTINGS.to_string());
        vec![Ask::ConfigShow]
    }

    /// Take in an answer of `config show`.
    fn read(&mut self, answer: &Answer) {
        match envelope::read::<ConfigShowData>(&answer.envelope, "config") {
            Ok(read) => match (read.data, error_of(&answer.envelope)) {
                (Some(data), _) => {
                    self.shown = Some(data);
                    self.unreadable = None;
                }
                (None, Some((_, message))) => self.cannot_read(message),
                (None, None) => self.cannot_read(text::UNEXPECTED_SETTINGS.to_string()),
            },
            Err(error) => self.cannot_read(text::sentence(&error.0)),
        }
    }

    /// The settings cannot be read: nothing is offered but reading them
    /// again.
    fn cannot_read(&mut self, message: String) {
        self.shown = None;
        self.editing = None;
        self.unreadable = Some(message);
    }

    /// The page.
    pub(crate) fn page(&self, cx: &Context) -> Page {
        let mut page = match (&self.shown, self.editing) {
            _ if self.unreadable.is_some() => Page {
                heading: text::SETTINGS_UNREADABLE.to_string(),
                note: self.unreadable.clone().unwrap_or_default(),
                urgent: true,
                action: Some(text::READ_AGAIN),
                ..tool_page(ToolKind::Settings, text::NOTHING_CHANGED)
            },
            (None, _) => Page {
                busy: Some(text::READING_SETTINGS.to_string()),
                ..tool_page(ToolKind::Settings, text::SETTINGS_WHEN)
            },
            (Some(shown), None) => self.list_page(shown),
            (Some(_), Some(index)) => self.key_page(&SETTINGS[index], cx.hidden),
        };
        if let Some(notice) = self.notice.as_ref().filter(|notice| **notice != page.note) {
            page.note = crate::model::pages::join(notice, &page.note);
        }
        page.busy = match cx.running {
            Some(Kind::Plan) => Some(text::CHECKING_CHANGE.to_string()),
            Some(Kind::Apply) => Some(text::SAVING.to_string()),
            Some(Kind::Config) => Some(text::READING_SETTINGS.to_string()),
            _ => page.busy,
        };
        page
    }

    /// The list of every key.
    fn list_page(&self, shown: &ConfigShowData) -> Page {
        Page {
            note: text::settings_file(&shown.path, shown.exists),
            choices: SETTINGS
                .iter()
                .map(|setting| Choice {
                    title: text::setting(setting.key).0.to_string(),
                    subtitle: format!(
                        "{}. {}",
                        self.shown_value(setting),
                        text::source(&self.source(setting))
                    ),
                })
                .collect(),
            ..tool_page(ToolKind::Settings, text::SETTINGS_WHEN)
        }
    }

    /// The page of `setting`, where it can change unless it is one of the
    /// keys a session's record names, in a hidden session when `hidden` or
    /// once the engine held them.
    fn key_page(&self, setting: &keys::Setting, hidden: bool) -> Page {
        let (label, what) = text::setting(setting.key);
        let mut page = Page {
            heading: label.to_string(),
            facts: vec![
                (text::FACT_NOW.to_string(), self.shown_value(setting)),
                (
                    text::FACT_FROM.to_string(),
                    text::source(&self.source(setting)).to_string(),
                ),
            ],
            ..tool_page(ToolKind::Settings, what)
        };
        if let Some(why) = self.fixed(setting, hidden) {
            page.note = why;
            return page;
        }
        let now = self.value(setting);
        match setting.kind {
            KeyKind::Bool => {
                page.choices = [(text::ON, true), (text::OFF, false)]
                    .iter()
                    .map(|(title, value)| Choice {
                        title: (*title).to_string(),
                        subtitle: chosen(now.as_ref() == Some(&Value::Bool(*value))),
                    })
                    .collect();
            }
            KeyKind::Choice(options) => {
                page.choices = options
                    .iter()
                    .map(|option| {
                        let (title, line) = text::choice(setting.key, option);
                        let mark = chosen(now.as_ref().and_then(Value::as_str) == Some(*option));
                        Choice {
                            title: title.to_string(),
                            subtitle: if mark.is_empty() {
                                line.to_string()
                            } else {
                                format!("{mark}. {line}")
                            },
                        }
                    })
                    .collect();
            }
            KeyKind::Integer | KeyKind::Path | KeyKind::Text | KeyKind::Names => {
                page.field = Some(Field {
                    label: text::FIELD_VALUE.to_string(),
                    text: self.typed.clone(),
                    hint: text::field_hint(kind_name(setting.kind)).to_string(),
                });
                page.action = Some(text::SAVE_ACTION);
                page.action_locked = typed_value(setting, &self.typed).is_none();
            }
        }
        if self.source(setting) == "file" {
            page.secondary = Some(text::USE_DEFAULT);
            if page.action.is_none() {
                // A second action needs a first beside it: the default is
                // the only action of a page of states or options.
                page.action = page.secondary.take();
            }
        }
        page
    }

    /// The value of `setting` in the last read, as JSON.
    fn value(&self, setting: &keys::Setting) -> Option<Value> {
        let config = &self.shown.as_ref()?.config;
        let mut parts = setting.key.split('.');
        let first = config.get(parts.next()?)?;
        match parts.next() {
            Some(inner) => first.get(inner).cloned(),
            None => Some(first.clone()),
        }
    }

    /// Where the value of `setting` comes from, as `config show` names the
    /// source of each key, a key of a table as `table.key`: the source of
    /// the table says only that the file holds it. A key it names no source
    /// for is of a source not known, never the file's.
    fn source(&self, setting: &keys::Setting) -> String {
        self.shown
            .as_ref()
            .and_then(|shown| shown.sources.get(setting.key))
            .cloned()
            .unwrap_or_default()
    }

    fn shown_value(&self, setting: &keys::Setting) -> String {
        shown(setting, self.value(setting).as_ref())
    }

    /// What a field shows when its page opens: the value now, as typed.
    fn field_text(&self, setting: &keys::Setting) -> String {
        match (setting.kind, self.value(setting)) {
            (KeyKind::Names, Some(Value::Array(names))) => names
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            (_, Some(Value::String(text))) => text,
            (_, Some(Value::Number(number))) => number.to_string(),
            _ => String::new(),
        }
    }
}

/// The mark of the state or option in force.
fn chosen(now: bool) -> String {
    if now {
        text::CHOSEN.to_string()
    } else {
        String::new()
    }
}

fn kind_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Integer => "integer",
        KeyKind::Path => "path",
        KeyKind::Names => "names",
        KeyKind::Bool | KeyKind::Text | KeyKind::Choice(_) => "text",
    }
}

/// The value typed for `setting`, when it has the shape its kind takes and
/// fits in a request.
fn typed_value(setting: &keys::Setting, typed: &str) -> Option<SettingValue> {
    let typed = typed.trim();
    if typed.len() > MAX_SETTING_BYTES || typed.chars().any(char::is_control) {
        return None;
    }
    match setting.kind {
        KeyKind::Integer => typed
            .parse::<u64>()
            .ok()
            .filter(|n| i64::try_from(*n).is_ok())
            .map(SettingValue::Integer),
        KeyKind::Path => typed
            .starts_with('/')
            .then(|| SettingValue::Text(typed.to_string())),
        KeyKind::Text => (!typed.is_empty()).then(|| SettingValue::Text(typed.to_string())),
        // One name at least, as `config set` takes them: Use the Default…
        // is the way back to none.
        KeyKind::Names => {
            let names: Vec<String> = typed
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
            (!names.is_empty() && names.len() <= MAX_LIST_ENTRIES)
                .then_some(SettingValue::List(names))
        }
        KeyKind::Bool | KeyKind::Choice(_) => None,
    }
}

/// `value` as the JSON `config show` and a change's data write it.
fn json_of(value: &SettingValue) -> Value {
    match value {
        SettingValue::Bool(value) => Value::Bool(*value),
        SettingValue::Integer(value) => Value::from(*value),
        SettingValue::Text(value) => Value::String(value.clone()),
        SettingValue::List(values) => Value::from(values.clone()),
    }
}

/// `value` of `setting` as a page shows it.
fn shown(setting: &keys::Setting, value: Option<&Value>) -> String {
    match (setting.kind, value) {
        (_, None | Some(Value::Null)) => text::NOT_SET.to_string(),
        (KeyKind::Bool, Some(Value::Bool(true))) => text::ON.to_string(),
        (KeyKind::Bool, Some(Value::Bool(false))) => text::OFF.to_string(),
        (KeyKind::Choice(_), Some(Value::String(option))) => {
            let (label, _) = text::choice(setting.key, option);
            if label.is_empty() {
                option.clone()
            } else {
                label.to_string()
            }
        }
        (KeyKind::Names, Some(Value::Array(names))) => match names.as_slice() {
            [] => text::NONE.to_string(),
            [one] if one == "*" => text::ALL.to_string(),
            names => names
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        },
        // A space that keeps the number and its unit on one line.
        (KeyKind::Integer, Some(Value::Number(number))) => match text::unit(setting.key) {
            Some(unit) => format!("{number}\u{a0}{unit}"),
            None => number.to_string(),
        },
        (_, Some(Value::String(text))) => text.clone(),
        (_, Some(other)) => other.to_string(),
    }
}

/// A change's value of the key `setting` names, or its default when the
/// file no longer sets it.
fn shown_or_default(setting: Option<&keys::Setting>, value: Option<&Value>) -> String {
    match (setting, value) {
        (_, None | Some(Value::Null)) => text::THE_DEFAULT.to_string(),
        (Some(setting), value) => shown(setting, value),
        (None, Some(value)) => value.to_string(),
    }
}
