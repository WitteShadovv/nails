// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails config set` and `nails config unset`: change settings in the
//! configuration file through the engine's writer
//! ([`nails_core::app::config_edit`]), which keeps the file's comments and
//! every other key, checks the result as `config validate` does and writes
//! nothing anywhere but the configuration beside the binary on its volume.
//! Under `--json` each prints one version-2 envelope line on stdout, errors
//! included.

use std::path::Path;

use nails_core::app::config_edit::{self, Applied, Edit, Failure};

use super::config_read_hint;
use crate::cli::output::envelope::{Envelope, ErrorBody, error_envelope, write_human_error};

/// What a subcommand prints and how it exits.
pub(super) struct Printed {
    /// The exit code.
    pub(super) code: i32,
    /// What goes to stdout.
    pub(super) stdout: String,
    /// What goes to stderr.
    pub(super) stderr: String,
}

/// `config set <key> <value>...`.
pub(super) fn set(
    config_override: Option<&Path>,
    key: &str,
    words: &[String],
    json: bool,
) -> Printed {
    let Some(setting) = config_edit::setting(key) else {
        return usage(config_edit::unknown_key(key), json);
    };
    match setting.parse(words) {
        Ok(value) => edit(
            config_override,
            &[Edit::Set(setting, value)],
            "config set",
            json,
        ),
        Err(message) => usage(message, json),
    }
}

/// `config unset <key>...`.
pub(super) fn unset(config_override: Option<&Path>, keys: &[String], json: bool) -> Printed {
    let mut edits = Vec::with_capacity(keys.len());
    for key in keys {
        match config_edit::setting(key) {
            Some(setting) => edits.push(Edit::Unset(setting)),
            None => return usage(config_edit::unknown_key(key), json),
        }
    }
    edit(config_override, &edits, "config unset", json)
}

fn edit(config_override: Option<&Path>, edits: &[Edit], command: &str, json: bool) -> Printed {
    match config_edit::edit(config_override, edits) {
        Ok(applied) if json => Printed {
            code: 0,
            stdout: format!(
                "{}\n",
                Envelope::success("config", applied.data()).to_line()
            ),
            stderr: String::new(),
        },
        Ok(applied) => Printed {
            code: 0,
            stdout: human(&applied),
            stderr: String::new(),
        },
        Err(failure) => failed(&failure, command, json),
    }
}

fn usage(message: String, json: bool) -> Printed {
    failed(&Failure::Usage(message), "config", json)
}

/// The error body of a refused or failed edit by `command`, with the `sudo`
/// line when a read or a write was refused for lack of permission.
pub(crate) fn failure_body(failure: &Failure, command: &str) -> ErrorBody {
    let exe = std::env::current_exe().ok();
    let body = failure.body(exe.as_deref());
    match failure
        .error()
        .and_then(|error| config_read_hint(error, command))
    {
        Some(hint) => body.with_hint(hint),
        None => body,
    }
}

/// A refused or failed edit, as one error envelope on stdout under `--json`
/// or the human error on stderr.
fn failed(failure: &Failure, command: &str, json: bool) -> Printed {
    let body = failure_body(failure, command);
    let code = i32::from(failure.exit_status().code());
    if json {
        return Printed {
            code,
            stdout: format!("{}\n", error_envelope("config", body).to_line()),
            stderr: String::new(),
        };
    }
    let mut stderr = Vec::new();
    write_human_error(&mut stderr, &body);
    Printed {
        code,
        stdout: String::new(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// One line per key with its value before and after, the file, and in a
/// hidden session when the change reaches its runtime units.
fn human(applied: &Applied) -> String {
    let mut out = String::new();
    for change in &applied.changes {
        let key = change.key;
        let line = match (&change.before, &change.after) {
            (_, Some(after)) if !change.changed() => format!("{key} = {after} (already)"),
            (Some(before), Some(after)) => format!("{key} = {after} (was {before})"),
            (None, Some(after)) => format!("{key} = {after} (was not set)"),
            (Some(before), None) => format!("{key} removed (was {before}): its default applies"),
            (None, None) => format!("{key} is not set"),
        };
        out.push_str(&line);
        out.push('\n');
    }
    let path = applied.path.display();
    if applied.written {
        out.push_str(&format!("Wrote {path}.\n"));
    } else {
        out.push_str(&format!("{path} is unchanged.\n"));
    }
    if applied.written && applied.in_session {
        out.push_str(
            "The watcher and the sleep guard of this hidden session keep the settings\n\
             it started with until the next activation.\n",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::config::edit::Change;
    use std::path::PathBuf;

    fn applied(changes: Vec<Change>, written: bool, in_session: bool) -> Applied {
        Applied {
            path: PathBuf::from("/mnt/data/config/nails.toml"),
            changes,
            written,
            in_session,
        }
    }

    /// What `edit` changes in a file that says `persona.mode = before`.
    fn change(before: Option<&str>, edit: Edit) -> Change {
        let text = before.map_or(String::new(), |mode| {
            format!("[persona]\nmode = {mode:?}\n")
        });
        nails_core::config::edit::apply(&text, &[edit])
            .unwrap()
            .changes
            .remove(0)
    }

    fn fresh() -> Edit {
        let setting = config_edit::setting("persona.mode").unwrap();
        Edit::Set(setting, config_edit::Value::Text("fresh-home".into()))
    }

    fn removed() -> Edit {
        Edit::Unset(config_edit::setting("persona.mode").unwrap())
    }

    #[test]
    fn each_change_reads_as_one_line_and_the_file_as_the_last() {
        let changes = vec![
            change(Some("shared-home"), fresh()),
            change(None, fresh()),
            change(Some("fresh-home"), fresh()),
            change(Some("fresh-home"), removed()),
            change(None, removed()),
        ];
        assert_eq!(
            human(&applied(changes, true, false)),
            "\
persona.mode = \"fresh-home\" (was \"shared-home\")
persona.mode = \"fresh-home\" (was not set)
persona.mode = \"fresh-home\" (already)
persona.mode removed (was \"fresh-home\"): its default applies
persona.mode is not set
Wrote /mnt/data/config/nails.toml.
"
        );
        assert_eq!(
            human(&applied(vec![change(None, removed())], false, true)),
            "persona.mode is not set\n/mnt/data/config/nails.toml is unchanged.\n"
        );
        let session = human(&applied(vec![change(None, fresh())], true, true));
        assert!(
            session.ends_with("keep the settings\nit started with until the next activation.\n"),
            "{session}"
        );
    }

    #[test]
    fn an_unknown_key_or_a_bad_value_is_a_usage_error_before_any_file_is_read() {
        let missing = Path::new("/nonexistent/config/nails.toml");
        let printed = set(Some(missing), "persona.mod", &["fresh-home".into()], false);
        assert_eq!(printed.code, 2);
        assert_eq!(
            printed.stderr,
            "error: unknown key `persona.mod` (did you mean `persona.mode`?)\n"
        );
        let printed = set(Some(missing), "minimum_space_mb", &["lots".into()], true);
        assert_eq!(printed.code, 2);
        let value: serde_json::Value = serde_json::from_str(printed.stdout.trim()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["command"], "config");
        assert_eq!(value["error"]["code"], "usage");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("`minimum_space_mb` takes a whole number"),
            "{value}"
        );
        let printed = unset(
            Some(missing),
            &["persona.mode".into(), "bogus".into()],
            false,
        );
        assert_eq!(printed.code, 2);
        assert!(
            printed.stderr.contains("unknown key `bogus`"),
            "{}",
            printed.stderr
        );
    }
}
