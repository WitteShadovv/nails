// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The paths the files name, as the check resolves them: with `~`, `$HOME`,
//! `$ZDOTDIR` and `$XDG_CONFIG_HOME` in them, and the directories `ZDOTDIR`
//! and `XDG_CONFIG_HOME` may name as the files set them.

use super::{GLOB, Reader, Word};
use crate::Filesystem;
use std::path::PathBuf;

impl<F: Filesystem> Reader<'_, F> {
    /// The paths `value` may name: one for each value `XDG_CONFIG_HOME` may
    /// have, each different one once; `None` when one of them is no path the
    /// check can know.
    pub(super) fn resolve(&self, value: &Word) -> Option<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for config in &self.xdg_config_homes {
            let path = self.resolve_in(value, config.as_deref())?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        (!paths.is_empty()).then_some(paths)
    }

    /// The path `value` names with `XDG_CONFIG_HOME` set to `config` as
    /// written, or unset: with `~`, `$HOME`, `$ZDOTDIR`, `$XDG_CONFIG_HOME`
    /// and their `${...:-...}` defaults in it, a `$ZDOTDIR` that neither the
    /// shell's environment nor a file sets being empty, as zsh expands it
    /// (`$ZDOTDIR/x` is `/x`), and a `$HOME` that a letter, a digit or a `_`
    /// follows being another parameter (`$HOMEBREW`); `None` when it names
    /// anything else the check cannot know, a modifier or a subscript on one
    /// of them among it (`$HOME:a`, `$ZDOTDIR:h`), or no absolute path.
    pub(super) fn resolve_in(&self, value: &Word, config: Option<&str>) -> Option<PathBuf> {
        let home = self.home?.to_string_lossy().into_owned();
        let default_config = format!("{home}/.config");
        let config = config.map(str::to_string);
        let zdotdir = match self.zdotdirs.as_slice() {
            [one] => Some(one.to_string_lossy().into_owned()),
            _ => None,
        };
        let bare_zdotdir = if self.zdotdir_set {
            zdotdir.clone()
        } else {
            Some(String::new())
        };
        let mut text = value.text.clone();
        if value.expands {
            for (pattern, with) in [
                (
                    "${XDG_CONFIG_HOME:-$HOME/.config}",
                    config.clone().or(Some(default_config.clone())),
                ),
                (
                    "${XDG_CONFIG_HOME:-${HOME}/.config}",
                    config.clone().or(Some(default_config.clone())),
                ),
                (
                    "${XDG_CONFIG_HOME:-~/.config}",
                    config.clone().or(Some(default_config)),
                ),
                ("${ZDOTDIR:-$HOME}", zdotdir.clone()),
                ("${ZDOTDIR:-${HOME}}", zdotdir.clone()),
                ("${ZDOTDIR:-~}", zdotdir.clone()),
                ("${XDG_CONFIG_HOME}", config.clone()),
                ("$XDG_CONFIG_HOME", config),
                ("${ZDOTDIR}", bare_zdotdir.clone()),
                ("$ZDOTDIR", bare_zdotdir),
                ("${HOME}", Some(home.clone())),
                ("$HOME", Some(home.clone())),
            ] {
                if text.contains(pattern) {
                    text = replace_parameter(&text, pattern, &with?);
                }
            }
        }
        if text == "~" || text.starts_with("~/") {
            text = format!("{home}{}", &text[1..]);
        }
        let plain = !text.contains(['$', '`', '~']) && !text.contains(GLOB);
        let path = PathBuf::from(text);
        (plain && path.is_absolute()).then_some(path)
    }

    /// Note the value `value` a file at `place` gives `ZDOTDIR` or
    /// `XDG_CONFIG_HOME` (`name`); `certain` when the assignment certainly
    /// runs.
    pub(super) fn assign(&mut self, name: &str, value: Word, certain: bool, place: &str) {
        if name == "XDG_CONFIG_HOME" {
            let config = Some(value.text);
            if certain {
                self.xdg_config_homes = vec![config];
            } else if !self.xdg_config_homes.contains(&config) {
                self.xdg_config_homes.push(config);
            }
            return;
        }
        match self.resolve(&value) {
            Some(dirs) if certain => {
                self.zdotdir_set = true;
                self.zdotdirs = dirs;
            }
            Some(dirs) => {
                self.zdotdir_set = true;
                for dir in dirs {
                    if !self.zdotdirs.contains(&dir) {
                        self.zdotdirs.push(dir);
                    }
                }
            }
            None => {
                self.zdotdir_set = true;
                if certain {
                    // zsh reads the user's files somewhere else now.
                    self.zdotdirs.clear();
                }
                self.doubt(format!(
                    "it cannot follow the ZDOTDIR that {place} sets (`{}`)",
                    value.text
                ));
            }
        }
    }
}

/// `text` with each `pattern`, a parameter's expansion as written (`$HOME`,
/// `${HOME}`), put as `with`, but where a letter, a digit or a `_` follows a
/// `$name` form, which makes it another parameter's name (`$HOMEBREW`), or a
/// `:` or a `[`, with which zsh applies a modifier (`$HOME:a`, `$HOME:h`) or
/// a subscript (`$HOME[1,-1]`) to the value: it stays as written, a path the
/// check cannot know.
fn replace_parameter(text: &str, pattern: &str, with: &str) -> String {
    let braced = pattern.ends_with('}');
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(pattern) {
        let after = &rest[at + pattern.len()..];
        out.push_str(&rest[..at]);
        if braced
            || !after
                .starts_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '['))
        {
            out.push_str(with);
        } else {
            out.push_str(pattern);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}
