// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions of zsh's own that the check knows by their code: the
//! stock `promptinit` and the ones it autoloads, as zsh 5.9, 5.9.1 and 5.9.2
//! ship them. A file whose bytes are one of those is read for what that code
//! does ([`Stock`]); any other, a changed one too, is read as code like any
//! function the files autoload. A function named `compinit` is none of them:
//! wherever zsh may load one, the check doubts what zsh runs as you complete
//! a word ([`super::completion`]).
//!
//! What each does, as its code shows, is what the check counts for it:
//!
//! - `promptinit` autoloads `add-zsh-hook` and `add-zle-hook-widget`, and
//!   marks the prompt themes it finds in `fpath`, the `prompt_*_setup` files,
//!   to be autoloaded. It defines `prompt`, which runs the theme it names
//!   (`prompt suse` runs `prompt_suse_setup`) each time it runs, a hook's
//!   among them, may turn `PROMPT_SUBST` on as
//!   the theme asks, keeps code a theme gives it to run as the theme changes
//!   (`prompt_cleanup`), and keeps code to restore the prompt, which runs
//!   `prompt_default_setup` (`prompt restore`).
//! - `add-zsh-hook` and `add-zle-hook-widget` make the function they are
//!   given a hook, which the walk reads where they are run
//!   ([`super::walk::Event::Hook`]), or take one away.

use super::{Reader, Word};
use crate::Filesystem;
use sha2::{Digest, Sha256};
use std::path::Path;

/// A function of zsh's own whose stock code the check knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stock {
    Promptinit,
    AddZshHook,
    AddZleHookWidget,
}

/// The stock functions: the name zsh autoloads each by, what it is, and the
/// SHA-256 of its file as a release ships it.
const STOCK: [(&str, Stock, &str); 3] = [
    // zsh 5.9 to 5.9.2.
    (
        "promptinit",
        Stock::Promptinit,
        "6cfb00c4be9b13b11e116b131d6650febc11a09a366e2a6cf929bf4f9b6c66f9", // pragma: allowlist secret
    ),
    (
        "add-zsh-hook",
        Stock::AddZshHook,
        "f0e9ac9dfe1b2367164d6674924b5297621881a4a325860942d72ec7f7281a8d", // pragma: allowlist secret
    ),
    (
        "add-zle-hook-widget",
        Stock::AddZleHookWidget,
        "0d00fe1f9ca24ab43d38d11e30ae2dcab64ecb375aad0c688d6c65a976f59d4e", // pragma: allowlist secret
    ),
];

/// The SHA-256 of `bytes`, in lower-case hex.
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The stock function the file of the function `name` holds, when its bytes
/// are that function's as a release ships them.
pub(super) fn known(name: &str, bytes: &[u8]) -> Option<Stock> {
    let digest = digest(bytes);
    let digest = digest.as_str();
    #[cfg(test)]
    if let Some(stock) = tests::known(name, digest) {
        return Some(stock);
    }
    STOCK
        .iter()
        .find(|(stock_name, _, stock_digest)| *stock_name == name && *stock_digest == digest)
        .map(|(_, stock, _)| *stock)
}

impl<F: Filesystem> Reader<'_, F> {
    /// Read the file at `path` of the function `name` the files autoload:
    /// for `compinit`, a doubt of what zsh runs as you complete a word
    /// ([`Reader::completion_system`]); for what its code does when it is a
    /// stock function of zsh's own ([`known`]); else as code like any file.
    pub(super) fn function(&mut self, path: &Path, name: &str) {
        let was = std::mem::replace(&mut self.function_code, true);
        let text = self.text(path);
        self.function_code = was;
        let Some(text) = text else {
            return;
        };
        if name == "compinit" {
            self.completion_system();
            return;
        }
        match known(name, text.as_bytes()) {
            Some(stock) => {
                // zsh expands the aliases the files define in its code as it
                // loads it unless the files autoload it with -U, so its words
                // count as uses of an alias then.
                if self.expanding.iter().any(|expanding| expanding == name) {
                    self.lines(&text, &path.to_string_lossy());
                    // It makes no file the check would read before zsh
                    // reads it.
                    self.stock_texts.push(self.texts.len() - 1);
                }
                self.stock(stock);
            }
            // The file is the function's code.
            None => self.code_in(path, &text, false, Some(name.to_string())),
        }
    }

    /// Note what the stock function `stock` does ([`stock`]).
    fn stock(&mut self, stock: Stock) {
        match stock {
            Stock::Promptinit => {
                self.promptinit = true;
                // A theme may ask for it.
                self.prompt_subst = true;
                for name in ["add-zsh-hook", "add-zle-hook-widget"] {
                    self.autoload_name(name, Some("promptinit"));
                }
            }
            Stock::AddZshHook | Stock::AddZleHookWidget => {}
        }
    }

    /// Whether the function `name` is a prompt theme the stock `promptinit`
    /// the files autoload marks to be autoloaded (`prompt_suse_setup`), which
    /// zsh runs only when it is run by name or as a hook.
    fn marks(&self, name: &str) -> bool {
        self.promptinit && name.starts_with("prompt_") && name.ends_with("_setup")
    }

    /// Follow what the stock `promptinit` the files autoload reads and runs:
    /// the prompt themes `prompt` runs, and the themes it marks that the files
    /// run by name or make hooks.
    pub(super) fn marked(&mut self) {
        for (name, args, place) in self.calls.clone() {
            if self.promptinit && name == "prompt" {
                // The code `prompt` keeps to restore the prompt, which a
                // theme runs (`prompt restore`), runs prompt_default_setup;
                // it runs the functions promptinit defines, which a file may
                // define in their place, as it runs, a hook among what runs it.
                self.autoload_name("prompt_default_setup", Some("prompt"));
                for helper in [
                    "prompt_default_setup",
                    "set_prompt",
                    "prompt_preview_safely",
                    "prompt_preview_theme",
                ] {
                    let edge = ("prompt".to_string(), helper.to_string());
                    if !self.edges.contains(&edge) {
                        self.edges.push(edge);
                    }
                }
                self.prompt(&args, &place);
            } else if self.promptinit
                && matches!(
                    name.as_str(),
                    "prompt_cleanup"
                        | "prompt_preview_safely"
                        | "prompt_preview_theme"
                        | "set_prompt"
                )
            {
                self.doubt(format!(
                    "it cannot follow the code that `{name}` in {place} runs, which promptinit \
                     defines"
                ));
            } else if self.marks(&name) {
                self.autoload_name(&name, None);
            }
        }
        for hook in self.hooks.clone() {
            if self.marks(&hook) {
                self.autoload_name(&hook, None);
            }
        }
    }

    /// Note the prompt theme a call of `prompt` with `args` in the file at
    /// `place` runs, once the stock `promptinit` defines it: the one it names
    /// (`prompt suse`), or with `-h`, `-s` or `-p` the ones after it; none
    /// with `-c` or `-l`. One it picks itself (`random`, `-p` alone), or that
    /// an expansion names, is a doubt.
    fn prompt(&mut self, args: &[Word], place: &str) {
        let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
        let doubt = || {
            format!(
                "it cannot tell which prompt theme `prompt {}` in {place} runs",
                words.join(" ")
            )
        };
        let theme = |name: &str| {
            (!name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
            .then(|| format!("prompt_{name}_setup"))
        };
        if args.iter().any(|arg| arg.expands || arg.bare) {
            let doubt = doubt();
            self.doubt(doubt);
            return;
        }
        let themes: Vec<&str> = match words.first().copied() {
            None => Vec::new(),
            Some("random") => vec![""],
            Some(flag) if flag.starts_with('-') => match flag.chars().nth(1) {
                Some('c' | 'l') => Vec::new(),
                Some('h' | 's') => words.get(1).copied().into_iter().collect(),
                Some('p') if words.len() > 1 => words[1..].to_vec(),
                Some('p') => vec![""],
                _ => Vec::new(),
            },
            Some(name) => vec![name],
        };
        for name in themes {
            match theme(name) {
                Some(function) => {
                    // A theme runs as `prompt` does, a hook's among them.
                    let edge = ("prompt".to_string(), function.clone());
                    if !self.edges.contains(&edge) {
                        self.edges.push(edge);
                    }
                    self.autoload_name(&function, Some("prompt"));
                }
                None => {
                    let doubt = doubt();
                    self.doubt(doubt);
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{Stock, digest};

    /// The text a test gives a stock function's file, which the check takes
    /// for the stock code of `name` in a test, as no test carries zsh's own.
    pub(in super::super) fn text(name: &str) -> String {
        format!("# The stock {name} of a test.\ntypeset -A _i_test\n")
    }

    /// The stock function `name` is in a test when `digest` is that of its
    /// [`text`].
    pub(super) fn known(name: &str, digest: &str) -> Option<Stock> {
        let stock = match name {
            "promptinit" => Stock::Promptinit,
            "add-zsh-hook" => Stock::AddZshHook,
            "add-zle-hook-widget" => Stock::AddZleHookWidget,
            _ => return None,
        };
        (digest == super::digest(text(name).as_bytes())).then_some(stock)
    }

    #[test]
    fn a_stock_function_is_known_by_its_name_and_its_bytes_alone() {
        assert_eq!(
            super::known("promptinit", text("promptinit").as_bytes()),
            Some(Stock::Promptinit)
        );
        // The same bytes under another name, or other bytes, are no stock
        // function, and compinit is none whatever its bytes.
        assert_eq!(
            super::known("add-zsh-hook", text("promptinit").as_bytes()),
            None
        );
        assert_eq!(
            super::known("promptinit", b"# The stock promptinit of a test.\n"),
            None
        );
        assert_eq!(super::known("compinit", text("compinit").as_bytes()), None);
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // pragma: allowlist secret
        );
    }

    /// Where the dev shell has zsh from the Nix store, its own functions are
    /// the ones the check knows.
    #[test]
    fn the_functions_of_the_zsh_of_the_dev_shell_are_known() {
        let Some(zsh) = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("zsh"))
            .find(|path| path.is_file())
            .and_then(|path| std::fs::canonicalize(path).ok())
        else {
            return;
        };
        let Some(version) = zsh
            .to_str()
            .and_then(|path| path.strip_prefix("/nix/store/"))
            .and_then(|path| path.strip_suffix("/bin/zsh"))
            .and_then(|name| name.split_once("-zsh-"))
            .map(|(_, version)| version.to_string())
        else {
            return;
        };
        let functions = zsh
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the store path")
            .join("share/zsh")
            .join(&version)
            .join("functions");
        for name in ["promptinit", "add-zsh-hook", "add-zle-hook-widget"] {
            let bytes = std::fs::read(functions.join(name)).expect("zsh's own function");
            assert!(
                super::STOCK
                    .iter()
                    .any(|(stock, _, known)| *stock == name && *known == digest(&bytes)),
                "{name} of zsh {version} is not among the stock functions"
            );
        }
    }
}
