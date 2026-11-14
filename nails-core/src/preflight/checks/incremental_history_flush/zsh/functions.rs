// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions the files autoload: where zsh looks for each as it first
//! runs it, the directories the files add to `fpath` and those it starts
//! with ([`super::Install`]), and what reading their files finds.

use super::{GLOB, Late, Reader, Word, zwc};
use crate::Filesystem;
use std::path::PathBuf;

impl<F: Filesystem> Reader<'_, F> {
    /// Note the function `function` that the file at `place` autoloads: by
    /// name, to be looked for where the files add to `fpath`, or by the path
    /// of its file, which is read at once ([`Reader::autoload_path`]); `later`
    /// where code that runs as a function autoloads it, after the files
    /// define it, so its path is read for every value of `ZDOTDIR` and
    /// `XDG_CONFIG_HOME` the files give ([`Reader::late`]).
    pub(super) fn autoload(&mut self, function: Word, place: &str, later: bool) {
        if function.text.contains('/') {
            if later {
                self.late
                    .push(Late::Autoload(function.clone(), place.to_string()));
            }
            self.autoload_path(&function, place, later);
        } else if function.expands || function.text.contains(GLOB) {
            self.doubt(format!(
                "it cannot tell which function `{}` in {place} autoloads",
                function.text
            ));
        } else if !self.autoloads.contains(&function.text) {
            self.autoloads.push(function.text);
        }
    }

    /// Read the file of the function the file at `place` autoloads by its
    /// path `function`, for every value of `ZDOTDIR` and `XDG_CONFIG_HOME`
    /// the files ever give where `ever`: but for one named `compinit`, a
    /// doubt of what zsh runs as you complete a word wherever it is there
    /// ([`Reader::completion_system`]). zsh runs the function from the
    /// compiled code of its file's directory in place of its file, as it does
    /// for an `fpath` directory: a `.zwc` beside that directory, or the
    /// directory itself where its name ends in `.zwc`.
    pub(super) fn autoload_path(&mut self, function: &Word, place: &str, ever: bool) {
        let files = if ever {
            self.resolve_ever(function)
        } else {
            self.resolve(function)
        };
        let Some(files) = files else {
            self.doubt(format!(
                "it cannot follow the function file that {place} autoloads as `{}`",
                function.text
            ));
            return;
        };
        for file in files {
            // zsh puts the file's directory in front of fpath for the
            // functions its code autoloads by name.
            if let Some(dir) = file.parent() {
                let entry = Ok((dir.to_path_buf(), true));
                if !self.fpath.contains(&entry) {
                    self.fpath.push(entry);
                }
                if dir.as_os_str().as_encoded_bytes().ends_with(b".zwc") {
                    self.compiled(dir);
                }
                self.compiled(&zwc(dir));
            }
            let name = file
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            if name.as_deref() == Some("compinit") {
                if self.text(&file).is_some() {
                    self.completion_system();
                }
                continue;
            }
            if !(ever && self.has_read(&file)) {
                self.file_in(&file, false, name);
            }
        }
    }

    /// Note the directory `dir` that the file at `place` adds to `fpath`, as
    /// written, in front where `first`, for every value of `ZDOTDIR` and
    /// `XDG_CONFIG_HOME` the files ever give where `ever` ([`Reader::late`]):
    /// one the check cannot follow is a doubt should a function be
    /// autoloaded.
    pub(super) fn fpath_dir(&mut self, dir: &Word, first: bool, place: &str, ever: bool) {
        let dirs = if ever {
            self.resolve_ever(dir)
        } else {
            self.resolve(dir)
        };
        match dirs {
            // A `:` in it parts it in two where FPATH's value is set from
            // FPATH again (`FPATH=$FPATH:/x`).
            Some(dirs) if !dirs.iter().any(|dir| dir.to_string_lossy().contains(':')) => {
                for dir in dirs {
                    let entry = Ok((dir, first));
                    if !self.fpath.contains(&entry) {
                        self.fpath.push(entry);
                    }
                }
            }
            _ => {
                let doubt = Err(format!(
                    "it cannot follow the directory that {place} adds to fpath as `{}`, where \
                     zsh looks for the functions the files autoload",
                    dir.text
                ));
                if !self.fpath.contains(&doubt) {
                    self.fpath.push(doubt);
                }
            }
        }
    }

    /// Note each element given `fpath` that SH_WORD_SPLIT or KSH_ARRAYS
    /// may change ([`super::Event::FpathSplits`]) as a directory the check cannot
    /// follow, once a file read may turn either on.
    fn split_fpath(&mut self) {
        let Some(place) = self.word_split.clone() else {
            return;
        };
        for (text, at) in std::mem::take(&mut self.fpath_splits) {
            self.fpath.push(Err(format!(
                "it cannot follow the directories that `{text}` gives fpath in {at}, as {place} \
                 may turn SH_WORD_SPLIT or KSH_ARRAYS on, which split them or keep the first, \
                 where zsh looks for the functions the files autoload"
            )));
        }
    }

    /// Read the files of the functions the files read autoload by name in
    /// each directory they add to `fpath`, where zsh looks for them as they
    /// first run, and in those zsh's `fpath` starts with when the check
    /// knows them ([`super::Install::fpath`]), until those files add no more, and
    /// what the stock `promptinit` among them reads and marks
    /// ([`Reader::marked`]). Once a function is autoloaded, a directory the
    /// check cannot follow is a doubt. When the check does not know where
    /// zsh's `fpath` starts, so is a function that no directory zsh looks in
    /// first holds: zsh then finds it in a directory the files do not add,
    /// one it was built with or one `FPATH` names in its environment.
    pub(super) fn autoloaded(&mut self) {
        let mut looked: Vec<PathBuf> = Vec::new();
        let mut digests: Vec<PathBuf> = Vec::new();
        let mut found: Vec<String> = Vec::new();
        loop {
            // What code that runs as a function names, read for each value
            // the files give ZDOTDIR and XDG_CONFIG_HOME.
            let late = self.late();
            let before = (looked.len(), self.autoloads.len(), self.fpath.len());
            self.split_fpath();
            self.profile_dirs();
            self.marked();
            for entry in self.fpath.clone() {
                let (dir, first) = match entry {
                    Ok(entry) => entry,
                    Err(doubt) => {
                        if !self.autoloads.is_empty() && !self.doubts.contains(&doubt) {
                            self.doubt(doubt);
                        }
                        continue;
                    }
                };
                for name in self.autoloads.clone() {
                    let path = dir.join(&name);
                    if first
                        && !found.contains(&name)
                        && matches!(self.fs.inode(&path), Ok(Some(_)))
                    {
                        found.push(name.clone());
                    }
                    if looked.contains(&path) {
                        continue;
                    }
                    looked.push(path.clone());
                    if !digests.contains(&dir) {
                        digests.push(dir.clone());
                        // zsh reads an element whose name ends in `.zwc` as
                        // the compiled code of the functions it holds
                        // (`fpath=(~/zc.zwc $fpath)`), and the `.zwc` beside
                        // a directory as that directory's.
                        if dir.as_os_str().as_encoded_bytes().ends_with(b".zwc") {
                            self.compiled(&dir);
                        }
                        self.compiled(&zwc(&dir));
                    }
                    self.function(&path, &name);
                }
            }
            if !late && (looked.len(), self.autoloads.len(), self.fpath.len()) == before {
                break;
            }
        }
        self.completions();
        if self.install.fpath.is_some() {
            // zsh looks in no directory the check does not read: a function
            // none holds is one zsh cannot load either.
            return;
        }
        let unfound: Vec<String> = self
            .autoloads
            .iter()
            .filter(|name| !found.contains(name))
            .map(|name| format!("`{name}`"))
            .collect();
        if let Some((last, rest)) = unfound.split_last() {
            let names = if rest.is_empty() {
                last.clone()
            } else {
                format!("{} and {last}", rest.join(", "))
            };
            self.doubt(format!(
                "it cannot read the functions the files autoload that no directory they put in \
                 front of fpath holds ({names}), which zsh then finds in one it was built with \
                 or one FPATH names"
            ));
        }
    }
}
