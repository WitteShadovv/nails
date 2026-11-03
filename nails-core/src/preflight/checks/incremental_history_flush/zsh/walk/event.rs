// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the walk finds a file's code does ([`Event`]).

use super::super::lexer::Word;

/// What a file's code does, in order, as [`super::Walker`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum Event {
    /// A `setopt` or the like turns an option on or off; `unconditional`
    /// when it certainly runs at the file's top level.
    Set {
        option: usize,
        on: bool,
        unconditional: bool,
    },
    /// A word names an option outside an understood `setopt`.
    Mention(usize),
    /// A line names an option where the walk read no code: in a comment, or
    /// in what a misread hid.
    Unread(usize),
    /// Something the check cannot follow, as the warning names it.
    Doubt(String),
    /// `source` or `.` of `path`, in the function `function` when in one,
    /// which runs the file's code as its own.
    Source {
        path: Word,
        unconditional: bool,
        function: Option<String>,
    },
    /// Oh My Zsh is loaded.
    OhMyZsh,
    /// `ZDOTDIR` or `XDG_CONFIG_HOME` is set.
    Assign {
        name: &'static str,
        value: Word,
        unconditional: bool,
    },
    /// A directory is added to `fpath`, where zsh looks for the functions it
    /// autoloads: the element as written, or `None` for what a line may add
    /// that the walk did not read; `first` when zsh looks in it before the
    /// directories `fpath` held, as where it is put in front of them or
    /// replaces them.
    Fpath { dir: Option<Word>, first: bool },
    /// A function is marked to be autoloaded: its name, or the path of its
    /// file.
    Autoload(Word),
    /// An `fc` that writes the history file, as written (`fc -AI`).
    Fc(String),
    /// A prompt that holds code zsh runs as it shows it when
    /// `PROMPT_SUBST` is on: the doubt it is then.
    Prompt(String),
    /// An option is turned on without being named, by what `what` says
    /// (`... runs \`emulate -R ksh\`, which turns on`).
    Turns { option: usize, what: String },
    /// Output is redirected to `target`, as written, in the function
    /// `function` when in one; `computed` when an expansion makes it, and
    /// `kept` when an `exec` keeps it open for the commands after it
    /// (`exec 3>>$f`), which a hook may write to.
    Redirect {
        target: String,
        function: Option<String>,
        computed: bool,
        kept: bool,
    },
    /// The files define a function, or a regular alias, named `name`.
    Define(String),
    /// A word in the function `function` names the history file, as a
    /// command that writes it by its name may (`tee -a ~/.zsh_history`).
    Names { word: String, function: String },
    /// The function `name` is made a hook, which zsh runs as each command
    /// is entered or ends (`add-zsh-hook precmd name`, `zle -N name`).
    Hook(String),
    /// An alias stands for an `fc` that writes nothing, as written
    /// (`h=fc -l`), whose name is `name`: zsh hands such an `fc` the words
    /// the alias is used with, which may write the history file
    /// (`h -W`).
    FcAlias { name: String, text: String },
    /// A command runs by the name `name`, as written, with the words `args`,
    /// in the function `function` when in one.
    Call {
        name: String,
        args: Vec<Word>,
        function: Option<String>,
    },
    /// A directory is added to `fpath` under each Nix profile that
    /// `NIX_PROFILES` names, as NixOS's `/etc/zshenv` adds them: written as
    /// `written`, `rest` past the profile (`/share/zsh/site-functions`).
    ProfileFpath {
        written: String,
        rest: String,
        first: bool,
    },
    /// `NIX_PROFILES` is set otherwise than by an assignment the walk read.
    ProfilesUnknown,
    /// The function `name` is autoloaded without `-U`, so zsh expands the
    /// aliases the files define in its code as it loads it.
    Expanding(String),
}
