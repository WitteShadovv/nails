// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the walk finds a file's code does ([`Event`]).

use super::super::lexer::Word;

/// What a command reads beside its words, which the shell's code may make
/// the command line: its standard input and its environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum Input {
    /// Nothing the code gives it.
    None,
    /// What an expansion makes: a here-string, a here-document or a file
    /// an expansion names, or a value an expansion makes in its environment
    /// (`LINE=$1 cmd`).
    Computed,
    /// What the commands before it in its pipeline write: each one's name
    /// as written, and whether an expansion makes a word of it; none when
    /// what feeds it is no simple command the walk read (a group).
    Piped(Vec<(String, bool)>),
}

/// Where an arithmetic expression stands ([`Event::Arith`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum Arith {
    /// Where zsh evaluates it whatever it holds (`(( ... ))`).
    Plain,
    /// The subscript of the array named, arithmetic unless its keys are
    /// strings.
    Keyed(String),
    /// The value assigned to the parameter named, arithmetic where it holds
    /// a number.
    Value(String),
    /// The parameter named, whose value zsh evaluates as it declares it to
    /// hold a number (`integer n`), which holds no number then.
    Old,
}

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
    /// in the function `function` when in one, reading `input`.
    Call {
        name: String,
        args: Vec<Word>,
        function: Option<String>,
        input: Input,
    },
    /// What the function `function` holds may write the history file should
    /// it be a hook, as `doubt` says (`zle complete-word`, which runs the
    /// completion functions the check does not read).
    HookDoubt { function: String, doubt: String },
    /// A global alias is defined, named `name` as written, by the word
    /// `text` (`G=| grep`). zsh puts its value in place of any word of code
    /// that is its name, a redirection's target among them (`/dev/tty`), as
    /// it reads the code.
    GlobalAlias { name: String, text: String },
    /// An element given `fpath` that the walk reads as the directories an
    /// expansion holds, each as it is (`$fpath`, `$p`), as written: one
    /// `SH_WORD_SPLIT` splits, or `KSH_ARRAYS` cuts to its first, may hold
    /// others.
    FpathSplits(String),
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
    /// The code a key or a command types as a line (`bindkey -s`, `zle -U`,
    /// `print -z`), as typed, which counts for the names it holds; `keys`
    /// when zsh reads it as keys pressed, which the files' key bindings may
    /// turn into others.
    Typed { text: String, keys: bool },
    /// A key a line is typed with is bound or unbound, a widget is made or a
    /// keymap made, linked or reset, which may change what typed keys do.
    Rebind,
    /// An arithmetic expression, as written, where `kind` says
    /// ([`super::arith`]).
    Arith { text: String, kind: Arith },
    /// A parameter is declared an array whose keys are strings (`typeset -A`)
    /// or one that holds numbers (`integer`).
    Declared {
        name: String,
        keyed: bool,
        numeric: bool,
    },
    /// A parameter is unset, by its name; empty when an expansion or a
    /// pattern names it.
    Unset(String),
    /// A test asks about the file a word names (`[[ -f ~/.x ]]`), as written.
    Tested(String),
    /// The function `function` sets the parameter `name` to what an
    /// expansion makes or what it reads, as written; `local` when it is the
    /// function's own, which zsh exports to no program unless every
    /// parameter is (`ALL_EXPORT`).
    Computed {
        function: String,
        name: String,
        local: bool,
    },
}
