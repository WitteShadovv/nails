// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions a file makes hooks, which zsh runs as each command is
//! entered or ends, or as keys are pressed, as the walk reads them:
//! `add-zsh-hook`, `add-zle-hook-widget`, the `zle` widgets, the arrays of
//! hook functions, and a function copied to a hook's name.

use super::super::lexer::Word;
use super::widgets::{COMPLETING_WIDGETS, STRICT_WIDGETS, expands_history};
use super::{Event, HOOKS, Input, Walker};

/// Whether `widget`, a widget's name as written, may be one zsh runs by its
/// name as each line is entered or edited (`zle-line-init`,
/// `zle-line-finish`): one that starts with `zle-`, or that an expansion
/// makes.
fn special_widget(widget: &Word) -> bool {
    widget.expands || widget.text.contains(['$', '`']) || widget.text.starts_with("zle-")
}

/// Whether `word`, a name of a function, a widget or a hook as written, is
/// one zsh may expand into another (`$n`, `{preexec,x}`, `preexe[c]`,
/// `=ls`, `~/x`): it may then name any, a hook among them.
pub(super) fn computed_name(word: &Word) -> bool {
    word.expands || may_expand(&word.text)
}

/// Whether `text`, a name as written, holds what zsh may expand it with
/// into another name ([`computed_name`]).
pub(in super::super) fn may_expand(text: &str) -> bool {
    text.contains([
        '$', '`', '{', '}', '*', '?', '[', ']', '(', ')', '|', '<', '>', '^', '#', '~', '=',
    ])
}

/// Whether `name` is an array of the functions zsh runs as hooks
/// (`precmd_functions`).
pub(super) fn hook_array(name: &str) -> bool {
    name.strip_suffix("_functions")
        .is_some_and(|hook| HOOKS.contains(&hook))
}

/// The functions of zsh's own whose work the check reads by the name a file
/// runs them by: the hooks `add-zsh-hook` and `add-zle-hook-widget` make,
/// the theme `prompt` runs, and what `promptinit` defines.
pub(in super::super) const STOCK_NAMES: &[&str] = &[
    "add-zsh-hook",
    "add-zle-hook-widget",
    "promptinit",
    "prompt",
    "prompt_cleanup",
    "prompt_preview_safely",
    "prompt_preview_theme",
    "set_prompt",
];

/// The hooks the stock `add-zsh-hook` of zsh 5.9 to 5.9.2 adds a function
/// to, which it returns before it autoloads one for any other.
const ADD_ZSH_HOOKS: &[&str] = &[
    "chpwd",
    "precmd",
    "preexec",
    "periodic",
    "zshaddhistory",
    "zshexit",
    "zsh_directory_name",
];

/// The letters `zle` takes as options (Src/Zle/zle_main.c).
const ZLE_FLAGS: &str = "aAcCDfFgGIKlLmMNrRTUw";

/// The letters that pick what `zle` does, in the order zsh tries them
/// (Src/Zle/zle_thingy.c): with none of them among its options, it runs the
/// widget its first word past them names, `-w` and the others aside.
const ZLE_OPERATIONS: &str = "lDANCRMUKIfFT";

/// The options of a `zle` of `args`, read as zsh reads a builtin's: each word
/// that starts with `-` holds options up to the first that does not or that
/// is a `-` and a digit, `-` and `--` end them and are dropped, and `--N`
/// reads as `-N`. The operation they
/// pick ([`ZLE_OPERATIONS`]), if any, and the words past them;
/// `Ok(None)` when a letter is none zle takes, with which it runs nothing;
/// `Err` with a word where options may stand that an expansion, brace
/// expansion or a glob may make other words of, which may be any option.
type ZleOptions<'a> = (Option<char>, &'a [Word]);
fn zle_options(args: &[Word]) -> Result<Option<ZleOptions<'_>>, &Word> {
    let mut letters = String::new();
    let mut at = 0;
    while let Some(word) = args.get(at) {
        if word.expands || word.bare {
            return Err(word);
        }
        let Some(flags) = word
            .text
            .strip_prefix('-')
            .filter(|flags| !flags.starts_with(|c: char| c.is_ascii_digit()))
        else {
            break;
        };
        at += 1;
        if flags.is_empty() || flags == "-" {
            break;
        }
        let flags = flags.strip_prefix('-').unwrap_or(flags);
        if !flags.chars().all(|c| ZLE_FLAGS.contains(c)) {
            return Ok(None);
        }
        letters.push_str(flags);
    }
    let op = ZLE_OPERATIONS.chars().find(|op| letters.contains(*op));
    Ok(Some((op, &args[at..])))
}

impl Walker<'_> {
    /// The events of a function's definition by the words `names` (`function
    /// a b`, `a b ()`, `paren` for the second form): each defines it, the
    /// first one's code is its body, and each other runs it, so that it
    /// counts as a hook where any is one. A name zsh may expand into another
    /// may be a hook's, so its code counts as a hook's ([`computed_name`]),
    /// and so does one that holds a backslash or a quote past those zsh takes
    /// off (`'s\udo'`), which the check may read otherwise than zsh, and so
    /// may an alias's in the second form ([`Event::NamedBody`]).
    pub(super) fn define(&mut self, names: Vec<Word>, paren: bool) {
        let mut first: Option<String> = None;
        // A definition at the file's top level that certainly runs where the
        // file runs to it, after which zsh runs the function by its name.
        let certain =
            self.reached(self.pending.after_condition, self.pending.piped) && self.at_top();
        for name in names {
            self.mention_word(&name);
            self.events.push(Event::Define {
                name: name.text.clone(),
                certain,
                alias: None,
            });
            if paren {
                self.events.push(Event::NamedBody(name.text.clone()));
            }
            if computed_name(&name) || name.text.contains(['\\', '\'', '"']) {
                self.events.push(Event::Hook(name.text.clone()));
            }
            match &first {
                None => first = Some(name.text),
                Some(first) => self.events.push(Event::Call {
                    name: first.clone(),
                    args: Vec::new(),
                    function: Some(name.text),
                    input: Input::None,
                }),
            }
        }
        self.pending.function_name = first;
    }

    /// The events of an `add-zsh-hook` or an `add-zle-hook-widget`
    /// (`command`) of `args`: the function it makes a hook, which zsh runs as
    /// commands are entered or end, or as each line is entered
    /// ([`Event::Hook`]), and autoloads; one an expansion names is a doubt.
    /// It runs the function of that name, run in `function` with `input`:
    /// the files' own or one they autoload, whose code the check reads as
    /// any other function's they run, where the stock one's work it reads by
    /// its bytes ([`super::super::stock`]).
    pub(super) fn hook(
        &mut self,
        command: &str,
        args: &[Word],
        function: Option<String>,
        input: Input,
    ) {
        self.hook_made(command, args);
        self.events.push(Event::Call {
            name: command.to_string(),
            args: args.to_vec(),
            function,
            input,
        });
    }

    /// The hook that an `add-zsh-hook` or an `add-zle-hook-widget`
    /// (`command`) of `args` makes ([`Walker::hook`]).
    fn hook_made(&mut self, command: &str, args: &[Word]) {
        for arg in args {
            self.mention_word(arg);
        }
        let words: Vec<&Word> = args
            .iter()
            .filter(|arg| !arg.text.starts_with('-'))
            .collect();
        // `add-zsh-hook hook function`, `add-zle-hook-widget hook widget`:
        // a word zsh may expand into others (`{preexec,w}`) may make any a
        // hook.
        if let Some(word) = words.iter().take(2).find(|word| computed_name(word)) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `{command} ... {}` in {} makes a hook",
                word.text, self.place
            )));
            return;
        }
        let Some(function) = words.get(1) else {
            return;
        };
        self.events.push(Event::Hook(function.text.clone()));
        // Both autoload the function they add, which zsh then loads from
        // `fpath` unless the files define it; with `-d`, `-D` or `-L` they
        // take one away or list them. The stock `add-zsh-hook` certainly
        // does only where its words are flags that change how it autoloads
        // alone, then a hook of its list and a function: it returns before
        // the autoload for any other.
        if !args
            .iter()
            .any(|arg| arg.text.starts_with('-') && arg.text.contains(['d', 'D', 'L']))
        {
            let flags = args
                .iter()
                .take_while(|arg| arg.text.starts_with('-'))
                .all(|arg| {
                    !arg.expands
                        && !arg.bare
                        && arg.text.len() > 1
                        && arg.text[1..].chars().all(|c| matches!(c, 'U' | 'z' | 'k'))
                });
            let plain = args.iter().skip_while(|arg| arg.text.starts_with('-'));
            let valid = command == "add-zsh-hook"
                && flags
                && matches!(
                    plain.collect::<Vec<_>>().as_slice(),
                    [hook, function] if ADD_ZSH_HOOKS.contains(&hook.text.as_str())
                        && !computed_name(function)
                );
            let in_function = self.function().is_some();
            self.events.push(Event::Autoload {
                function: (*function).clone(),
                in_function,
                certain: self.certain_command && valid,
            });
        }
    }

    /// The events of a `zle` of `args`, its options read as zsh reads them
    /// ([`zle_options`]): the function it makes a hook ([`Event::Hook`]), as
    /// a key bound to a widget may run it as a line is typed: `zle -N`'s,
    /// `zle -C`'s, which complete a word, a `zle -T` transformation's and
    /// `zle -F`'s, which run as zle prints and as a descriptor has input,
    /// and the name `zle -A` gives a widget, as the widgets `run-help` and
    /// `which-command` run the command named as the key ran them, with the
    /// line at hand (`zle -A run-help logit`). One an expansion names is a
    /// doubt, and so is a word of its options that an expansion, brace
    /// expansion or a glob may make (`{-N,zle-line-finish}`), which may be
    /// any, and so is a widget it makes run as each line is entered with the
    /// function of another (`zle -A old zle-line-finish`). A widget made,
    /// copied or deleted may change what typed keys do ([`Event::Rebind`]).
    pub(super) fn zle(&mut self, args: &[Word]) {
        for arg in args {
            self.mention_word(arg);
        }
        let line = || {
            args.iter()
                .map(|arg| arg.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let (op, words) = match zle_options(args) {
            Ok(Some(read)) => read,
            // A flag zle does not take: it runs nothing.
            Ok(None) => return,
            Err(word) => {
                self.events.push(Event::Rebind);
                self.events.push(Event::Doubt(format!(
                    "it cannot tell what `zle {}` in {} does, as zsh may expand `{}` into its \
                     options",
                    line(),
                    self.place,
                    word.text
                )));
                return;
            }
        };
        let words: Vec<&Word> = words.iter().collect();
        if matches!(op, Some('N' | 'C' | 'A' | 'D')) {
            self.events.push(Event::Rebind);
        }
        // The words that name the widget and the function: one zsh may
        // expand into others may make any a hook.
        let named: &[&Word] = match op {
            Some('N' | 'A') => &words[..words.len().min(2)],
            Some('C' | 'T' | 'F') => &words,
            _ => &[],
        };
        if let Some(word) = named.iter().find(|word| computed_name(word)) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle ... {}` in {} makes a hook",
                word.text, self.place
            )));
            return;
        }
        if matches!(op, Some('N' | 'C'))
            && let Some(widget) = words.first()
        {
            self.events.push(Event::Widget(widget.text.clone()));
        }
        if op.is_none()
            && let Some(widget) = words.first()
        {
            // `zle up-history`: a widget run by its name.
            self.runs_widget(widget);
        }
        // `zle -K vicmd` in a widget: the keys typed next run as the commands
        // of that keymap, `k` fetching a line from the history.
        if op == Some('K')
            && let Some(keymap) = words.first()
            && !matches!(keymap.text.as_str(), "main" | "emacs" | "viins")
            && let Some(function) = self.function()
        {
            self.events.push(Event::HookDoubt {
                doubt: format!(
                    "it cannot tell what line the keys you type give zsh to run, as `zle {}` in \
                     `{function}` in {} makes them run as the commands of another keymap",
                    line(),
                    self.place
                ),
                function,
            });
        }
        // `zle -A up-history self-insert`: each key typed runs another
        // widget, which may put other text in the line.
        if op == Some('A')
            && let [old, new, ..] = words.as_slice()
            && matches!(new.text.as_str(), "self-insert" | "magic-space")
            && ![STRICT_WIDGETS, COMPLETING_WIDGETS]
                .iter()
                .any(|known| known.contains(&old.text.trim_start_matches('.')))
        {
            self.events.push(Event::Doubt(format!(
                "it cannot tell what line the keys you type give zsh to run, as `zle {}` in {} \
                 makes them run `{}`",
                line(),
                self.place,
                old.text
            )));
        }
        let function = match op {
            // `zle -N widget [function]`.
            Some('N') => words.get(1).or(words.first()),
            // `zle -C widget builtin function`, `zle -T transformation
            // function`, `zle -F fd handler`, run as the descriptor has input.
            Some('C' | 'T' | 'F') => words.last().filter(|_| words.len() > 1),
            _ => None,
        };
        if op == Some('A') && words.get(1).is_some_and(|widget| special_widget(widget)) {
            // `zle -A old zle-line-finish`: the widget runs as each line is
            // entered, with the function of another.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle {}` in {} makes run as each line is entered",
                line(),
                self.place
            )));
            return;
        }
        if op == Some('A')
            && let Some(widget) = words.get(1)
        {
            self.events.push(Event::Hook(widget.text.clone()));
        }
        if op == Some('U') {
            // `zle -U string`: what the string types runs as the line typed,
            // its control characters as keys (Tab, which completes a word).
            for typed in &words {
                if typed.expands
                    || typed.bare
                    || typed.text.contains(['$', '`'])
                    || typed.text.chars().any(|c| c.is_control() && c != '\n')
                    || expands_history(&typed.text)
                {
                    self.events.push(Event::Doubt(format!(
                        "it cannot tell what `zle -U {}` in {} types",
                        typed.text, self.place
                    )));
                } else {
                    let hook = format!("zle -U {}", typed.text);
                    self.events.push(Event::Typed {
                        text: typed.text.clone(),
                        keys: true,
                    });
                    self.events.push(Event::Hook(hook.clone()));
                    self.nested_in(&typed.text, false, Some(hook), true);
                }
            }
            return;
        }
        match function {
            Some(function) if function.expands => self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle ... {}` in {} makes a hook",
                function.text, self.place
            ))),
            Some(function) => self.events.push(Event::Hook(function.text.clone())),
            None => {}
        }
    }

    /// The events of `word`, a function a hook's array is given
    /// (`precmd_functions[1]=name`, `set -A precmd_functions name`): a hook,
    /// or a doubt when an expansion names it.
    pub(super) fn hook_value(&mut self, word: &Word) {
        if computed_name(word) {
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `{}` in {} makes a hook",
                word.text, self.place
            )));
        } else if !word.text.is_empty() {
            self.events.push(Event::Hook(word.text.clone()));
        }
    }

    /// The events of a `functions -c` of `args`, which copies a function to
    /// another name, whose code it then runs as that function: a call of the
    /// first by the second, so that it counts as a hook where the second is
    /// one; one an expansion names is a doubt, and so is a copy of a function
    /// of zsh's own whose work the check reads by its name where it runs
    /// ([`STOCK_NAMES`]): the copy does that work under a name the check does
    /// not follow (`functions -c add-zsh-hook azh`, then `azh preexec f`).
    pub(super) fn copy_function(&mut self, args: &[Word]) {
        let names: Vec<&Word> = args
            .iter()
            .filter(|arg| !arg.text.starts_with('-'))
            .collect();
        match names.as_slice() {
            [from, to] if STOCK_NAMES.contains(&from.text.as_str()) => {
                self.events.push(Event::Doubt(format!(
                    "it cannot follow what `{}` does in place of `{}`, which `functions -c` in {} \
                     copies it from and whose work the check reads by its name",
                    to.text, from.text, self.place
                )));
            }
            [from, to] if !computed_name(from) => {
                // A copy of a function zsh does not have defines none, so it
                // is no certain definition.
                self.events.push(Event::Define {
                    name: to.text.clone(),
                    certain: false,
                    alias: None,
                });
                // A name zsh may expand into another may be a hook's.
                if computed_name(to) {
                    self.events.push(Event::Hook(to.text.clone()));
                }
                self.events.push(Event::Call {
                    name: from.text.clone(),
                    args: Vec::new(),
                    function: Some(to.text.clone()),
                    input: Input::None,
                });
            }
            _ => {
                let words: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
                self.events.push(Event::Doubt(format!(
                    "it cannot tell which function `functions {}` in {} copies to which",
                    words.join(" "),
                    self.place
                )));
            }
        }
    }
}
