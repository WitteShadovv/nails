// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The functions a file makes hooks, which zsh runs as each command is
//! entered or ends, or as keys are pressed, as the walk reads them:
//! `add-zsh-hook`, `add-zle-hook-widget`, the `zle` widgets, the arrays of
//! hook functions, and a function copied to a hook's name.

use super::super::lexer::Word;
use super::{Event, HOOKS, Input, Walker};

/// Whether `widget`, a widget's name as written, may be one zsh runs by its
/// name as each line is entered or edited (`zle-line-init`,
/// `zle-line-finish`): one that starts with `zle-`, or that an expansion
/// makes.
fn special_widget(widget: &Word) -> bool {
    widget.expands || widget.text.contains(['$', '`']) || widget.text.starts_with("zle-")
}

/// The builtin widgets that complete a word, which the stock `compinit`
/// makes run the completion functions in `fpath` (`_main_complete`), and
/// `menu-select` of zsh/complist.
const COMPLETION_WIDGETS: &[&str] = &[
    "accept-and-menu-complete",
    "complete-word",
    "delete-char-or-list",
    "expand-or-complete",
    "expand-or-complete-prefix",
    "list-choices",
    "menu-complete",
    "menu-expand-or-complete",
    "menu-select",
    "reverse-menu-complete",
];

/// Whether `widget`, a widget's name as written, may complete a word, which
/// runs completion functions the check does not read: one of
/// [`COMPLETION_WIDGETS`], by its name or its builtin's (`.complete-word`),
/// one whose name starts with `_`, as `compinit`'s and `compdef`'s do, or
/// one an expansion names.
pub(super) fn completes(widget: &Word) -> bool {
    let name = widget.text.strip_prefix('.').unwrap_or(&widget.text);
    widget.expands
        || widget.text.contains(['$', '`'])
        || name.starts_with('_')
        || COMPLETION_WIDGETS.contains(&name)
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
/// the dump file `compinit` sources, what `compdef` binds and autoloads, the
/// theme `prompt` runs, and what `promptinit` defines.
const STOCK_NAMES: &[&str] = &[
    "add-zsh-hook",
    "add-zle-hook-widget",
    "compinit",
    "compdef",
    "compaudit",
    "compdump",
    "promptinit",
    "prompt",
    "prompt_cleanup",
    "prompt_preview_safely",
    "prompt_preview_theme",
    "set_prompt",
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
/// pick ([`ZLE_OPERATIONS`]), if any, their letters and the words past them;
/// `Ok(None)` when a letter is none zle takes, with which it runs nothing;
/// `Err` with a word where options may stand that an expansion, brace
/// expansion or a glob may make other words of, which may be any option.
type ZleOptions<'a> = (Option<char>, String, &'a [Word]);
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
    Ok(Some((op, letters, &args[at..])))
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
        for name in names {
            self.mention(&name.text);
            self.events.push(Event::Define(name.text.clone()));
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
    /// ([`Event::Hook`]), and autoloads; one an expansion names is a doubt,
    /// and so is a widget that completes a word ([`completes`]) that
    /// `add-zle-hook-widget` makes run as each line is entered, which runs
    /// completion functions the check does not read.
    pub(super) fn hook(&mut self, command: &str, args: &[Word]) {
        for arg in args {
            self.mention(&arg.text);
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
        if command == "add-zle-hook-widget" && completes(function) {
            // The hook runs the widget as each line is entered.
            let line: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
            self.events.push(Event::Doubt(format!(
                "it cannot tell what the completion functions that `add-zle-hook-widget {}` in \
                 {} runs as each line is entered write",
                line.join(" "),
                self.place
            )));
            return;
        }
        self.events.push(Event::Hook(function.text.clone()));
        // Both autoload the function they add, which zsh then loads from
        // `fpath` unless the files define it; with `-d`, `-D` or `-L` they
        // take one away or list them.
        if !args
            .iter()
            .any(|arg| arg.text.starts_with('-') && arg.text.contains(['d', 'D', 'L']))
        {
            self.events.push(Event::Autoload((*function).clone()));
        }
    }

    /// The events of a `zle` of `args`, its options read as zsh reads them
    /// ([`zle_options`]): the function it makes a hook ([`Event::Hook`]), as
    /// a key bound to a widget may run it as a line is typed: `zle -N`'s,
    /// `zle -C`'s, which complete a word, a `zle -T` transformation's and
    /// `zle -F`'s, which run as zle prints and as a descriptor has input. One
    /// an expansion names is a doubt, and so is a word of its options that
    /// an expansion, brace expansion or a glob may make (`{-N,zle-line-finish}`),
    /// which may be any. A widget that completes a word ([`completes`]) that
    /// it runs (`zle complete-word`, `zle -w complete-word`) where a hook
    /// runs, or makes run as a line is entered (`zle -A complete-word
    /// accept-line`), runs completion functions the check does not read: a
    /// doubt. A widget made, copied or deleted may change what typed keys do
    /// ([`Event::Rebind`]).
    pub(super) fn zle(&mut self, args: &[Word]) {
        for arg in args {
            self.mention(&arg.text);
        }
        let line = || {
            args.iter()
                .map(|arg| arg.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        let (op, letters, words) = match zle_options(args) {
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
        let function = match op {
            // `zle -N widget [function]`.
            Some('N') => words.get(1).or(words.first()),
            // `zle -C widget builtin function`, `zle -T transformation
            // function`, `zle -F fd handler`, run as the descriptor has input.
            Some('C' | 'T' | 'F') => words.last().filter(|_| words.len() > 1),
            _ => None,
        };
        if op == Some('A')
            && (words.get(1).is_some_and(|widget| special_widget(widget))
                || words.first().is_some_and(|widget| completes(widget)))
            || (op == Some('F') && letters.contains('w') && function.is_some_and(|f| completes(f)))
        {
            // `zle -A old zle-line-finish`: the widget runs as each line is
            // entered, with the function of another; `zle -A complete-word
            // accept-line`: a key that enters a line completes a word; `zle
            // -Fw fd complete-word`: input on a descriptor completes one.
            self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle {}` in {} makes run as each line is entered",
                line(),
                self.place
            )));
            return;
        }
        if op.is_none()
            && let Some(widget) = words.first()
            && completes(widget)
            && let Some(function) = self.function()
        {
            // `zle complete-word`, `zle -w complete-word`, as a hook runs it.
            self.events.push(Event::HookDoubt {
                doubt: format!(
                    "it cannot tell what the completion functions that `zle {}` in `{function}` \
                     in {} runs write",
                    widget.text, self.place
                ),
                function,
            });
        }
        if op == Some('U') {
            // `zle -U string`: what the string types runs as the line typed,
            // its control characters as keys (Tab, which completes a word).
            for typed in &words {
                if typed.expands
                    || typed.bare
                    || typed.text.contains(['$', '`'])
                    || typed.text.chars().any(|c| c.is_control() && c != '\n')
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
                    self.nested_in(&typed.text, false, Some(hook));
                }
            }
            return;
        }
        match function {
            Some(function) if function.expands => self.events.push(Event::Doubt(format!(
                "it cannot tell which function `zle ... {}` in {} makes a hook",
                function.text, self.place
            ))),
            Some(function) => {
                self.events.push(Event::Hook(function.text.clone()));
                // A completion widget's function, which zsh runs as a word is
                // completed with it.
                if op == Some('C') {
                    self.events.push(Event::Completes {
                        function: (*function).clone(),
                        what: format!("zle {}", line()),
                    });
                }
            }
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
                self.events.push(Event::Define(to.text.clone()));
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
