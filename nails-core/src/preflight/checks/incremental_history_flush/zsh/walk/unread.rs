// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the lines of a file name beyond what the walk read of its code
//! ([`super::events`]): such an option counts as on, an `fpath` setting adds
//! a directory the check cannot follow, a prompt holds code it cannot follow,
//! and the rest is a doubt, in case the walk read the code otherwise than
//! zsh does.

use super::super::arith::READ_AS_NUMBER;
use super::super::backstop::Named;
use super::{Event, Walked};

/// The events of what `named`, what the lines of the file at `place` name,
/// holds beyond what the walk read of its code: `read`, the options its
/// tokens name, and `walked`, the rest it counted.
pub(super) fn beyond(named: &Named, read: &[usize; 3], walked: &Walked, place: &str) -> Vec<Event> {
    let mut events = Vec::new();
    for (at, (&lines, &tokens)) in named.options.iter().zip(read).enumerate() {
        if lines > tokens {
            events.push(Event::Unread(at));
        }
    }
    if named.sources > walked.sources {
        events.push(Event::Doubt(format!(
            "it cannot follow a `source` or `.` that a line of {place} may run"
        )));
    }
    if named.evals > walked.evals {
        events.push(Event::Doubt(format!(
            "it cannot follow an `eval` that a line of {place} may run"
        )));
    }
    if named.zdotdirs > walked.zdotdirs {
        events.push(Event::Doubt(format!(
            "it cannot follow a ZDOTDIR that a line of {place} may set"
        )));
    }
    if named.xdg_config_homes > walked.xdg_config_homes {
        events.push(Event::Doubt(format!(
            "it cannot follow an XDG_CONFIG_HOME that a line of {place} may set or take away"
        )));
    }
    if named.autoloads > walked.autoloads {
        events.push(Event::Doubt(format!(
            "it cannot follow an `autoload` that a line of {place} may run"
        )));
    }
    if named.fpaths > walked.fpaths {
        events.push(Event::Fpath {
            dir: None,
            first: false,
        });
    }
    if named.fcs > walked.fcs {
        events.push(Event::Doubt(format!(
            "it cannot follow an `fc` that a line of {place} may run, which can write the \
             history file"
        )));
    }
    if named.nix_profiles > walked.nix_profiles {
        events.push(Event::ProfilesUnknown);
    }
    if named.indirects > walked.indirects {
        events.push(Event::Doubt(format!(
            "it cannot tell which parameter a line of {place} may set by the name another one \
             holds"
        )));
    }
    if named.hooks > walked.hooks {
        events.push(Event::Doubt(format!(
            "it cannot tell which functions a line of {place} may make hooks, which zsh runs as \
             each command is entered or ends"
        )));
    }
    if named.prompts > walked.prompts {
        events.push(Event::Prompt(format!(
            "it cannot follow a prompt that a line of {place} may set, whose code zsh runs as it \
             shows the prompt, as PROMPT_SUBST may be on"
        )));
    }
    if named.numbers > walked.numbers {
        events.push(Event::Doubt(format!(
            "it cannot follow the value a line of {place} may give {}, which zsh reads as \
             arithmetic each time it uses it, so that it may run code",
            READ_AS_NUMBER.join(", ")
        )));
    }
    if named.alias_params > walked.alias_params {
        events.push(Event::Doubt(format!(
            "it cannot tell what alias a line of {place} may give by the parameters that hold \
             them, which zsh then expands"
        )));
    }
    if named.arith > walked.marks {
        events.push(Event::Doubt(format!(
            "it cannot follow arithmetic that a line of {place} may hold, which may set a \
             parameter by a name the check cannot read"
        )));
    }
    if named.function_params > walked.function_params {
        events.push(Event::Doubt(format!(
            "it cannot tell what code a line of {place} may give a function by `functions`"
        )));
    }
    events
}
