// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output settings resolved once per run
//!
//! [`OutputSettings::resolve`] is the only place that decides verbosity, colour
//! and ASCII rendering. `main` resolves it from the global flags and the
//! environment, installs it into `nails_core::output`, hands it to the tracing
//! subscriber and passes it to every command handler and renderer.

use std::io::IsTerminal;

use nails_core::Verbosity;
use nails_core::output::Style;
use tracing_subscriber::filter::LevelFilter;

use crate::cli::args::{ColorChoice, GlobalArgs};

/// Whether results are rendered for people or for programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Human-readable text.
    Human,
    /// JSON on stdout.
    Json,
}

/// Rendering and verbosity decisions for one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputSettings {
    /// How much diagnostic output to show.
    pub verbosity: Verbosity,
    /// Human text or JSON.
    pub mode: OutputMode,
    /// Emit ANSI colour on stdout.
    pub color_stdout: bool,
    /// Emit ANSI colour on stderr (diagnostics, prompts, tracing).
    pub color_stderr: bool,
    /// Use ASCII markers and no box drawing.
    pub ascii: bool,
    /// Animate progress (a redrawn spinner line) on stderr. Only for human
    /// output on an interactive terminal that understands cursor control.
    pub progress_animation: bool,
}

impl Default for OutputSettings {
    /// Plain human output at normal verbosity: no colour, Unicode marks.
    fn default() -> Self {
        Self {
            verbosity: Verbosity::Normal,
            mode: OutputMode::Human,
            color_stdout: false,
            color_stderr: false,
            ascii: false,
            progress_animation: false,
        }
    }
}

/// The parts of the process environment the resolver depends on, captured once
/// so the decision is testable without a terminal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// stdout is a terminal.
    pub stdout_tty: bool,
    /// stderr is a terminal.
    pub stderr_tty: bool,
    /// `TERM`.
    pub term: Option<String>,
    /// `NO_COLOR`.
    pub no_color: Option<String>,
    /// `CLICOLOR_FORCE`.
    pub clicolor_force: Option<String>,
    /// The effective character-type locale (`LC_ALL`, else `LC_CTYPE`, else `LANG`).
    pub locale: Option<String>,
}

impl Environment {
    /// Build from the startup environment snapshot plus the live terminal state.
    ///
    /// Whether stdout and stderr are terminals is a property of the open file
    /// descriptors, not of the environment, so it is probed here; every variable
    /// comes from the [`RuntimeEnv`](nails_core::RuntimeEnv) `main` read once.
    pub fn from_runtime_env(env: &nails_core::RuntimeEnv) -> Self {
        let locale = [&env.lc_all, &env.lc_ctype, &env.lang]
            .into_iter()
            .flatten()
            .find(|value| !value.is_empty())
            .cloned();
        Self {
            stdout_tty: std::io::stdout().is_terminal(),
            stderr_tty: std::io::stderr().is_terminal(),
            term: env.term.clone(),
            no_color: env.no_color.clone(),
            clicolor_force: env.clicolor_force.clone(),
            locale,
        }
    }

    fn term_is_dumb(&self) -> bool {
        self.term.as_deref() == Some("dumb")
    }

    /// Per no-color.org an empty `NO_COLOR` is the same as unset.
    fn no_color_requested(&self) -> bool {
        self.no_color
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    }

    fn color_forced(&self) -> bool {
        self.clicolor_force
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value != "0")
    }

    fn locale_is_utf8(&self) -> bool {
        self.locale.as_deref().is_some_and(|locale| {
            let lower = locale.to_ascii_lowercase();
            lower.contains("utf-8") || lower.contains("utf8")
        })
    }

    /// The `auto` colour decision for one stream.
    ///
    /// `NO_COLOR` wins over `CLICOLOR_FORCE`, which wins over detection; an
    /// explicit `--color` flag overrides all three.
    fn auto_color(&self, is_tty: bool) -> bool {
        if self.no_color_requested() {
            false
        } else if self.color_forced() {
            true
        } else {
            is_tty && !self.term_is_dumb()
        }
    }
}

impl OutputSettings {
    /// Decide the settings for this run from the global flags and `env`.
    pub fn resolve(args: &GlobalArgs, env: &Environment) -> Self {
        let verbosity = if args.quiet {
            Verbosity::Quiet
        } else {
            match args.verbose {
                0 => Verbosity::Normal,
                1 => Verbosity::Verbose,
                _ => Verbosity::Debug,
            }
        };
        let mode = if args.json {
            OutputMode::Json
        } else {
            OutputMode::Human
        };

        let color = |is_tty: bool| match args.color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => env.auto_color(is_tty),
        };
        // JSON on stdout must stay parseable, whatever was asked for.
        let color_stdout = mode == OutputMode::Human && color(env.stdout_tty);
        let color_stderr = color(env.stderr_tty);

        // Results go to stdout, so its sink decides whether Unicode is safe.
        let ascii = args.ascii || env.term_is_dumb() || !env.stdout_tty || !env.locale_is_utf8();

        // A spinner redraws its line in place, so it needs a real terminal on
        // stderr that honours cursor control; pipes, files, the journal and
        // `TERM=dumb` get one plain line per step instead.
        let progress_animation = mode == OutputMode::Human && env.stderr_tty && !env.term_is_dumb();

        Self {
            verbosity,
            mode,
            color_stdout,
            color_stderr,
            ascii,
            progress_animation,
        }
    }

    /// Resolve against the startup environment snapshot.
    pub fn detect(args: &GlobalArgs, env: &nails_core::RuntimeEnv) -> Self {
        Self::resolve(args, &Environment::from_runtime_env(env))
    }

    /// Install the rendering decisions into `nails_core::output`, which the
    /// library's own messages and the `colored` crate follow.
    pub fn install(&self) {
        nails_core::output::configure(self.color_stdout, self.color_stderr, self.ascii);
    }

    /// Results are printed as JSON.
    pub fn is_json(&self) -> bool {
        self.mode == OutputMode::Json
    }

    /// Only errors and the final result are printed.
    pub fn is_quiet(&self) -> bool {
        self.verbosity == Verbosity::Quiet
    }

    /// Style for text written to stdout.
    pub fn stdout_style(&self) -> Style {
        Style {
            color: self.color_stdout,
            ascii: self.ascii,
        }
    }

    /// Style for text written to stderr.
    pub fn stderr_style(&self) -> Style {
        Style {
            color: self.color_stderr,
            ascii: self.ascii,
        }
    }

    /// Most verbose tracing level shown on the console.
    pub fn tracing_level(&self) -> LevelFilter {
        LevelFilter::from_level(self.verbosity.to_tracing_level())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terminal() -> Environment {
        Environment {
            stdout_tty: true,
            stderr_tty: true,
            term: Some("xterm-256color".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            ..Environment::default()
        }
    }

    fn resolve(args: GlobalArgs, env: &Environment) -> OutputSettings {
        OutputSettings::resolve(&args, env)
    }

    #[test]
    fn terminal_with_utf8_locale_gets_colour_and_unicode() {
        let settings = resolve(GlobalArgs::default(), &terminal());
        assert!(settings.color_stdout && settings.color_stderr);
        assert!(!settings.ascii);
        assert_eq!(settings.verbosity, Verbosity::Normal);
        assert_eq!(settings.mode, OutputMode::Human);
    }

    #[test]
    fn auto_colour_is_off_for_a_non_terminal_stream() {
        let piped_stdout = Environment {
            stdout_tty: false,
            ..terminal()
        };
        let settings = resolve(GlobalArgs::default(), &piped_stdout);
        assert!(!settings.color_stdout);
        assert!(settings.color_stderr, "stderr is still a terminal");
        assert!(settings.ascii, "non-terminal stdout falls back to ASCII");

        let piped_stderr = Environment {
            stderr_tty: false,
            ..terminal()
        };
        let settings = resolve(GlobalArgs::default(), &piped_stderr);
        assert!(settings.color_stdout);
        assert!(!settings.color_stderr);
    }

    #[test]
    fn empty_no_color_keeps_colour_on_a_terminal() {
        let env = Environment {
            no_color: Some(String::new()),
            ..terminal()
        };
        let settings = resolve(GlobalArgs::default(), &env);
        assert!(settings.color_stdout && settings.color_stderr);
    }

    #[test]
    fn non_empty_no_color_disables_colour_but_not_unicode() {
        let env = Environment {
            no_color: Some("1".to_string()),
            ..terminal()
        };
        let settings = resolve(GlobalArgs::default(), &env);
        assert!(!settings.color_stdout && !settings.color_stderr);
        assert!(!settings.ascii);
    }

    #[test]
    fn clicolor_force_turns_colour_on_when_piped() {
        let env = Environment {
            stdout_tty: false,
            stderr_tty: false,
            clicolor_force: Some("1".to_string()),
            ..terminal()
        };
        let settings = resolve(GlobalArgs::default(), &env);
        assert!(settings.color_stdout && settings.color_stderr);

        let disabled = Environment {
            clicolor_force: Some("0".to_string()),
            ..env.clone()
        };
        assert!(!resolve(GlobalArgs::default(), &disabled).color_stdout);

        let both = Environment {
            no_color: Some("1".to_string()),
            ..env
        };
        assert!(!resolve(GlobalArgs::default(), &both).color_stdout);
    }

    #[test]
    fn dumb_terminal_gets_no_colour_and_ascii() {
        let env = Environment {
            term: Some("dumb".to_string()),
            ..terminal()
        };
        let settings = resolve(GlobalArgs::default(), &env);
        assert!(!settings.color_stdout && !settings.color_stderr);
        assert!(settings.ascii);
    }

    #[test]
    fn non_utf8_or_missing_locale_falls_back_to_ascii() {
        for locale in [Some("C"), Some("POSIX"), Some("de_DE.ISO-8859-1"), None] {
            let env = Environment {
                locale: locale.map(str::to_string),
                ..terminal()
            };
            assert!(resolve(GlobalArgs::default(), &env).ascii, "{locale:?}");
        }
        let env = Environment {
            locale: Some("C.utf8".to_string()),
            ..terminal()
        };
        assert!(!resolve(GlobalArgs::default(), &env).ascii);
    }

    #[test]
    fn explicit_colour_flag_overrides_the_environment() {
        let piped = Environment {
            stdout_tty: false,
            stderr_tty: false,
            no_color: Some("1".to_string()),
            ..terminal()
        };
        let always = GlobalArgs {
            color: ColorChoice::Always,
            ..GlobalArgs::default()
        };
        let settings = resolve(always, &piped);
        assert!(settings.color_stdout && settings.color_stderr);

        let never = GlobalArgs {
            color: ColorChoice::Never,
            ..GlobalArgs::default()
        };
        let settings = resolve(never, &terminal());
        assert!(!settings.color_stdout && !settings.color_stderr);
    }

    #[test]
    fn ascii_flag_forces_ascii() {
        let args = GlobalArgs {
            ascii: true,
            ..GlobalArgs::default()
        };
        assert!(resolve(args, &terminal()).ascii);
    }

    #[test]
    fn json_never_colours_stdout() {
        let args = GlobalArgs {
            json: true,
            color: ColorChoice::Always,
            ..GlobalArgs::default()
        };
        let settings = resolve(args, &terminal());
        assert!(settings.is_json());
        assert!(!settings.color_stdout);
        assert!(settings.color_stderr);
    }

    #[test]
    fn verbosity_maps_to_tracing_levels() {
        let level = |verbose: u8, quiet: bool| {
            resolve(
                GlobalArgs {
                    verbose,
                    quiet,
                    ..GlobalArgs::default()
                },
                &terminal(),
            )
            .tracing_level()
        };
        assert_eq!(level(0, true), LevelFilter::ERROR);
        assert_eq!(level(0, false), LevelFilter::INFO);
        assert_eq!(level(1, false), LevelFilter::DEBUG);
        assert_eq!(level(2, false), LevelFilter::TRACE);
        assert_eq!(level(3, false), LevelFilter::TRACE);
    }

    #[test]
    fn activate_command_lines_reach_the_tracing_filter() {
        let level = |argv: &[&str]| {
            let cli = crate::cli::Cli::try_parse_checked_from(argv).unwrap();
            OutputSettings::resolve(&cli.global, &terminal()).tracing_level()
        };
        assert_eq!(level(&["nails", "activate", "-vv"]), LevelFilter::TRACE);
        assert_eq!(level(&["nails", "-vv", "activate"]), LevelFilter::TRACE);
        assert_eq!(level(&["nails", "activate", "-v"]), LevelFilter::DEBUG);
        assert_eq!(level(&["nails", "activate", "-q"]), LevelFilter::ERROR);
        assert_eq!(level(&["nails", "-q", "activate"]), LevelFilter::ERROR);
        assert_eq!(level(&["nails", "activate"]), LevelFilter::INFO);
    }

    #[test]
    fn styles_follow_the_per_stream_decision() {
        let settings = OutputSettings {
            color_stdout: false,
            color_stderr: true,
            ascii: true,
            ..OutputSettings::default()
        };
        assert_eq!(
            settings.stdout_style(),
            Style {
                color: false,
                ascii: true
            }
        );
        assert_eq!(
            settings.stderr_style(),
            Style {
                color: true,
                ascii: true
            }
        );
    }

    #[test]
    fn progress_animates_only_for_human_output_on_a_capable_terminal() {
        assert!(resolve(GlobalArgs::default(), &terminal()).progress_animation);

        let piped = Environment {
            stderr_tty: false,
            ..terminal()
        };
        assert!(!resolve(GlobalArgs::default(), &piped).progress_animation);

        let dumb = Environment {
            term: Some("dumb".to_string()),
            ..terminal()
        };
        assert!(!resolve(GlobalArgs::default(), &dumb).progress_animation);

        let json = GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        };
        assert!(!resolve(json, &terminal()).progress_animation);
    }
}
