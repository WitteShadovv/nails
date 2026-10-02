//! CLI argument definitions
//!
//! Output and logging options live in [`GlobalArgs`] and are accepted before or
//! after the subcommand (`nails -q status` and `nails status -q` are the same).
//! Each subcommand has its own argument struct holding only what that command
//! means.

use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::PathBuf;

/// Overlay environment manager for NixOS
#[derive(Parser, Debug)]
#[command(name = "nails")]
#[command(author = "NAILS Project")]
#[command(version)]
#[command(about = "Overlay environment manager for NixOS", long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    /// Parse the process arguments, exiting with a usage error (code 2) on failure.
    pub fn parse_checked() -> Self {
        Self::try_parse_checked_from(std::env::args_os()).unwrap_or_else(|error| error.exit())
    }

    /// Parse `argv` and apply the checks clap cannot express for global flags.
    ///
    /// Clap merges a global flag given before and after the subcommand into
    /// one value and checks conflicts only within one side, so `-q status -v`
    /// would otherwise be accepted with both set.
    pub fn try_parse_checked_from<I, T>(argv: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let cli = Self::try_parse_from(argv)?;
        if cli.global.quiet && cli.global.verbose > 0 {
            return Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "the argument '--quiet' cannot be used with '--verbose'",
            ));
        }
        Ok(cli)
    }
}

/// What to do with the graphical session during activation.
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionPolicy {
    /// Terminate the graphical session before mounting (the secure default).
    ///
    /// Activation detaches to a background service, closes the display manager
    /// and user session, mounts the overlays and restarts the session.
    #[default]
    Kill,
    /// Keep the current session running (mounts only what can be overlaid live).
    Keep,
}

/// How to handle a volume that can only be mounted with a pivot overlay.
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PivotPolicy {
    /// Abort rather than fall back to a pivot mount (the secure default).
    #[default]
    Refuse,
    /// Fall back to a pivot mount without asking (degraded security).
    Allow,
    /// Prompt on a terminal before falling back to a pivot mount; refuse without one.
    Ask,
}

/// What to do with risky services still referencing a target at activation.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskyServicesArg {
    /// Restart them so they no longer reference the decoy.
    Restart,
    /// Leave them running; they are reported as surviving writers.
    Skip,
}

impl From<RiskyServicesArg> for nails_core::RiskyServicePolicy {
    fn from(arg: RiskyServicesArg) -> Self {
        match arg {
            RiskyServicesArg::Restart => nails_core::RiskyServicePolicy::Restart,
            RiskyServicesArg::Skip => nails_core::RiskyServicePolicy::Skip,
        }
    }
}

/// When to emit ANSI colour.
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ColorChoice {
    /// Colour a stream only when it is a terminal, TERM is not `dumb` and
    /// NO_COLOR is unset or empty
    #[default]
    Auto,
    /// Always colour, even when piped
    Always,
    /// Never colour
    Never,
}

/// Options shared by every command, accepted in any position.
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalArgs {
    /// Path to the configuration file (overrides binary-relative discovery)
    #[arg(short = 'c', long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// More diagnostics on stderr: -v for debug, -vv for trace
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Print only errors and the final result
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// When to use colour
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "WHEN",
        default_value_t = ColorChoice::Auto
    )]
    pub color: ColorChoice,

    /// Use ASCII markers instead of Unicode symbols and box drawing
    #[arg(long, global = true)]
    pub ascii: bool,

    /// Print machine-readable JSON on stdout
    #[arg(long, global = true)]
    pub json: bool,

    /// Do not write the log file on the hidden volume (diagnostics still go to stderr)
    #[arg(long, global = true)]
    pub no_log_file: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Activate the hidden NixOS environment (mount overlayfs + switch profiles)
    Activate(ActivateArgs),
    /// Deactivate and reboot into the decoy state (unmount + cleanup + reboot)
    Deactivate(DeactivateArgs),
    /// Emergency mode: rapid deactivation with countdown
    Emergency(EmergencyArgs),
    /// Show current status and uptime
    Status(StatusArgs),
    /// Verify system is clean of NAILS artifacts
    Verify(VerifyArgs),
    /// Initialize NAILS directory structure on a hidden volume
    Init(InitArgs),
    /// Delete a target's persistent overlay upper on the hidden volume
    #[command(name = "reset-upper")]
    ResetUpper(ResetUpperArgs),
    /// Inspect and check the configuration file (nails.toml)
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Dispatch pending desktop notifications (called by XDG autostart on login)
    #[command(name = "notify-dispatch")]
    NotifyDispatch,
}

/// `nails activate` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct ActivateArgs {
    /// Skip pre-flight checks (DANGEROUS - expert use only)
    #[arg(long)]
    pub no_preflight: bool,

    /// What to do with the graphical session (default: kill)
    #[arg(long, value_enum, value_name = "POLICY", default_value_t = SessionPolicy::Kill)]
    pub session: SessionPolicy,

    /// How to handle a volume that needs a pivot mount (default: refuse)
    #[arg(long, value_enum, value_name = "POLICY", default_value_t = PivotPolicy::Refuse)]
    pub pivot: PivotPolicy,

    /// Proceed without confirmation prompts
    ///
    /// Without this flag activation prompts on a terminal and refuses to run
    /// without one, so it never ends a graphical session unattended.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// NixOS flake reference (e.g., /etc/nixos#hostname)
    ///
    /// When set, this value is passed directly to `nixos-rebuild --flake`
    /// instead of auto-detecting the flake path. Supports attribute
    /// selection (e.g., /etc/nixos#amnesia-virtualbox).
    #[arg(
        long = "flake",
        value_name = "FLAKE_REF",
        conflicts_with = "overlay_only"
    )]
    pub nixos_flake: Option<String>,

    /// Preview activation steps without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Mount overlays only, skip NixOS profile switch
    #[arg(long)]
    pub overlay_only: bool,

    /// What to do with risky services still referencing a target (overrides the
    /// `risky_services` config key)
    ///
    /// Unset: restart when the session is killed, prompt on a terminal
    /// otherwise, and refuse a non-interactive run that keeps the session.
    #[arg(long = "risky-services", value_enum, value_name = "POLICY")]
    pub risky_services: Option<RiskyServicesArg>,

    /// Force-terminate interactive user programs (shells, editors, `tail -f`)
    /// holding a target instead of aborting
    ///
    /// Off by default: activation refuses to SIGKILL a program a user is working
    /// in and aborts before mounting. This flag ends them anyway.
    #[arg(long)]
    pub terminate_interactive: bool,
}

impl ActivateArgs {
    /// Map the parsed activation flags onto the core [`nails_core::ActivateOptions`].
    ///
    /// Only the policy and mode flags are set here; the output fields
    /// (`quiet`, `verbosity`, `json`, `no_color`) and the confirmation state
    /// are left at their defaults and filled in by the handler from the
    /// resolved output settings and the terminal. Mapping the default
    /// arguments therefore yields [`nails_core::ActivateOptions::default()`].
    pub fn to_activate_options(&self) -> nails_core::ActivateOptions {
        nails_core::ActivateOptions {
            kill_session: self.session == SessionPolicy::Kill,
            accept_pivot_risks: self.pivot == PivotPolicy::Allow,
            no_pivot: self.pivot == PivotPolicy::Refuse,
            yes: self.yes,
            overlay_only: self.overlay_only,
            risky_services: self.risky_services.map(Into::into),
            terminate_interactive: self.terminate_interactive,
            ..nails_core::ActivateOptions::default()
        }
    }
}

/// `nails deactivate` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct DeactivateArgs {
    /// Skip shell history cleanup
    ///
    /// By default, deactivation removes all 'nails' commands from shell history.
    /// Use this flag to preserve history (not recommended for forensic safety).
    #[arg(long)]
    pub no_clear_history: bool,

    /// Proceed without the confirmation prompt
    ///
    /// Deactivation restores the decoy configuration and reboots. Without this
    /// flag it prompts on a terminal and refuses to run without one.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// `nails emergency` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct EmergencyArgs {
    /// Skip the 3-second countdown (proceed immediately)
    #[arg(long)]
    pub no_countdown: bool,
}

/// `nails status` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusArgs {
    /// Show resolved paths and overlay mount details
    #[arg(long)]
    pub details: bool,

    /// Reflect the security posture in the exit code instead of always exiting 0
    #[arg(long)]
    pub exit_status: bool,
}

/// `nails verify` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Perform deep scan (slower, more thorough)
    #[arg(long)]
    pub deep: bool,
}

/// `nails config` subcommands
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigCommand {
    /// Print the resolved configuration file path and whether it exists
    Path,
    /// Print the effective configuration and where each value comes from
    Show {
        /// Print a commented example configuration instead (not with --json)
        #[arg(long)]
        example: bool,

        /// Preview the effect of `activate --flake FLAKE_REF`
        #[arg(long = "flake", value_name = "FLAKE_REF", conflicts_with = "example")]
        nixos_flake: Option<String>,

        /// Preview the effect of `deactivate --no-clear-history`
        #[arg(long, conflicts_with = "example")]
        no_clear_history: bool,
    },
    /// Check a configuration file strictly (syntax, types, unknown keys)
    Validate {
        /// File to check (default: the resolved configuration file)
        path: Option<PathBuf>,
    },
}

/// `nails init` arguments
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    /// Path to the hidden volume mount point
    pub path: PathBuf,
}

/// `nails reset-upper` arguments
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ResetUpperArgs {
    /// Overlay target whose persistent upper to delete (e.g. /home, /etc, /nix)
    pub target: PathBuf,

    /// Proceed without the confirmation prompt
    ///
    /// Without this flag reset-upper lists what it would delete and confirms on
    /// a terminal, refusing to run without one.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_checked_from(std::iter::once("nails").chain(args.iter().copied()))
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn reset_upper_parses_target_and_yes() {
        let cli = parse(&["reset-upper", "/home", "-y"]).expect("should parse");
        match cli.command {
            Commands::ResetUpper(args) => {
                assert_eq!(args.target, PathBuf::from("/home"));
                assert!(args.yes);
            }
            other => panic!("expected reset-upper, got {other:?}"),
        }
    }

    #[test]
    fn reset_upper_requires_a_target() {
        assert!(parse(&["reset-upper"]).is_err());
    }

    #[test]
    fn reset_upper_defaults_to_prompting() {
        let cli = parse(&["reset-upper", "/nix"]).expect("should parse");
        match cli.command {
            Commands::ResetUpper(args) => assert!(!args.yes),
            other => panic!("expected reset-upper, got {other:?}"),
        }
    }

    #[test]
    fn global_flags_are_accepted_before_and_after_the_subcommand() {
        for (before, after) in [
            (&["-q", "status"][..], &["status", "-q"][..]),
            (&["--json", "status"][..], &["status", "--json"][..]),
            (&["-vv", "activate"][..], &["activate", "-vv"][..]),
            (&["--ascii", "verify"][..], &["verify", "--ascii"][..]),
            (
                &["--color", "never", "status"][..],
                &["status", "--color", "never"][..],
            ),
            (
                &["--no-log-file", "deactivate"][..],
                &["deactivate", "--no-log-file"][..],
            ),
            (
                &["-c", "/x.toml", "emergency"][..],
                &["emergency", "-c", "/x.toml"][..],
            ),
            (
                &["--json", "config", "path"][..],
                &["config", "path", "--json"][..],
            ),
        ] {
            let a = parse(before).unwrap().global;
            let b = parse(after).unwrap().global;
            assert_eq!(a, b, "{before:?} vs {after:?}");
            assert_ne!(a, GlobalArgs::default(), "{before:?}");
        }
    }

    #[test]
    fn verbose_and_quiet_are_mutually_exclusive_in_any_position() {
        for args in [
            &["-q", "-v", "status"][..],
            &["-q", "status", "-v"][..],
            &["status", "-v", "-q"][..],
            &["-v", "activate", "--quiet"][..],
        ] {
            let error = parse(args).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{args:?}"
            );
        }
    }

    #[test]
    fn verbose_count_is_kept_in_either_position() {
        assert_eq!(parse(&["-vv", "status"]).unwrap().global.verbose, 2);
        assert_eq!(parse(&["activate", "-vvv"]).unwrap().global.verbose, 3);
        assert_eq!(parse(&["activate", "-v", "-v"]).unwrap().global.verbose, 2);
    }

    #[test]
    fn removed_output_flags_are_rejected() {
        for args in [
            &["status", "--plain"][..],
            &["status", "--no-color"][..],
            &["--no-logs", "status"][..],
            &["status", "--verbose-details"][..],
        ] {
            assert!(parse(args).is_err(), "{args:?} should be rejected");
        }
    }

    #[test]
    fn status_details_is_its_own_flag() {
        let cli = parse(&["status", "--details"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Status(StatusArgs { details: true, .. })
        ));
        // -v on status is verbosity, not details.
        let cli = parse(&["status", "-v"]).unwrap();
        assert_eq!(cli.global.verbose, 1);
        assert!(matches!(
            cli.command,
            Commands::Status(StatusArgs { details: false, .. })
        ));
    }

    #[test]
    fn color_takes_only_known_values() {
        assert_eq!(
            parse(&["--color", "always", "status"])
                .unwrap()
                .global
                .color,
            ColorChoice::Always
        );
        assert!(parse(&["--color", "sometimes", "status"]).is_err());
    }

    /// No subcommand redeclares an output or verbosity option: those are global.
    #[test]
    fn subcommands_do_not_declare_output_options() {
        const GLOBAL_ONLY: [&str; 7] = [
            "json", "no_color", "plain", "verbose", "quiet", "color", "ascii",
        ];

        fn walk(command: &clap::Command, root: bool) {
            for arg in command.get_arguments() {
                if !root && !arg.is_global_set() {
                    assert!(
                        !GLOBAL_ONLY.contains(&arg.get_id().as_str()),
                        "{} declares {}",
                        command.get_name(),
                        arg.get_id()
                    );
                }
            }
            for sub in command.get_subcommands() {
                walk(sub, false);
            }
        }

        walk(&Cli::command(), true);
    }
}
