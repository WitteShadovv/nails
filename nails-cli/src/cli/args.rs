// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! CLI argument definitions
//!
//! Output and logging options live in [`GlobalArgs`] and are accepted before or
//! after the subcommand (`nails -q status` and `nails status -q` are the same).
//! Each subcommand has its own argument struct holding only what that command
//! means.

use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use std::ffi::OsString;
use std::path::PathBuf;

/// The workflow description shown in `nails --help` (long form).
const ROOT_LONG_ABOUT: &str = "\
Run a hidden session on a decoy Linux system.

NAILS runs a hidden session on a decoy system: one OverlayFS over the whole
decoy root, with every change kept on the hidden volume, entered and left with
`systemctl soft-reboot` (systemd 254 or newer). The binary and its
configuration live on the hidden volume, so you run it by its
full path from the mounted volume (e.g. `sudo /mnt/data/nails status`),
never from a copy on the decoy disk.

The workflow has four steps:
  1. Open and mount the hidden backend (e.g. unlock the LUKS/VeraCrypt volume).
  2. `init <root>` once, to lay out the hidden volume.
  3. `activate` to soft-reboot into the hidden session. You are logged out;
     the hidden session starts at its own login screen (a display manager set
     to log an account in automatically logs it in again, as at boot).
  4. `deactivate` to soft-reboot back to the plain decoy, or `emergency` to
     kill the hidden session at once and return (or power off). If an
     activation was interrupted, `recover` removes what it left behind.";

/// The EXAMPLES and EXIT STATUS sections shown at the foot of `nails --help`.
///
/// Examples use neutral placeholders only (`/mnt/data` for the mounted backend,
/// `/mnt/usb` for an offline image): no default hidden path appears here, so the
/// security binary scan and `help_and_version_carry_no_blocked_substrings` stay
/// green. The EXIT STATUS table is kept in step with the
/// [`ExitStatus`](crate::cli::output::ExitStatus) enum by
/// `exit_status_help_lists_every_code`.
const EXIT_STATUS_HELP: &str = "\
EXAMPLES:
  # Run by full path from the mounted backend, never from a decoy copy.
  sudo /mnt/data/nails init /mnt/data   Lay out the hidden volume (once)
  sudo /mnt/data/nails activate         Soft-reboot into the hidden session
  sudo /mnt/data/nails status --json    Machine-readable state and uptime
  sudo /mnt/data/nails deactivate       Soft-reboot back to the decoy
  sudo /mnt/data/nails emergency        Kill the hidden session and return now
  source <(/mnt/data/nails completions bash)   Load completions in the session

EXIT STATUS:
  0    success
  1    the operation failed
  2    command-line usage error
  3    the configuration file or environment was unusable
  4    a pre-flight check refused the operation
  5    the operation needs privileges it did not have
  6    the on-disk state could not be trusted
  7    a degraded or interrupted session, or an incomplete cleanup
  8    the host is not one NAILS can operate on
  9    completed, but with a warning the caller should act on
  10   verify found warnings
  11   verify found critical artifacts, or rehearse scan found its canary
  130  cancelled by a signal (SIGINT/SIGTERM)";

/// Run a hidden session on a decoy Linux system
#[derive(Parser, Debug)]
#[command(name = "nails")]
#[command(version)]
#[command(about = "Run a hidden session on a decoy Linux system", long_about = ROOT_LONG_ABOUT)]
#[command(after_long_help = EXIT_STATUS_HELP)]
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
    #[arg(short = 'c', long, global = true, value_name = "PATH", value_hint = ValueHint::FilePath)]
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
    /// Soft-reboot into the hidden session (whole-root overlay on the hidden volume)
    Activate(ActivateArgs),
    /// Soft-reboot from the hidden session back to the plain decoy
    Deactivate(DeactivateArgs),
    /// Kill the hidden session at once and soft-reboot back to the decoy (or power off)
    Emergency(EmergencyArgs),
    /// Remove what an interrupted activation left in /run
    Recover(RecoverArgs),
    /// Show the session, security posture and hidden volume
    Status(StatusArgs),
    /// Check for known NAILS traces (evidence, not proof)
    Verify(VerifyArgs),
    /// Rehearse: plant a canary in a hidden session, then scan the raw decoy for it
    Rehearse(RehearseArgs),
    /// Check readiness to activate without making any changes (alias: doctor)
    #[command(alias = "doctor")]
    Check(CheckArgs),
    /// Initialize NAILS directory structure on a hidden volume
    Init(InitArgs),
    /// Delete a path's hidden copy from the hidden root's upper
    #[command(name = "reset-upper")]
    ResetUpper(ResetUpperArgs),
    /// Inspect and check the configuration file (nails.toml)
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Print a shell completion script on stdout (for `source <(...)`)
    Completions(CompletionsArgs),
    /// In-session backend watcher (a runtime unit of the hidden session)
    #[command(hide = true)]
    Watch,
    /// Sleep guard holding a logind inhibitor (a runtime unit of the hidden session)
    #[command(name = "sleep-guard", hide = true)]
    SleepGuard,
    /// The last step before each soft-reboot switch (run by systemd, not by hand)
    #[command(hide = true)]
    Transition,
    /// Make a disk the hidden session does not use read-only (run by udev, not by hand)
    #[command(name = "guard-device", hide = true)]
    GuardDevice {
        /// The device node.
        device: std::path::PathBuf,
    },
}

/// `nails activate` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
WHAT HAPPENS:
  Activation builds one overlay over the whole decoy root at /run/nextroot,
  with every change stored on the hidden volume, and soft-reboots into it
  (systemd 254 or newer). Every program is closed and you are logged out; the
  hidden session starts at its own login screen (a display manager set to log
  an account in automatically logs it in again, as at boot). Nothing the
  hidden session writes through the decoy's filesystems reaches the decoy
  disk: the ESP is read-only, other decoy filesystems are overlaid, and decoy
  swap is never used. docs/threat-model.md lists the residual channels.

EXAMPLES:
  nails activate                      Enter the hidden session
  nails activate --overlay-only       Enter with the decoy's own system (NixOS)
  nails activate --dry-run            Preview without changing anything")]
pub struct ActivateArgs {
    /// Skip pre-flight checks (DANGEROUS - expert use only)
    #[arg(long)]
    pub no_preflight: bool,

    /// Proceed without the confirmation prompt
    ///
    /// Without this flag activation prompts on a terminal and refuses to run
    /// without one, because it logs you out.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// NixOS: the hidden configuration as a flake reference <path>#<host>
    ///
    /// The hidden system is built from it into the hidden root's store before
    /// the soft-reboot. Supports attribute selection after the `#`.
    #[arg(
        long = "nixos-flake",
        value_name = "FLAKE_REF",
        conflicts_with = "overlay_only"
    )]
    pub nixos_flake: Option<String>,

    /// Preview activation steps without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// NixOS: enter with the decoy's own system, without building the hidden
    /// configuration (the hidden /etc and home still apply)
    #[arg(long)]
    pub overlay_only: bool,

    /// Accept a persistent decoy posture instead of refusing activation
    ///
    /// By default activation refuses a host that keeps forensic traces on the
    /// decoy disk: a persistent systemd-journald journal, or an active
    /// rsyslog/syslog-ng/auditd. What the decoy logs while it shuts down for
    /// the soft-reboot, and while it starts again afterwards, would survive on
    /// the decoy disk. This flag accepts that risk (and overrides
    /// `accept_persistent_decoy` in `nails.toml`).
    #[arg(long)]
    pub accept_persistent_decoy: bool,

    /// Use a hidden root that this computer's own storage seems to hold
    ///
    /// By default activation refuses a root that this computer's own storage
    /// holds (a subvolume or a bind mount of one of its filesystems, a volume
    /// inside its storage, an image file on it): everything the session writes
    /// there lands on this computer's disk. Use this flag only for storage you
    /// know this computer does not use, such as a disk its fstab lists but
    /// never mounts. It turns those refusals into a warning, adds a line to the
    /// logout confirmation and records the choice for `status`. A folder that
    /// is no mount point, a root with a second filesystem mounted over it,
    /// storage that cannot be judged, and a decoy entry that opens the volume
    /// are still refused.
    #[arg(long)]
    pub allow_decoy_storage: bool,
}

/// `nails deactivate` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
WHAT HAPPENS:
  In the hidden session, deactivation mounts the decoy root at /run/nextroot,
  marks the hidden volume for closing and soft-reboots: every hidden program
  is stopped in order, the top of /run is scrubbed of the hidden session
  (network links it set up stay), and the decoy starts again at its own login
  screen (a display manager set to log an account in automatically logs it in
  again, as at boot). The scrub also deletes the runtime journal, which the
  decoy shares with the hidden session, so a volatile decoy's journal starts
  again at the return. The hidden volume is unmounted and its encryption
  mapping closed by the switch itself.

EXAMPLES:
  nails deactivate                    Soft-reboot back to the decoy
  nails deactivate --poweroff         Power off instead
  nails deactivate -y                 Skip the confirmation prompt")]
pub struct DeactivateArgs {
    /// Proceed without the confirmation prompt
    ///
    /// Deactivation ends the hidden session. Without this flag it prompts on
    /// a terminal and refuses to run without one.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Power the machine off instead of returning to the decoy.
    ///
    /// Powering off lets RAM decay; leave the machine off for a few minutes
    /// before handing it over.
    #[arg(long)]
    pub poweroff: bool,
}

/// `nails emergency` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
WHAT HAPPENS:
  In the hidden session: the decoy root is mounted at /run/nextroot, the
  hidden volume is marked for closing, the soft-reboot is enqueued and every
  hidden program is killed at once. The machine returns to the plain decoy,
  which shows its normal login screen; log in with the decoy password (a
  display manager set to log an account in automatically logs it in again, as
  at boot). With --poweroff the machine powers off instead. On the decoy,
  emergency removes what an interrupted activation left in /run.

EXAMPLES:
  nails emergency                     Kill the hidden session and return now
  nails emergency --countdown 5       Wait 5s (Ctrl+C to abort), then act
  nails emergency --poweroff          Kill the hidden session and power off
  nails emergency --reboot            Kill the hidden session and reboot fully")]
pub struct EmergencyArgs {
    /// Wait this many seconds before acting, printing a Ctrl+C abort hint.
    ///
    /// Omitted (the default) acts immediately. The wait is never affected by
    /// `--quiet` or `--json`, so output flags never change the timing.
    #[arg(long, value_name = "SECS")]
    pub countdown: Option<u64>,

    /// Power the machine off instead of returning to the decoy, whatever the
    /// outcome. RAM decays: the strongest answer to a seizure. Leave the
    /// machine off for a few minutes. Mutually exclusive with `--reboot`.
    #[arg(long, conflicts_with = "reboot")]
    pub poweroff: bool,

    /// Reboot fully (firmware and bootloader) instead of the soft-reboot back.
    ///
    /// A warm reboot does not clear RAM. Prefer `--poweroff` when RAM residue
    /// matters. Mutually exclusive with `--poweroff`.
    #[arg(long)]
    pub reboot: bool,
}

/// `nails recover` arguments
///
/// Recover takes no options of its own: on the decoy it detaches a next root
/// an interrupted activation left at `/run/nextroot`, removes its runtime files
/// and resets the state, so a later reboot never enters the leftover tree.
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  nails recover                       Remove an interrupted activation's leftovers")]
pub struct RecoverArgs {}

/// `nails status` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  sudo /mnt/data/nails status             Show the current state and uptime
  sudo /mnt/data/nails status --details   Add resolved paths and overlay details
  sudo /mnt/data/nails status --json      Emit a machine-readable envelope

The configuration `init` writes is readable by root only, so status runs with
sudo like the other commands, by the binary's full path: sudo's secure_path
never includes the hidden volume.")]
pub struct StatusArgs {
    /// Show resolved paths and overlay mount details
    #[arg(long)]
    pub details: bool,
}

/// `nails verify` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  nails verify                        Scan the live host for NAILS artifacts
  nails verify --deep                 Slower, more thorough scan
  nails verify --offline --root /mnt  Scan a mounted decoy image
  nails verify --offline --root /mnt --examiner --disk /dev/sdb
                                      Add the examiner's view of setup traces")]
pub struct VerifyArgs {
    /// Perform deep scan (slower, more thorough)
    #[arg(long)]
    pub deep: bool,

    /// Scan a read-only mounted decoy image or partition instead of the live
    /// host. Requires `--root`; live checks (processes, mounts, block devices)
    /// are skipped and every path is read from under the image root.
    #[arg(long, requires = "root")]
    pub offline: bool,

    /// Root of the mounted decoy image to scan in `--offline` mode.
    #[arg(long, value_name = "MOUNT", value_hint = ValueHint::DirPath, requires = "offline")]
    pub root: Option<std::path::PathBuf>,

    /// Also report setup traces an examiner looks for (encryption headers,
    /// containers, crypttab, LVM archives, tooling and history), grouped by
    /// what they suggest. Reports only; changes nothing. Needs `--offline`.
    #[arg(long, requires = "offline")]
    pub examiner: bool,

    /// The raw disk or disk image behind `--root`, read-only, for the
    /// partition-level examiner checks (LUKS headers, random-looking space).
    #[arg(long, value_name = "DEVICE", value_hint = ValueHint::FilePath, requires = "examiner")]
    pub disk: Option<std::path::PathBuf>,
}

/// `nails rehearse` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
STEPS:
  1. In an active hidden session:     nails rehearse plant
  2. Deactivate as usual, then on the decoy unlock and mount the hidden volume
  3. From the decoy, or a later session: nails rehearse scan
  Then `nails rehearse reset` removes the rehearsal from the hidden volume.

EXAMPLES:
  nails rehearse                      Show where the rehearsal stands
  nails rehearse plant --user alice   Plant the canary for alice's session
  nails rehearse scan                 Scan the mounted decoy devices
  nails rehearse scan --offline --image decoy.raw
                                      Scan a disk image instead

The scan exits 0 when no canary is found, 11 when one is, and 9 when a device
could not be scanned completely.")]
pub struct RehearseArgs {
    /// The step to run; without one, show the status and the next step
    #[command(subcommand)]
    pub step: Option<RehearseStep>,
}

/// One step of a rehearsal.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RehearseStep {
    /// Step 1, in an active hidden session: plant a random canary in the
    /// session's files, log, a process, recent files and a notification
    Plant(RehearsePlantArgs),
    /// Step 3, after deactivating: scan the raw decoy devices for the canary
    Scan(RehearseScanArgs),
    /// Show where the rehearsal stands and the next step
    Status,
    /// Remove the rehearsal state and its planted files from the hidden volume
    Reset,
}

/// `nails rehearse plant` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct RehearsePlantArgs {
    /// The operator whose home, recent files and notifications are used
    /// (default: the user who ran sudo)
    #[arg(long, value_name = "NAME")]
    pub user: Option<String>,
}

/// `nails rehearse scan` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
pub struct RehearseScanArgs {
    /// Scan this block device instead of the mounted decoy devices (repeatable)
    #[arg(long = "device", value_name = "DEVICE", value_hint = ValueHint::FilePath, conflicts_with = "offline")]
    pub devices: Vec<std::path::PathBuf>,

    /// Scan disk images or devices given with --image, not this machine's mounts
    #[arg(long, requires = "images")]
    pub offline: bool,

    /// An image or device to scan in --offline mode (repeatable)
    #[arg(long = "image", value_name = "IMAGE", value_hint = ValueHint::FilePath, requires = "offline")]
    pub images: Vec<std::path::PathBuf>,

    /// Read the canary token from this file instead of the hidden volume's
    /// rehearsal state (--offline only)
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath, requires = "offline")]
    pub token_file: Option<std::path::PathBuf>,

    /// Scan even in the session the canary was planted in (proves little: the
    /// session's writes may not have reached the disk yet)
    #[arg(long)]
    pub allow_same_boot: bool,

    /// Stop each device after this many bytes
    #[arg(long, value_name = "BYTES")]
    pub max_bytes: Option<u64>,
}

/// `nails check` (alias `doctor`) arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  nails check                         Report readiness to activate
  nails doctor                        Same, via the alias
  nails check --overlay-only          Skip the hidden NixOS build checks")]
pub struct CheckArgs {
    /// Check as for `activate --overlay-only` (skip the hidden NixOS build checks)
    #[arg(long)]
    pub overlay_only: bool,

    /// NixOS layer: check a specific flake reference as <path>#<host> (e.g. /mnt/data/nixos#my-host)
    #[arg(
        long = "nixos-flake",
        value_name = "FLAKE_REF",
        conflicts_with = "overlay_only"
    )]
    pub nixos_flake: Option<String>,

    /// Report a persistent decoy posture as a warning instead of a failure
    ///
    /// Mirrors `activate --accept-persistent-decoy` so `check`/`--dry-run`
    /// reflects what activation would do.
    #[arg(long)]
    pub accept_persistent_decoy: bool,

    /// Report a hidden root on this computer's own storage as a warning
    ///
    /// Mirrors `activate --allow-decoy-storage`: a root this computer's own
    /// storage seems to hold then warns instead of failing. A folder that is
    /// no mount point, a covered root and storage that cannot be judged still
    /// fail.
    #[arg(long)]
    pub allow_decoy_storage: bool,
}

/// `nails config` subcommands
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  nails config path                   Print the resolved config file path
  nails config show                   Print the effective configuration
  nails config show --example         Print a commented example config
  nails config validate ./nails.toml  Strictly check a config file")]
pub enum ConfigCommand {
    /// Print the resolved configuration file path and whether it exists
    Path,
    /// Print the effective configuration and where each value comes from
    Show {
        /// Print a commented example configuration instead (not with --json)
        #[arg(long)]
        example: bool,

        /// Preview the effect of `activate --nixos-flake FLAKE_REF`
        #[arg(
            long = "nixos-flake",
            value_name = "FLAKE_REF",
            conflicts_with = "example"
        )]
        nixos_flake: Option<String>,
    },
    /// Check a configuration file strictly (syntax, types, unknown keys)
    Validate {
        /// File to check (default: the resolved configuration file)
        #[arg(value_hint = ValueHint::FilePath)]
        path: Option<PathBuf>,
    },
}

/// `nails init` arguments
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  nails init /mnt/data                Lay out the hidden volume at /mnt/data
  nails init /mnt/data --no-hardware-config   Skip the hidden NixOS layout")]
pub struct InitArgs {
    /// Path to the mounted hidden volume to initialize
    #[arg(value_hint = ValueHint::DirPath)]
    pub path: PathBuf,

    /// Initialize a volume that this computer's own storage seems to hold
    ///
    /// By default `init` refuses a target that this computer's own storage
    /// holds (a subvolume or a bind mount of one of its filesystems, a volume
    /// inside its storage, an image file on it), because writing the NAILS
    /// layout there leaves an identifying tree on this computer's disk. Use
    /// this flag only for storage you know this computer does not use; it
    /// turns those refusals into a warning. A folder that is no mount point, a
    /// target with a second filesystem mounted over it, and one whose storage
    /// cannot be judged are still refused.
    #[arg(long)]
    pub allow_decoy_storage: bool,

    /// Base hardware configuration to seed the hidden NixOS layout from
    ///
    /// Overrides the default `/etc/nixos/hardware-configuration.nix`. On a
    /// non-NixOS host the layout is skipped unless this is given.
    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath, conflicts_with = "no_hardware_config")]
    pub hardware_config: Option<PathBuf>,

    /// Do not create the hidden NixOS layout at all
    #[arg(long)]
    pub no_hardware_config: bool,
}

/// `nails reset-upper` arguments
#[derive(Args, Debug, Clone, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  nails reset-upper /home             Delete the hidden copy of /home
  nails reset-upper /nix -y           Delete the hidden /nix without prompting")]
pub struct ResetUpperArgs {
    /// Path whose hidden copy to delete (e.g. /home, /etc, /nix); the decoy's
    /// own files show through again
    #[arg(value_hint = ValueHint::DirPath)]
    pub target: PathBuf,

    /// Proceed without the confirmation prompt
    ///
    /// Without this flag reset-upper lists what it would delete and confirms on
    /// a terminal, refusing to run without one.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

/// `nails completions` arguments
#[derive(Args, Debug, Clone, PartialEq, Eq)]
#[command(after_long_help = "\
EXAMPLES:
  source <(nails completions bash)    Load completions in the current shell
  nails completions zsh               Print the zsh completion script
  nails completions fish              Print the fish completion script

The script is written to stdout only; nothing is installed, so running this from
the hidden session leaves no completion file on the decoy.")]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
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
    fn exit_status_help_lists_every_code() {
        use crate::cli::output::ExitStatus;

        // Listing every variant here means adding one to the enum without a row in
        // the EXIT STATUS help table fails this test.
        let all = [
            ExitStatus::Ok,
            ExitStatus::Failed,
            ExitStatus::Usage,
            ExitStatus::Config,
            ExitStatus::PreflightRefused,
            ExitStatus::NeedsRoot,
            ExitStatus::InvalidState,
            ExitStatus::DegradedReboot,
            ExitStatus::Unsupported,
            ExitStatus::SuccessWithWarnings,
            ExitStatus::VerifyWarning,
            ExitStatus::VerifyCritical,
            ExitStatus::Cancelled,
        ];

        for status in all {
            let code = status.code().to_string();
            assert!(
                EXIT_STATUS_HELP
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{code} "))),
                "EXIT STATUS help is missing a row for exit code {code}"
            );
        }
    }

    #[test]
    fn internal_subcommands_are_hidden_from_help() {
        let command = Cli::command();
        for name in ["watch", "sleep-guard", "transition", "guard-device"] {
            let sub = command
                .get_subcommands()
                .find(|cmd| cmd.get_name() == name)
                .expect("the subcommand exists");
            assert!(sub.is_hide_set(), "{name} must be hidden from help");
        }
    }

    #[test]
    fn recover_is_a_visible_subcommand() {
        let command = Cli::command();
        let recover = command
            .get_subcommands()
            .find(|cmd| cmd.get_name() == "recover")
            .expect("recover subcommand exists");
        assert!(!recover.is_hide_set(), "recover must be visible in help");
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
