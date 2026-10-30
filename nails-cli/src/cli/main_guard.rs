// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Early privilege gate for the commands that mutate the host.
//!
//! Activation, deactivation and the emergency teardown all drive privileged
//! syscalls (overlay mounts, pivots, process signalling) and write a log and a
//! state file onto the hidden volume. Run without root they would fail partway,
//! after the subscriber was initialised and a log file was already opened on the
//! decoy. This gate runs in `main` *before* logging init and before any command
//! handler, so an unprivileged invocation leaves nothing behind and the operator
//! gets one clear, copy-pasteable instruction instead of a mid-run syscall error.
//!
//! The check is a compile-time constant in shipped builds: there is no
//! environment variable or path layout that disables it. Only a `test-hooks`
//! build (the binary `cargo test` drives) honours `NAILS_TEST_ENFORCE_ROOT`, and
//! then only to *enable* the gate for the one integration test that asserts the
//! exit-5 behaviour — the hundreds of other integration tests that drive the
//! real write paths unprivileged are never affected.

use crate::cli::args::{Commands, RehearseStep};
use crate::cli::output::envelope::{EnvelopePrint, ErrorBody, error_envelope};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Whether `command` must run as root.
///
/// `activate --dry-run` is an alias for `check`, which keeps nothing it
/// writes, so it is exempt; every other activation, and deactivation and
/// emergency teardown, require root.
pub fn requires_root(command: &Commands) -> bool {
    match command {
        Commands::Activate(args) => !args.dry_run,
        Commands::Deactivate(_)
        | Commands::Emergency(_)
        | Commands::Recover(_)
        | Commands::Transition
        | Commands::GuardDevice { .. }
        | Commands::ReconcileRecords { .. }
        | Commands::BootWriter { .. } => true,
        // The window's helper reads the root-only configuration and runs the
        // mutating operations for a window that runs as the operator.
        #[cfg(feature = "gui")]
        Commands::Helper(_) => true,
        // The launcher reads the root-only configuration, starts the helper as
        // root and drops the window to the operator.
        #[cfg(feature = "gui")]
        Commands::Gui => true,
        // Planting writes into the overlays, a live scan reads raw block devices
        // and reset deletes from the hidden volume. An offline scan of image
        // files and the status view are not gated here: they still read the
        // configuration, which `init` leaves readable by root only, and a
        // refused read names the `sudo` line (`commands::config_read_hint`).
        Commands::Rehearse(args) => match &args.step {
            Some(RehearseStep::Plant(_) | RehearseStep::Reset) => true,
            Some(RehearseStep::Scan(scan)) => !scan.offline,
            Some(RehearseStep::Status) | None => false,
        },
        _ => false,
    }
}

/// The subcommand name used in the remediation hint.
fn subcommand_name(command: &Commands) -> &'static str {
    match command {
        Commands::Activate(_) => "activate",
        Commands::Deactivate(_) => "deactivate",
        Commands::Emergency(_) => "emergency",
        Commands::Recover(_) => "recover",
        Commands::Status(_) => "status",
        Commands::Verify(_) => "verify",
        Commands::Rehearse(_) => "rehearse",
        Commands::Check(_) => "check",
        Commands::Init(_) => "init",
        Commands::Discard(_) => "discard",
        Commands::Config(_) => "config",
        Commands::Completions(_) => "completions",
        Commands::Watch => "watch",
        Commands::SleepGuard => "sleep-guard",
        Commands::Transition => "transition",
        Commands::GuardDevice { .. } => "guard-device",
        Commands::ReconcileRecords { .. } => "reconcile-records",
        Commands::BootWriter { .. } => "boot-writer",
        #[cfg(feature = "gui")]
        Commands::Helper(_) => "helper",
        #[cfg(feature = "gui")]
        Commands::Gui => "gui",
    }
}

/// The `sudo` line that runs this invocation again as root: the running
/// binary followed by `args`, the arguments it was given (the global
/// `--config` and every flag included), each quoted for a POSIX shell where it
/// needs it. Without arguments it names `subcommand` alone.
///
/// The absolute path to the running binary is used so the suggested `sudo`
/// invocation works regardless of the caller's `PATH` (sudo's `secure_path`
/// never includes the hidden volume) and regardless of whether the binary is
/// reached through a decoy symlink. When the path cannot be resolved the bare
/// command name is used as a last resort.
pub(crate) fn sudo_command(
    argv0: Option<&std::path::Path>,
    subcommand: &str,
    args: &[std::ffi::OsString],
) -> String {
    use nails_core::next_step::shell_word;
    let binary = argv0
        .map(|path| shell_word(path.as_os_str()))
        .unwrap_or_else(|| "nails".to_string());
    let args = if args.is_empty() {
        subcommand.to_string()
    } else {
        args.iter()
            .map(|arg| shell_word(arg))
            .collect::<Vec<_>>()
            .join(" ")
    };
    format!("sudo {binary} {args}")
}

/// The arguments this process was started with, without the program name.
pub(crate) fn invocation_args() -> Vec<std::ffi::OsString> {
    std::env::args_os().skip(1).collect()
}

/// Build the "must run as root" message for `subcommand`, run with `args`.
fn needs_root_message(
    argv0: Option<&std::path::Path>,
    subcommand: &str,
    args: &[std::ffi::OsString],
) -> String {
    format!(
        "this command must run as root: try `{}`",
        sudo_command(argv0, subcommand, args)
    )
}

/// True when the effective user is root.
pub(crate) fn effective_user_is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Whether the root gate is enforced in this build.
///
/// Shipped builds always enforce it. A `test-hooks` build enforces it only when
/// `NAILS_TEST_ENFORCE_ROOT` is set in the startup snapshot, so the integration suite — which runs
/// unprivileged and must still exercise the real activate/deactivate/emergency
/// paths — is unaffected unless a test opts in.
#[cfg(any(test, feature = "test-hooks"))]
fn gate_enforced(env: &nails_core::RuntimeEnv) -> bool {
    env.test_hooks.enforce_root.is_some()
}

#[cfg(not(any(test, feature = "test-hooks")))]
#[inline]
fn gate_enforced(_env: &nails_core::RuntimeEnv) -> bool {
    true
}

/// Enforce the root requirement for `command`.
///
/// Returns `Some(ExitStatus::NeedsRoot)` after printing the remediation hint
/// when a privileged command is run unprivileged, and `None` otherwise. `main`
/// turns the returned status into the process exit code (5) without initialising
/// logging or running the command handler.
pub fn enforce_root(
    command: &Commands,
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
) -> Option<ExitStatus> {
    if !gate_enforced(env) || !requires_root(command) || effective_user_is_root() {
        return None;
    }

    let argv0 = std::env::current_exe().ok();
    let subcommand = subcommand_name(command);
    let message = needs_root_message(argv0.as_deref(), subcommand, &invocation_args());
    emit_needs_root(settings, subcommand, &message);
    Some(ExitStatus::NeedsRoot)
}

/// Report the refused privileged command: one error envelope on stdout under
/// `--json` (the code is `needs_root`, exit 5 now carries JSON too), otherwise
/// the remediation message on stderr using the resolved stderr style.
///
/// Errors are always shown, even under `--quiet`: a refused privileged command
/// that printed nothing would look like a silent failure.
fn emit_needs_root(settings: &OutputSettings, command: &'static str, message: &str) {
    if settings.is_json() {
        error_envelope(command, ErrorBody::new("needs_root", message)).print();
    } else {
        use nails_core::output::Mark;
        eprintln!("{}", settings.stderr_style().marked(Mark::Fail, message));
    }
}

/// Every user-facing subcommand name, for recognising the command a clap usage
/// error was about from the raw arguments (clap has not produced a parsed
/// command when it fails).
const SUBCOMMAND_NAMES: &[&str] = &[
    "activate",
    "deactivate",
    "emergency",
    "recover",
    "status",
    "verify",
    "rehearse",
    "check",
    "init",
    "discard",
    "config",
    "completions",
];

/// The subcommand a raw argument list names, for the `command` field of the
/// envelope of a usage error or a panic. When no subcommand is present (a bad
/// global option on its own), the envelope names the tool itself.
pub(crate) fn command_from_argv(argv: &[std::ffi::OsString]) -> &'static str {
    for arg in argv {
        if let Some(word) = arg.to_str()
            && let Some(name) = SUBCOMMAND_NAMES.iter().find(|n| **n == word)
        {
            return name;
        }
    }
    "nails"
}

/// Exit on a clap parse result, enveloping a usage error under `--json`.
///
/// Help and version are not errors: they print to stdout and exit 0, so clap's
/// own exit handles them. A real usage error exits 2; under `--json` it prints
/// one error envelope on stdout (code `usage`) naming the command it was about,
/// so a script sees the same one-document contract every other command gives.
/// A command that needs a subcommand of its own and got none (`nails --json
/// config`) is one of them: clap shows its help for it, but on stderr and with
/// exit 2, so under `--json` it is the usage envelope too.
pub fn exit_on_clap_error(error: clap::Error) -> ! {
    use clap::error::ErrorKind;
    let json = std::env::args_os().any(|arg| arg == "--json");
    if !json
        || matches!(
            error.kind(),
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
        )
    {
        error.exit()
    }
    let command = command_from_argv(&invocation_args());
    let message = match error.kind() {
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => missing_subcommand(command),
        _ => error.to_string(),
    };
    error_envelope(command, ErrorBody::new("usage", message)).print();
    crate::cli::chokepoint::exit_process(ExitStatus::Usage.code())
}

/// The usage message for `command` run without the subcommand it needs, naming
/// the ones it takes: `config needs a subcommand: path, show or validate`.
fn missing_subcommand(command: &str) -> String {
    let cli = <crate::cli::Cli as clap::CommandFactory>::command();
    let parent = cli.find_subcommand(command).unwrap_or(&cli);
    let names: Vec<&str> = parent
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
        .map(clap::Command::get_name)
        .collect();
    let list = match names.split_last() {
        Some((last, [])) => (*last).to_string(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    };
    format!("{command} needs a subcommand: {list}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{ActivateArgs, DeactivateArgs, EmergencyArgs, StatusArgs, VerifyArgs};
    use std::path::Path;

    #[test]
    fn mutating_commands_require_root() {
        assert!(requires_root(&Commands::Activate(ActivateArgs::default())));
        assert!(requires_root(&Commands::Deactivate(
            DeactivateArgs::default()
        )));
        assert!(requires_root(
            &Commands::Emergency(EmergencyArgs::default())
        ));
    }

    #[test]
    fn dry_run_activate_is_read_only() {
        let args = ActivateArgs {
            dry_run: true,
            ..ActivateArgs::default()
        };
        assert!(!requires_root(&Commands::Activate(args)));
    }

    #[test]
    fn read_only_commands_do_not_require_root() {
        assert!(!requires_root(&Commands::Status(StatusArgs::default())));
        assert!(!requires_root(&Commands::Verify(VerifyArgs::default())));
        assert!(!requires_root(&Commands::Check(Default::default())));
    }

    fn args(args: &[&str]) -> Vec<std::ffi::OsString> {
        args.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn message_names_the_absolute_binary_and_every_argument() {
        let msg = needs_root_message(
            Some(Path::new("/opt/hidden/nails")),
            "activate",
            &args(&[
                "--config",
                "/opt/hidden/config/nails.toml",
                "activate",
                "-y",
            ]),
        );
        assert_eq!(
            msg,
            "this command must run as root: try \
             `sudo /opt/hidden/nails --config /opt/hidden/config/nails.toml activate -y`"
        );
    }

    #[test]
    fn message_falls_back_to_bare_name_without_argv0_or_arguments() {
        let msg = needs_root_message(None, "deactivate", &[]);
        assert!(msg.contains("sudo nails deactivate"));
    }

    /// `nails --json config` names the subcommands `config` takes, as the
    /// usage envelope's message, instead of clap's help on stderr.
    #[test]
    fn a_missing_subcommand_names_the_ones_the_command_takes() {
        assert_eq!(
            missing_subcommand("config"),
            "config needs a subcommand: path, show or validate"
        );
        let top = missing_subcommand("nails");
        assert!(
            top.starts_with("nails needs a subcommand: activate, deactivate, "),
            "{top}"
        );
        assert!(top.ends_with(" or completions"), "{top}");
        assert!(
            !top.contains("watch"),
            "a hidden command is not named: {top}"
        );
    }

    #[test]
    fn an_argument_a_shell_would_split_or_expand_is_quoted() {
        assert_eq!(
            sudo_command(
                Some(Path::new("/mnt/my data/nails")),
                "status",
                &args(&["--config", "/mnt/my data/it's.toml", "status", "--details"]),
            ),
            "sudo '/mnt/my data/nails' --config '/mnt/my data/it'\\''s.toml' status --details"
        );
        assert_eq!(sudo_command(None, "x", &args(&[""])), "sudo nails ''");
    }
}
