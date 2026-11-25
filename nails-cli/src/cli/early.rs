// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Early dispatch, before clap, the configuration, the environment snapshot and
//! tracing exist: these paths must act even when the hidden volume has failed
//! or the configuration cannot be read.
//!
//! `main` calls [`dispatch`] first. These command lines are handled here:
//!
//! - **`emergency`**, run as root: the whole hot path of
//!   `nails_teardown::whole_root::emergency` runs here (the countdown, the way
//!   back, the soft-reboot or power action, the kill of all hidden userspace).
//!   Its report is parked for the emergency command, which prints and logs it
//!   once the CLI is initialised, if it is still alive by then;
//! - **`transition`**, run by systemd as the last step before each soft-reboot
//!   switch: `nails_teardown::whole_root::transition` runs and the process ends
//!   at once, with no output and no log. It is told how it was started
//!   ([`started`]), for the check of its own domain before an armed switch.
//! - **`guard-device <node>`**, run by the hidden session's udev rule for every
//!   disk that appears (`[session_mounts] read_only`):
//!   `nails_teardown::whole_root::disk_guard` makes it read-only unless the
//!   session uses it, and the process ends at once, with no output and no log.
//! - **`reconcile-records`**, run by a one-shot unit the way back leaves for an
//!   FHS decoy's first start: `nails_teardown::whole_root::boot_records` makes
//!   the login and boot records read as a clean power cycle and removes itself,
//!   then the process ends at once, with no output and no log.
//! - **`boot-writer`**, run in place of the decoy's wtmpdb boot writer on that
//!   start: `nails_teardown::whole_root::boot_writer` starts the writer in
//!   this process's place, so that it records the way back as a power cycle.
//!
//! Before the last two do their work, and before the hidden session's
//! **`watch`** and **`sleep-guard`** go on to the normal path, a process PID 1
//! started checks that it runs in the domain the SELinux label of its RAM
//! copy gives it, where a policy is loaded
//! (`nails_teardown::whole_root::program_label::enter_domain`): one that runs
//! elsewhere gives its copy the label again and starts itself again from it,
//! once. One that still runs elsewhere does not do its work there. [`end_of`]
//! decides which end each takes ([`UnitEnd`]), and `dispatch` acts on it: the
//! watcher and the sleep guard power the machine off through the emergency's
//! hot path, as the emergency does where its way back's last step would not
//! start right; the reconcile step leaves the records as they are and only
//! cleans up after itself
//! (`nails_teardown::whole_root::boot_records::clean_up`); the boot writer's
//! drop-in starts the writer as the decoy runs it.
//!
//! In every other case `dispatch` does nothing and the normal path runs.
//!
//! The emergency recogniser is deliberately strict: it accepts only the global
//! and emergency options, each at most once, and leaves anything else (help, a
//! typo, an unknown flag) to clap, so the early path never runs for a command
//! line clap would refuse. A test checks the two agree.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use nails_teardown::whole_root::emergency::{self, Finish, HotReport};
use nails_teardown::whole_root::program_label::{self, Started};
use nails_teardown::whole_root::selinux::Selinux;

/// The hot path's report, waiting for the emergency command.
static EARLY_REPORT: Mutex<Option<HotReport>> = Mutex::new(None);

/// What the strict recogniser read from an emergency command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyArgs {
    /// `--countdown <SECS>`.
    pub countdown: Option<u64>,
    /// How the emergency ends (`--poweroff`, `--reboot`, or the default, which
    /// powers a hidden session off).
    pub finish: Finish,
    /// `--json`: a countdown cancelled with Ctrl+C prints the cancel envelope.
    pub json: bool,
    /// `--ascii`: the cancel notice uses an ASCII marker.
    pub ascii: bool,
}

impl Default for EarlyArgs {
    fn default() -> Self {
        Self {
            countdown: None,
            finish: Finish::Default,
            json: false,
            ascii: false,
        }
    }
}

/// The value-less global options.
const GLOBAL_FLAGS: &[&str] = &["-q", "--quiet", "--ascii", "--json", "--no-log-file"];
/// The value-less emergency options.
const EMERGENCY_FLAGS: &[&str] = &["--poweroff", "--reboot"];

/// Recognise `argv` (program name first) as an emergency command clap accepts,
/// or `None` for anything else.
pub fn recognise(argv: &[OsString]) -> Option<EarlyArgs> {
    let words: Vec<&str> = argv
        .iter()
        .skip(1)
        .map(|w| w.to_str())
        .collect::<Option<_>>()?;
    let mut seen: Vec<&str> = Vec::new();
    let mut once = |name: &'static str| {
        if seen.contains(&name) {
            return false;
        }
        seen.push(name);
        true
    };
    let mut args = EarlyArgs::default();
    let mut subcommand = false;
    let mut verbose = 0u32;
    let mut quiet = false;
    let mut iter = words.into_iter();
    while let Some(word) = iter.next() {
        if !subcommand && word == "emergency" {
            subcommand = true;
            continue;
        }
        if let Some(flag) = GLOBAL_FLAGS.iter().find(|f| **f == word) {
            let name = if *flag == "-q" { "--quiet" } else { flag };
            if !once(name) {
                return None;
            }
            quiet |= name == "--quiet";
            args.json |= name == "--json";
            args.ascii |= name == "--ascii";
            continue;
        }
        if subcommand && let Some(flag) = EMERGENCY_FLAGS.iter().find(|f| **f == word) {
            if !once(flag) {
                return None;
            }
            continue;
        }
        if word == "--verbose"
            || (word.len() >= 2 && word.starts_with('-') && word[1..].chars().all(|c| c == 'v'))
        {
            verbose += if word == "--verbose" {
                1
            } else {
                (word.len() - 1) as u32
            };
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (word, None),
        };
        let mut value = || {
            inline
                .map(str::to_string)
                .or_else(|| iter.next().map(str::to_string))
        };
        match name {
            "--config" | "-c" if inline.is_none() || name == "--config" => {
                let path = value()?;
                if path.is_empty() || path.starts_with('-') || !once("--config") {
                    return None;
                }
            }
            "--color" => {
                let when = value()?;
                if !matches!(when.as_str(), "auto" | "always" | "never") || !once("--color") {
                    return None;
                }
            }
            "--countdown" if subcommand => {
                let secs = value()?.parse().ok()?;
                if !once("--countdown") {
                    return None;
                }
                args.countdown = Some(secs);
            }
            _ => return None,
        }
    }
    let conflicting = seen.contains(&"--poweroff") && seen.contains(&"--reboot");
    if seen.contains(&"--poweroff") {
        args.finish = Finish::Poweroff;
    } else if seen.contains(&"--reboot") {
        args.finish = Finish::Reboot;
    }
    (subcommand && !conflicting && !(quiet && verbose > 0)).then_some(args)
}

/// Whether this process may run the hot path: as root, and (in a test-hooks
/// build) not under the runtime-safety switch the test suites set.
fn may_run() -> bool {
    #[cfg(feature = "test-hooks")]
    if std::env::var_os("NAILS_TEST_RUNTIME").is_some() {
        return false;
    }
    nix::unistd::geteuid().is_root()
}

/// The host the hot path may act on, with (in a test-hooks build) the pids
/// the end-to-end harness names for sparing.
fn host() -> emergency::Host {
    #[cfg_attr(not(feature = "test-hooks"), allow(unused_mut))]
    let mut host = emergency::Host::system();
    #[cfg(feature = "test-hooks")]
    {
        host.protected_pids = std::env::var("NAILS_SHELL_CLEANUP_PROTECTED_PIDS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
    }
    host
}

/// Whether `argv` is exactly the transition step systemd runs.
pub fn is_transition(argv: &[OsString]) -> bool {
    argv.len() == 2 && argv[1] == nails_teardown::whole_root::transition::TRANSITION_ARG
}

/// The boot-record reconcile step's command line, as its one-shot unit gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileArgs {
    /// The boot clock at the switch back to the decoy.
    pub switched_at: Duration,
    /// Whether to make `/run` `noexec` again (the flag is present only when
    /// the way back cleared it).
    pub restore_noexec: bool,
}

/// Whether `argv` is exactly the boot-record reconcile step the way back leaves
/// for an FHS decoy's first start
/// (`nails_teardown::whole_root::boot_records::reconcile_args`).
pub fn reconcile_records(argv: &[OsString]) -> Option<ReconcileArgs> {
    use nails_teardown::whole_root::boot_records::{NOEXEC_FLAG, RECONCILE_ARG, parse_clock_arg};
    let (clock, restore_noexec) = match argv.get(1..)? {
        [verb, clock] if verb == RECONCILE_ARG => (clock, false),
        [verb, clock, flag] if verb == RECONCILE_ARG && flag == NOEXEC_FLAG => (clock, true),
        _ => return None,
    };
    Some(ReconcileArgs {
        switched_at: parse_clock_arg(clock)?,
        restore_noexec,
    })
}

/// Whether `argv` is exactly the start of the decoy's wtmpdb boot writer that
/// the way back's drop-in gives (`nails_teardown::whole_root::boot_writer::writer_args`):
/// the boot clock at the switch and the writer's command, an absolute path
/// and its arguments.
pub fn boot_writer(argv: &[OsString]) -> Option<(Duration, &[OsString])> {
    use nails_teardown::whole_root::boot_records::parse_clock_arg;
    use nails_teardown::whole_root::boot_writer::WRITER_ARG;
    match argv.get(1..)? {
        [verb, clock, writer @ ..]
            if verb == WRITER_ARG
                && writer
                    .first()
                    .is_some_and(|program| program.as_encoded_bytes().starts_with(b"/")) =>
        {
            Some((parse_clock_arg(clock)?, writer))
        }
        _ => None,
    }
}

/// Whether `argv` is exactly the start command of one of the hidden session's
/// own units, the watcher's or the sleep guard's
/// (`nails_session::session::units`).
pub fn session_unit(argv: &[OsString]) -> bool {
    argv.len() == 2 && (argv[1] == "watch" || argv[1] == "sleep-guard")
}

/// A unit PID 1 starts from a RAM copy of the binary after a switch, which
/// checks the domain it runs in before its work (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyUnit<'a> {
    /// The hidden session's watcher or sleep guard ([`session_unit`]).
    Session,
    /// The reconcile step of the decoy's first start after the way back
    /// ([`reconcile_records`]).
    Reconcile(ReconcileArgs),
    /// The decoy's wtmpdb boot writer on that start, by its drop-in: the boot
    /// clock at the switch and the writer's command ([`boot_writer`]).
    Writer(Duration, &'a [OsString]),
}

impl<'a> CopyUnit<'a> {
    /// The unit `argv` is the command line of, as its unit file or drop-in
    /// gives it.
    pub fn of(argv: &'a [OsString]) -> Option<Self> {
        if session_unit(argv) {
            return Some(Self::Session);
        }
        if let Some(args) = reconcile_records(argv) {
            return Some(Self::Reconcile(args));
        }
        boot_writer(argv).map(|(switched_at, writer)| Self::Writer(switched_at, writer))
    }

    /// The RAM copy the unit starts from: the session's for the hidden
    /// session's own units, the one the way back leaves for the decoy's
    /// first start for the others.
    pub fn copy(&self) -> PathBuf {
        match self {
            Self::Session => session_copy(),
            Self::Reconcile(_) | Self::Writer(..) => fixup_copy(),
        }
    }
}

/// What a unit PID 1 started from a RAM copy does once it checked its domain
/// ([`end_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitEnd<'a> {
    /// Its work: the watcher and the sleep guard go on to the normal path,
    /// the reconcile step makes the records read as a power cycle, and the
    /// drop-in starts the writer with the boot clock of the switch.
    Work(CopyUnit<'a>),
    /// The watcher or the sleep guard ends the session through the
    /// emergency's hot path, as this finish has it.
    Emergency(Finish),
    /// The reconcile step leaves the records as they are and only removes
    /// its pieces from `/run`, which it makes `noexec` again where its flag
    /// says (`nails_teardown::whole_root::boot_records::clean_up`).
    CleanUp {
        /// Its `--restore-noexec` flag.
        restore_noexec: bool,
    },
    /// The drop-in starts this writer command as the decoy runs it
    /// (`nails_teardown::whole_root::boot_writer::run_as_decoy`).
    AsDecoy(&'a [OsString]),
}

/// The end of `unit`, started from the RAM copy at `copy` as `started` says:
/// its work where it runs in the domain the copy's label gives it, as
/// `selinux` tells it, where no policy is loaded, and where PID 1 did not
/// start it ([`program_label::enter_domain`]). One that runs elsewhere gives
/// the copy the label again and starts itself again from it, and does not
/// come back unless that start fails. One that cannot run in the domain takes
/// its fail-closed end: the watcher and the sleep guard power off, the
/// reconcile step only cleans up after itself with its own `noexec` flag, and
/// the drop-in starts the writer as the decoy runs it.
pub fn end_of<'a>(
    unit: CopyUnit<'a>,
    copy: &Path,
    selinux: &dyn Selinux,
    started: &Started,
) -> UnitEnd<'a> {
    if started.enter_domain(selinux, copy).is_ok() {
        return UnitEnd::Work(unit);
    }
    match unit {
        CopyUnit::Session => UnitEnd::Emergency(Finish::Poweroff),
        CopyUnit::Reconcile(args) => UnitEnd::CleanUp {
            restore_noexec: args.restore_noexec,
        },
        CopyUnit::Writer(_, writer) => UnitEnd::AsDecoy(writer),
    }
}

/// How PID 1 or a person started this process, for the check of its domain:
/// whether by PID 1 ([`by_pid1`]), whether as its own start again from its
/// copy ([`program_label::STARTED_AGAIN`]), and how it starts itself again
/// ([`start_again_from`]).
fn started() -> Started {
    Started {
        by_pid1: by_pid1(),
        again: std::env::var_os(program_label::STARTED_AGAIN).is_some(),
        start_again: start_again_from,
    }
}

/// Whether PID 1 started this process, as it starts every unit's command:
/// in a process of its own that runs the command in its place. Whatever a
/// person starts by hand has another parent.
fn by_pid1() -> bool {
    nix::unistd::getppid() == nix::unistd::Pid::from_raw(1)
}

/// Start this process again from `copy`, with the command line it was
/// started with ([`again_command`]): this returns only where that start
/// fails.
fn start_again_from(copy: &Path) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let argv: Vec<OsString> = std::env::args_os().collect();
    again_command(copy, &argv).exec()
}

/// The start of this process again from `copy`: the same `argv`, and
/// [`program_label::STARTED_AGAIN`] set, so that it does not start itself
/// once more.
fn again_command(copy: &Path, argv: &[OsString]) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(copy);
    if let Some((first, rest)) = argv.split_first() {
        command.arg0(first).args(rest);
    }
    command.env(program_label::STARTED_AGAIN, "1");
    command
}

/// The RAM copy of the binary the hidden session's own units start from.
fn session_copy() -> PathBuf {
    use nails_teardown::whole_root::plan::{BINARY_NAME, RUNTIME_DIR};
    Path::new(RUNTIME_DIR).join(BINARY_NAME)
}

/// The RAM copy of the binary the way back leaves for the decoy's first
/// start.
fn fixup_copy() -> PathBuf {
    use nails_teardown::whole_root::boot_records::{FIXUP_BINARY, FIXUP_DIR_PATH};
    Path::new(FIXUP_DIR_PATH).join(FIXUP_BINARY)
}

/// Act on the end of a unit started from a RAM copy ([`end_of`]): each but
/// the work of the hidden session's own units ends the process here.
fn finish_unit(end: UnitEnd<'_>) {
    use nails_teardown::whole_root::{boot_records, boot_writer, plan};
    let run = Path::new("/run");
    let code = match end {
        UnitEnd::Work(CopyUnit::Session) => return,
        UnitEnd::Emergency(finish) => {
            let plan = plan::Plan::load(&plan::default_plan_path()).ok();
            let _ = emergency::run(plan, &host(), finish);
            0
        }
        UnitEnd::Work(CopyUnit::Reconcile(args)) => {
            boot_records::run(run, Path::new("/"), args.switched_at, args.restore_noexec);
            0
        }
        UnitEnd::CleanUp { restore_noexec } => {
            boot_records::clean_up(run, restore_noexec);
            0
        }
        // Only a writer that could not be started comes back: the unit then
        // fails, as it would if its own command were missing.
        UnitEnd::Work(CopyUnit::Writer(switched_at, writer)) => {
            let _ = boot_writer::run(run, switched_at, writer);
            1
        }
        UnitEnd::AsDecoy(writer) => {
            let _ = boot_writer::run_as_decoy(run, writer);
            1
        }
    };
    crate::cli::chokepoint::exit_process(code);
}

/// The device node of exactly the read-only guard udev runs.
pub fn guarded_device(argv: &[OsString]) -> Option<&std::path::Path> {
    (argv.len() == 3
        && argv[1] == nails_teardown::whole_root::disk_guard::GUARD_ARG
        && argv[2].as_encoded_bytes().starts_with(b"/dev/"))
    .then(|| std::path::Path::new(&argv[2]))
}

/// Make `node` read-only for the session, from the plan in the runtime
/// directory. No plan, no session: nothing to do.
fn guard_device(node: &std::path::Path) {
    use nails_teardown::whole_root::{disk_guard, plan};
    let Ok(plan) = plan::Plan::load(&plan::default_plan_path()) else {
        return;
    };
    if !plan.read_only_disks {
        return;
    }
    let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap_or_default();
    let _ = disk_guard::guard(
        node,
        &plan,
        &mounts,
        &disk_guard::Sysfs::system(),
        std::path::Path::new(plan::RUNTIME_DIR),
    );
}

/// Run the early paths. See the module docs. Returns whether the emergency hot
/// path ran; the transition and the device guard never return.
pub fn dispatch() -> bool {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if is_transition(&argv) && nix::unistd::geteuid().is_root() {
        // Fail closed: an outcome that ends the session exits non-zero, which
        // fails the service, so PID 1 powers off through its FailureAction=
        // instead of switching (transition::dropin_text).
        let outcome = nails_teardown::whole_root::transition::run(
            &nails_teardown::whole_root::transition::Env::system(started()),
        );
        crate::cli::chokepoint::exit_process(outcome.exit_code());
    }
    if let Some(node) = guarded_device(&argv)
        && may_run()
    {
        guard_device(node);
        crate::cli::chokepoint::exit_process(0);
    }
    if let Some(unit) = CopyUnit::of(&argv)
        && may_run()
    {
        let copy = unit.copy();
        finish_unit(end_of(
            unit,
            &copy,
            &nails_teardown::whole_root::selinux::KERNEL,
            &started(),
        ));
    }
    let Some(args) = recognise(&argv) else {
        return false;
    };
    if !may_run() {
        return false;
    }
    // A cwd inside the hidden volume would pin it.
    let _ = std::env::set_current_dir("/");
    // Ctrl+C during the countdown cancels the emergency before it acts, and
    // ends the process with the cancel reported.
    crate::cli::commands::emergency::early_countdown(args.countdown, args.json, args.ascii);
    let plan = nails_teardown::whole_root::plan::Plan::load(
        &nails_teardown::whole_root::plan::default_plan_path(),
    )
    .ok();
    let report = emergency::run(plan, &host(), args.finish);
    *EARLY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
    true
}

/// Take the report of a hot path [`dispatch`] already ran, if any.
pub fn take_report() -> Option<HotReport> {
    EARLY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

#[cfg(test)]
#[path = "early_tests.rs"]
mod tests;
