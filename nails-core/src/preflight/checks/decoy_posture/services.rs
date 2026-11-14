// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Daemons whose own command line decides whether they write to the decoy
//! disk around a switch, and ABRT, which keeps crash reports there. The
//! units systemd-coredump starts for each crash, as apport's hook, and an
//! enabled apport are read the same way ([`coredump_hooks`]).
//!
//! - tuned started with its log option, `-l` (`--log`), or with `-d`, writes
//!   its log to `/var/log/tuned/tuned.log`, unless the option names another
//!   file. It logs there when it stops for the switch and when it starts
//!   again after the way back, each line with the time, so the decoy disk
//!   keeps both times, as a syslog daemon's log would. Fedora's
//!   `tuned.service` passes `-l`, and Fedora enables it by preset wherever it
//!   is installed (its Cloud image has none). Without a log file it logs
//!   every line to its standard error, which the journal takes unless its
//!   unit sends it to a file ([`streams`]); such a file counts as a log file.
//!   tuned-ppd, which translates the power profiles of desktops for tuned,
//!   writes its log with `-l` to `/var/log/tuned/tuned-ppd.log`, and to its
//!   standard error without it: not a line at each stop and start, but the
//!   power profiles it sets and the holds it adds or releases, around a
//!   switch too, each with the time. These refuse activation, which
//!   `--allow-persistent-decoy` turns into a warning.
//! - firewalld with its default log target, `mixed`, appends its warnings
//!   and errors to `/var/log/firewalld`, and every message it logs with
//!   `--debug` or the target `file`. Fedora's unit takes further options from
//!   `$FIREWALLD_ARGS`, which `/etc/sysconfig/firewalld` sets. This warns.
//! - ABRT keeps crash reports in its dump location, `/var/spool/abrt` unless
//!   `abrt.conf` names another: made from the core dumps systemd-coredump
//!   keeps of the programs packages install (it drops those of others, as of
//!   NAILS's own, unless `ProcessUnpackaged` is on), the kernel oops messages
//!   in the journal and, each time it starts, the crash records pstore holds,
//!   a kernel crash of the hidden session among them. This warns.
//!
//! Each is read two ways. Its unit counts when the service manager can start
//! it: it is enabled or active ([`unit_enabled`], [`loggers::unit_active`]),
//! and for tuned also when tuned-ppd is installed, which needs it and which
//! D-Bus starts whenever a program asks for power profiles; a masked unit
//! starts by none of these. Its `[Service]` section is read from the unit
//! file and every drop-in, as the service manager loads them
//! ([`unit_section`]), and the commands of its `ExecStart=` are split as
//! systemd splits them, with the variables the unit sets itself
//! ([`environment`]); the program's own words in them are read as it reads
//! its options ([`options`]). Its processes count as they run, by their name
//! or the script their Python runs ([`processes`]), their options read from
//! their command line, so a daemon started by hand, or still running with
//! options its unit no longer has, is seen too. A daemon that logs to its
//! standard output or standard error is judged by where its unit sends that
//! stream, or by where the stream of the process leads ([`streams`]).
//!
//! What NAILS cannot read of a unit's files, of a command or of a process,
//! its streams among it, counts against the decoy: for tuned it refuses, as
//! if the daemon logged to a file, and for firewalld and ABRT it warns.
//! Whether a unit is enabled or active is read from the links and markers
//! systemd leaves, as [`unit_enabled`] and [`loggers::unit_active`] read
//! them; a unit NAILS cannot tell is enabled or active counts as one that
//! starts, wherever its commands would make the daemon log to a file or NAILS
//! cannot tell whether they would.
//! Every file is read as the locate-database check reads the decoy
//! ([`DecoyFiles`]): no write, no access time, nothing through a link onto
//! the hidden volume.

mod coredump_hooks;
mod environment;
mod options;
mod processes;
mod streams;

pub(super) use coredump_hooks::{apport_finding, finding as coredump_hook_finding};

use super::super::locate_database::exec::{ExecCommand, Variables, exec_commands_with};
use super::super::locate_database::files::DecoyFiles;
use super::super::locate_database::unit::{
    SYSTEM_UNIT_PATH, UnitSection, list_values, unit_section,
};
use super::loggers::{self, Activity};
use super::{Enabled, PersistenceFinding, unit_enabled};
use crate::Filesystem;
use options::Log;
use processes::{Processes, own_args, runs_anywhere};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A daemon judged by its command line.
struct Daemon {
    /// Its service unit.
    unit: &'static str,
    /// The file name of its program, which is also its process name.
    program: &'static str,
    /// Where a command line of it makes it log.
    judge: fn(&[Vec<u8>]) -> Log,
    /// What becomes of what it logs around a switch, as a finding says it
    /// after naming its log file.
    around_a_switch: &'static str,
}

/// tuned.
const TUNED: Daemon = Daemon {
    unit: "tuned.service",
    program: "tuned",
    judge: options::tuned,
    around_a_switch: "it logs there, on the decoy disk, when it stops or starts around a switch, \
                      with the time",
};

/// tuned-ppd, whose unit needs tuned's (`Requires=tuned.service`).
const TUNED_PPD: Daemon = Daemon {
    unit: "tuned-ppd.service",
    program: "tuned-ppd",
    judge: options::tuned_ppd,
    around_a_switch: "what it logs as it stops for a switch or starts again after the way back, \
                      a power profile it sets or a hold it releases, stays there, on the decoy \
                      disk, with the time",
};

/// firewalld.
const FIREWALLD: Daemon = Daemon {
    unit: "firewalld.service",
    program: "firewalld",
    judge: options::firewalld,
    around_a_switch: "what it logs when it stops or starts around a switch stays on the decoy \
                      disk with the time",
};

/// ABRT's daemon, which every other ABRT unit needs running.
const ABRTD_UNIT: &str = "abrtd.service";

/// The program, and process, of ABRT's daemon.
const ABRTD: &str = "abrtd";

/// The programs whose processes are read.
const PROCESS_NAMES: &[&str] = &[TUNED.program, TUNED_PPD.program, FIREWALLD.program, ABRTD];

/// Those of [`PROCESS_NAMES`] that are Python scripts.
const PYTHON_SCRIPTS: &[&str] = &[TUNED.program, TUNED_PPD.program, FIREWALLD.program];

/// What D-Bus does that lets tuned-ppd start, as a finding says it after
/// naming what it starts.
const PPD_ACTIVATION: &str = "whenever a program asks for power profiles";

/// What this module finds of tuned and tuned-ppd on the decoy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Tuned {
    /// Their fail-closed findings: one NAILS cannot tell about counts as one
    /// that logs to a file.
    pub(super) blockers: Vec<PersistenceFinding>,
    /// The units of those findings, whose fix the remediation names.
    pub(super) units: Vec<&'static str>,
    /// The programs of those findings that only a running process shows,
    /// which the remediation names when no unit does.
    pub(super) programs: Vec<&'static str>,
}

/// How the service manager starts a unit on its own, as [`Decoy::started`]
/// reads it.
enum Start {
    /// It is enabled, active or both, as a finding names it.
    Sure(String),
    /// NAILS cannot tell whether it is either, for this reason, which names
    /// the unit and the path it could not look up.
    Untold(String),
}

/// A word as a finding shows it.
fn shown(word: &[u8]) -> String {
    String::from_utf8_lossy(word).into_owned()
}

/// The first log of `logs` that is a file, else the first NAILS cannot tell,
/// else the first to a standard stream; no file when none is.
fn first_file(logs: Vec<Log>) -> Log {
    let mut unknown = None;
    let mut stream = None;
    for log in logs {
        match log {
            Log::File(_) => return log,
            Log::Unknown(_) if unknown.is_none() => unknown = Some(log),
            Log::Stream { .. } if stream.is_none() => stream = Some(log),
            Log::Unknown(_) | Log::Stream { .. } | Log::NoFile => {}
        }
    }
    unknown.or(stream).unwrap_or(Log::NoFile)
}

/// Where a daemon logs, by every way NAILS sees it start or run.
#[derive(Default)]
struct Logs {
    /// Each file it writes, with what it writes there and what shows it.
    files: BTreeMap<String, (&'static str, Vec<String>)>,
    /// What NAILS cannot tell, each with what shows it.
    unknown: Vec<String>,
    /// Whether its unit shows any of them.
    by_unit: bool,
}

impl Logs {
    /// Add where `log` says the daemon logs when its unit starts as `start`
    /// says, `unit` being the unit: one NAILS cannot tell starts counts as
    /// one that does, where it would log to a file or NAILS cannot tell
    /// whether it would.
    fn add_unit(&mut self, unit: &str, start: Start, log: Log) {
        self.by_unit |= log != Log::NoFile;
        match start {
            Start::Sure(source) => self.add(&source, ", with", log),
            Start::Untold(why) => {
                let would = match log {
                    Log::NoFile => return,
                    Log::File(file) => {
                        format!(
                            "{unit} would start it with {}, which logs to {}",
                            file.by, file.path
                        )
                    }
                    Log::Stream { stream, .. } => {
                        format!("{unit} would start it logging to its {}", stream.name())
                    }
                    Log::Unknown(reason) => format!("{unit} would start it, and {reason}"),
                };
                self.unknown.push(format!("{would}, and {why}"));
            }
        }
    }

    /// Add where `log` says the daemon logs when it starts or runs as
    /// `source` says, `with` joining the options that make it log there.
    fn add(&mut self, source: &str, with: &str, log: Log) {
        match log {
            Log::NoFile => {}
            Log::File(file) => self
                .files
                .entry(file.path)
                .or_insert_with(|| (file.what, Vec::new()))
                .1
                .push(format!("{source}{with} {}", file.by)),
            Log::Stream { stream, .. } => self
                .unknown
                .push(format!("{source}, and it logs to its {}", stream.name())),
            Log::Unknown(why) => self.unknown.push(format!("{source}: {why}")),
        }
    }

    fn is_empty(&self) -> bool {
        self.files.is_empty() && self.unknown.is_empty()
    }
}

/// The decoy's units and processes, as the judges read them.
struct Decoy<'a, F: Filesystem> {
    fs: &'a F,
    root: &'a Path,
    files: DecoyFiles<'a, F>,
    /// The system manager's unit directories, highest priority first.
    dirs: Vec<PathBuf>,
    processes: Processes,
}

impl<'a, F: Filesystem> Decoy<'a, F> {
    fn new(fs: &'a F, root: &'a Path, hidden: &'a [PathBuf]) -> Self {
        Self {
            fs,
            root,
            files: DecoyFiles::new(fs, root, hidden),
            dirs: SYSTEM_UNIT_PATH.iter().map(|dir| root.join(dir)).collect(),
            processes: processes::processes(fs, root, PROCESS_NAMES, PYTHON_SCRIPTS),
        }
    }

    /// What `unit`'s files say of its `[Service]` section.
    fn section(&self, unit: &str) -> UnitSection {
        unit_section(&self.files, &self.dirs, unit, "Service")
    }

    /// How the service manager starts `unit` on its own: it is enabled,
    /// active or both, or NAILS cannot tell whether it is either, which
    /// counts as one that is. `None` when it is neither.
    fn started(&self, unit: &str) -> Option<Start> {
        let enabled = unit_enabled(self.fs, self.root, unit);
        let active = loggers::unit_active(self.fs, self.root, unit);
        let state = match (enabled, active) {
            (Enabled::Yes, Activity::Active) => "is enabled and active",
            (Enabled::Yes, Activity::Inactive | Activity::Untold(_)) => "is enabled",
            (Enabled::No | Enabled::Untold(_), Activity::Active) => "is active",
            (Enabled::Untold(why), Activity::Inactive | Activity::Untold(_))
            | (Enabled::No, Activity::Untold(why)) => return Some(Start::Untold(why)),
            (Enabled::No, Activity::Inactive) => return None,
        };
        Some(Start::Sure(format!("{unit} {state}")))
    }

    /// Where the commands of `daemon`'s unit make it log, its `[Service]`
    /// section being `section`, and the environment files the unit read.
    fn unit_log(&self, daemon: &Daemon, section: &UnitSection) -> (Log, Vec<String>) {
        let assignments = match section {
            UnitSection::Assignments(assignments) => assignments,
            UnitSection::Unknown(why) => return (Log::Unknown(why.clone()), Vec::new()),
            UnitSection::Missing | UnitSection::Masked => return (Log::NoFile, Vec::new()),
        };
        let values = list_values(assignments, "ExecStart");
        let (variables, env_files) = if values.iter().any(|value| value.contains('$')) {
            match environment::environment(&self.files, assignments) {
                Ok(found) => (found.variables, found.files),
                Err(why) => return (Log::Unknown(why), Vec::new()),
            }
        } else {
            (Variables::new(), Vec::new())
        };
        let mut logs = Vec::new();
        for value in values {
            let commands = match exec_commands_with(&value, &variables) {
                Ok(commands) => commands,
                Err(e) => {
                    return (
                        Log::Unknown(format!("NAILS cannot read its ExecStart={value} ({e})")),
                        env_files,
                    );
                }
            };
            logs.extend(
                commands
                    .iter()
                    .map(|command| self.command_log(daemon, command)),
            );
        }
        let log = match first_file(logs) {
            Log::Stream { stream, by } => streams::of_unit(assignments, stream, by),
            log => log,
        };
        (log, env_files)
    }

    /// Where one command of `daemon`'s unit makes it log.
    fn command_log(&self, daemon: &Daemon, command: &ExecCommand) -> Log {
        let words: Vec<Vec<u8>> = std::iter::once(command.program.clone())
            .chain(command.args.iter().cloned())
            .collect();
        match own_args(daemon.program, &words) {
            Some(args) => (daemon.judge)(&args),
            None => Log::Unknown(format!(
                "its ExecStart= runs {}, which is no {}",
                shown(&command.program),
                daemon.program
            )),
        }
    }

    /// Add where `daemon`'s processes log to `logs`, and, where the daemon is
    /// `installed`, a process NAILS cannot read, which may be one of them.
    fn add_processes(&self, daemon: &Daemon, installed: bool, logs: &mut Logs) {
        if installed && let Some(why) = &self.processes.unread {
            logs.unknown.push(format!(
                "a process NAILS cannot read may run {}: {why}",
                daemon.program
            ));
        }
        for process in self
            .processes
            .found
            .iter()
            .filter(|p| p.name == daemon.program)
        {
            let source = format!("process {} runs", process.pid);
            let log = match &process.argv {
                Err(why) => Log::Unknown(why.clone()),
                Ok(argv) => match own_args(daemon.program, argv) {
                    None => Log::Unknown(format!(
                        "its command line names no {}, so NAILS cannot read its options",
                        daemon.program
                    )),
                    Some(args) => match (daemon.judge)(&args) {
                        Log::Stream { stream, by } => {
                            streams::of_process(self.fs, self.root, &process.pid, stream, by)
                        }
                        log => log,
                    },
                },
            };
            logs.add(&source, " with", log);
        }
    }

    /// Where tuned and tuned-ppd log (see the [module docs](self)).
    fn tuned(&self) -> (Logs, Logs) {
        let tuned = self.section(TUNED.unit);
        let ppd = self.section(TUNED_PPD.unit);
        let installed = |section: &UnitSection| {
            matches!(
                section,
                UnitSection::Assignments(_) | UnitSection::Unknown(_)
            )
        };
        // tuned-ppd needs tuned, and D-Bus starts it whenever it may.
        let ppd_starts = installed(&ppd) && installed(&tuned);
        let mut tuned_logs = Logs::default();
        if installed(&tuned) {
            let start = match self.started(TUNED.unit) {
                Some(Start::Sure(source)) => Some(Start::Sure(source)),
                // tuned-ppd starts it for sure.
                _ if ppd_starts => Some(Start::Sure(format!(
                    "{} can start, as {ppd} needs it and D-Bus starts {ppd} {PPD_ACTIVATION}",
                    TUNED.unit,
                    ppd = TUNED_PPD.unit
                ))),
                untold => untold,
            };
            if let Some(start) = start {
                tuned_logs.add_unit(TUNED.unit, start, self.unit_log(&TUNED, &tuned).0);
            }
        }
        let mut ppd_logs = Logs::default();
        if ppd_starts {
            let start = match self.started(TUNED_PPD.unit) {
                Some(Start::Sure(source)) => Start::Sure(source),
                // D-Bus starts it for sure.
                Some(Start::Untold(_)) | None => Start::Sure(format!(
                    "{} can start, as D-Bus starts it {PPD_ACTIVATION}",
                    TUNED_PPD.unit
                )),
            };
            ppd_logs.add_unit(TUNED_PPD.unit, start, self.unit_log(&TUNED_PPD, &ppd).0);
        }
        let present = |section: &UnitSection| !matches!(section, UnitSection::Missing);
        self.add_processes(&TUNED, present(&tuned), &mut tuned_logs);
        self.add_processes(&TUNED_PPD, present(&ppd), &mut ppd_logs);
        (tuned_logs, ppd_logs)
    }

    /// Where firewalld logs, and the environment files its unit read.
    fn firewalld(&self) -> (Logs, Vec<String>) {
        let mut logs = Logs::default();
        let mut env_files = Vec::new();
        let section = self.section(FIREWALLD.unit);
        if !matches!(section, UnitSection::Missing | UnitSection::Masked)
            && let Some(start) = self.started(FIREWALLD.unit)
        {
            let (log, files) = self.unit_log(&FIREWALLD, &section);
            env_files = files;
            logs.add_unit(FIREWALLD.unit, start, log);
        }
        let present = !matches!(section, UnitSection::Missing);
        self.add_processes(&FIREWALLD, present, &mut logs);
        (logs, env_files)
    }

    /// What shows ABRT in use: its daemon's unit, enabled or active, whose
    /// `ExecStart=` runs abrtd or cannot be read, and its daemon's processes;
    /// and what shows it may be: such a unit NAILS cannot tell is enabled or
    /// active, with why.
    fn abrt(&self) -> AbrtSigns {
        let mut signs = AbrtSigns::default();
        let section = self.section(ABRTD_UNIT);
        let present = !matches!(section, UnitSection::Missing);
        let start = match section {
            UnitSection::Missing | UnitSection::Masked => None,
            UnitSection::Assignments(_) | UnitSection::Unknown(_) => self.started(ABRTD_UNIT),
        };
        let (source, sure) = match start {
            None => (None, true),
            Some(Start::Sure(source)) => (Some(source), true),
            Some(Start::Untold(why)) => (Some(why), false),
        };
        let mut found = Vec::new();
        if let Some(source) = source {
            match section {
                UnitSection::Assignments(assignments) => {
                    let runs = list_values(&assignments, "ExecStart").iter().any(|value| {
                        exec_commands_with(value, &Variables::new()).map_or(true, |commands| {
                            commands.iter().any(|command| {
                                let words: Vec<Vec<u8>> = std::iter::once(command.program.clone())
                                    .chain(command.args.iter().cloned())
                                    .collect();
                                runs_anywhere(ABRTD, &words)
                            })
                        })
                    });
                    if runs {
                        found.push(source);
                    }
                }
                UnitSection::Unknown(why) => {
                    found.push(format!("{source}, and NAILS cannot read it ({why})"));
                }
                UnitSection::Missing | UnitSection::Masked => {}
            }
        }
        if sure {
            signs.sure = found;
        } else {
            signs.untold = found;
        }
        if present && let Some(why) = &self.processes.unread {
            signs
                .untold
                .push(format!("a process NAILS cannot read may be abrtd: {why}"));
        }
        signs.sure.extend(
            self.processes
                .found
                .iter()
                .filter(|process| process.name == ABRTD)
                .map(|process| format!("process {} is abrtd", process.pid)),
        );
        signs
    }
}

/// What shows ABRT in use on the decoy.
#[derive(Default)]
struct AbrtSigns {
    /// What shows it in use.
    sure: Vec<String>,
    /// What shows it may be, where NAILS cannot tell whether its daemon's
    /// unit starts, with why.
    untold: Vec<String>,
}

/// The fail-closed findings of `logs`, the logs of `daemon`: a log file it
/// writes, and one NAILS cannot tell it does not, which counts as one it
/// writes.
fn tuned_findings(daemon: &Daemon, logs: &Logs) -> Vec<PersistenceFinding> {
    let program = daemon.program;
    let mut out: Vec<PersistenceFinding> = logs
        .files
        .iter()
        .map(|(path, (what, sources))| {
            PersistenceFinding::kept(format!(
                "{program} writes {what} to {path} ({}): {}",
                sources.join("; "),
                daemon.around_a_switch
            ))
        })
        .collect();
    if !logs.unknown.is_empty() {
        let why = logs.unknown.join("; ");
        out.push(PersistenceFinding::untold_as(
            format!(
                "NAILS cannot tell whether {program} writes a log file on the decoy disk, so it \
                 counts as one that does ({why})"
            ),
            why,
        ));
    }
    out
}

/// firewalld's warning, from its `logs` and the environment files its unit
/// read, which the fix names, for a NixOS decoy when `is_nixos`, whose
/// `/etc/sysconfig/firewalld` the configuration writes.
fn firewalld_warning(logs: &Logs, env_files: &[String], is_nixos: bool) -> Option<String> {
    if logs.is_empty() {
        return None;
    }
    let mut what: Vec<String> = logs
        .files
        .iter()
        .map(|(path, (what, sources))| {
            format!("firewalld writes {what} to {path} ({})", sources.join("; "))
        })
        .collect();
    if !logs.unknown.is_empty() {
        what.push(format!(
            "NAILS cannot tell whether firewalld writes a log file on the decoy disk ({})",
            logs.unknown.join("; ")
        ));
    }
    let option = match env_files.last() {
        _ if is_nixos => "set services.firewalld.extraArgs = [ \"--log-target=syslog\" ] in the \
                          decoy configuration and run nixos-rebuild switch"
            .to_string(),
        Some(file) => format!("add --log-target=syslog to FIREWALLD_ARGS in {file}"),
        None => "add --log-target=syslog to its ExecStart= in a drop-in".to_string(),
    };
    Some(format!(
        "{}, so {}; make it log to the journal: {option}, then restart it (systemctl restart \
         firewalld.service)",
        what.join(", and "),
        FIREWALLD.around_a_switch
    ))
}

/// ABRT's warning, from what shows it in use or may.
fn abrt_warning(signs: &AbrtSigns) -> Option<String> {
    let in_use = match (signs.sure.is_empty(), signs.untold.is_empty()) {
        (true, true) => return None,
        (false, _) => "is in use",
        (true, false) => "may be in use",
    };
    let shown: Vec<&str> = signs
        .sure
        .iter()
        .chain(&signs.untold)
        .map(String::as_str)
        .collect();
    Some(format!(
        "ABRT {in_use} on the decoy ({}): it keeps crash reports in its dump location \
         (/var/spool/abrt unless DumpLocation in /etc/abrt/abrt.conf names another) on the \
         decoy disk, made from the core dumps systemd-coredump keeps of the programs packages \
         install, the kernel oops messages in the journal and, each time it starts, the crash \
         records pstore holds, so a crash on the decoy around a switch, dated then, or a crash \
         record of the hidden session that pstore kept lands there; turn it off with systemctl \
         disable --now abrtd.service, which the other ABRT units need",
        shown.join("; ")
    ))
}

/// What the decoy under `root` shows of tuned and tuned-ppd; `hidden` are
/// the hidden volume's locations, resolved, which no read follows a link
/// onto.
pub(super) fn blockers<F: Filesystem>(fs: &F, root: &Path, hidden: &[PathBuf]) -> Tuned {
    let decoy = Decoy::new(fs, root, hidden);
    let mut found = Tuned::default();
    let (tuned, ppd) = decoy.tuned();
    for (daemon, logs) in [(&TUNED, &tuned), (&TUNED_PPD, &ppd)] {
        found.blockers.extend(tuned_findings(daemon, logs));
        if logs.by_unit {
            found.units.push(daemon.unit);
        } else if !logs.is_empty() {
            found.programs.push(daemon.program);
        }
    }
    found
}

/// The warnings of what the decoy under `root` shows of firewalld and ABRT,
/// with the fixes of a NixOS decoy when `is_nixos`; `hidden` as for
/// [`blockers`].
pub(super) fn warnings<F: Filesystem>(
    fs: &F,
    root: &Path,
    hidden: &[PathBuf],
    is_nixos: bool,
) -> Vec<String> {
    let decoy = Decoy::new(fs, root, hidden);
    let (firewalld, env_files) = decoy.firewalld();
    let mut out: Vec<String> = firewalld_warning(&firewalld, &env_files, is_nixos)
        .into_iter()
        .collect();
    out.extend(abrt_warning(&decoy.abrt()));
    out
}

/// The fix of the tuned findings, `units` being those of the units that
/// show one and `programs` those of the programs only a process shows, for a
/// NixOS decoy when `is_nixos`.
pub(super) fn tuned_fix(units: &[&str], programs: &[&str], is_nixos: bool) -> String {
    if is_nixos {
        return "make tuned log to the journal: set services.tuned.enable = false in the decoy \
                configuration, or there clear ExecStart= of systemd.services.tuned (and of \
                systemd.services.tuned-ppd) and set it again without -l, with StandardError= \
                set to journal, then run nixos-rebuild switch"
            .to_string();
    }
    let mut fixes = Vec::new();
    if !units.is_empty() {
        let names = units.join(" ");
        fixes.push(format!(
            "make tuned log to the journal: for each of {names}, add a drop-in (such as \
             /etc/systemd/system/{first}.d/50-journal.conf) that clears ExecStart= and sets it \
             again without -l and -d (Fedora's tuned.service: ExecStart=/usr/sbin/tuned -P; its \
             tuned-ppd.service: ExecStart=/usr/sbin/tuned-ppd) and sets StandardError=journal, \
             then run systemctl daemon-reload and systemctl restart {names}; or mask them \
             (systemctl mask --now {names})",
            first = units[0]
        ));
    }
    if !programs.is_empty() {
        let restart: Vec<String> = programs
            .iter()
            .map(|program| format!("{program}.service"))
            .collect();
        // tuned-ppd has no -d.
        let options = if programs.contains(&TUNED.program) {
            "-l and -d"
        } else {
            "-l"
        };
        fixes.push(format!(
            "stop each {} process that logs to a file and start it again without {options}, its \
             standard error sent to no file, as systemctl restart {} does once its unit no \
             longer makes it log to one",
            programs.join(" and "),
            restart.join(" ")
        ));
    }
    fixes.join(", and ")
}

#[cfg(test)]
#[path = "services_tests.rs"]
mod tests;
