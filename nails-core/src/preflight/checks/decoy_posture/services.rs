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
//!   unit sends it elsewhere ([`streams`]); a file counts as a log file, and
//!   so does the journal of a namespace that keeps it on the disk
//!   ([`namespace`]).
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
//! a timer, path or socket unit that runs starts it ([`triggers`]), and for
//! tuned also when tuned-ppd is installed, which needs it and which
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
//! stream, or by where the stream of the process leads ([`streams`]): a
//! socket by PID 1's socket table ([`sockets`]). One that logs to the
//! journal is judged by the journal namespace of its unit or process
//! ([`namespace`]).
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
mod namespace;
mod options;
mod processes;
mod sockets;
mod streams;

pub(super) use coredump_hooks::{apport_finding, finding as coredump_hook_finding};

use super::super::locate_database::exec::{ExecCommand, Variables, exec_commands_with};
use super::super::locate_database::files::DecoyFiles;
use super::super::locate_database::unit::{
    SYSTEM_UNIT_PATH, UnitSection, list_values, unit_section,
};
use super::loggers::{self, Activity};
use super::triggers::{self, Triggers};
use super::{Enabled, PersistenceFinding, unit_enabled};
use crate::Filesystem;
use options::{JournalFix, Log};
use processes::{Processes, own_args, runs_anywhere};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use streams::{Stream, listed};

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

/// What becomes of what firewalld logs around a switch where NAILS can only
/// not tell whether it logs to a file.
const FIREWALLD_MAY_KEEP: &str =
    "what it logs when it stops or starts around a switch may stay on the decoy disk with the time";

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
    /// The units of those findings that show a log file of the daemon's own,
    /// or what NAILS cannot tell, whose fix the remediation names.
    pub(super) units: Vec<&'static str>,
    /// The programs of those findings that only a running process shows so,
    /// whose restart the remediation names, beside the fix of any unit.
    pub(super) programs: Vec<&'static str>,
    /// The journal namespaces of those findings whose journal the decoy
    /// keeps on its disk, or NAILS cannot tell whether it does, whose fix the
    /// remediation names.
    pub(super) namespaces: Vec<String>,
    /// The units of those findings whose `LogNamespace=` names the
    /// namespace with a specifier, which NAILS does not expand, whose fix the
    /// remediation names.
    pub(super) specified: Vec<&'static str>,
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
/// else the first to a standard stream or the journal, which may lead to
/// one; no file when none is.
fn first_file(logs: Vec<Log>) -> Log {
    let mut unknown = None;
    let mut stream = None;
    for log in logs {
        match log {
            Log::File(_) => return log,
            Log::Unknown(_) | Log::UntoldJournal { .. } if unknown.is_none() => {
                unknown = Some(log);
            }
            Log::Stream { .. } | Log::Journal { .. } | Log::Socket { .. } if stream.is_none() => {
                stream = Some(log);
            }
            Log::Unknown(_)
            | Log::UntoldJournal { .. }
            | Log::Stream { .. }
            | Log::Journal { .. }
            | Log::Socket { .. }
            | Log::NoFile => {}
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
    /// The journal namespaces whose journal on the decoy disk it logs to, or
    /// may, or would where NAILS cannot tell whether its unit starts, and
    /// those it logs to, or may, whose storage NAILS cannot tell: their fix
    /// is the remediation's.
    namespaces: BTreeSet<String>,
    /// Whether its unit names its journal namespace with a specifier, which
    /// NAILS does not expand: naming it without one is the remediation's.
    specifier: bool,
    /// Whether its unit shows a file of its own, or what NAILS cannot tell:
    /// a log to a journal namespace aside.
    by_unit: bool,
    /// Whether a process shows one so.
    by_process: bool,
}

impl Logs {
    /// Note where `log` leads: to a journal namespace's file, or to a
    /// journal NAILS cannot tell of, whose fix is a namespace's or naming it
    /// without a specifier, or to one of the daemon's own or what else NAILS
    /// cannot tell, which sets `own`.
    fn note(&mut self, log: &Log, own: impl FnOnce(&mut Self)) {
        match log {
            Log::NoFile => {}
            Log::UntoldJournal {
                fix: JournalFix::Namespaces(namespaces),
                ..
            } => self.namespaces.extend(namespaces.iter().cloned()),
            Log::UntoldJournal {
                fix: JournalFix::Specifier,
                ..
            } => self.specifier = true,
            log => match log.namespace() {
                Some(namespace) => {
                    self.namespaces.insert(namespace.to_string());
                }
                None => own(self),
            },
        }
    }

    /// Add where `log` says the daemon logs when its unit starts as `start`
    /// says, `unit` being the unit: one NAILS cannot tell starts counts as
    /// one that does, where it would log to a file or NAILS cannot tell
    /// whether it would.
    fn add_unit(&mut self, unit: &str, start: Start, log: Log) {
        self.note(&log, |logs| logs.by_unit = true);
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
                    Log::Journal { .. } | Log::Socket { .. } => {
                        format!("{unit} would start it logging to a journal")
                    }
                    Log::Unknown(reason) | Log::UntoldJournal { why: reason, .. } => {
                        format!("{unit} would start it, and {reason}")
                    }
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
            Log::Journal { .. } | Log::Socket { .. } => self
                .unknown
                .push(format!("{source}, and it logs to a journal")),
            Log::Unknown(why) | Log::UntoldJournal { why, .. } => {
                self.unknown.push(format!("{source}: {why}"));
            }
        }
    }

    /// Add where `log` says a process logs, as `source` says.
    fn add_process(&mut self, source: &str, log: Log) {
        self.note(&log, |logs| logs.by_process = true);
        self.add(source, " with", log);
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
    /// The hidden volume's locations, resolved, which no read follows a link
    /// onto.
    hidden: &'a [PathBuf],
    /// What the decoy's timers, paths and sockets start, read once it is
    /// asked.
    triggers: std::cell::OnceCell<Triggers>,
    /// What PID 1's socket table shows, read once it is asked.
    sockets: std::cell::OnceCell<Result<sockets::Sockets, String>>,
}

impl<'a, F: Filesystem> Decoy<'a, F> {
    fn new(fs: &'a F, root: &'a Path, hidden: &'a [PathBuf]) -> Self {
        Self {
            fs,
            root,
            files: DecoyFiles::new(fs, root, hidden),
            dirs: SYSTEM_UNIT_PATH.iter().map(|dir| root.join(dir)).collect(),
            processes: processes::processes(fs, root, PROCESS_NAMES, PYTHON_SCRIPTS),
            hidden,
            triggers: std::cell::OnceCell::new(),
            sockets: std::cell::OnceCell::new(),
        }
    }

    /// What `unit`'s files say of its `[Service]` section.
    fn section(&self, unit: &str) -> UnitSection {
        unit_section(&self.files, &self.dirs, unit, "Service")
    }

    /// How the service manager starts `unit` on its own: it is enabled,
    /// active or both, or a trigger that runs starts it ([`triggers`]), or
    /// NAILS cannot tell whether one of these is so, which counts as one
    /// that is. `None` when none is.
    fn started(&self, unit: &str) -> Option<Start> {
        let enabled = unit_enabled(self.fs, self.root, unit);
        let active = loggers::unit_active(self.fs, self.root, unit);
        let state = match (enabled, active) {
            (Enabled::Yes, Activity::Active) => "is enabled and active",
            (Enabled::Yes, Activity::Inactive | Activity::Untold(_)) => "is enabled",
            (Enabled::No | Enabled::Untold(_), Activity::Active) => "is active",
            (Enabled::Untold(why), Activity::Inactive | Activity::Untold(_))
            | (Enabled::No, Activity::Untold(why)) => return Some(Start::Untold(why)),
            (Enabled::No, Activity::Inactive) => {
                let triggers = self
                    .triggers
                    .get_or_init(|| triggers::read(self.fs, self.root, self.hidden));
                return match triggers.of(unit)? {
                    Ok(how) => Some(Start::Sure(how)),
                    Err(why) => Some(Start::Untold(why)),
                };
            }
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
        let log = match log {
            Log::Journal { by, what } => namespace::journal_log(
                self.fs,
                self.root,
                namespace::of_unit(assignments),
                &by,
                what,
            ),
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
            logs.by_process = true;
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
                    Some(args) => {
                        let log = match (daemon.judge)(&args) {
                            Log::Stream { stream, by } => {
                                streams::of_process(self.fs, self.root, &process.pid, stream, by)
                            }
                            log => log,
                        };
                        match log {
                            Log::Journal { by, what } => namespace::journal_log(
                                self.fs,
                                self.root,
                                namespace::of_process(self.fs, self.root, &process.pid),
                                &by,
                                what,
                            ),
                            Log::Socket { stream, inode, by } => {
                                self.socket_log(&process.pid, stream, inode, &by)
                            }
                            log => log,
                        }
                    }
                },
            };
            logs.add_process(&source, log);
        }
    }

    /// Where `stream` of process `pid` leads, a socket whose inode is
    /// `inode`, for a daemon that logs to it as `by` says: to the journal of
    /// its own namespace, as its mount table shows it, and where that keeps
    /// nothing on the decoy disk, as PID 1's socket table shows ([`sockets`]).
    fn socket_log(&self, pid: &str, stream: Stream, inode: u64, by: &str) -> Log {
        match namespace::journal_log(
            self.fs,
            self.root,
            namespace::of_process(self.fs, self.root, pid),
            by,
            "its log",
        ) {
            Log::NoFile => sockets::judge(
                self.sockets
                    .get_or_init(|| sockets::read(self.fs, self.root)),
                stream,
                inode,
            ),
            log => log,
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
    let around = if logs.files.is_empty() {
        FIREWALLD_MAY_KEEP
    } else {
        FIREWALLD.around_a_switch
    };
    let mut fixes = Vec::new();
    // A journal namespace's file, or a journal NAILS cannot tell of, needs
    // the namespace's fix alone, or naming the namespace without a
    // specifier.
    if logs.by_unit || logs.by_process || (logs.namespaces.is_empty() && !logs.specifier) {
        let option = match env_files.last() {
            _ if is_nixos => "set services.firewalld.extraArgs = [ \"--log-target=syslog\" ] in \
                              the decoy configuration and run nixos-rebuild switch"
                .to_string(),
            Some(file) => format!("add --log-target=syslog to FIREWALLD_ARGS in {file}"),
            None => "add --log-target=syslog to its ExecStart= in a drop-in".to_string(),
        };
        fixes.push(format!(
            "make it log to the journal: {option}, then restart it (systemctl restart \
             firewalld.service)"
        ));
    }
    if !logs.namespaces.is_empty() {
        let namespaces: Vec<String> = logs.namespaces.iter().cloned().collect();
        fixes.push(namespace_fix(&namespaces, is_nixos));
    }
    if logs.specifier {
        fixes.push(specifier_fix(&[FIREWALLD.unit], is_nixos));
    }
    Some(format!(
        "{}, so {around}; {}",
        what.join(", and "),
        fixes.join(", and ")
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
    let mut namespaces = BTreeSet::new();
    let (tuned, ppd) = decoy.tuned();
    for (daemon, logs) in [(&TUNED, &tuned), (&TUNED_PPD, &ppd)] {
        found.blockers.extend(tuned_findings(daemon, logs));
        namespaces.extend(logs.namespaces.iter().cloned());
        if logs.specifier {
            found.specified.push(daemon.unit);
        }
        if logs.by_unit {
            found.units.push(daemon.unit);
        } else if logs.by_process {
            found.programs.push(daemon.program);
        }
    }
    found.namespaces = namespaces.into_iter().collect();
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

/// How to keep the journals of `namespaces` off the decoy disk, on a NixOS
/// decoy when `is_nixos`: each namespace's journald reads its own
/// `journald@<namespace>.conf`, never `journald.conf`, and restarts to take a
/// new `Storage=`.
fn namespace_fix(namespaces: &[String], is_nixos: bool) -> String {
    let one = namespaces.len() == 1;
    let names = listed(namespaces);
    let files = listed(
        &namespaces
            .iter()
            .map(|namespace| format!("/etc/systemd/journald@{namespace}.conf"))
            .collect::<Vec<_>>(),
    );
    let restart = namespaces
        .iter()
        .map(|namespace| format!("systemd-journald@{namespace}.service"))
        .collect::<Vec<_>>()
        .join(" ");
    let (journals, units) = if one {
        (
            format!("the journal of the namespace {names}"),
            "the unit that sets it",
        )
    } else {
        (
            format!("the journals of the namespaces {names}"),
            "the units that set them",
        )
    };
    if is_nixos {
        let options = listed(
            &namespaces
                .iter()
                .map(|namespace| {
                    format!("environment.etc.\"systemd/journald@{namespace}.conf\".text")
                })
                .collect::<Vec<_>>(),
        );
        return format!(
            "keep {journals} off the decoy disk: in the decoy configuration, set Storage=volatile \
             in the [Journal] section of {files} by {options}, or drop LogNamespace from the \
             serviceConfig of {units}, then run nixos-rebuild switch and systemctl restart \
             {restart}"
        );
    }
    let that = if one { "that unit" } else { "those units" };
    format!(
        "keep {journals} off the decoy disk: set Storage=volatile in the [Journal] section of \
         {files}, then run systemctl restart {restart}, or drop LogNamespace= from {units}, then \
         run systemctl daemon-reload and restart {that}"
    )
}

/// How to name the journal namespace of `units`, whose `LogNamespace=`
/// names it with a specifier, without one, which lets NAILS tell where they
/// log, on a NixOS decoy when `is_nixos`.
fn specifier_fix(units: &[&str], is_nixos: bool) -> String {
    let names = units.join(" ");
    if is_nixos {
        let services: Vec<String> = units
            .iter()
            .map(|unit| {
                format!(
                    "systemd.services.{}",
                    unit.strip_suffix(".service").unwrap_or(unit)
                )
            })
            .collect();
        return format!(
            "name the journal namespace in the LogNamespace of the serviceConfig of {} without a \
             specifier, which NAILS does not expand, or drop it, in the decoy configuration, then \
             run nixos-rebuild switch",
            listed(&services)
        );
    }
    format!(
        "name the journal namespace in the LogNamespace= of {names} without a specifier, which \
         NAILS does not expand, or drop it, then run systemctl daemon-reload and systemctl \
         restart {names}"
    )
}

/// The fix of the tuned findings, `units` being those of the units that
/// show a log file of their own or what NAILS cannot tell, `programs` those
/// of the programs only a process shows so, `namespaces` the journal
/// namespaces of the findings whose journal the decoy keeps or NAILS cannot
/// tell whether it does, and `specified` the units whose `LogNamespace=`
/// has a specifier, for a NixOS decoy when `is_nixos`.
pub(super) fn tuned_fix(
    units: &[&str],
    programs: &[&str],
    namespaces: &[String],
    specified: &[&str],
    is_nixos: bool,
) -> String {
    let mut fixes = Vec::new();
    if is_nixos && !(units.is_empty() && programs.is_empty()) {
        fixes.push(
            "make tuned log to the journal: set services.tuned.enable = false in the decoy \
             configuration, or there clear ExecStart= of systemd.services.tuned (and of \
             systemd.services.tuned-ppd) and set it again without -l, with StandardError= set \
             to journal, then run nixos-rebuild switch"
                .to_string(),
        );
    }
    if !is_nixos && !units.is_empty() {
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
    if !is_nixos && !programs.is_empty() {
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
    if !namespaces.is_empty() {
        fixes.push(namespace_fix(namespaces, is_nixos));
    }
    if !specified.is_empty() {
        fixes.push(specifier_fix(specified, is_nixos));
    }
    fixes.join(", and ")
}

#[cfg(test)]
#[path = "services_tests.rs"]
mod tests;
