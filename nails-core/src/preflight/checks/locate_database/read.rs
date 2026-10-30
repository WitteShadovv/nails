// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the decoy holds of updatedb, read under a root so that a scan of an
//! offline image can read it too: the runs [`super::judge`] judges.
//!
//! A run is one way updatedb comes to scan the decoy, with the lists it prunes
//! with:
//!
//! - running now: a service that runs updatedb and is active, or a process
//!   whose name or program is an updatedb, read from `<root>/proc`, which also
//!   shows one a person started;
//! - scheduled: a service that runs updatedb and that an enabled or active
//!   timer or path unit starts, or that is enabled itself ([`super::units`]),
//!   or a cron job that runs updatedb ([`super::cron`]);
//! - started by hand: an updatedb program, or plocate's, mlocate's or NixOS's
//!   own service that nothing schedules;
//! - maybe: a unit directory, crontab or cron script NAILS cannot read.
//!
//! A run reads `/etc/updatedb.conf`, or the file its `--config-file` names,
//! with its options on top ([`super::options`]): a service's from its
//! command, a process's from its command line, a cron job's from its line or
//! script. A program run by hand reads the file alone. updatedb resolves a
//! relative path in its options from its working directory: for a service
//! that sets no `WorkingDirectory=`, `/` under the system manager and the
//! user's home under a user's, and the process's own for a process. A
//! relative path elsewhere is one NAILS cannot tell about. findutils'
//! updatedb does not read the file: what it skips comes from its command line
//! and its environment, which NAILS does not read.
//!
//! Every file is read through [`DecoyFiles`].

use super::conf::{ConfError, UpdatedbConf, parse_updatedb_conf};
use super::cron::cron_jobs;
use super::exec::{ExecCommand, is_updatedb};
use super::files::{DecoyFile, DecoyFiles};
use super::judge::{Entry, List, Lists, Run, Start};
use super::options::{Invocation, ListChange, Scan, invocation};
use super::units::units;
use crate::Filesystem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The configuration file updatedb reads without `--config-file`.
pub const UPDATEDB_CONF: &str = "/etc/updatedb.conf";

/// Where an updatedb program is installed, relative to the root.
const PROGRAMS: &[&str] = &[
    "usr/bin/updatedb",
    "usr/sbin/updatedb",
    "bin/updatedb",
    "sbin/updatedb",
    "usr/local/bin/updatedb",
    "usr/local/sbin/updatedb",
    "usr/sbin/updatedb.plocate",
    "usr/bin/updatedb.mlocate",
    "usr/bin/updatedb.findutils",
    "run/current-system/sw/bin/updatedb",
];

/// A configuration file of updatedb as the decoy holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfState {
    /// There is none.
    Absent,
    /// Its settings.
    Parsed(UpdatedbConf),
    /// updatedb refuses it and scans nothing.
    Malformed(ConfError),
    /// NAILS cannot read it, for this reason.
    Unread(String),
}

/// Read the configuration file at `path`, as the decoy names it.
pub fn read_conf<F: Filesystem>(files: &DecoyFiles<'_, F>, path: &Path) -> ConfState {
    let under = files.root().join(path.strip_prefix("/").unwrap_or(path));
    match files.read(&under) {
        DecoyFile::Absent => ConfState::Absent,
        // A link to /dev/null reads as an empty file.
        DecoyFile::Null => ConfState::Parsed(UpdatedbConf::default()),
        DecoyFile::Text(bytes) => match parse_updatedb_conf(&bytes) {
            Ok(conf) => ConfState::Parsed(conf),
            Err(error) => ConfState::Malformed(error),
        },
        DecoyFile::Unread(why) => ConfState::Unread(why),
    }
}

/// The lists updatedb reads from the configuration file `name`, which holds
/// `conf`, before its options. A missing `/etc/updatedb.conf` prunes
/// nothing; another file, which `--config-file` names, must exist.
pub fn conf_lists(conf: &ConfState, name: &str) -> Result<Lists, String> {
    let list = |entries: &[Vec<u8>], variable: &str| {
        List::complete(
            entries
                .iter()
                .map(|value| Entry {
                    value: value.clone(),
                    origin: format!("{variable} in {name}"),
                })
                .collect(),
        )
    };
    match conf {
        ConfState::Absent if name == UPDATEDB_CONF => Ok(Lists {
            paths: List::complete(Vec::new()),
            names: List::complete(Vec::new()),
            fs: List::complete(Vec::new()),
            ..Lists::default()
        }),
        ConfState::Absent => Err(format!(
            "updatedb stops before it scans, because {name}, which --config-file names, does \
             not exist"
        )),
        ConfState::Parsed(conf) => Ok(Lists {
            paths: list(&conf.prunepaths, "PRUNEPATHS"),
            names: list(&conf.prunenames, "PRUNENAMES"),
            fs: list(&conf.prunefs, "PRUNEFS"),
            ..Lists::default()
        }),
        ConfState::Malformed(error) => Err(format!(
            "updatedb stops before it scans, because in {name} {error}"
        )),
        ConfState::Unread(why) => Ok(Lists {
            incomplete: Some(why.clone()),
            ..Lists::default()
        }),
    }
}

/// `list` with the changes `change` makes to it, the options named as given
/// in `whose` (such as `the ExecStart of update-locatedb.service`).
fn changed(list: &List, change: &ListChange, whose: &str) -> List {
    let flagged = change.entries.iter().map(|(value, option)| Entry {
        value: value.clone(),
        origin: format!("{option} in {whose}"),
    });
    if change.replaced {
        List::complete(flagged.collect())
    } else {
        List {
            entries: list.entries.iter().cloned().chain(flagged).collect(),
            complete: list.complete,
        }
    }
}

/// Where a run resolves a relative path in its options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cwd {
    /// From `/`, as a service without `WorkingDirectory=`.
    Root,
    /// From this directory, as the decoy names it.
    Dir(PathBuf),
    /// From a directory NAILS does not know, for this reason.
    Unknown(String),
}

impl Cwd {
    /// The path `path` names, as the decoy names it.
    fn resolve(&self, path: &[u8]) -> Result<PathBuf, String> {
        let path = Path::new(std::ffi::OsStr::from_bytes(path));
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        match self {
            Cwd::Root => Ok(Path::new("/").join(path)),
            Cwd::Dir(dir) => Ok(dir.join(path)),
            Cwd::Unknown(why) => Err(format!(
                "it names {} relative to a directory NAILS does not know: {why}",
                path.display()
            )),
        }
    }
}

/// How one run of updatedb reads its configuration and its options.
pub struct RunReader<'a, F: Filesystem> {
    fs: &'a F,
    files: &'a DecoyFiles<'a, F>,
    /// The lists of `/etc/updatedb.conf`, read once.
    base: Result<Lists, String>,
    /// Whether a bare `updatedb` is findutils' on the decoy.
    bare_findutils: bool,
}

impl<'a, F: Filesystem> RunReader<'a, F> {
    /// The reader over `files`, with `/etc/updatedb.conf` read.
    pub fn new(fs: &'a F, files: &'a DecoyFiles<'a, F>) -> Self {
        let base = conf_lists(&read_conf(files, Path::new(UPDATEDB_CONF)), UPDATEDB_CONF);
        let root = files.root();
        let bare_findutils = PROGRAMS
            .iter()
            .filter(|program| program.ends_with("/updatedb"))
            .any(|program| {
                fs.canonicalize(&root.join(program))
                    .is_ok_and(|resolved| resolved.as_os_str().as_bytes().ends_with(b"findutils"))
            });
        Self {
            fs,
            files,
            base,
            bare_findutils,
        }
    }

    /// Whether `program` is findutils' updatedb, which reads no
    /// `updatedb.conf`: by its own name, by the path it leads to, or as a
    /// bare `updatedb` where the decoy's is findutils'.
    fn findutils(&self, program: &[u8]) -> bool {
        let path = Path::new(std::ffi::OsStr::from_bytes(program));
        if program.ends_with(b"findutils") {
            return true;
        }
        if path.is_absolute() {
            let root = self.files.root();
            return self
                .fs
                .canonicalize(&root.join(path.strip_prefix("/").unwrap_or(path)))
                .is_ok_and(|resolved| resolved.as_os_str().as_bytes().ends_with(b"findutils"));
        }
        self.bare_findutils
    }

    /// [`Self::with_options`] for an updatedb `command`, which is no
    /// plocate or mlocate when it is findutils'.
    pub fn command(
        &self,
        command: &ExecCommand,
        whose: &str,
        cwd: &Cwd,
    ) -> (Result<Lists, String>, Option<String>, Option<Scan>) {
        if self.findutils(&command.program) {
            return (
                Err(format!(
                    "{whose} runs findutils' updatedb, whose prune options NAILS does not read"
                )),
                None,
                None,
            );
        }
        self.with_options(&command.args, whose, cwd)
    }

    /// The lists `/etc/updatedb.conf` gives a run without options.
    pub fn base(&self) -> &Result<Lists, String> {
        &self.base
    }

    /// The lists and the database of a run whose command line is `args`
    /// (after the program); `whose` names where the options are written,
    /// and `cwd` where the run resolves a relative path. The scan of
    /// `--prunepaths` comes back too, for the fix on NixOS.
    pub fn with_options(
        &self,
        args: &[Vec<u8>],
        whose: &str,
        cwd: &Cwd,
    ) -> (Result<Lists, String>, Option<String>, Option<Scan>) {
        let scan: Scan = match invocation(args) {
            Invocation::Scans(scan) => scan,
            Invocation::Stops(why) => {
                return (
                    Err(format!(
                        "updatedb stops before it scans, because {why} ({whose})"
                    )),
                    None,
                    None,
                );
            }
        };
        let database = scan
            .output
            .as_ref()
            .map(|output| match cwd.resolve(output) {
                Ok(path) => path.display().to_string(),
                Err(_) => String::from_utf8_lossy(output).into_owned(),
            });
        let file_lists;
        let lists = match &scan.config_file {
            None => &self.base,
            Some(file) => {
                file_lists = cwd.resolve(file).and_then(|path| {
                    conf_lists(&read_conf(self.files, &path), &path.display().to_string())
                });
                &file_lists
            }
        };
        let lists = match lists {
            Ok(lists) => lists,
            Err(why) => return (Err(format!("{why} ({whose})")), database, Some(scan)),
        };
        let mut out = Lists {
            paths: changed(&lists.paths, &scan.paths, whose),
            names: changed(&lists.names, &scan.names, whose),
            fs: changed(&lists.fs, &scan.fs, whose),
            scan_root: None,
            incomplete: lists.incomplete.clone(),
        };
        if let Some(dir) = &scan.database_root {
            match cwd.resolve(dir).and_then(|dir| self.resolve(&dir)) {
                Ok(resolved) => {
                    out.scan_root = Some((resolved, format!("--database-root in {whose}")));
                }
                Err(why) => return (Err(format!("{why} ({whose})")), database, Some(scan)),
            }
        }
        (Ok(out), database, Some(scan))
    }

    /// The directory `dir` names on the decoy, resolved as updatedb's
    /// `realpath()` resolves it.
    fn resolve(&self, dir: &Path) -> Result<PathBuf, String> {
        let root = self.files.root();
        let under = root.join(dir.strip_prefix("/").unwrap_or(dir));
        match self.fs.canonicalize(&under) {
            Ok(resolved) => {
                let inside = resolved.strip_prefix(root).unwrap_or(&resolved);
                Ok(Path::new("/").join(inside))
            }
            Err(e) if e.io_kind() == Some(std::io::ErrorKind::NotFound) => Err(format!(
                "updatedb stops before it scans, because the scan root {} does not exist",
                dir.display()
            )),
            Err(e) => Err(format!(
                "NAILS cannot resolve the scan root {} ({e})",
                dir.display()
            )),
        }
    }
}

/// What the decoy holds of updatedb.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// Whether any updatedb is installed: a program, a service that runs
    /// one, or a cron job that names one.
    pub installed: bool,
    /// Its runs.
    pub runs: Vec<Run>,
    /// How to stop what schedules a run, for the fix.
    pub remedies: Vec<String>,
    /// Why an installed updatedb does not run, for a message.
    pub notes: Vec<String>,
    /// The paths the `ExecStart=` of NixOS's `update-locatedb.service`
    /// prunes with `--prunepaths` (none without one), for the fix.
    pub nixos_prunepaths: Option<Vec<Vec<u8>>>,
}

/// Read what the decoy under `root` holds of updatedb. `hidden` are the
/// hidden volume's locations, resolved, which no read follows a link onto.
pub fn read_decoy<F: Filesystem>(fs: &F, root: &Path, hidden: &[PathBuf]) -> Found {
    let files = DecoyFiles::new(fs, root, hidden);
    let reader = RunReader::new(fs, &files);
    let mut found = Found::default();
    services(fs, &files, &reader, &mut found);
    processes(fs, root, &reader, &mut found);
    cron(fs, &files, &reader, &mut found);
    programs(fs, root, &reader, &mut found);
    found
}

/// The runs of the services that run updatedb.
fn services<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    reader: &RunReader<'_, F>,
    found: &mut Found,
) {
    let units = units(fs, files);
    found.installed |= units.installed;
    found.remedies.extend(units.remedies);
    found.notes.extend(units.notes);
    for run in units.runs {
        let cwd = run.cwd;
        let commands = match run.commands {
            Ok(commands) => commands,
            Err(why) => {
                found.runs.push(Run {
                    start: run.start,
                    lists: Err(why),
                    database: run.database.map(str::to_string),
                });
                continue;
            }
        };
        for (key, command) in commands {
            let whose = format!("the {key} of {}", run.service);
            let (lists, database, scan) = reader.command(&command, &whose, &cwd);
            if run.service == "update-locatedb.service"
                && key == "ExecStart"
                && let Some(scan) = scan
            {
                found.nixos_prunepaths = Some(if scan.paths.replaced {
                    scan.paths
                        .entries
                        .into_iter()
                        .map(|(value, _)| value)
                        .collect()
                } else {
                    Vec::new()
                });
            }
            found.runs.push(Run {
                start: run.start.clone(),
                lists,
                database: database.or_else(|| run.database.map(str::to_string)),
            });
        }
    }
}

/// The runs of the updatedb processes under `<root>/proc`.
fn processes<F: Filesystem>(fs: &F, root: &Path, reader: &RunReader<'_, F>, found: &mut Found) {
    let Ok(entries) = fs.list_directory(&root.join("proc")) else {
        return;
    };
    let mut pids: Vec<PathBuf> = entries
        .into_iter()
        .filter(|entry| {
            entry.file_name().is_some_and(|name| {
                !name.is_empty() && name.as_bytes().iter().all(u8::is_ascii_digit)
            })
        })
        .collect();
    pids.sort();
    for dir in pids {
        let pid = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let comm = fs.read_file_bytes(&dir.join("comm")).unwrap_or_default();
        let comm = comm.strip_suffix(b"\n").unwrap_or(&comm);
        let argv: Vec<Vec<u8>> = fs
            .read_file_bytes(&dir.join("cmdline"))
            .unwrap_or_default()
            .split(|&byte| byte == 0)
            .map(<[u8]>::to_vec)
            .collect();
        let program = argv.first().filter(|program| is_updatedb(program));
        if program.is_none() && !is_updatedb(comm) {
            continue;
        }
        found.installed = true;
        let start = Start::Now(format!("updatedb runs as process {pid}"));
        let whose = format!("the command line of process {pid}");
        let (lists, database) = match program {
            Some(program) => {
                // The last word of a command line is followed by a NUL too.
                let args: Vec<Vec<u8>> = match argv[1..].split_last() {
                    Some((last, rest)) if last.is_empty() => rest.to_vec(),
                    _ => argv[1..].to_vec(),
                };
                // The process resolves a relative path from its own working
                // directory.
                let cwd = match fs.canonicalize(&dir.join("cwd")) {
                    Ok(cwd) => {
                        Cwd::Dir(Path::new("/").join(cwd.strip_prefix(root).unwrap_or(&cwd)))
                    }
                    Err(e) => {
                        Cwd::Unknown(format!("NAILS cannot read where process {pid} runs ({e})"))
                    }
                };
                let command = ExecCommand {
                    program: program.clone(),
                    args,
                };
                let (lists, database, _) = reader.command(&command, &whose, &cwd);
                (lists, database)
            }
            // Its name is an updatedb's, its program is not: an interpreter
            // runs a script, as findutils' updatedb is one.
            None => (
                Err(format!(
                    "process {pid} runs an updatedb that is a script, such as findutils', whose \
                     prune options NAILS does not read"
                )),
                None,
            ),
        };
        found.runs.push(Run {
            start,
            lists,
            database,
        });
    }
}

/// The runs that cron and anacron schedule.
fn cron<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    reader: &RunReader<'_, F>,
    found: &mut Found,
) {
    for job in cron_jobs(fs, files) {
        let start = match &job.removal {
            Some(removal) => {
                // A job NAILS read names updatedb.
                found.installed = true;
                if !found.remedies.contains(removal) {
                    found.remedies.push(removal.clone());
                }
                Start::Cron(job.place.clone())
            }
            // One NAILS cannot read only may.
            None => Start::Unread(job.place.clone()),
        };
        let cwd = Cwd::Unknown("cron runs a job from its user's home".to_string());
        for run in job.runs {
            let (lists, database) = match run {
                Ok(command) => {
                    let (lists, database, _) = reader.command(&command, &job.place, &cwd);
                    (lists, database)
                }
                Err(why) => (Err(why), None),
            };
            found.runs.push(Run {
                start: start.clone(),
                lists,
                database,
            });
        }
    }
}

/// The runs a person starts with an updatedb program.
fn programs<F: Filesystem>(fs: &F, root: &Path, reader: &RunReader<'_, F>, found: &mut Found) {
    let mut seen: Vec<PathBuf> = Vec::new();
    for program in PROGRAMS {
        let path = root.join(program);
        if !fs.path_exists(&path).unwrap_or(false) {
            continue;
        }
        let resolved = fs.canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.contains(&resolved) {
            continue;
        }
        seen.push(resolved.clone());
        found.installed = true;
        let shown = format!("/{program}");
        let name = resolved
            .file_name()
            .map(|name| name.as_bytes().to_vec())
            .unwrap_or_default();
        let (lists, database) = if name.ends_with(b"findutils") {
            (
                Err(format!(
                    "{shown} is findutils' updatedb, whose prune options NAILS does not read"
                )),
                None,
            )
        } else if name.ends_with(b"mlocate") {
            (
                reader.base().clone(),
                Some("/var/lib/mlocate/mlocate.db".to_string()),
            )
        } else if resolved.starts_with("/nix/store") {
            // nixpkgs builds plocate with its database in /var/cache.
            let plocate = resolved
                .as_os_str()
                .as_bytes()
                .windows(9)
                .any(|w| w == b"-plocate-");
            (
                reader.base().clone(),
                plocate.then(|| "/var/cache/locatedb".to_string()),
            )
        } else {
            (
                reader.base().clone(),
                Some("/var/lib/plocate/plocate.db".to_string()),
            )
        };
        found.runs.push(Run {
            start: Start::ByHand(shown),
            lists,
            database,
        });
    }
}
