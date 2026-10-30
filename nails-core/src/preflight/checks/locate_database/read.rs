// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the decoy holds of updatedb, read under a root so that a scan of an
//! offline image can read it too: the runs [`super::judge`] judges.
//!
//! A run is one way updatedb comes to scan the decoy, with the lists it prunes
//! with:
//!
//! - running now: an active `plocate-updatedb.service`,
//!   `mlocate-updatedb.service` or `update-locatedb.service` (NixOS), or a
//!   process whose name or program is an updatedb, read from `<root>/proc`,
//!   which also shows one a person started;
//! - scheduled: the timer of one of these services, enabled or active and
//!   neither it nor its service masked, or a cron job that runs updatedb.
//!   Debian's `/etc/cron.daily/plocate` ends at once where systemd runs, so
//!   it does not count while its first command is that test;
//! - started by hand: an updatedb program, or one of these services that
//!   nothing schedules.
//!
//! A service's lists are `/etc/updatedb.conf` with the options of its
//! `ExecStart=` on top, a process's the file with its own command line on
//! top, and a cron job's or a program's the file alone. findutils' updatedb
//! does not read the file; what it skips comes from its command line and its
//! environment, which NAILS does not read.
//!
//! Every file is read through [`DecoyFiles`].

use super::conf::{ConfError, UpdatedbConf, parse_updatedb_conf};
use super::exec::{exec_commands, is_updatedb};
use super::files::{DecoyFile, DecoyFiles};
use super::judge::{Entry, List, Lists, Run, Start};
use super::options::{Invocation, ListChange, Scan, invocation};
use super::unit::{UnitExec, unit_exec};
use crate::Filesystem;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The configuration file updatedb reads, relative to the root.
pub const UPDATEDB_CONF: &str = "etc/updatedb.conf";

/// A locate service, with its timer and the database it writes.
struct Service {
    unit: &'static str,
    timer: &'static str,
    database: &'static str,
}

/// The services that run updatedb: plocate's and mlocate's, and the one
/// NixOS's `services.locate` makes.
const SERVICES: &[Service] = &[
    Service {
        unit: "plocate-updatedb.service",
        timer: "plocate-updatedb.timer",
        database: "/var/lib/plocate/plocate.db",
    },
    Service {
        unit: "mlocate-updatedb.service",
        timer: "mlocate-updatedb.timer",
        database: "/var/lib/mlocate/mlocate.db",
    },
    Service {
        unit: "update-locatedb.service",
        timer: "update-locatedb.timer",
        database: "/var/cache/locatedb",
    },
];

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

/// The directories whose files cron runs, relative to the root.
const CRON_DIRS: &[&str] = &[
    "etc/cron.hourly",
    "etc/cron.daily",
    "etc/cron.weekly",
    "etc/cron.monthly",
    "etc/cron.d",
];

/// The system crontab, relative to the root.
const CRONTAB: &str = "etc/crontab";

/// `/etc/updatedb.conf` as the decoy holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfState {
    /// There is none: updatedb prunes nothing the file would name.
    Absent,
    /// Its settings.
    Parsed(UpdatedbConf),
    /// updatedb refuses it and scans nothing.
    Malformed(ConfError),
    /// NAILS cannot read it, for this reason.
    Unread(String),
}

/// Read the decoy's `/etc/updatedb.conf`.
pub fn read_conf<F: Filesystem>(files: &DecoyFiles<'_, F>) -> ConfState {
    match files.read(&files.root().join(UPDATEDB_CONF)) {
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

/// The lists updatedb reads from `conf`, before its options.
pub fn conf_lists(conf: &ConfState) -> Result<Lists, String> {
    let list = |entries: &[Vec<u8>], name: &str| {
        List::complete(
            entries
                .iter()
                .map(|value| Entry {
                    value: value.clone(),
                    origin: format!("{name} in /etc/updatedb.conf"),
                })
                .collect(),
        )
    };
    match conf {
        ConfState::Absent => Ok(Lists {
            paths: List::complete(Vec::new()),
            names: List::complete(Vec::new()),
            fs: List::complete(Vec::new()),
            ..Lists::default()
        }),
        ConfState::Parsed(conf) => Ok(Lists {
            paths: list(&conf.prunepaths, "PRUNEPATHS"),
            names: list(&conf.prunenames, "PRUNENAMES"),
            fs: list(&conf.prunefs, "PRUNEFS"),
            ..Lists::default()
        }),
        ConfState::Malformed(error) => Err(format!(
            "updatedb stops before it scans, because in /etc/updatedb.conf {error}"
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

/// The lists and the database of a run whose command line is `args` (after
/// the program), on top of the file's `base` lists; `whose` names where the
/// options are written.
fn with_options<F: Filesystem>(
    fs: &F,
    root: &Path,
    base: &Result<Lists, String>,
    args: &[Vec<u8>],
    whose: &str,
) -> (Result<Lists, String>, Option<String>) {
    let scan: Scan = match invocation(args) {
        Invocation::Scans(scan) => scan,
        Invocation::Stops(why) => {
            return (
                Err(format!(
                    "updatedb stops before it scans, because {why} ({whose})"
                )),
                None,
            );
        }
    };
    let database = scan.output.as_ref().map(|output| {
        let output = String::from_utf8_lossy(output);
        if output.starts_with('/') {
            output.into_owned()
        } else {
            format!("/{output}")
        }
    });
    let lists = match base {
        Ok(lists) => lists,
        Err(why) => return (Err(why.clone()), database),
    };
    let mut out = Lists {
        paths: changed(&lists.paths, &scan.paths, whose),
        names: changed(&lists.names, &scan.names, whose),
        fs: changed(&lists.fs, &scan.fs, whose),
        scan_root: None,
        incomplete: lists.incomplete.clone(),
    };
    if let Some(dir) = &scan.database_root {
        match resolve(fs, root, dir) {
            Ok(resolved) => {
                out.scan_root = Some((resolved, format!("--database-root in {whose}")));
            }
            Err(why) => return (Err(format!("{why} ({whose})")), database),
        }
    }
    (Ok(out), database)
}

/// The directory `dir` names on the decoy, resolved as updatedb's
/// `realpath()` resolves it (from `/`, the working directory of a service).
fn resolve<F: Filesystem>(fs: &F, root: &Path, dir: &[u8]) -> Result<PathBuf, String> {
    let dir = Path::new(std::ffi::OsStr::from_bytes(dir));
    let under = root.join(dir.strip_prefix("/").unwrap_or(dir));
    match fs.canonicalize(&under) {
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

/// What the decoy holds of updatedb.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// Whether any updatedb is installed: a program, a locate service or a
    /// cron job that runs one.
    pub installed: bool,
    /// Its runs.
    pub runs: Vec<Run>,
    /// The timers that schedule a run, for the fix.
    pub timers: Vec<&'static str>,
    /// The cron jobs that schedule one, for the fix.
    pub cron_jobs: Vec<String>,
}

/// Read what the decoy under `root` holds of updatedb. `hidden` are the
/// hidden volume's locations, resolved, which no read follows a link onto.
pub fn read_decoy<F: Filesystem>(fs: &F, root: &Path, hidden: &[PathBuf]) -> Found {
    let files = DecoyFiles::new(fs, root, hidden);
    let base = conf_lists(&read_conf(&files));
    let mut found = Found::default();
    services(fs, &files, &base, &mut found);
    processes(fs, root, &base, &mut found);
    cron(&files, &base, &mut found);
    programs(fs, root, &base, &mut found);
    found
}

/// The runs of the locate services.
fn services<F: Filesystem>(
    fs: &F,
    files: &DecoyFiles<'_, F>,
    base: &Result<Lists, String>,
    found: &mut Found,
) {
    use super::super::decoy_posture::{masked, unit_active, unit_enabled};
    let root = files.root();
    for service in SERVICES {
        let commands = match unit_exec(files, service.unit) {
            UnitExec::Missing => continue,
            UnitExec::Masked => {
                found.installed = true;
                continue;
            }
            UnitExec::Commands(commands) => Ok(commands),
            UnitExec::Unknown(why) => Err(why),
        };
        found.installed = true;
        let scheduled = (unit_enabled(fs, root, service.timer)
            || unit_active(fs, root, service.timer))
            && !masked(fs, root, service.timer);
        if scheduled {
            found.timers.push(service.timer);
        }
        let start = if unit_active(fs, root, service.unit) {
            Start::Now(format!("{} is active", service.unit))
        } else if scheduled {
            Start::Timer(service.timer.to_string())
        } else {
            Start::ByHand(format!("systemctl start {}", service.unit))
        };
        let whose = format!("the ExecStart of {}", service.unit);
        let commands = match commands {
            Ok(values) => values,
            Err(why) => {
                found.runs.push(Run {
                    start,
                    lists: Err(why),
                    database: Some(service.database.to_string()),
                });
                continue;
            }
        };
        for value in commands {
            let parsed = match exec_commands(&value) {
                Ok(parsed) => parsed,
                Err(why) => {
                    found.runs.push(Run {
                        start: start.clone(),
                        lists: Err(format!("{whose} cannot be read: {why}")),
                        database: Some(service.database.to_string()),
                    });
                    continue;
                }
            };
            for command in parsed {
                let (lists, database) = if is_updatedb(&command.program) {
                    with_options(fs, root, base, &command.args, &whose)
                } else {
                    (
                        Err(format!(
                            "{whose} runs {}, which NAILS does not read as updatedb",
                            String::from_utf8_lossy(&command.program)
                        )),
                        None,
                    )
                };
                found.runs.push(Run {
                    start: start.clone(),
                    lists,
                    database: database.or_else(|| Some(service.database.to_string())),
                });
            }
        }
    }
}

/// The runs of the updatedb processes under `<root>/proc`.
fn processes<F: Filesystem>(fs: &F, root: &Path, base: &Result<Lists, String>, found: &mut Found) {
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
            Some(program) if !program.ends_with(b"updatedb.findutils") => {
                // The last word of a command line is followed by a NUL too.
                let args: Vec<Vec<u8>> = match argv[1..].split_last() {
                    Some((last, rest)) if last.is_empty() => rest.to_vec(),
                    _ => argv[1..].to_vec(),
                };
                with_options(fs, root, base, &args, &whose)
            }
            _ => (
                Err(format!(
                    "process {pid} runs an updatedb that is no plocate or mlocate, such as \
                     findutils' script, whose prune options NAILS does not read"
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

/// Whether a cron job is Debian's plocate one, which ends at once where
/// systemd runs: its first command other than `set -e` and assignments is
/// `if [ -d /run/systemd/system ]; then exit 0; fi`.
fn ends_under_systemd(text: &[u8]) -> bool {
    let text = String::from_utf8_lossy(text);
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| *line != "set -e")
        // A plain assignment, `NAME=value` without a blank, runs nothing;
        // `NAME=value command` runs the command.
        .filter(|line| {
            !(line.split_once('=').is_some_and(|(name, _)| {
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            }) && !line.contains(char::is_whitespace))
        });
    lines.next() == Some("if [ -d /run/systemd/system ]; then")
        && lines.next() == Some("exit 0")
        && lines.next() == Some("fi")
}

/// The runs that cron schedules.
fn cron<F: Filesystem>(files: &DecoyFiles<'_, F>, base: &Result<Lists, String>, found: &mut Found) {
    let root = files.root();
    let mut jobs: Vec<PathBuf> = vec![root.join(CRONTAB)];
    for dir in CRON_DIRS {
        let mut entries = files.list(&root.join(dir)).unwrap_or_default();
        entries.sort();
        jobs.extend(entries);
    }
    for job in jobs {
        let shown = Path::new("/")
            .join(job.strip_prefix(root).unwrap_or(&job))
            .display()
            .to_string();
        let named_for_locate = job.file_name().is_some_and(|name| {
            matches!(
                name.as_bytes(),
                b"locate" | b"mlocate" | b"plocate" | b"updatedb"
            )
        });
        let text = match files.read(&job) {
            DecoyFile::Text(text) => text,
            DecoyFile::Unread(why) if named_for_locate => {
                found.installed = true;
                found.cron_jobs.push(shown.clone());
                found.runs.push(Run {
                    start: Start::Cron(shown),
                    lists: Err(why),
                    database: None,
                });
                continue;
            }
            _ => continue,
        };
        if !contains(&text, b"updatedb") {
            continue;
        }
        found.installed = true;
        if ends_under_systemd(&text) {
            continue;
        }
        let lists = if job.file_name().is_some_and(|name| name == "locate")
            || contains(&text, b"findutils")
        {
            Err(format!(
                "{shown} runs findutils' updatedb, whose prune options NAILS does not read"
            ))
        } else if contains(&text, b"prune")
            || contains(&text, b"database")
            || contains(&text, b"-U")
        {
            Err(format!(
                "{shown} passes updatedb options of its own, which NAILS does not read"
            ))
        } else {
            base.clone()
        };
        found.cron_jobs.push(shown.clone());
        found.runs.push(Run {
            start: Start::Cron(shown),
            lists,
            database: None,
        });
    }
}

fn contains(text: &[u8], needle: &[u8]) -> bool {
    text.windows(needle.len()).any(|window| window == needle)
}

/// The runs a person starts with an updatedb program.
fn programs<F: Filesystem>(fs: &F, root: &Path, base: &Result<Lists, String>, found: &mut Found) {
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
                base.clone(),
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
                base.clone(),
                plocate.then(|| "/var/cache/locatedb".to_string()),
            )
        } else {
            (
                base.clone(),
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
