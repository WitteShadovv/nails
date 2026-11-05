// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! unattended-upgrades' install at shutdown, which every switch sets off.
//!
//! unattended-upgrades (Debian, Ubuntu) runs a shutdown helper,
//! `unattended-upgrades.service` (`unattended-upgrade-shutdown
//! --wait-for-signal`), that waits for logind's shutdown signal. A switch
//! sends that signal, as `systemctl soft-reboot` does, and the helper does
//! not ask what kind of shutdown comes. With
//! `Unattended-Upgrade::InstallOnShutdown` on, it reads apt's configuration
//! again on the signal and starts unattended-upgrade in its shutdown mode,
//! which installs the pending updates its settings allow: at activation on
//! the decoy disk, the overlays already mounted on it, and it logs that run
//! there. With python3-gi installed the helper holds the switch back while
//! the install runs; without it the helper polls for the signal and exits
//! right after it starts the install, which then runs on into the switch.
//! The setting is off unless a file of apt's configuration turns it on.
//!
//! So a decoy whose helper runs at activation with the setting on is
//! refused, a finding of its own that `--allow-persistent-decoy` turns into
//! a warning for one run. The setting is read the way the helper reads it,
//! through [`apt_conf`]: each file of `/etc/apt/apt.conf.d` apt reads, in
//! apt's order, then `/etc/apt/apt.conf`, the last assignment winning. A file
//! that cannot be read or that apt refuses, and whatever makes apt read other
//! files than these (`#include`, a `Dir` or `RootDir` setting), leave the
//! setting unknown, which is refused as if it were on. The helper reads the
//! files again on the signal without forgetting what it read when it
//! started, so a `false` there wins, while a line only deleted stays in
//! effect until the helper restarts: the fix says to set it to false.
//!
//! The hidden session runs its own copy of the helper wherever the unit is
//! enabled. At the way back through logind (`nails deactivate`) that copy
//! installs the updates into the session's overlay. That alone only warns:
//! when the decoy's helper is stopped but enabled, so that the session starts
//! it again, and when the session's overlay turns the setting on. The session
//! sees the decoy's files with the root overlay's upper on top: a file of the
//! upper replaces the decoy's, and a whiteout deletes it. A directory the
//! upper holds may be one a session deleted and made again (an opaque one),
//! below which the decoy's files no longer show; that mark is not read here,
//! so such a directory is read both ways, and either way that turns the
//! setting on warns.
//!
//! Every read is a lookup, a listing or a read of a file; nothing is
//! written.

use super::{ADMIN_UNIT_DIR, loggers, masked, unit_linked};
use crate::Filesystem;
use crate::next_step::{NextStep, sudo_line};
use nails_base::packages::apt_conf::{self, Statement};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The helper's unit.
const UNIT: &str = "unattended-upgrades.service";

/// The setting, by its tags, and as the docs write it.
const KEY: &[&str] = &["Unattended-Upgrade", "InstallOnShutdown"];
const SETTING: &str = "Unattended-Upgrade::InstallOnShutdown";

/// What apt reads, relative to a root: its parts directory, then its main
/// file. The directories on the way, which a session's overlay may hold.
const PARTS: &str = "etc/apt/apt.conf.d";
const MAIN: &str = "etc/apt/apt.conf";
const ETC: &str = "etc";
const APT: &str = "etc/apt";

/// The items that tell apt which files to read: one set or cleared moves
/// what it reads next, which NAILS does not follow.
const MOVERS: &[&[&str]] = &[
    &["Dir"],
    &["Dir", "Etc"],
    &["Dir", "Etc", "parts"],
    &["Dir", "Etc", "main"],
    &["RootDir"],
];

/// The most of one configuration file read, 1 MiB.
const FILE_LIMIT: u64 = 1 << 20;

/// What the files say of the setting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Setting {
    /// On, set at this place.
    On(String),
    /// Off: set off, cleared, or not set at all.
    Off,
    /// NAILS cannot tell, for this reason.
    Unknown(String),
}

/// One file apt reads: as the system it belongs to names it, where it lies
/// (nothing for the decoy, or the session's overlay), and where it is read
/// from.
struct Source {
    shown: String,
    place: &'static str,
    read: PathBuf,
}

/// The file at `path`, at most [`FILE_LIMIT`] bytes of it.
fn read_bounded<F: Filesystem>(fs: &F, path: &Path) -> Result<Vec<u8>, String> {
    let size = fs
        .file_size(path)
        .map_err(|e| format!("cannot be read ({e})"))?;
    if size > FILE_LIMIT {
        return Err(format!(
            "holds {size} bytes, more than NAILS reads of an apt configuration file"
        ));
    }
    fs.read_file_bytes(path)
        .map_err(|e| format!("cannot be read ({e})"))
}

/// The setting after apt reads `sources` in order.
fn evaluate<F: Filesystem>(fs: &F, sources: &[Source]) -> Setting {
    let mut value: Option<(Vec<u8>, String)> = None;
    for source in sources {
        let at = |line: usize| format!("{}:{line}{}", source.shown, source.place);
        let bytes = match read_bounded(fs, &source.read) {
            Ok(bytes) => bytes,
            Err(why) => {
                return Setting::Unknown(format!("{}{} {why}", source.shown, source.place));
            }
        };
        let parsed = match apt_conf::parse(&bytes) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Setting::Unknown(format!(
                    "{} is refused by apt ({})",
                    at(e.line),
                    e.reason
                ));
            }
        };
        for statement in parsed.statements {
            match statement {
                Statement::Set {
                    item,
                    value: set,
                    line,
                } => {
                    if MOVERS
                        .iter()
                        .any(|mover| apt_conf::names(&item, mover, false))
                    {
                        return Setting::Unknown(format!(
                            "{} sets {}, which moves the files apt reads",
                            at(line),
                            String::from_utf8_lossy(&item)
                        ));
                    }
                    if apt_conf::names(&item, KEY, false) {
                        value = Some((set, at(line)));
                    }
                }
                Statement::Clear { name, line } => {
                    if MOVERS
                        .iter()
                        .any(|mover| apt_conf::names(&name, mover, true))
                    {
                        return Setting::Unknown(format!(
                            "{} clears {}, which moves the files apt reads",
                            at(line),
                            String::from_utf8_lossy(&name)
                        ));
                    }
                    if apt_conf::names(&name, KEY, true) {
                        value = None;
                    }
                }
                Statement::Include { line } => {
                    return Setting::Unknown(format!(
                        "{} has apt read another file, which NAILS does not follow",
                        at(line)
                    ));
                }
                Statement::ConfigureIndex { line } => {
                    return Setting::Unknown(format!(
                        "{} has apt load an index of its options, which NAILS does not follow",
                        at(line)
                    ));
                }
            }
        }
    }
    match value {
        Some((set, at)) if apt_conf::string_to_bool(&set, false) => Setting::On(at),
        _ => Setting::Off,
    }
}

/// The name of a directory entry, as bytes.
fn name_of(entry: &Path) -> Option<Vec<u8>> {
    entry.file_name().map(|name| name.as_bytes().to_vec())
}

/// Whether `path` is a regular file once its links are followed, which is
/// what apt reads; an error says NAILS cannot tell.
fn regular<F: Filesystem>(fs: &F, path: &Path, shown: &str) -> Result<bool, String> {
    fs.is_regular_file(path)
        .map_err(|e| format!("{shown} cannot be looked up ({e})"))
}

/// What a session's overlay holds at a directory on the way to apt's files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Nothing: the decoy's shows through.
    Nothing,
    /// A directory, which may be one a session made again.
    Dir,
    /// A whiteout or a file: the session has no directory there.
    Gone,
}

/// What `upper` holds at `rel`, a directory on the way to apt's files.
fn held<F: Filesystem>(fs: &F, upper: &Path, rel: &str) -> Result<Held, String> {
    let path = upper.join(rel);
    let doubt =
        |e| format!("what the hidden session's overlay holds at /{rel} cannot be read ({e})");
    if fs.is_overlay_whiteout(&path).map_err(doubt)? {
        return Ok(Held::Gone);
    }
    if fs.is_symlink(&path).map_err(doubt)? {
        return Err(format!(
            "the hidden session's overlay holds a symbolic link at /{rel}"
        ));
    }
    if !fs.path_exists(&path).map_err(doubt)? {
        return Ok(Held::Nothing);
    }
    Ok(if fs.is_directory(&path).map_err(doubt)? {
        Held::Dir
    } else {
        Held::Gone
    })
}

/// Where a view of the system reads apt's files from: the decoy root's parts
/// directory and main file where the view shows them, with the session's
/// overlay on top.
#[derive(Clone, Copy)]
struct View<'a> {
    /// The decoy root, for the parts directory, unless the view cuts it off.
    parts_lower: Option<&'a Path>,
    /// The upper, for the parts directory, when it holds one.
    parts_upper: Option<&'a Path>,
    /// The decoy root, for the main file, unless the view cuts it off.
    main_lower: Option<&'a Path>,
    /// The upper, for the main file, when its `etc/apt` shows.
    main_upper: Option<&'a Path>,
}

/// The files apt reads in `view`, in its order.
fn sources<F: Filesystem>(fs: &F, view: View<'_>) -> Result<Vec<Source>, String> {
    const IN_UPPER: &str = " in the hidden session's overlay";
    // Name -> where it is read from and whether the upper holds it; `None`
    // for a whiteout of the upper, which deletes the decoy's file.
    let mut parts: BTreeMap<Vec<u8>, Option<(PathBuf, bool)>> = BTreeMap::new();
    let layers = [(view.parts_lower, false), (view.parts_upper, true)];
    for (base, upper) in layers {
        let Some(base) = base else {
            continue;
        };
        let dir = base.join(PARTS);
        let place = if upper { IN_UPPER } else { "" };
        match fs.is_directory(&dir) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => return Err(format!("/{PARTS}{place} cannot be looked up ({e})")),
        }
        let entries = fs
            .list_directory(&dir)
            .map_err(|e| format!("/{PARTS}{place} cannot be listed ({e})"))?;
        for entry in entries {
            let Some(name) = name_of(&entry) else {
                continue;
            };
            let whiteout = upper && fs.is_overlay_whiteout(&entry).unwrap_or(false);
            parts.insert(name, (!whiteout).then_some((entry, upper)));
        }
    }
    let mut found = Vec::new();
    for (name, read) in parts {
        let Some((read, upper)) = read else {
            continue;
        };
        if !apt_conf::part_name(&name) {
            continue;
        }
        let shown = format!("/{PARTS}/{}", String::from_utf8_lossy(&name));
        let place = if upper { IN_UPPER } else { "" };
        if regular(fs, &read, &format!("{shown}{place}"))? {
            found.push(Source { shown, place, read });
        }
    }
    // The main file: the upper's, unless it is a whiteout there, else the
    // decoy's where the view shows it.
    let mut main = view.main_lower.map(|lower| (lower.join(MAIN), ""));
    if let Some(upper) = view.main_upper {
        let path = upper.join(MAIN);
        if fs.is_overlay_whiteout(&path).unwrap_or(false) {
            main = None;
        } else if fs.path_exists(&path).unwrap_or(false) || fs.is_symlink(&path).unwrap_or(false) {
            main = Some((path, IN_UPPER));
        }
    }
    if let Some((read, place)) = main {
        let shown = format!("/{MAIN}");
        if regular(fs, &read, &format!("{shown}{place}"))? {
            found.push(Source { shown, place, read });
        }
    }
    Ok(found)
}

/// The setting on the decoy under `root`.
fn decoy_setting<F: Filesystem>(fs: &F, root: &Path) -> Setting {
    let view = View {
        parts_lower: Some(root),
        parts_upper: None,
        main_lower: Some(root),
        main_upper: None,
    };
    match sources(fs, view) {
        Ok(found) => evaluate(fs, &found),
        Err(why) => Setting::Unknown(why),
    }
}

/// The setting the session's copy of the helper reads: the decoy's files
/// under `root` with `upper` on top, each way a directory of the upper may
/// be read.
fn session_setting<F: Filesystem>(fs: &F, root: &Path, upper: &Path) -> Setting {
    let kinds = (|| {
        Ok::<_, String>((
            held(fs, upper, ETC)?,
            held(fs, upper, APT)?,
            held(fs, upper, PARTS)?,
        ))
    })();
    let (etc, apt, parts) = match kinds {
        Ok(kinds) => kinds,
        Err(why) => return Setting::Unknown(why),
    };
    if etc == Held::Gone || apt == Held::Gone {
        // The session has no /etc/apt.
        return Setting::Off;
    }
    let parts_upper = (parts == Held::Dir).then_some(upper);
    let shown_lower = (parts != Held::Gone).then_some(root);
    let main_upper = (apt == Held::Dir).then_some(upper);
    let mut views = vec![View {
        parts_lower: shown_lower,
        parts_upper,
        main_lower: Some(root),
        main_upper,
    }];
    if parts == Held::Dir {
        // apt.conf.d made again in a session.
        views.push(View {
            parts_lower: None,
            parts_upper,
            main_lower: Some(root),
            main_upper,
        });
    }
    if etc == Held::Dir || apt == Held::Dir {
        // /etc or /etc/apt made again in a session.
        views.push(View {
            parts_lower: None,
            parts_upper,
            main_lower: None,
            main_upper,
        });
    }
    let mut unknown = None;
    for view in views {
        match sources(fs, view).map(|found| evaluate(fs, &found)) {
            Ok(Setting::On(at)) => return Setting::On(at),
            Ok(Setting::Unknown(why)) | Err(why) => {
                unknown.get_or_insert(why);
            }
            Ok(Setting::Off) => {}
        }
    }
    unknown.map_or(Setting::Off, Setting::Unknown)
}

/// Whether the hidden session starts its own copy of the helper: the unit is
/// linked where systemd pulls it in, on the decoy or in the session's
/// overlay, and not masked as the session sees it. A link the overlay
/// deletes is not looked for, so a unit the session disabled still counts.
fn session_starts_helper<F: Filesystem>(fs: &F, root: &Path, upper: Option<&Path>) -> bool {
    let linked =
        unit_linked(fs, root, UNIT) || upper.is_some_and(|upper| unit_linked(fs, upper, UNIT));
    if !linked {
        return false;
    }
    let mask = |base: &Path| base.join(ADMIN_UNIT_DIR).join(UNIT);
    let masked_there = match upper {
        // The session removed the decoy's mask.
        Some(upper) if fs.is_overlay_whiteout(&mask(upper)).unwrap_or(false) => false,
        Some(upper) if fs.is_symlink(&mask(upper)).unwrap_or(false) => masked(fs, upper, UNIT),
        _ => masked(fs, root, UNIT),
    };
    !masked_there
}

/// What the check makes of unattended-upgrades' install at shutdown.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Finding {
    /// The refusal, with its fix, when the decoy's helper would install at
    /// activation, or NAILS cannot tell.
    pub(super) blocker: Option<(String, String)>,
    /// The warning, when only the session's copy would install, at the way
    /// back.
    pub(super) warning: Option<String>,
}

/// The fix of a setting turned on at `at`.
fn turn_off(at: &str) -> String {
    let file = at.rsplit_once(':').map_or(at, |(file, _)| file);
    format!(
        "set `{SETTING} \"false\";` on the decoy, in {file} or in a file of /etc/apt/apt.conf.d \
         that apt reads after it (a line only deleted stays in effect until \
         unattended-upgrades.service restarts)"
    )
}

/// unattended-upgrades' install at shutdown on the decoy under `root`, with
/// the root overlay's upper at `upper` (`None`: the decoy alone).
pub(super) fn finding<F: Filesystem>(fs: &F, root: &Path, upper: Option<&Path>) -> Finding {
    let running = loggers::unit_active(fs, root, UNIT);
    let in_session = session_starts_helper(fs, root, upper);
    if !running && !in_session {
        return Finding::default();
    }
    let decoy = decoy_setting(fs, root);
    if running {
        let way_back = if in_session {
            ", and when a session ends with deactivate, the session's own copy installs them \
             again, into its overlay on the hidden volume"
        } else {
            ""
        };
        match &decoy {
            Setting::On(at) => {
                return Finding {
                    blocker: Some((
                        format!(
                            "unattended-upgrades installs the pending updates when the system \
                             shuts down ({SETTING} is on in {at}), and its shutdown helper takes \
                             a switch for a shutdown: at activation it runs that install on the \
                             decoy disk and logs that run there{way_back}"
                        ),
                        turn_off(at),
                    )),
                    warning: None,
                };
            }
            Setting::Unknown(why) => {
                return Finding {
                    blocker: Some((
                        format!(
                            "NAILS cannot tell whether unattended-upgrades installs the pending \
                             updates at activation, as its shutdown helper does when {SETTING} \
                             is on, so it counts as on: {why}"
                        ),
                        format!(
                            "fix or remove what NAILS cannot read of apt's configuration ({why}), \
                             and set `{SETTING} \"false\";` on the decoy if anything turns it on"
                        ),
                    )),
                    warning: None,
                };
            }
            Setting::Off => {}
        }
    }
    if !in_session {
        return Finding::default();
    }
    let session = match upper {
        Some(upper) => session_setting(fs, root, upper),
        None => decoy,
    };
    let how = if running {
        "the hidden session starts its own copy of unattended-upgrades' shutdown helper"
    } else {
        "unattended-upgrades.service is stopped on the decoy but enabled, so the hidden session \
         starts it"
    };
    let warning = match session {
        Setting::On(at) => Some(format!(
            "{how}, and {SETTING} is on there ({at}): when the session ends with deactivate, it \
             installs the pending updates into the session's overlay on the hidden volume (set \
             it to false, or end the session with `{}`, which sends no shutdown signal)",
            sudo_line(NextStep::DeactivatePoweroff)
        )),
        Setting::Unknown(why) => Some(format!(
            "{how}, and NAILS cannot tell whether {SETTING} is on there, which would make it \
             install the pending updates when the session ends with deactivate: {why}"
        )),
        Setting::Off => None,
    };
    Finding {
        blocker: None,
        warning,
    }
}

#[cfg(test)]
#[path = "install_on_shutdown_tests.rs"]
mod tests;
