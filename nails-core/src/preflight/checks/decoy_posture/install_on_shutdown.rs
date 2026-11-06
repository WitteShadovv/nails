// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! unattended-upgrades' install at shutdown, which a switch through logind
//! sets off.
//!
//! unattended-upgrades (Debian, Ubuntu) runs a shutdown helper,
//! `unattended-upgrades.service` (`unattended-upgrade-shutdown
//! --wait-for-signal`), that waits for logind's shutdown signal. Activation
//! sends that signal, as `systemctl soft-reboot` does, and so does the way
//! back with `nails deactivate` (`emergency` asks PID 1 directly and sends
//! none). The helper does not ask what kind of shutdown comes. With
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
//! that cannot be read or that apt refuses, a line NAILS does not read the
//! way apt does, whatever makes apt read other files than these
//! (`#include`, a `Dir` or `RootDir` setting), and a file name or a value
//! that apt reads by the system's locale (a byte beyond ASCII) leave the
//! setting unknown, which is refused as if it were on. The helper reads the
//! files again on the signal without forgetting what it read when it
//! started, so a `false` there wins, while a line only deleted stays in
//! effect until the helper restarts: the fix says to set it to false. Which
//! files it reads on the signal is settled by what it read first, so after a
//! `Dir` or `RootDir` line was removed it reads the files that line named
//! until it restarts, which NAILS does not see.
//!
//! The hidden session runs its own copy of the helper wherever the unit is
//! enabled and not masked, on the decoy or in the session's overlay. At the
//! way back through logind (`nails deactivate`) that copy installs the
//! updates into the session's overlay. That alone only warns: when the
//! decoy's helper is stopped but the session starts it, and when the
//! session's overlay turns the setting on. The session sees the decoy's
//! files with the root overlay's upper on top: a file of the upper replaces
//! the decoy's, and a whiteout deletes it. A directory the upper holds may be
//! one a session deleted and made again (an opaque one), below which the
//! decoy's files no longer show; that mark is not read here, so where the
//! upper holds `/etc/apt` its files are read both with the decoy's and on
//! their own, and either way that turns the setting on warns. A link among
//! apt's files, or on the way to them, resolves in the session through the
//! overlay, which NAILS does not follow, so it leaves the session's setting
//! unknown.
//!
//! A decoy whose enabled helper starts without python3-gi, and so writes two
//! lines to its log on the decoy disk at every start, is warned of too
//! ([`polling`]).
//!
//! Every read is a lookup, a listing or a read of a file; nothing is
//! written.

use super::{ADMIN_UNIT_DIR, loggers, masked, unit_linked};
use crate::Filesystem;
use crate::next_step::{NextStep, sudo_line};
use nails_base::packages::apt_conf::{self, PartName, Statement};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

mod polling;

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

/// Where a file of the session's overlay lies, as the texts say it.
const IN_UPPER: &str = " in the hidden session's overlay";

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
            Err(e) if e.by_apt => {
                return Setting::Unknown(format!(
                    "{} is refused by apt ({})",
                    at(e.line),
                    e.reason
                ));
            }
            Err(e) => {
                return Setting::Unknown(format!(
                    "{} holds {}, which NAILS does not read",
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
        Some((set, at)) if apt_conf::value_by_locale(&set) => Setting::Unknown(format!(
            "{at} sets it to a value with a byte beyond ASCII, which apt reads by the system's \
             locale"
        )),
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

/// That `path`, which the hidden session sees through its overlay, is no
/// link: the session resolves one through the overlay, which NAILS does not
/// follow.
fn no_link<F: Filesystem>(fs: &F, path: &Path, shown: &str) -> Result<(), String> {
    match fs.is_symlink(path) {
        Ok(false) => Ok(()),
        Ok(true) => Err(format!(
            "{shown} is a symbolic link, which NAILS does not follow through the hidden \
             session's overlay"
        )),
        Err(e) => Err(format!("{shown} cannot be looked up ({e})")),
    }
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
    /// Whether it is the hidden session's view, in which a link among apt's
    /// files resolves through the overlay ([`no_link`]). On the decoy it
    /// resolves as the decoy's helper resolves it, and is followed.
    session: bool,
}

/// The files apt reads in `view`, in its order.
fn sources<F: Filesystem>(fs: &F, view: View<'_>) -> Result<Vec<Source>, String> {
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
            let whiteout = upper
                && fs.is_overlay_whiteout(&entry).map_err(|e| {
                    format!(
                        "/{PARTS}/{}{place} cannot be looked up ({e})",
                        String::from_utf8_lossy(&name)
                    )
                })?;
            parts.insert(name, (!whiteout).then_some((entry, upper)));
        }
    }
    let mut found = Vec::new();
    for (name, read) in parts {
        let Some((read, upper)) = read else {
            continue;
        };
        let by_name = apt_conf::part_name(&name);
        if by_name == PartName::Skipped {
            continue;
        }
        let shown = format!("/{PARTS}/{}", String::from_utf8_lossy(&name));
        let place = if upper { IN_UPPER } else { "" };
        if view.session {
            no_link(fs, &read, &format!("{shown}{place}"))?;
        }
        if !regular(fs, &read, &format!("{shown}{place}"))? {
            continue;
        }
        if by_name == PartName::ByLocale {
            return Err(format!(
                "{shown}{place} has a name with a byte beyond ASCII, which apt reads or skips by \
                 the system's locale"
            ));
        }
        found.push(Source { shown, place, read });
    }
    // The main file: the upper's, unless it is a whiteout there, else the
    // decoy's where the view shows it.
    let mut main = view.main_lower.map(|lower| (lower.join(MAIN), ""));
    if let Some(upper) = view.main_upper {
        let path = upper.join(MAIN);
        let doubt = |e| format!("/{MAIN}{IN_UPPER} cannot be looked up ({e})");
        if fs.is_overlay_whiteout(&path).map_err(doubt)? {
            main = None;
        } else if fs.path_exists(&path).map_err(doubt)? || fs.is_symlink(&path).map_err(doubt)? {
            main = Some((path, IN_UPPER));
        }
    }
    if let Some((read, place)) = main {
        let shown = format!("/{MAIN}");
        if view.session {
            no_link(fs, &read, &format!("{shown}{place}"))?;
        }
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
        session: false,
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
    // The decoy's directories on the way, which the session sees through
    // the overlay.
    for rel in [ETC, APT, PARTS] {
        if let Err(why) = no_link(fs, &root.join(rel), &format!("/{rel} on the decoy")) {
            return Setting::Unknown(why);
        }
    }
    let parts_upper = (parts == Held::Dir).then_some(upper);
    let main_upper = (apt == Held::Dir).then_some(upper);
    let mut views = vec![View {
        parts_lower: (parts != Held::Gone).then_some(root),
        parts_upper,
        main_lower: Some(root),
        main_upper,
        session: true,
    }];
    if apt == Held::Dir {
        // /etc/apt, or /etc, made again in a session: the upper's files on
        // their own. An apt.conf.d made again on its own needs no view of its
        // own: where it turns the setting on, the merged view or this one
        // turns it on too, or the merged view leaves it unknown.
        views.push(View {
            parts_lower: None,
            parts_upper,
            main_lower: None,
            main_upper,
            session: true,
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

/// How the hidden session comes to start its own copy of the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionStart {
    /// The decoy enables the unit; else the session's overlay alone does.
    decoy_enables: bool,
    /// The decoy masks the unit, and the session's overlay takes the mask
    /// away.
    overlay_unmasks: bool,
}

/// Whether the hidden session starts its own copy of the helper, and how:
/// the unit is linked where systemd pulls it in, on the decoy or in the
/// session's overlay, and not masked as the session sees it. A link the
/// overlay deletes is not looked for, so a unit the session disabled still
/// counts. In the overlay, anything at the mask's place but a link to
/// `/dev/null` takes the decoy's mask away, a unit file of the session's
/// included. An error says NAILS cannot tell.
fn session_starts_helper<F: Filesystem>(
    fs: &F,
    root: &Path,
    upper: Option<&Path>,
) -> Result<Option<SessionStart>, String> {
    let decoy_enables = unit_linked(fs, root, UNIT);
    if !decoy_enables && !upper.is_some_and(|upper| unit_linked(fs, upper, UNIT)) {
        return Ok(None);
    }
    let decoy_masks = masked(fs, root, UNIT);
    let session_masks = match upper {
        Some(upper) => {
            let path = upper.join(ADMIN_UNIT_DIR).join(UNIT);
            let doubt = |e| {
                format!(
                    "what the hidden session's overlay holds at /{ADMIN_UNIT_DIR}/{UNIT} cannot \
                     be read ({e})"
                )
            };
            if fs.is_overlay_whiteout(&path).map_err(doubt)? {
                false
            } else if fs.is_symlink(&path).map_err(doubt)?
                || fs.path_exists(&path).map_err(doubt)?
            {
                masked(fs, upper, UNIT)
            } else {
                decoy_masks
            }
        }
        None => decoy_masks,
    };
    Ok((!session_masks).then_some(SessionStart {
        decoy_enables,
        overlay_unmasks: decoy_masks,
    }))
}

/// A refusal of the check's.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Blocker {
    /// What it found.
    pub(super) finding: String,
    /// What to do about it.
    pub(super) fix: String,
    /// Whether it is for the setting found on, not for one NAILS cannot
    /// tell: only then does the warning under `--allow-persistent-decoy` say
    /// that the install runs.
    pub(super) installs: bool,
}

/// What the check makes of unattended-upgrades' install at shutdown.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Finding {
    /// The refusal, when the decoy's helper would install at activation, or
    /// NAILS cannot tell.
    pub(super) blocker: Option<Blocker>,
    /// The warning, when only the session's copy would install, at the way
    /// back.
    pub(super) warning: Option<String>,
    /// The warning of a decoy's helper that starts without python3-gi
    /// ([`polling::warning`]).
    pub(super) polling: Option<String>,
}

/// The fix of a setting turned on at `at`, a file of the decoy and a line.
fn turn_off(at: &str) -> String {
    let file = at.rsplit_once(':').map_or(at, |(file, _)| file);
    // apt reads its main file after every part, so no part can turn off
    // what the main file turns on.
    let place = if file.strip_prefix('/') == Some(MAIN) {
        file.to_string()
    } else {
        format!("{file} or in a file of /{PARTS} that apt reads after it")
    };
    format!(
        "set `{SETTING} \"false\";` on the decoy, in {place} (a line only deleted stays in \
         effect until unattended-upgrades.service restarts)"
    )
}

/// How the hidden session comes to run its copy of the helper, as the
/// warning says it: `running` when the decoy's helper runs.
fn how_it_starts(start: &Result<SessionStart, String>, running: bool) -> String {
    let start = match start {
        Err(why) => {
            return format!(
                "NAILS cannot tell whether the hidden session starts its own copy of \
                 unattended-upgrades' shutdown helper ({why})"
            );
        }
        Ok(_) if running => {
            return "the hidden session starts its own copy of unattended-upgrades' shutdown \
                    helper"
                .to_string();
        }
        Ok(start) => start,
    };
    match (start.decoy_enables, start.overlay_unmasks) {
        (true, false) => {
            format!("{UNIT} is stopped on the decoy but enabled, so the hidden session starts it")
        }
        (false, false) => format!(
            "{UNIT} is stopped on the decoy, and the hidden session's overlay enables it, so the \
             session starts it"
        ),
        (true, true) => format!(
            "{UNIT} is masked on the decoy, but the hidden session's overlay unmasks it, so the \
             session starts it"
        ),
        (false, true) => format!(
            "{UNIT} is masked on the decoy, but the hidden session's overlay unmasks and enables \
             it, so the session starts it"
        ),
    }
}

/// What the refusal adds of the way back: what the session's own copy does
/// when the session ends with deactivate, where it has one.
fn way_back(start: Option<&Result<SessionStart, String>>) -> String {
    match start {
        None => String::new(),
        Some(Ok(_)) => {
            ", and when a session ends with deactivate, the session's own copy installs \
                        them again, into its overlay on the hidden volume"
                .to_string()
        }
        Some(Err(why)) => format!(
            ", and NAILS cannot tell whether a session's own copy installs them again, into its \
             overlay on the hidden volume, when the session ends with deactivate ({why})"
        ),
    }
}

/// The warning of what the session's copy of the helper does at the way
/// back, with the setting as the session reads it; `None` when it does
/// nothing.
fn session_warning(
    start: &Result<SessionStart, String>,
    running: bool,
    session: Setting,
) -> Option<String> {
    let how = how_it_starts(start, running);
    let installs = if start.is_ok() {
        "when the session ends with deactivate, it installs the pending updates"
    } else {
        "if the session starts it, it installs the pending updates when the session ends with \
         deactivate,"
    };
    match session {
        Setting::On(at) => Some(format!(
            "{how}, and {SETTING} is on there ({at}): {installs} into the session's overlay on \
             the hidden volume (set it to false, or end the session with `{}`, which sends no \
             shutdown signal)",
            sudo_line(NextStep::DeactivatePoweroff)
        )),
        Setting::Unknown(why) => Some(format!(
            "{how}, and NAILS cannot tell whether {SETTING} is on there, which would make it \
             install the pending updates when the session ends with deactivate: {why}"
        )),
        Setting::Off => None,
    }
}

/// unattended-upgrades' install at shutdown on the decoy under `root`, with
/// the root overlay's upper at `upper` (`None`: the decoy alone).
pub(super) fn finding<F: Filesystem>(fs: &F, root: &Path, upper: Option<&Path>) -> Finding {
    let polling = polling::warning(fs, root);
    let running = loggers::unit_active(fs, root, UNIT);
    let start = match session_starts_helper(fs, root, upper) {
        Ok(start) => start.map(Ok),
        Err(why) => Some(Err(why)),
    };
    if !running && start.is_none() {
        // No helper reads the setting at a switch.
        return Finding {
            polling,
            ..Finding::default()
        };
    }
    let decoy = decoy_setting(fs, root);
    if running {
        let way_back = way_back(start.as_ref());
        match &decoy {
            Setting::On(at) => {
                return Finding {
                    blocker: Some(Blocker {
                        finding: format!(
                            "unattended-upgrades installs the pending updates when the system \
                             shuts down ({SETTING} is on in {at}), and its shutdown helper takes \
                             a switch for a shutdown: at activation it runs that install on the \
                             decoy disk and logs that run there{way_back}"
                        ),
                        fix: turn_off(at),
                        installs: true,
                    }),
                    warning: None,
                    polling,
                };
            }
            Setting::Unknown(why) => {
                return Finding {
                    blocker: Some(Blocker {
                        finding: format!(
                            "NAILS cannot tell whether unattended-upgrades installs the pending \
                             updates at activation, as its shutdown helper does when {SETTING} \
                             is on, so it counts as on: {why}"
                        ),
                        fix: format!(
                            "fix or remove what keeps NAILS from reading the setting ({why}), \
                             and set `{SETTING} \"false\";` on the decoy if anything turns it on"
                        ),
                        installs: false,
                    }),
                    warning: None,
                    polling,
                };
            }
            Setting::Off => {}
        }
    }
    let Some(start) = start else {
        return Finding {
            polling,
            ..Finding::default()
        };
    };
    let session = match upper {
        Some(upper) => session_setting(fs, root, upper),
        None => decoy,
    };
    Finding {
        blocker: None,
        warning: session_warning(&start, running, session),
        polling,
    }
}

#[cfg(test)]
#[path = "install_on_shutdown_tests.rs"]
mod tests;
