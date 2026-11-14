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
//! through [`apt_conf`]: the file the helper's `APT_CONFIG` names, if it runs
//! with one ([`helper`]), then each file of `/etc/apt/apt.conf.d` apt reads,
//! in apt's order, then `/etc/apt/apt.conf`, the last assignment winning. A
//! file that cannot be read, a line NAILS does not read the way apt does,
//! whatever makes apt read other files than these (`#include`, a `Dir` or
//! `RootDir` setting), an `#x-apt-configure-index`, at which apt stops
//! reading the file when it cannot load the index (so a line after it that
//! apt would refuse is left unknown too), and a file name or a value that apt
//! reads by the system's locale (a byte beyond ASCII) leave the setting
//! unknown, which is refused as if it were on. A file apt refuses is refused
//! too, for what the helper then does: it installs nothing, but at the switch
//! it writes two ERROR lines, to its log on the decoy disk unless it started
//! with the file already refused, and the refusal says so. An environment of
//! the helper that only root may read leaves the setting unknown to a run
//! without root, and the fix says to run the check as root.
//!
//! The helper reads the files again on the signal without forgetting what it
//! read when it started, so a `false` (or a `#clear`) there wins, while a
//! line only deleted stays in effect until the helper restarts. So when no
//! file sets the setting, NAILS cannot tell whether the helper still holds a
//! `true` when one of apt's files, `/etc/apt`, `/etc/apt/apt.conf.d` or the
//! directory that holds the file `APT_CONFIG` names changed after the helper
//! started, or one of them is reached through a symbolic link, a link among
//! apt's files that leads to no file now included, as apt skips it at the
//! signal, and that is refused as well: the fix says to set it to false.
//! Which files it reads on the signal is settled by what it read first, so
//! after a `Dir` or `RootDir` line was removed it reads the files that line
//! named until it restarts, which NAILS does not see.
//!
//! The hidden session runs its own copy of the helper wherever the unit is
//! enabled and not masked, on the decoy or in the session's overlay. At the
//! way back through logind (`nails deactivate`) that copy installs the
//! updates into the session's overlay. That alone only warns: when the
//! decoy's helper is stopped but the session starts it, and when the
//! session's overlay turns the setting on. Where apt refuses a file the
//! session reads, the warning says what its copy does: it starts with the
//! file refused, logs to the session's journal and installs nothing while the
//! file stays refused. The session sees the decoy's files with the root
//! overlay's upper on top: a file of the upper replaces the decoy's, and a
//! whiteout deletes it. A directory the upper holds may be one a session
//! deleted and made again (an opaque one), below which the decoy's files no
//! longer show; that mark is not read here, so where the upper holds
//! `/etc/apt` its files are read both with the decoy's and on their own, and
//! either way that turns the setting on warns. A link among apt's files, or
//! on the way to them, resolves in the session through the overlay, which
//! NAILS does not follow, so it leaves the session's setting unknown.
//!
//! Every read is a lookup, a listing or a read of a file; nothing is
//! written.

use super::{ADMIN_UNIT_DIR, loggers, masked, unit_linked};
use crate::Filesystem;
use crate::next_step::{NextStep, sudo_line};
use nails_base::packages::apt_conf::{self, PartName, Statement};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

mod helper;
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
    /// Off: set off or cleared by a file.
    Off,
    /// Off, as no file sets or clears it: what a running helper read when it
    /// started still counts.
    Unset,
    /// apt refuses a file, at this place, for this reason.
    Refused { at: String, reason: String },
    /// NAILS cannot tell, for this reason.
    Unknown(String),
}

/// One file apt reads: as the system it belongs to names it (the file
/// `APT_CONFIG` names as that), where it lies (nothing for the decoy, or the
/// session's overlay), and where it is read from.
struct Source {
    shown: String,
    place: String,
    read: PathBuf,
}

/// How the texts name the file `APT_CONFIG` names, before its path.
const BY_APT_CONFIG: &str = "the helper's APT_CONFIG file ";

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

/// What the texts say of a `#x-apt-configure-index`, after its place: apt
/// loads an index of its options there, which NAILS does not read, and stops
/// reading the file when it cannot.
const LOADS_AN_INDEX: &str = " has apt load an index of its options, which NAILS does not follow, \
                              and apt stops reading the file there when it cannot";

/// The setting after apt reads `sources` in order.
fn evaluate<F: Filesystem>(fs: &F, sources: &[Source]) -> Setting {
    let mut value: Option<(Vec<u8>, String)> = None;
    // Whether a file sets or clears the setting.
    let mut touched = false;
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
            // apt stops reading the file at the directive when it cannot load
            // the index, and then never gets to the line it would refuse.
            Err(apt_conf::SyntaxError {
                index_before: Some(line),
                ..
            }) => {
                return Setting::Unknown(format!("{}{LOADS_AN_INDEX}", at(line)));
            }
            Err(e) if e.by_apt => {
                return Setting::Refused {
                    at: at(e.line),
                    reason: e.reason.to_string(),
                };
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
                        touched = true;
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
                        touched = true;
                    }
                }
                Statement::Include { line } => {
                    return Setting::Unknown(format!(
                        "{} has apt read another file, which NAILS does not follow",
                        at(line)
                    ));
                }
                Statement::ConfigureIndex { line } => {
                    return Setting::Unknown(format!("{}{LOADS_AN_INDEX}", at(line)));
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
        _ if touched => Setting::Off,
        _ => Setting::Unset,
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
    /// The file the helper's `APT_CONFIG` names, relative to the root, which
    /// apt reads first ([`apt_config_source`]).
    apt_config: Option<&'a Path>,
    /// The decoy root and, in the session's view, the upper, which the file
    /// `APT_CONFIG` names is read through.
    root: &'a Path,
    upper: Option<&'a Path>,
}

/// The file `APT_CONFIG` names, at `rel` below the root, as `view` reads it:
/// on the decoy where its links lead, as the decoy's helper reads it; in the
/// session the upper's copy where the upper holds one, else the decoy's,
/// which is read too where the upper deletes it, as that can only make the
/// setting read on where it is off. A link on the way to it, in either
/// layer, resolves in the session through the overlay, which NAILS does not
/// follow. A file NAILS cannot read leaves the setting unknown: apt would
/// skip it, but it cannot tell what was there when the helper read it.
fn apt_config_source<F: Filesystem>(fs: &F, view: View<'_>, rel: &Path) -> Result<Source, String> {
    let shown = format!("{BY_APT_CONFIG}/{}", rel.display());
    let named = shown.clone();
    if rel
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{named} has a `..` in its path, which NAILS does not follow"
        ));
    }
    if let (true, Some(upper)) = (view.session, view.upper) {
        let mut prefix = PathBuf::new();
        for component in rel.components() {
            prefix.push(component);
            let at = prefix.display();
            no_link(fs, &view.root.join(&prefix), &format!("/{at} on the decoy"))?;
            no_link(fs, &upper.join(&prefix), &format!("/{at}{IN_UPPER}"))?;
        }
        let in_upper = upper.join(rel);
        if regular(fs, &in_upper, &format!("{named}{IN_UPPER}"))? {
            return Ok(Source {
                shown,
                place: IN_UPPER.to_string(),
                read: in_upper,
            });
        }
    }
    let read = view.root.join(rel);
    if !regular(fs, &read, &named)? {
        return Err(format!("{named} is no file NAILS can read"));
    }
    Ok(Source {
        shown,
        place: String::new(),
        read,
    })
}

/// The files apt reads in a view, in its order, and on the decoy the links
/// among them that lead to no file now.
struct Sources {
    found: Vec<Source>,
    /// apt skips such a link at the signal, as what is no file, but the
    /// decoy's helper may have read what it led to when it started, so its
    /// change is looked for as a file's is ([`helper::changed_since_start`]).
    /// The session's view refuses every link ([`no_link`]) and has none.
    unread_links: Vec<PathBuf>,
}

/// Whether `path`, which leads to no file apt reads, is a link on the decoy
/// ([`Sources::unread_links`]); an error says NAILS cannot tell.
fn unread_link<F: Filesystem>(fs: &F, path: &Path, shown: &str) -> Result<bool, String> {
    fs.is_symlink(path)
        .map_err(|e| format!("{shown} cannot be looked up ({e})"))
}

/// The files apt reads in `view`, in its order.
fn sources<F: Filesystem>(fs: &F, view: View<'_>) -> Result<Sources, String> {
    let mut found = Vec::new();
    let mut unread_links = Vec::new();
    if let Some(rel) = view.apt_config {
        found.push(apt_config_source(fs, view, rel)?);
    }
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
            if !view.session && unread_link(fs, &read, &shown)? {
                unread_links.push(read);
            }
            continue;
        }
        if by_name == PartName::ByLocale {
            return Err(format!(
                "{shown}{place} has a name with a byte beyond ASCII, which apt reads or skips by \
                 the system's locale"
            ));
        }
        found.push(Source {
            shown,
            place: place.to_string(),
            read,
        });
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
            found.push(Source {
                shown,
                place: place.to_string(),
                read,
            });
        } else if !view.session && unread_link(fs, &read, &shown)? {
            unread_links.push(read);
        }
    }
    Ok(Sources {
        found,
        unread_links,
    })
}

/// The setting on the decoy under `root`, read first from the file at
/// `apt_config` where the helper's `APT_CONFIG` names one, and what of apt's
/// files the decoy's helper may have read when it started: the files the
/// setting is read from, and the links among them that lead to no file now.
fn decoy_setting<F: Filesystem>(
    fs: &F,
    root: &Path,
    apt_config: Option<&Path>,
) -> (Setting, Vec<PathBuf>) {
    let view = View {
        parts_lower: Some(root),
        parts_upper: None,
        main_lower: Some(root),
        main_upper: None,
        session: false,
        apt_config,
        root,
        upper: None,
    };
    match sources(fs, view) {
        Ok(Sources {
            found,
            unread_links,
        }) => (
            evaluate(fs, &found),
            found
                .into_iter()
                .map(|source| source.read)
                .chain(unread_links)
                .collect(),
        ),
        Err(why) => (Setting::Unknown(why), Vec::new()),
    }
}

/// The setting the session's copy of the helper reads: the decoy's files
/// under `root` with `upper` on top, each way a directory of the upper may
/// be read, the file at `apt_config` first where the decoy's helper runs with
/// an `APT_CONFIG` naming one. That is the environment the decoy's files gave
/// the running helper when it started, which the session's copy gets as well
/// unless a drop-in of the unit or PID 1's environment changed since, which
/// is not followed.
fn session_setting<F: Filesystem>(
    fs: &F,
    root: &Path,
    upper: &Path,
    apt_config: Option<&Path>,
) -> Setting {
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
        // The session has no /etc/apt: apt reads only the file APT_CONFIG
        // names, where it is named.
        let view = View {
            parts_lower: None,
            parts_upper: None,
            main_lower: None,
            main_upper: None,
            session: true,
            apt_config,
            root,
            upper: Some(upper),
        };
        return match sources(fs, view) {
            Ok(sources) => evaluate(fs, &sources.found),
            Err(why) => Setting::Unknown(why),
        };
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
        apt_config,
        root,
        upper: Some(upper),
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
            apt_config,
            root,
            upper: Some(upper),
        });
    }
    let (mut unknown, mut refused) = (None, None);
    for view in views {
        match sources(fs, view).map(|sources| evaluate(fs, &sources.found)) {
            Ok(Setting::On(at)) => return Setting::On(at),
            Ok(Setting::Unknown(why)) | Err(why) => {
                unknown.get_or_insert(why);
            }
            Ok(refusal @ Setting::Refused { .. }) => {
                refused.get_or_insert(refusal);
            }
            Ok(Setting::Off | Setting::Unset) => {}
        }
    }
    unknown
        .map(Setting::Unknown)
        .or(refused)
        .unwrap_or(Setting::Off)
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
/// included. An error says NAILS cannot tell, a link or a mask it could not
/// look up included.
fn session_starts_helper<F: Filesystem>(
    fs: &F,
    root: &Path,
    upper: Option<&Path>,
) -> Result<Option<SessionStart>, String> {
    let decoy_enables = unit_linked(fs, root, UNIT)?;
    let session_enables = match upper {
        Some(upper) if !decoy_enables => unit_linked(fs, upper, UNIT)?,
        _ => false,
    };
    if !decoy_enables && !session_enables {
        return Ok(None);
    }
    let decoy_masks = masked(fs, root, UNIT)?;
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
                masked(fs, upper, UNIT)?
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

/// What the decoy's helper does at the switch, as far as NAILS can tell:
/// what the warning under `--allow-persistent-decoy` says of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AtTheSwitch {
    /// The setting is on: it installs the pending updates on the decoy disk.
    Installs,
    /// apt refuses a file: it installs nothing, but writes two ERROR lines.
    ErrorLines,
    /// NAILS cannot tell.
    Unknown,
    /// NAILS cannot tell without root: only root may read the helper's
    /// environment, which a run as root reads.
    NeedsRoot,
}

/// What the warning under `--allow-persistent-decoy` adds for the ERROR
/// lines of a file apt refuses, whose finding says that the helper installs
/// nothing.
pub(super) const ERROR_LINES: &str = "At the switch unattended-upgrades' shutdown helper writes \
                                      those two ERROR lines on the decoy disk, unless it started \
                                      with the file already refused.";

/// A refusal of the check's.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Blocker {
    /// What it found.
    pub(super) finding: String,
    /// What to do about it.
    pub(super) fix: String,
    /// What the helper does at the switch: only for the setting found on does
    /// the warning under `--allow-persistent-decoy` say that the install
    /// runs.
    pub(super) at_the_switch: AtTheSwitch,
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
        // The session's copy starts with the file refused, so it logs to
        // its standard error, the session's journal, for its whole run, and
        // at the way back its read fails again, which leaves it no install.
        Setting::Refused { at, reason } => Some(format!(
            "{how}, and apt refuses {at} ({reason}): {copy} installs nothing when the \
             session ends with deactivate as long as apt refuses that file, and logs apt's \
             errors to the session's journal, but a session that fixes the file has it read \
             {SETTING} again then (set it to false, or end the session with `{}`, which sends no \
             shutdown signal)",
            sudo_line(NextStep::DeactivatePoweroff),
            copy = if start.is_ok() {
                "that copy"
            } else {
                "if the session starts it, that copy"
            },
        )),
        Setting::Off | Setting::Unset => None,
    }
}

/// The refusal of a setting NAILS cannot tell, for this reason.
fn cannot_tell(why: &str) -> Blocker {
    Blocker {
        finding: format!(
            "NAILS cannot tell whether unattended-upgrades installs the pending updates at \
             activation, as its shutdown helper does when {SETTING} is on, so it counts as on: \
             {why}"
        ),
        fix: format!(
            "fix or remove what keeps NAILS from reading the setting ({why}), and set `{SETTING} \
             \"false\";` on the decoy if anything turns it on"
        ),
        at_the_switch: AtTheSwitch::Unknown,
    }
}

/// The refusal of a running helper whose environment NAILS may not read
/// without root, for this reason: a run as root can tell.
fn cannot_tell_without_root(why: &str) -> Blocker {
    Blocker {
        fix: format!(
            "run the check as root (`{}`), which can read the environment of unattended-upgrades' \
             shutdown helper",
            sudo_line(NextStep::Check)
        ),
        at_the_switch: AtTheSwitch::NeedsRoot,
        ..cannot_tell(why)
    }
}

/// The refusal of the decoy under `root` whose helper runs, its processes
/// `pids` reading first the file at `apt_config`, `None` when there is none:
/// `start` says how a session's own copy of the helper starts, for what the
/// way back does.
fn decoy_blocker<F: Filesystem>(
    fs: &F,
    root: &Path,
    pids: &[u32],
    apt_config: Option<&Path>,
    start: Option<&Result<SessionStart, String>>,
) -> Option<Blocker> {
    let (decoy, read) = decoy_setting(fs, root, apt_config);
    match decoy {
        Setting::On(at) => Some(Blocker {
            finding: format!(
                "unattended-upgrades installs the pending updates when the system shuts down \
                 ({SETTING} is on in {at}), and its shutdown helper takes a switch for a \
                 shutdown: at activation it runs that install on the decoy disk and logs that run \
                 there{}",
                way_back(start)
            ),
            fix: turn_off(&at),
            at_the_switch: AtTheSwitch::Installs,
        }),
        Setting::Refused { at, reason } => Some(Blocker {
            finding: format!(
                "apt refuses {at} ({reason}): at activation unattended-upgrades' shutdown helper \
                 reads apt's configuration again, finds that file refused and installs nothing, \
                 but writes two ERROR lines (`Apt returned an error thus shutdown mode is \
                 disabled` and apt's message) to \
                 /var/log/unattended-upgrades/unattended-upgrades-shutdown.log on the decoy disk, \
                 or to the journal if it started with the file already refused"
            ),
            fix: format!("fix what apt refuses at {at} ({reason}), or remove that file"),
            at_the_switch: AtTheSwitch::ErrorLines,
        }),
        Setting::Unknown(why) => Some(cannot_tell(&why)),
        Setting::Unset => {
            // No file sets it now, but the helper keeps what it read when it
            // started.
            let changed = helper::started(fs, root, pids).and_then(|started| {
                helper::changed_since_start(fs, root, &read, apt_config, started)
            });
            match changed {
                Ok(None) => None,
                Ok(Some(what)) => Some(Blocker {
                    finding: format!(
                        "NAILS cannot tell whether unattended-upgrades installs the pending \
                         updates at activation, as its shutdown helper does when {SETTING} is \
                         on, so it counts as on: no file of apt's configuration sets it now, but \
                         {what}, and the helper keeps what it read when it started, the value \
                         of a line deleted since included, until it restarts"
                    ),
                    fix: format!(
                        "set `{SETTING} \"false\";` on the decoy in a file of /{PARTS}, which \
                         the helper reads again at the switch, where a false wins over what it \
                         holds, or reboot the decoy so that the helper reads apt's \
                         configuration afresh"
                    ),
                    at_the_switch: AtTheSwitch::Unknown,
                }),
                Err(why) => Some(cannot_tell(&why)),
            }
        }
        Setting::Off => None,
    }
}

/// unattended-upgrades' install at shutdown on the decoy under `root`, with
/// the root overlay's upper at `upper` (`None`: the decoy alone). What
/// decides the refusal, whether the decoy's helper runs and what it reads, is
/// read through `blocking`; what only warns, python3-gi's module and how the
/// hidden session's own copy starts and what it reads, through `warning`. So
/// where a check reads them through views of their own, a lookup the
/// automount guard does not make refuses only where it decides the refusal.
pub(super) fn finding<F: Filesystem>(
    blocking: &F,
    warning: &F,
    root: &Path,
    upper: Option<&Path>,
) -> Finding {
    let polling = polling::warning(warning, root);
    let running = match loggers::unit_active(blocking, root, UNIT) {
        loggers::Activity::Active => true,
        loggers::Activity::Inactive => false,
        // A helper NAILS cannot tell runs may install at activation.
        loggers::Activity::Untold(why) => {
            return Finding {
                blocker: Some(cannot_tell(&why)),
                warning: None,
                polling,
            };
        }
    };
    let start = match session_starts_helper(warning, root, upper) {
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
    // What the decoy's running helper reads first.
    let mut apt_config = None;
    if running {
        let blocker = match helper::running(blocking, root) {
            Err(doubt) if doubt.needs_root => Some(cannot_tell_without_root(&doubt.why)),
            Err(doubt) => Some(cannot_tell(&doubt.why)),
            Ok((pids, read_first)) => {
                apt_config = read_first;
                decoy_blocker(blocking, root, &pids, apt_config.as_deref(), start.as_ref())
            }
        };
        if blocker.is_some() {
            return Finding {
                blocker,
                warning: None,
                polling,
            };
        }
    }
    let Some(start) = start else {
        return Finding {
            polling,
            ..Finding::default()
        };
    };
    let session = match upper {
        Some(upper) => session_setting(warning, root, upper, apt_config.as_deref()),
        None => decoy_setting(warning, root, apt_config.as_deref()).0,
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

#[cfg(test)]
#[path = "install_on_shutdown/lookup_tests.rs"]
mod lookup_tests;
