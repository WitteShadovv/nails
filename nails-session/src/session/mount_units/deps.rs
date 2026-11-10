// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What PID 1 starts with one unit ([`edges`]): the units a start job for it
//! gives start jobs to in the same transaction, whether they are active
//! already or not, and those it starts later because of it.
//!
//! - the units its files name in `Requires=`, `BindsTo=`, `Wants=`,
//!   `Upholds=`, `OnFailure=` and `OnSuccess=`, and those linked in its
//!   `.requires`, `.wants` and `.upholds` directories, those of its
//!   template, its name's prefixes and its type included (a template linked
//!   for an instance names the instance of it), specifiers resolved
//!   ([`resolve_specifiers`]);
//! - the mounts systemd has it require or want for a path: those of the path
//!   and of each of its parents ([`mounts_for`]), for its
//!   `RequiresMountsFor=` and `WantsMountsFor=`; for a mount or automount its
//!   parent directories; for a mount the source its `What=` names, unless it
//!   is a network filesystem that is no bind or loop mount; for a swap its
//!   file; for a service, socket, mount or swap its working directory (one
//!   that may be missing too, the user's home `~` aside), root directory or
//!   image, the directories it keeps (`StateDirectory=` and the like) and its
//!   private `/tmp`; for a socket the paths it listens on, for a path unit
//!   the paths it watches, for a persistent timer its stamp directory;
//! - the device a mount or swap waits for, the `network-online.target` a
//!   network filesystem's mount wants, a service's, socket's, mount's or
//!   swap's slice (`system.slice`, or its template's, unless it names one)
//!   and a slice's parent, the sockets a service takes (`Sockets=`,
//!   `dbus.socket` for a D-Bus service, its log namespace's), and the unit a
//!   socket, path unit, timer or automount starts;
//! - the names it shares: the unit an alias link of its name names, and the
//!   names whose alias links lead to it, which have directories of links and
//!   drop-ins of their own ([`UnitDirs::alias_of`]);
//! - for a unit an fstab line makes, the line's source and device, its
//!   checkers, and what it names with `x-systemd.requires=`,
//!   `x-systemd.wants=`, `x-systemd.requires-mounts-for=` and
//!   `x-systemd.wants-mounts-for=`.
//!
//! A device or a slice loads from its drop-ins when it has no file of its
//! own; a unit the decoy masks starts nothing. [`boot_targets`] tells the
//! targets the hidden boot starts whatever a skip pulls in.

use super::pulls::MAX_UNITS;
use super::unit_dirs::{Load, UnitDirs, instance_of, template_of};
use super::unit_file::{UnitFile, resolve_specifiers};
use super::{acts_on_device, unit_path};
use crate::session::fstab::{FstabEntry, checkers, escape_path, is_bind_option, mount_unit};
use crate::session::policy::Units;
use std::path::Path;

/// How many alias links in a row NAILS follows from one name.
const MAX_ALIAS_HOPS: usize = 8;

/// The target the hidden boot starts.
const DEFAULT_TARGET: &str = "default.target";

/// The target a network filesystem's mount wants.
const NETWORK_ONLINE: &str = "network-online.target";

/// The filesystem types systemd counts as network filesystems
/// (`fstype_is_network()`), a `fuse.` prefix taken off first.
const NETWORK_TYPES: &[&str] = &[
    "afs",
    "ceph",
    "cifs",
    "davfs",
    "gfs",
    "gfs2",
    "glusterfs",
    "lustre",
    "ncp",
    "ncpfs",
    "nfs",
    "nfs4",
    "ocfs2",
    "orangefs",
    "pvfs2",
    "smb3",
    "smbfs",
    "sshfs",
];

/// A unit that PID 1 starts with, or because of, the unit that pulls it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// The unit pulled in.
    pub unit: String,
    /// Whether the unit that pulls it in requires it, and so does not start
    /// without it, rather than only wanting it.
    pub required: bool,
    /// Whether PID 1 gives it a start job in the same transaction (a
    /// requirement, a want, a name of the same unit), rather than starting it
    /// later (a trigger, `OnFailure=`) or NAILS taking it in for caution (a
    /// link that may name the same unit).
    pub start: bool,
    /// How it is pulled in, for a warning.
    pub how: &'static str,
}

/// The types of unit systemd knows.
const UNIT_TYPES: &[&str] = &[
    "service",
    "socket",
    "target",
    "device",
    "mount",
    "automount",
    "swap",
    "timer",
    "path",
    "slice",
    "scope",
];

/// Whether `name` can name a unit: a name of a type systemd knows, with no
/// `/` or NUL in it, that does not begin with a dot and is not longer than
/// systemd lets one be. systemd refuses more names, never fewer.
fn is_unit_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(stem, kind)| !stem.is_empty() && UNIT_TYPES.contains(&kind))
        && !name.starts_with('.')
        && !name.contains(['/', '\0'])
        && name.len() <= 255
}

/// The kind of the unit `name`: what follows its last dot.
pub(super) fn kind(name: &str) -> &str {
    name.rsplit_once('.').map_or("", |(_, kind)| kind)
}

/// The name `name` without its type (`srv-data` for `srv-data.mount`).
fn stem(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

/// Whether `name` is a mount, swap or automount unit.
pub(super) fn is_storage_unit(name: &str) -> bool {
    matches!(kind(name), "mount" | "swap" | "automount")
}

/// The mount units of `path` and of each of its parents, the root's left
/// out (the root overlay is always there): what a `RequiresMountsFor=` of
/// `path` requires, as far as such units exist.
pub fn mounts_for(path: &Path) -> Vec<String> {
    path.ancestors()
        .filter(|dir| *dir != Path::new("/"))
        .map(mount_unit)
        .collect()
}

/// The fstab lines among `fstab` that make the unit `name`.
pub(super) fn lines_of<'a>(fstab: &'a [FstabEntry], name: &str) -> Vec<&'a FstabEntry> {
    fstab
        .iter()
        .filter(|entry| {
            let units = Units::of(entry);
            units.unit.as_deref() == Some(name) || units.automount.as_deref() == Some(name)
        })
        .collect()
}

/// Whether a mount of the type `vfstype` with `options` is a bind mount: an
/// option named `bind` or `rbind`, with a value too (`bind=x`), as systemd's
/// `fstab_test_option()` matches an option by its name before `=`
/// ([`is_bind_option`]).
fn is_bind(vfstype: &str, options: &[&str]) -> bool {
    matches!(vfstype, "bind" | "rbind") || options.iter().any(|option| is_bind_option(option))
}

/// Whether systemd counts a mount of the type `vfstype` with `options` as
/// one of a network filesystem (`_netdev` makes one).
fn is_network(vfstype: &str, options: &[&str]) -> bool {
    NETWORK_TYPES.contains(&vfstype.strip_prefix("fuse.").unwrap_or(vfstype))
        || options.contains(&"_netdev")
}

/// Whether systemd has a mount of the type `vfstype` with `options` require
/// the mounts for its source: a bind or loop mount always, and any mount of
/// another filesystem than a network one.
fn needs_its_source(vfstype: &str, options: &[&str]) -> bool {
    is_bind(vfstype, options) || options.contains(&"loop") || !is_network(vfstype, options)
}

/// The edge of a network filesystem's mount to the network it waits for:
/// systemd has it want `network-online.target`.
fn network_edge(edges: &mut Vec<Edge>, how: &'static str) {
    push(edges, NETWORK_ONLINE.to_string(), false, true, how);
}

/// Whether `path` names a device node, as systemd's `is_device_path()`
/// tells one.
fn is_device_path(path: &str) -> bool {
    path.starts_with("/dev/") || path.starts_with("/sys/")
}

/// The device unit of the device node `path`.
fn device_unit(path: &str) -> String {
    format!("{}.device", escape_path(Path::new(path)))
}

/// The slice systemd puts the unit `name` in when it names none: an
/// instance in the slice of its template (`system-systemd\x2dfsck.slice`),
/// any other unit in `system.slice`.
fn default_slice(name: &str) -> String {
    match template_of(name) {
        Some((template, _)) => format!(
            "system-{}.slice",
            escape_path(Path::new(stem(&template).trim_end_matches('@')))
        ),
        None => "system.slice".to_string(),
    }
}

/// The parent of the slice `name`, as its name says (`-.slice` for one
/// without a dash); `None` for the root slice.
fn parent_slice(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".slice")?;
    if stem == "-" {
        return None;
    }
    Some(match stem.rfind('-') {
        Some(dash) => format!("{}.slice", &stem[..dash]),
        None => "-.slice".to_string(),
    })
}

/// Add an edge to `unit`.
fn push(edges: &mut Vec<Edge>, unit: String, required: bool, start: bool, how: &'static str) {
    edges.push(Edge {
        unit,
        required,
        start,
        how,
    });
}

/// `value`, a setting of the unit `name`, its specifiers resolved; `Err`
/// with why when NAILS does not resolve one.
fn resolved(value: &str, name: &str) -> Result<String, String> {
    resolve_specifiers(value, name)
        .ok_or_else(|| format!("{name} names {value} by a specifier NAILS does not resolve"))
}

/// The edges the words of `words`, a setting of the unit `name` that lists
/// units, add, specifiers resolved.
fn unit_words(
    edges: &mut Vec<Edge>,
    words: &str,
    name: &str,
    required: bool,
    start: bool,
    how: &'static str,
) -> Result<(), String> {
    for word in words.split_ascii_whitespace() {
        let unit = resolved(word, name)?;
        push(edges, unit, required, start, how);
    }
    Ok(())
}

/// The edges to the mounts for the absolute path `path` ([`mounts_for`]),
/// read as it is: a relative one adds none.
fn path_edges(edges: &mut Vec<Edge>, path: &str, required: bool, how: &'static str) {
    if path.starts_with('/') {
        for unit in mounts_for(Path::new(path)) {
            push(edges, unit, required, true, how);
        }
    }
}

/// The edges the paths among `words`, a setting of the unit `name`, add: the
/// mounts for each, specifiers resolved. `prefix` goes before a relative
/// path, as for a service's state directory, and what follows a `:` (a link
/// to make beside it) is left out; without a prefix a relative path adds
/// none.
fn path_words(
    edges: &mut Vec<Edge>,
    words: &str,
    name: &str,
    prefix: Option<&str>,
    required: bool,
    how: &'static str,
) -> Result<(), String> {
    for word in words.split_ascii_whitespace() {
        let word = resolved(word, name)?;
        let path = match prefix {
            Some(prefix) => {
                let dir = word.split(':').next().unwrap_or(&word);
                format!("{prefix}/{}", dir.trim_start_matches('/'))
            }
            None => word,
        };
        path_edges(edges, &path, required, how);
    }
    Ok(())
}

/// The edges of the settings of a service, socket, mount or swap `name`
/// that has `section` for its own: what it runs in and keeps (see the module
/// docs), and its slice.
fn exec_edges(
    edges: &mut Vec<Edge>,
    unit: &UnitFile,
    section: &str,
    name: &str,
) -> Result<(), String> {
    for key in ["WorkingDirectory", "RootDirectory", "RootImage"] {
        for value in unit.values(section, key) {
            // `-` lets the directory be missing, and from systemd 256 the
            // unit still wants the mounts for it. `~` is the user's home,
            // for which systemd adds none.
            let value = value.strip_prefix('-').unwrap_or(value);
            if !value.starts_with('~') {
                path_edges(
                    edges,
                    &resolved(value, name)?,
                    false,
                    "a directory it runs in",
                );
            }
        }
    }
    for (key, prefix) in [
        ("StateDirectory", "/var/lib"),
        ("CacheDirectory", "/var/cache"),
        ("LogsDirectory", "/var/log"),
        ("ConfigurationDirectory", "/etc"),
        ("RuntimeDirectory", "/run"),
    ] {
        for value in unit.values(section, key) {
            path_words(
                edges,
                value,
                name,
                Some(prefix),
                true,
                "a directory it keeps",
            )?;
        }
    }
    if unit
        .values(section, "PrivateTmp")
        .any(|value| !matches!(value, "" | "no" | "false" | "0" | "off"))
    {
        path_edges(edges, "/tmp", false, "its private /tmp");
        path_edges(edges, "/var/tmp", false, "its private /tmp");
    }
    for value in unit.values(section, "LogNamespace") {
        if !value.is_empty() {
            let namespace = resolved(value, name)?;
            for socket in ["systemd-journald", "systemd-journald-varlink"] {
                let unit = format!("{socket}@{namespace}.socket");
                push(edges, unit, true, true, "its log namespace");
            }
        }
    }
    for value in unit.values(section, "Slice") {
        if !value.is_empty() {
            push(edges, resolved(value, name)?, true, true, "its slice");
        }
    }
    if unit.last(section, "Slice").is_none() {
        push(edges, default_slice(name), true, true, "its slice");
    }
    Ok(())
}

/// The unit a socket, path unit or timer `name` starts: the one its
/// `setting` in `section` names, or the service of its own name (for a
/// socket that accepts each connection, an instance of its template).
fn triggered(unit: &UnitFile, section: &str, setting: &str, name: &str) -> Result<String, String> {
    if let Some(value) = unit
        .values(section, setting)
        .filter(|v| !v.is_empty())
        .last()
    {
        return resolved(value, name);
    }
    let accepts = section == "Socket"
        && unit
            .values("Socket", "Accept")
            .last()
            .is_some_and(|value| matches!(value, "yes" | "true" | "1" | "on"));
    let own = stem(name);
    Ok(if accepts {
        let prefix = own.split_once('@').map_or(own, |(prefix, _)| prefix);
        format!("{prefix}@.service")
    } else {
        format!("{own}.service")
    })
}

/// The edges the files of the unit `name` give it (see the module docs).
fn file_edges(edges: &mut Vec<Edge>, unit: &UnitFile, name: &str) -> Result<(), String> {
    for (key, required, start, how) in [
        ("Requires", true, true, "Requires="),
        ("BindsTo", true, true, "BindsTo="),
        ("Wants", false, true, "Wants="),
        ("Upholds", false, true, "Upholds="),
        ("OnFailure", false, false, "OnFailure="),
        ("OnSuccess", false, false, "OnSuccess="),
    ] {
        for value in unit.values("Unit", key) {
            unit_words(edges, value, name, required, start, how)?;
        }
    }
    for (key, required, how) in [
        ("RequiresMountsFor", true, "RequiresMountsFor="),
        ("WantsMountsFor", false, "WantsMountsFor="),
    ] {
        for value in unit.values("Unit", key) {
            path_words(edges, value, name, None, required, how)?;
        }
    }
    match kind(name) {
        "mount" => {
            exec_edges(edges, unit, "Mount", name)?;
            let vfstype = unit.last("Mount", "Type").unwrap_or("");
            let options = unit.last("Mount", "Options").unwrap_or("");
            let options: Vec<&str> = options.split(',').collect();
            if is_network(vfstype, &options) {
                network_edge(edges, "the network it mounts over");
            }
            if let Some(what) = unit.last("Mount", "What") {
                let what = resolved(what, name)?;
                if needs_its_source(vfstype, &options) {
                    path_edges(edges, &what, true, "the source it mounts");
                }
                if !is_bind(vfstype, &options)
                    && is_device_path(&what)
                    && !matches!(what.as_str(), "/dev/root" | "/dev/nfs")
                {
                    push(
                        edges,
                        device_unit(&what),
                        true,
                        true,
                        "the device it mounts",
                    );
                }
            }
        }
        "swap" => {
            exec_edges(edges, unit, "Swap", name)?;
            if let Some(what) = unit.last("Swap", "What") {
                let what = resolved(what, name)?;
                path_edges(edges, &what, true, "the file it swaps on");
                if is_device_path(&what) {
                    push(
                        edges,
                        device_unit(&what),
                        true,
                        true,
                        "the device it swaps on",
                    );
                }
            }
        }
        "service" => {
            exec_edges(edges, unit, "Service", name)?;
            for value in unit.values("Service", "Sockets") {
                unit_words(edges, value, name, false, true, "Sockets=")?;
            }
            let dbus = unit.last("Service", "Type") == Some("dbus")
                || unit.last("Service", "BusName").is_some();
            if dbus {
                push(
                    edges,
                    "dbus.socket".to_string(),
                    true,
                    true,
                    "its D-Bus name",
                );
            }
        }
        "socket" => {
            exec_edges(edges, unit, "Socket", name)?;
            for key in [
                "ListenStream",
                "ListenDatagram",
                "ListenSequentialPacket",
                "ListenFIFO",
                "ListenSpecial",
                "ListenUSBFunction",
            ] {
                for value in unit.values("Socket", key) {
                    let value = resolved(value, name)?;
                    path_edges(edges, &value, true, "a path it listens on");
                }
            }
            if let Some(device) = unit.last("Socket", "BindToDevice") {
                let device = format!(
                    "sys-subsystem-net-devices-{}.device",
                    escape_path(Path::new(device))
                );
                push(edges, device, true, true, "the device it binds to");
            }
            let service = triggered(unit, "Socket", "Service", name)?;
            push(edges, service, false, false, "the service it starts");
        }
        "path" => {
            for key in [
                "PathExists",
                "PathExistsGlob",
                "PathChanged",
                "PathModified",
                "DirectoryNotEmpty",
            ] {
                for value in unit.values("Path", key) {
                    let value = resolved(value, name)?;
                    path_edges(edges, &value, true, "a path it watches");
                }
            }
            let target = triggered(unit, "Path", "Unit", name)?;
            push(edges, target, false, false, "the unit it starts");
        }
        "timer" => {
            let persistent = unit
                .last("Timer", "Persistent")
                .is_some_and(|value| matches!(value, "yes" | "true" | "1" | "on"));
            if persistent {
                path_edges(
                    edges,
                    "/var/lib/systemd/timers",
                    true,
                    "its stamp directory",
                );
            }
            let target = triggered(unit, "Timer", "Unit", name)?;
            push(edges, target, false, false, "the unit it starts");
        }
        _ => {}
    }
    Ok(())
}

/// The edges the fstab line `entry`, which makes the unit `name`, gives it:
/// its source, its device, its checkers and the units and paths its
/// `x-systemd` options name. NAILS counts any specifier in those options
/// as one it cannot resolve.
fn line_edges(edges: &mut Vec<Edge>, entry: &FstabEntry, name: &str) -> Result<(), String> {
    let options: Vec<&str> = entry.options.iter().map(String::as_str).collect();
    let source = entry
        .device()
        .map_or_else(|| entry.spec.clone(), |device| device.display().to_string());
    if entry.is_swap() || needs_its_source(&entry.vfstype, &options) {
        path_edges(edges, &source, true, "the source its line mounts");
    }
    if !entry.is_swap() && is_network(&entry.vfstype, &options) {
        network_edge(edges, "the network its line mounts over");
    }
    let root_alias = !entry.is_swap() && matches!(source.as_str(), "/dev/root" | "/dev/nfs");
    if !is_bind(&entry.vfstype, &options) && !root_alias && is_device_path(&source) {
        push(
            edges,
            device_unit(&source),
            true,
            true,
            "the device its line mounts",
        );
    }
    for checker in checkers(entry) {
        push(edges, checker, true, true, "the checker of its line");
    }
    for option in &entry.options {
        let Some((key, value)) = option.split_once('=') else {
            continue;
        };
        if !matches!(
            key,
            "x-systemd.requires"
                | "x-systemd.wants"
                | "x-systemd.requires-mounts-for"
                | "x-systemd.wants-mounts-for"
        ) {
            continue;
        }
        if value.contains('%') {
            return Err(format!(
                "the fstab line of {name} names {value} with a specifier, which NAILS does not \
                 resolve"
            ));
        }
        match key {
            "x-systemd.requires" | "x-systemd.wants" => {
                let unit = if is_device_path(value) {
                    device_unit(value)
                } else if value.starts_with('/') {
                    mount_unit(Path::new(value))
                } else if is_unit_name(value) {
                    value.to_string()
                } else {
                    return Err(format!(
                        "the fstab line of {name} names {value}, which is no unit name"
                    ));
                };
                let (required, how) = if key == "x-systemd.requires" {
                    (true, "x-systemd.requires= on its fstab line")
                } else {
                    (false, "x-systemd.wants= on its fstab line")
                };
                push(edges, unit, required, true, how);
            }
            "x-systemd.requires-mounts-for" => {
                let how = "x-systemd.requires-mounts-for= on its fstab line";
                path_edges(edges, value, true, how);
            }
            _ => {
                let how = "x-systemd.wants-mounts-for= on its fstab line";
                path_edges(edges, value, false, how);
            }
        }
    }
    Ok(())
}

/// The names alias links lead to from a name, one after the other, each
/// with whether every link up to it is an alias for sure; `Err` when NAILS
/// cannot follow them to their end ([`alias_chain`]).
type AliasChain = Result<Vec<(String, bool)>, ()>;

/// What a walk reads, gathered once for all the skips of a session.
pub struct Graph<'a> {
    /// The unit directories the hidden systemd reads.
    pub(super) dirs: UnitDirs<'a>,
    /// The decided fstab lines.
    pub(super) fstab: &'a [FstabEntry],
    /// The units the session's decisions keep off or put in place.
    pub(super) covered: &'a [String],
    /// The targets the hidden boot starts anyway ([`boot_targets`]).
    pub(super) boot: Vec<String>,
    /// The names with directories of links or drop-ins of their own
    /// ([`UnitDirs::named_dirs`]), each with the names its alias links lead
    /// to and whether each is an alias for sure; `Err` for one whose links
    /// cannot be read.
    named: Vec<(String, AliasChain)>,
    /// Why the unit directories cannot be listed, if they cannot.
    unlisted: Option<String>,
}

impl<'a> Graph<'a> {
    /// The graph of the units in `dirs`, given `fstab`, the decided lines,
    /// and `covered`, the units the session's decisions keep off or put in
    /// place.
    pub fn new(dirs: UnitDirs<'a>, fstab: &'a [FstabEntry], covered: &'a [String]) -> Self {
        let (named, unlisted) = match dirs.named_dirs() {
            Ok(names) => (
                names
                    .into_iter()
                    .map(|name| {
                        let chain = alias_chain(dirs, &name);
                        (name, chain)
                    })
                    .collect(),
                None,
            ),
            Err(unlisted) => (
                Vec::new(),
                Some(format!(
                    "NAILS cannot list the unit directory {}: {}",
                    unlisted.dir.display(),
                    unlisted.error
                )),
            ),
        };
        let mut graph = Self {
            dirs,
            fstab,
            covered,
            boot: Vec::new(),
            named,
            unlisted,
        };
        graph.boot = boot_targets(&graph);
        graph
    }
}

/// The names the alias links from `name` lead to, one after the other, each
/// with whether every link up to it is an alias for sure
/// ([`UnitDirs::alias_of`]); `Err` when one cannot be read, or the links lead
/// on further than NAILS follows them.
fn alias_chain(dirs: UnitDirs<'_>, name: &str) -> AliasChain {
    let mut chain: Vec<(String, bool)> = Vec::new();
    let mut current = name.to_string();
    let mut sure = true;
    for _ in 0..MAX_ALIAS_HOPS {
        let Some((next, hop_sure)) = dirs.alias_of(&current)? else {
            return Ok(chain);
        };
        if next == name || chain.iter().any(|(seen, _)| *seen == next) {
            return Ok(chain);
        }
        sure &= hop_sure;
        chain.push((next.clone(), sure));
        current = next;
    }
    Err(())
}

/// The edges of the names `name` shares: the one its alias link names, and
/// those whose alias links lead to it.
fn alias_edges(graph: &Graph<'_>, edges: &mut Vec<Edge>, name: &str) -> Result<(), String> {
    let own = graph
        .dirs
        .alias_of(name)
        .map_err(|()| format!("a link of the name {name} cannot be read"))?;
    if let Some((alias, sure)) = own {
        push(edges, alias, true, sure, "a name it shares");
    }
    let template = template_of(name);
    for (other, chain) in &graph.named {
        if other == name || kind(other) != kind(name) {
            continue;
        }
        let chain = chain.as_ref().map_err(|()| {
            format!(
                "the alias links of {other} cannot be followed to their end, and they may name \
                 {name}"
            )
        })?;
        let found = chain.iter().find_map(|(to, sure)| {
            if to == name {
                return Some((other.clone(), *sure));
            }
            // An alias of a template names each instance of it.
            let (own, instance) = template.as_ref()?;
            if to != own {
                return None;
            }
            Some((instance_of(other, instance)?, *sure))
        });
        if let Some((alias, sure)) = found {
            push(edges, alias, true, sure, "a name it shares");
        }
    }
    Ok(())
}

/// The units PID 1 starts with the unit `name`, or because of it (see the
/// module docs), each once, the root's mount and `name` itself left out.
/// `Err` with the reason when NAILS cannot tell them all: a file of the unit
/// or a link that may name it cannot be read, one names a unit or path by a
/// specifier NAILS does not resolve, a directory of its links cannot be
/// listed, or the unit does not load where it would need to.
pub fn edges(graph: &Graph<'_>, name: &str) -> Result<Vec<Edge>, String> {
    if let Some(why) = &graph.unlisted {
        return Err(why.clone());
    }
    let dirs = graph.dirs;
    let mut edges: Vec<Edge> = Vec::new();
    let unit_kind = kind(name);
    if matches!(unit_kind, "mount" | "automount") {
        let suffix = if unit_kind == "mount" {
            ".mount"
        } else {
            ".automount"
        };
        if let Some(parent) = unit_path(name, suffix).as_deref().and_then(Path::parent) {
            for unit in mounts_for(parent) {
                push(
                    &mut edges,
                    unit,
                    true,
                    true,
                    "the mount of a parent directory",
                );
            }
        }
    }
    if let Some(parent) = parent_slice(name) {
        push(&mut edges, parent, true, true, "its parent slice");
    }
    let lines = lines_of(graph.fstab, name);
    let bare = matches!(unit_kind, "device" | "slice");
    let load = if bare {
        dirs.load_bare(name)
    } else {
        dirs.load(name)
    };
    match load {
        Load::Loaded { unit, .. } => file_edges(&mut edges, &unit, name)?,
        Load::Unreadable => return Err(format!("the unit files of {name} cannot be read")),
        // A masked unit starts nothing.
        Load::Masked => return Ok(Vec::new()),
        Load::Missing if bare || is_storage_unit(name) || !lines.is_empty() => {}
        // A checker comes with systemd and acts on its device alone.
        Load::Missing if acts_on_device(name) => {}
        Load::Missing => {
            return Err(format!(
                "{name} does not load here, and a generator of the hidden session may make it"
            ));
        }
    }
    if unit_kind == "automount" {
        let mount = format!("{}.mount", stem(name));
        push(&mut edges, mount, false, false, "the mount it starts");
    }
    for (link_kind, required, how) in [
        ("requires", true, "a link in its .requires directory"),
        ("wants", false, "a link in its .wants directory"),
        ("upholds", false, "a link in its .upholds directory"),
    ] {
        let links = dirs
            .links(name, link_kind)
            .map_err(|_| format!("a directory of the units {name} pulls in cannot be listed"))?;
        for link in links {
            // A template linked for an instance names the instance of it.
            let unit = if stem(&link).ends_with('@') {
                match template_of(name) {
                    Some((_, instance)) => instance_of(&link, instance),
                    None => None,
                }
            } else {
                Some(link)
            };
            if let Some(unit) = unit {
                push(&mut edges, unit, required, true, how);
            }
        }
    }
    alias_edges(graph, &mut edges, name)?;
    for entry in lines {
        line_edges(&mut edges, entry, name)?;
    }
    let mut unique: Vec<Edge> = Vec::new();
    for edge in edges {
        if edge.unit == name || edge.unit == "-.mount" || !is_unit_name(&edge.unit) {
            continue;
        }
        match unique.iter_mut().find(|seen| seen.unit == edge.unit) {
            Some(seen) => {
                if edge.required && !seen.required {
                    seen.how = edge.how;
                }
                seen.required |= edge.required;
                seen.start |= edge.start;
            }
            None => unique.push(edge),
        }
    }
    Ok(unique)
}

/// The targets the hidden boot starts whatever a skip pulls in:
/// `default.target` and every target it requires, binds to, wants or
/// upholds, by a setting, a link or a name it shares for sure, and those
/// targets' in turn, as far as NAILS can tell them. A target whose pulls
/// NAILS cannot tell adds none: the walk follows what it is not sure the
/// boot starts.
pub fn boot_targets(graph: &Graph<'_>) -> Vec<String> {
    let mut targets = vec![DEFAULT_TARGET.to_string()];
    let mut next = 0;
    while let Some(target) = targets.get(next).cloned() {
        next += 1;
        let Ok(pulled) = edges(graph, &target) else {
            continue;
        };
        for edge in pulled {
            if edge.start
                && kind(&edge.unit) == "target"
                && !targets.contains(&edge.unit)
                && targets.len() < MAX_UNITS
            {
                targets.push(edge.unit);
            }
        }
    }
    targets
}
