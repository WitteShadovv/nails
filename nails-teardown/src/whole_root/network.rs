// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's network identity, recorded at entry and put back on the way
//! back.
//!
//! The overlay shares the host's network identity between the decoy and the
//! hidden session: the same links, hardware addresses, hostname and the
//! per-link state the service manager keeps in `/run`. A session that changes
//! any of these leaves a tell on the decoy when the way back does nothing about
//! it:
//!
//! - a virtual link the session brought up (a WireGuard tunnel, a dummy or a
//!   bridge) is still there when the decoy's NetworkManager starts, which adopts
//!   it as connected externally and writes a profile for it, with a timestamp,
//!   to the decoy disk;
//! - a device whose hardware address the session randomised keeps that address
//!   (a device holds its current address when the decoy's profile sets none);
//! - on a decoy without `/etc/hostname` the hostname the session set stays,
//!   because nothing on the decoy resets it after a soft-reboot;
//! - the hidden service manager's per-link records below `/run/NetworkManager`
//!   and `/run/systemd/resolve` lie deeper than the `/run` scrub reaches.
//!
//! So [the record](NetworkRecord), taken in the decoy before the first switch,
//! holds the decoy's links (index, name, whether the kernel made it, and the
//! hardware address), whether the decoy has an `/etc/hostname`, the decoy's
//! live hostname, and a copy of the two runtime-state directories. The way
//! back, once every hidden unit has stopped and before it switches back,
//! [restores](restore) it: delete the virtual links that were not there at
//! entry, give each device its recorded address again, set the hostname back on
//! a decoy that would not reset it itself, and make the two runtime directories
//! what entry left them.
//!
//! Deleting a link and setting an address go through `ip` (iproute2), the one
//! tool that speaks to the kernel for both and is present wherever networking
//! is; the hostname and the runtime directories are plain files. Reading the
//! current links and writing nothing but files makes all of it testable without
//! a privileged network.
//!
//! Many drivers cannot change the address of a device that is up (USB Ethernet
//! adapters such as `ax88179_178a` and `asix`, Wi-Fi drivers without powered
//! address change): the kernel refuses the change with `EBUSY` while the link
//! runs. So an address that did not take is set again with the link down, as
//! NetworkManager does, and the link is brought back up; a link that was down
//! stays down. Every address is read back afterwards, and [`restore`] returns
//! the devices that still have another one, which the transition puts in its
//! outcome instead of dropping the failure.
//!
//! The way back never touches any of this when no record was taken (an older
//! session, or one whose recording failed): [`restore`] with no record is a
//! no-op, never a blanket wipe, so it is safe on a path that runs for every
//! switch.

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// The record's file name inside the runtime directory (neutral, no product
/// name, like the other runtime files).
pub const RECORD_NAME: &str = "net-identity";

/// The default location of the kernel's live hostname, read and written as a
/// plain file (a write sets the hostname as `sethostname(2)` would).
pub const PROC_HOSTNAME: &str = "/proc/sys/kernel/hostname";

/// The default location the kernel lists the host's links under.
pub const SYS_CLASS_NET: &str = "/sys/class/net";

/// The runtime-state directories, relative to a `/run` root, that the service
/// manager keeps per-link state in and the way back makes what entry left them.
pub const RUN_DIRS: &[&str] = &["NetworkManager/devices", "systemd/resolve/netif"];

/// How deep below a runtime-state directory the copy reaches.
const RUN_MAX_DEPTH: usize = 4;

/// The most runtime-state content the copy holds; a larger state is not copied.
const RUN_MAX_BYTES: usize = 1 << 20;

/// How long a single `ip` call may take.
const IP_BUDGET: Duration = Duration::from_secs(3);

/// A link's administrative up flag in its sysfs `flags` (`IFF_UP` in
/// `<linux/if.h>`), set by `ip link set up` and cleared by `ip link set down`.
const IFF_UP: u32 = 0x1;

/// One of the decoy's links as it was at entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// The kernel's interface index.
    pub index: u32,
    /// The interface name.
    pub name: String,
    /// Whether the kernel made the link (no backing hardware device), so the
    /// way back may delete it with `ip link delete`.
    pub virtual_link: bool,
    /// The hardware address, lower-case and colon-separated as the kernel
    /// prints it, or `None` when the link has none.
    pub mac: Option<String>,
}

/// One entry in a runtime-state directory copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum RunKind {
    Dir,
    File(Vec<u8>),
    Link(PathBuf),
}

/// A copied runtime-state entry by its path relative to the `/run` root; a
/// parent sorts before its children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunEntry {
    path: PathBuf,
    kind: RunKind,
}

/// The decoy's network identity, taken in the decoy before the first switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRecord {
    /// The decoy's links.
    links: Vec<Link>,
    /// The decoy's live hostname, without a trailing newline.
    hostname: Vec<u8>,
    /// Whether the decoy has an `/etc/hostname`. A decoy that has one resets
    /// its hostname itself after the way back; a decoy without one does not,
    /// so only then does the way back set it.
    etc_hostname_present: bool,
    /// A copy of the runtime-state directories.
    run: Vec<RunEntry>,
}

impl NetworkRecord {
    /// Take the record from `sys_class_net` (the links), `proc_hostname` (the
    /// live hostname), `etc_hostname` (whether it exists) and `run` (the
    /// runtime-state directories). Reading only; nothing is changed.
    pub fn capture(
        sys_class_net: &Path,
        proc_hostname: &Path,
        etc_hostname: &Path,
        run: &Path,
    ) -> Self {
        NetworkRecord {
            links: observe_links(sys_class_net),
            hostname: read_hostname(proc_hostname),
            etc_hostname_present: std::fs::symlink_metadata(etc_hostname).is_ok(),
            run: snapshot_run(run),
        }
    }

    /// The record as bytes for the runtime directory.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parse [`NetworkRecord::encode`] output; `None` for anything malformed or
    /// for a runtime path that is not below a runtime-state directory.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let record: NetworkRecord = serde_json::from_slice(bytes).ok()?;
        record
            .run
            .iter()
            .all(|entry| is_run_path(&entry.path))
            .then_some(record)
    }
}

/// What the way back does to the live network to put the decoy's identity back.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorePlan {
    /// Virtual links to delete (there now, not there at entry).
    pub delete: Vec<String>,
    /// Devices whose hardware address the way back sets back, by name.
    pub set_mac: Vec<(String, String)>,
    /// The hostname to set back, or `None` when the decoy resets it itself or
    /// it never changed.
    pub hostname: Option<Vec<u8>>,
}

/// The decoy's links the way back `current` observed differently.
///
/// A link that is there now, is virtual, and was not there at entry is deleted:
/// a hardware device is left alone even if it appeared (a hot-plugged adapter is
/// the decoy's, not the session's). A link that was there at entry and still is
/// gets its recorded address back when the current one differs. The hostname is
/// set back only on a decoy without `/etc/hostname`, which would not reset it
/// itself, and only when it actually changed.
pub fn plan(record: &NetworkRecord, current: &[Link], current_hostname: &[u8]) -> RestorePlan {
    let at_entry = |name: &str| record.links.iter().any(|link| link.name == name);
    let delete = current
        .iter()
        .filter(|link| link.virtual_link && !at_entry(&link.name))
        .map(|link| link.name.clone())
        .collect();

    let mut set_mac = Vec::new();
    for link in &record.links {
        let Some(mac) = &link.mac else { continue };
        let still_here = current.iter().find(|now| now.name == link.name);
        if let Some(now) = still_here
            && now.mac.as_deref() != Some(mac.as_str())
        {
            set_mac.push((link.name.clone(), mac.clone()));
        }
    }

    let hostname = (!record.etc_hostname_present
        && !record.hostname.is_empty()
        && current_hostname != record.hostname.as_slice())
    .then(|| record.hostname.clone());

    RestorePlan {
        delete,
        set_mac,
        hostname,
    }
}

/// Read the links the kernel lists under `sys_class_net`.
pub fn observe_links(sys_class_net: &Path) -> Vec<Link> {
    let Ok(entries) = std::fs::read_dir(sys_class_net) else {
        return Vec::new();
    };
    let mut links: Vec<Link> = entries
        .flatten()
        .filter_map(|entry| read_link(sys_class_net, &entry.file_name()))
        .collect();
    links.sort_by(|a, b| a.name.cmp(&b.name));
    links
}

/// Read one link's facts, or `None` when the name has no interface index (so it
/// is not a link).
fn read_link(sys_class_net: &Path, name: &OsStr) -> Option<Link> {
    let dir = sys_class_net.join(name);
    let index: u32 = read_trimmed(&dir.join("ifindex"))?.parse().ok()?;
    // A hardware device has a `device` link to its backing bus device; a link
    // the kernel made (lo, a tunnel, a bridge) has none.
    let virtual_link = std::fs::symlink_metadata(dir.join("device")).is_err();
    let mac = read_trimmed(&dir.join("address")).filter(|mac| !mac.is_empty());
    Some(Link {
        index,
        name: name.to_string_lossy().into_owned(),
        virtual_link,
        mac,
    })
}

/// Read a one-line sysfs or proc file, trimmed of trailing whitespace.
fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_end().to_string())
}

/// Read the live hostname, without a trailing newline.
pub fn read_hostname(proc_hostname: &Path) -> Vec<u8> {
    let mut bytes = std::fs::read(proc_hostname).unwrap_or_default();
    while bytes.last().is_some_and(|b| b.is_ascii_whitespace()) {
        bytes.pop();
    }
    bytes
}

/// Put the decoy's network identity back, the way [the record](NetworkRecord)
/// holds it. `record_bytes` is the recorded copy, read from the runtime
/// directory before the scrub removed it; with none, or one that does not
/// parse, nothing is done.
///
/// Returns the devices that still have another hardware address than the one
/// recorded at entry: the way back could not set it back, and the decoy will
/// start with the session's address on them.
///
/// Call it once every hidden unit has stopped: the hidden service manager must
/// not be running, or it would adopt a link again or rewrite the runtime state.
#[must_use]
pub fn restore(
    run: &Path,
    sys_class_net: &Path,
    proc_hostname: &Path,
    record_bytes: Option<&[u8]>,
) -> Vec<String> {
    let Some(record) = record_bytes.and_then(NetworkRecord::decode) else {
        return Vec::new();
    };
    let current = observe_links(sys_class_net);
    let current_hostname = read_hostname(proc_hostname);
    let plan = plan(&record, &current, &current_hostname);
    let kept = apply_links(&plan, sys_class_net);
    if let Some(hostname) = &plan.hostname {
        let _ = write_hostname(proc_hostname, hostname);
    }
    restore_run(run, &record);
    kept
}

/// Run the link part of a plan with `ip`: delete the links the session made
/// and set each recorded address back, reading the links' state from
/// `sys_class_net`. Finds `ip` only when there is work. A failed delete is
/// silent, as the way back is best effort throughout; the devices whose address
/// is still not the recorded one are returned. Separated so a real-kernel test
/// can drive it against a network namespace.
#[must_use]
pub fn apply_links(plan: &RestorePlan, sys_class_net: &Path) -> Vec<String> {
    if plan.delete.is_empty() && plan.set_mac.is_empty() {
        return Vec::new();
    }
    let ip = crate::whole_root::tools::find(None, "ip");
    apply_links_with(ip.as_deref(), plan, sys_class_net)
}

/// [`apply_links`] with the `ip` at `ip`, or none. Without one nothing is
/// changed, and every device the plan sets an address on is returned.
fn apply_links_with(ip: Option<&Path>, plan: &RestorePlan, sys_class_net: &Path) -> Vec<String> {
    if let Some(ip) = ip {
        for name in &plan.delete {
            let args = ["link", "delete", "dev", name.as_str()];
            let _ = crate::whole_root::tools::run(ip, &args, IP_BUDGET);
        }
        for (name, mac) in &plan.set_mac {
            set_address(ip, sys_class_net, name, mac);
        }
    }
    plan.set_mac
        .iter()
        .filter(|(name, mac)| keeps_other_address(sys_class_net, name, mac))
        .map(|(name, _)| name.clone())
        .collect()
}

/// Give link `name` the address `mac`. The address is read back rather than
/// the exit status trusted: when it did not take on a link that is up, the
/// driver may refuse to change a running device (`EBUSY`), so the link is taken
/// down for the change and brought up again, as NetworkManager does. A link
/// that is down is never brought up.
fn set_address(ip: &Path, sys_class_net: &Path, name: &str, mac: &str) {
    let set = ["link", "set", "dev", name, "address", mac];
    let _ = crate::whole_root::tools::run(ip, &set, IP_BUDGET);
    if !keeps_other_address(sys_class_net, name, mac) || !is_up(sys_class_net, name) {
        return;
    }
    let down = ["link", "set", "dev", name, "down"];
    let _ = crate::whole_root::tools::run(ip, &down, IP_BUDGET);
    let _ = crate::whole_root::tools::run(ip, &set, IP_BUDGET);
    let up = ["link", "set", "dev", name, "up"];
    let _ = crate::whole_root::tools::run(ip, &up, IP_BUDGET);
}

/// Whether link `name` is there with another hardware address than `mac`. A
/// link that is gone has none left to keep.
fn keeps_other_address(sys_class_net: &Path, name: &str, mac: &str) -> bool {
    read_trimmed(&sys_class_net.join(name).join("address")).is_some_and(|now| now != mac)
}

/// Whether link `name` is up: [`IFF_UP`] in its `flags`, which the kernel
/// prints in hex (`0x1003`).
fn is_up(sys_class_net: &Path, name: &str) -> bool {
    read_trimmed(&sys_class_net.join(name).join("flags"))
        .and_then(|flags| {
            let hex = flags.strip_prefix("0x").unwrap_or(&flags);
            u32::from_str_radix(hex, 16).ok()
        })
        .is_some_and(|flags| flags & IFF_UP != 0)
}

/// Write `hostname` to the live-hostname file, which sets it.
fn write_hostname(proc_hostname: &Path, hostname: &[u8]) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(proc_hostname)?
        .write_all(hostname)
}

/// Copy the runtime-state directories of `run` below [`RUN_DIRS`], bounded in
/// depth and size. Sockets, FIFOs and devices are never copied.
fn snapshot_run(run: &Path) -> Vec<RunEntry> {
    let mut entries = Vec::new();
    let mut bytes = 0;
    for dir in RUN_DIRS {
        if collect_run(run, Path::new(dir), 0, &mut entries, &mut bytes).is_err() {
            return Vec::new();
        }
    }
    entries
}

fn collect_run(
    run: &Path,
    rel: &Path,
    depth: usize,
    entries: &mut Vec<RunEntry>,
    bytes: &mut usize,
) -> std::io::Result<()> {
    let path = run.join(rel);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let kind = meta.file_type();
    if kind.is_dir() {
        entries.push(RunEntry {
            path: rel.to_path_buf(),
            kind: RunKind::Dir,
        });
        if depth < RUN_MAX_DEPTH {
            for child in std::fs::read_dir(&path)? {
                collect_run(
                    run,
                    &rel.join(child?.file_name()),
                    depth + 1,
                    entries,
                    bytes,
                )?;
            }
        }
    } else if kind.is_file() {
        let content = std::fs::read(&path)?;
        *bytes += content.len();
        if *bytes > RUN_MAX_BYTES {
            return Err(std::io::Error::other(
                "the runtime state is too large to copy",
            ));
        }
        entries.push(RunEntry {
            path: rel.to_path_buf(),
            kind: RunKind::File(content),
        });
    } else if kind.is_symlink() {
        entries.push(RunEntry {
            path: rel.to_path_buf(),
            kind: RunKind::Link(std::fs::read_link(&path)?),
        });
    }
    Ok(())
}

/// Make the runtime-state directories of `run` what the record holds: clear
/// each one and recreate exactly what entry copied. A directory absent at entry
/// (the decoy did not run that service) is left absent.
fn restore_run(run: &Path, record: &NetworkRecord) {
    for dir in RUN_DIRS {
        let _ = std::fs::remove_dir_all(run.join(dir));
    }
    for entry in &record.run {
        let path = run.join(&entry.path);
        let _ = match &entry.kind {
            RunKind::Dir => std::fs::create_dir_all(&path),
            RunKind::File(content) => create_parent(&path).and_then(|()| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&path)
                    .and_then(|mut file| file.write_all(content))
            }),
            RunKind::Link(target) => {
                create_parent(&path).and_then(|()| std::os::unix::fs::symlink(target, &path))
            }
        };
    }
}

fn create_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => std::fs::create_dir_all(parent),
        None => Ok(()),
    }
}

/// Whether `path` is a plain relative path at or below one of [`RUN_DIRS`].
fn is_run_path(path: &Path) -> bool {
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return false;
    }
    RUN_DIRS.iter().any(|dir| path.starts_with(dir))
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
