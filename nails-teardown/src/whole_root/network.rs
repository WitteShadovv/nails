// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's network state, recorded at entry and put back on the way back.
//!
//! The overlay shares the host's network state between the decoy and the
//! hidden session: the same links, hardware addresses and hostname, the same
//! routing policy, firewall tables and network settings, and the per-link
//! state the service manager keeps in `/run`. A soft-reboot carries all of it
//! across the switch, so a session that changes any of it leaves a tell on the
//! decoy when the way back does nothing about it:
//!
//! - a virtual link the session brought up (a WireGuard tunnel, a dummy or a
//!   bridge) is still there when the decoy's NetworkManager starts, which
//!   adopts it as connected externally and writes a profile for it, with a
//!   timestamp, to the decoy disk; so is a Wi-Fi interface the session added
//!   on one of the decoy's radios (a monitor or access point interface);
//! - a device whose hardware address the session randomised keeps that address
//!   (a device holds its current address when the decoy's profile sets none);
//! - the hostname the session set stays: after a soft-reboot PID 1 sets the
//!   hostname again only from a valid `/etc/hostname` (or the kernel command
//!   line), and keeps the current one when the file is missing, empty, or holds
//!   only comments or an invalid name;
//! - the routing policy, firewall tables and settings of
//!   [`network_policy`](crate::whole_root::network_policy);
//! - the per-link records of [`network_run`](crate::whole_root::network_run),
//!   which lie deeper than the `/run` scrub reaches.
//!
//! So [the record](NetworkRecord), taken in the decoy before the first switch,
//! holds the decoy's links (index, name, whether the kernel made it, the
//! hardware address and, for a Wi-Fi interface, its radio), the decoy's live
//! hostname, its routing policy, tables and settings, and a copy of the
//! runtime-state directories. The way back, once every hidden unit has stopped
//! and before it switches back, [restores](restore) it.
//!
//! A link is the decoy's only when a recorded link has its index, which stays
//! with a link for as long as it exists. The kernel gives a link made again a
//! new index, so a link the session made under the name of one the decoy had
//! (which the decoy's own stop took down for the switch) is the session's,
//! while a link of the decoy's that the session only renamed is still the
//! decoy's, and keeps the session's name. The way back deletes every virtual
//! link that is not the decoy's, and every Wi-Fi interface that is not the
//! decoy's on a radio the decoy had (an adapter plugged in during the session
//! is the decoy's, and left alone); gives each of the decoy's devices its
//! recorded address again; sets the hostname back wherever it differs, which
//! is harmless where PID 1 then sets it again from a valid `/etc/hostname`;
//! puts the routing policy, tables and settings back; and makes the runtime
//! directories what entry left them. It makes nothing again that the session
//! deleted, so a radio whose interface software in the session replaced with
//! one of its own (iwd does by default when it starts) has none after the way
//! back.
//!
//! Deleting a link and setting an address go through `ip` (iproute2), the one
//! tool that speaks to the kernel for both and is present wherever networking
//! is; a Wi-Fi interface goes through `iw`, since the kernel deletes one only
//! through its wireless configuration interface. The hostname and the runtime
//! directories are plain files. Reading the current links and writing nothing
//! but files makes all of it testable without a privileged network.
//!
//! Many drivers cannot change the address of a device that is up (USB Ethernet
//! adapters such as `ax88179_178a` and `asix`, Wi-Fi drivers without powered
//! address change): the kernel refuses the change with `EBUSY` while the link
//! runs. So an address that did not take is set again with the link down, as
//! NetworkManager does, and the link is brought back up; a link that was down
//! stays down. Every address is read back afterwards.
//!
//! Entry records each part on its own, and a part it cannot read (the list of
//! links, the copy of the runtime state, a tool's list of rules or tables) is
//! recorded as unknown. The way back leaves an unknown part as the session
//! leaves it: an empty list in its place would read as a decoy without links,
//! rules or runtime state, and the way back would delete the decoy's. It never
//! touches anything when no record was taken (an older session, or one whose
//! recording failed): [`restore`] with no record is a no-op, never a blanket
//! wipe, so it is safe on a path that runs for every switch. [`restore`]
//! returns what it could not put back and the parts it left alone ([`Kept`]),
//! which the transition puts in its outcome, since nothing on the way back may
//! log.

use crate::whole_root::network_policy::Policy;
use crate::whole_root::{network_run, tools};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The record's file name inside the runtime directory (neutral, no product
/// name, like the other runtime files).
pub const RECORD_NAME: &str = "net-identity";

/// The default location of the kernel's live hostname, read and written as a
/// plain file (a write sets the hostname as `sethostname(2)` would).
pub const PROC_HOSTNAME: &str = "/proc/sys/kernel/hostname";

/// The default location the kernel lists the host's links under.
pub const SYS_CLASS_NET: &str = "/sys/class/net";

/// The default root of the kernel's settings, of which the record holds the
/// network ones.
pub const PROC_SYS: &str = "/proc/sys";

/// How long a single `ip` or `iw` call may take.
const IP_BUDGET: Duration = Duration::from_secs(3);

/// A link's administrative up flag in its sysfs `flags` (`IFF_UP` in
/// `<linux/if.h>`), set by `ip link set up` and cleared by `ip link set down`.
const IFF_UP: u32 = 0x1;

/// Where the network state is read and written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Places {
    /// The `/run` root the per-link runtime state sits under.
    pub run: PathBuf,
    /// Where the kernel lists the links ([`SYS_CLASS_NET`]).
    pub sys_class_net: PathBuf,
    /// The kernel's live hostname ([`PROC_HOSTNAME`]).
    pub proc_hostname: PathBuf,
    /// The kernel's settings ([`PROC_SYS`]).
    pub proc_sys: PathBuf,
}

impl Places {
    /// The real system's places, with the runtime state below `run`.
    pub fn system(run: &Path) -> Self {
        Places {
            run: run.to_path_buf(),
            sys_class_net: PathBuf::from(SYS_CLASS_NET),
            proc_hostname: PathBuf::from(PROC_HOSTNAME),
            proc_sys: PathBuf::from(PROC_SYS),
        }
    }
}

/// The tools the record and the way back run, by absolute path. A tool that is
/// not installed is `None`: the part that needs it is left alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetTools {
    /// `ip` (iproute2): links, addresses and policy-routing rules.
    pub ip: Option<PathBuf>,
    /// `iw`: Wi-Fi interfaces.
    pub iw: Option<PathBuf>,
    /// `nft` (nftables): firewall tables.
    pub nft: Option<PathBuf>,
}

impl NetTools {
    /// The tools in the system directories ([`tools::find`]).
    pub fn find() -> Self {
        NetTools {
            ip: tools::find(None, "ip"),
            iw: tools::find(None, "iw"),
            nft: tools::find(None, "nft"),
        }
    }
}

/// A link as the kernel lists it.
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
    /// The Wi-Fi radio the link is an interface of (`phy0`), or `None` for a
    /// link that is not a Wi-Fi interface.
    pub phy: Option<String>,
}

/// The decoy's network state, taken in the decoy before the first switch. A
/// part that could not be read is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRecord {
    /// The decoy's links.
    links: Option<Vec<Link>>,
    /// The decoy's live hostname, without a trailing newline; empty when it
    /// could not be read.
    hostname: Vec<u8>,
    /// The decoy's routing policy, firewall tables and network settings.
    policy: Policy,
    /// A copy of the runtime-state directories.
    run: Option<Vec<network_run::RunEntry>>,
}

impl NetworkRecord {
    /// Take the record at `places` with `tools`. Reading only; nothing is
    /// changed.
    pub fn capture(places: &Places, tools: &NetTools) -> Self {
        NetworkRecord {
            links: observe_links(&places.sys_class_net),
            hostname: read_hostname(&places.proc_hostname),
            policy: Policy::capture(tools.ip.as_deref(), tools.nft.as_deref(), &places.proc_sys),
            run: network_run::snapshot(&places.run),
        }
    }

    /// The record as bytes for the runtime directory.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parse [`NetworkRecord::encode`] output; `None` for anything malformed,
    /// for a runtime path that is not below a runtime-state directory and for
    /// a policy the way back could not act on.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let record: NetworkRecord = serde_json::from_slice(bytes).ok()?;
        let valid =
            record.run.as_deref().is_none_or(network_run::is_valid) && record.policy.is_valid();
        valid.then_some(record)
    }
}

/// What the way back does to the live links and hostname.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorePlan {
    /// Virtual links to delete with `ip`: there now, not the decoy's.
    pub delete: Vec<String>,
    /// Wi-Fi interfaces to delete with `iw`: there now, not the decoy's, on a
    /// radio the decoy had.
    pub delete_wireless: Vec<String>,
    /// The decoy's devices whose hardware address the way back sets back, by
    /// name.
    pub set_mac: Vec<(String, String)>,
    /// The hostname to set back, or `None` when it never changed.
    pub hostname: Option<Vec<u8>>,
}

/// What the way back left as the session left it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Kept {
    /// The decoy's devices that still have another hardware address than the
    /// one recorded at entry.
    pub addresses: Vec<String>,
    /// The session's links that are still there.
    pub links: Vec<String>,
    /// The session's policy-routing rules that are still there.
    pub rules: Vec<String>,
    /// The session's firewall tables that are still there.
    pub tables: Vec<String>,
    /// The network settings that still differ from the decoy's.
    pub settings: Vec<String>,
    /// The parts entry could not record or the way back could not read, which
    /// it left alone.
    pub unknown: Vec<&'static str>,
}

/// What the way back does to the links `current` and the hostname
/// `current_hostname`. See the module docs.
///
/// A link is the decoy's when a recorded link has its index, whatever it is
/// called now: it gets its recorded address back when the current one
/// differs. Another link is deleted when it is a Wi-Fi interface on a radio
/// the decoy had, or virtual; a hardware device that appeared is the decoy's
/// (a hot-plugged adapter) and left alone. Without the decoy's links no link
/// is deleted or changed. The hostname is set back whenever it differs and was
/// read at entry.
pub fn plan(record: &NetworkRecord, current: &[Link], current_hostname: &[u8]) -> RestorePlan {
    let mut plan = RestorePlan {
        hostname: (!record.hostname.is_empty() && current_hostname != record.hostname.as_slice())
            .then(|| record.hostname.clone()),
        ..RestorePlan::default()
    };
    let Some(then) = record.links.as_deref() else {
        return plan;
    };
    let decoys = |now: &Link| then.iter().find(|was| was.index == now.index);
    let decoy_radio = |phy: &str| then.iter().any(|was| was.phy.as_deref() == Some(phy));
    for link in current {
        match decoys(link) {
            Some(was) => {
                if let Some(mac) = &was.mac
                    && link.mac.as_deref() != Some(mac.as_str())
                {
                    plan.set_mac.push((link.name.clone(), mac.clone()));
                }
            }
            None if link.phy.as_deref().is_some_and(decoy_radio) => {
                plan.delete_wireless.push(link.name.clone());
            }
            None if link.virtual_link => plan.delete.push(link.name.clone()),
            None => {}
        }
    }
    plan
}

/// Read the links the kernel lists under `sys_class_net`; `None` when the list
/// or one of its links cannot be read.
pub fn observe_links(sys_class_net: &Path) -> Option<Vec<Link>> {
    let mut links = Vec::new();
    for entry in std::fs::read_dir(sys_class_net).ok()? {
        if let Some(link) = read_link(sys_class_net, &entry.ok()?.file_name()).ok()? {
            links.push(link);
        }
    }
    links.sort_by(|a, b| a.name.cmp(&b.name));
    Some(links)
}

/// Read one link's facts: `None` when the name is not a link (a file such as
/// `bonding_masters`, or a directory without an interface index) or the link
/// went away while it was read.
fn read_link(sys_class_net: &Path, name: &OsStr) -> std::io::Result<Option<Link>> {
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let dir = sys_class_net.join(name);
    match std::fs::metadata(&dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Ok(None),
        Err(e) if gone(&e) => return Ok(None),
        Err(e) => return Err(e),
    }
    let index = match std::fs::read_to_string(dir.join("ifindex")) {
        Ok(text) => text
            .trim()
            .parse()
            .map_err(|_| std::io::Error::other("an interface index that is no number"))?,
        Err(e) if gone(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    // A hardware device has a `device` link to its backing bus device; a link
    // the kernel made (lo, a tunnel, a bridge) has none. A Wi-Fi interface
    // has a `phy80211` link to its radio as well.
    let virtual_link = std::fs::symlink_metadata(dir.join("device")).is_err();
    let mac = read_trimmed(&dir.join("address")).filter(|mac| !mac.is_empty());
    let phy = std::fs::read_link(dir.join("phy80211"))
        .ok()
        .and_then(|radio| radio.file_name().map(|n| n.to_string_lossy().into_owned()));
    Ok(Some(Link {
        index,
        name: name.to_string_lossy().into_owned(),
        virtual_link,
        mac,
        phy,
    }))
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

/// Put the decoy's network state back at `places` with the tools installed,
/// the way [the record](NetworkRecord) holds it. `record_bytes` is the
/// recorded copy, read from the runtime directory before the scrub removed it;
/// with none, or one that does not parse, nothing is done.
///
/// Returns what is still as the session left it ([`Kept`]): the decoy's
/// devices whose address could not be set back, the session's links, rules
/// and tables that could not be deleted, the settings that could not be
/// written back, and the parts left alone because they could not be read.
///
/// Call it once every hidden unit has stopped: the hidden service manager must
/// not be running, or it would adopt a link again or rewrite the runtime state.
#[must_use]
pub fn restore(places: &Places, record_bytes: Option<&[u8]>) -> Kept {
    restore_with(places, &NetTools::find(), record_bytes)
}

/// [`restore`] with `tools`.
#[must_use]
pub fn restore_with(places: &Places, tools: &NetTools, record_bytes: Option<&[u8]>) -> Kept {
    let Some(record) = record_bytes.and_then(NetworkRecord::decode) else {
        return Kept::default();
    };
    let current = observe_links(&places.sys_class_net);
    let current_hostname = read_hostname(&places.proc_hostname);
    let plan = plan(
        &record,
        current.as_deref().unwrap_or_default(),
        &current_hostname,
    );
    let mut kept = apply_links_with(
        tools.ip.as_deref(),
        tools.iw.as_deref(),
        &plan,
        &places.sys_class_net,
    );
    if record.links.is_none() || current.is_none() {
        kept.unknown.push("links");
    }
    if let Some(hostname) = &plan.hostname {
        let _ = write_hostname(&places.proc_hostname, hostname);
    }
    record.policy.restore(
        tools.ip.as_deref(),
        tools.nft.as_deref(),
        &places.proc_sys,
        &mut kept,
    );
    match &record.run {
        Some(entries) => network_run::restore(&places.run, entries),
        None => kept.unknown.push("runtime state"),
    }
    kept
}

/// Run the link part of a plan: delete the Wi-Fi interfaces with `iw` and the
/// virtual links with `ip`, and set each recorded address back with `ip`,
/// reading the links' state from `sys_class_net`. Finds the tools only when
/// there is work. A failed call is silent, as the way back is best effort
/// throughout; the links still there and the devices whose address is still
/// not the recorded one are returned. Separated so a real-kernel test can
/// drive it against a network namespace.
#[must_use]
pub fn apply_links(plan: &RestorePlan, sys_class_net: &Path) -> Kept {
    if plan.delete.is_empty() && plan.delete_wireless.is_empty() && plan.set_mac.is_empty() {
        return Kept::default();
    }
    let ip = tools::find(None, "ip");
    let iw = tools::find(None, "iw");
    apply_links_with(ip.as_deref(), iw.as_deref(), plan, sys_class_net)
}

/// [`apply_links`] with the `ip` and `iw` at those paths, or none. A tool
/// that is missing changes nothing, and what it would have changed is
/// returned.
fn apply_links_with(
    ip: Option<&Path>,
    iw: Option<&Path>,
    plan: &RestorePlan,
    sys_class_net: &Path,
) -> Kept {
    if let Some(iw) = iw {
        for name in &plan.delete_wireless {
            let _ = tools::run(iw, &["dev", name.as_str(), "del"], IP_BUDGET);
        }
    }
    if let Some(ip) = ip {
        for name in &plan.delete {
            let args = ["link", "delete", "dev", name.as_str()];
            let _ = tools::run(ip, &args, IP_BUDGET);
        }
        for (name, mac) in &plan.set_mac {
            set_address(ip, sys_class_net, name, mac);
        }
    }
    Kept {
        links: plan
            .delete
            .iter()
            .chain(&plan.delete_wireless)
            .filter(|name| std::fs::symlink_metadata(sys_class_net.join(name)).is_ok())
            .cloned()
            .collect(),
        addresses: plan
            .set_mac
            .iter()
            .filter(|(name, mac)| keeps_other_address(sys_class_net, name, mac))
            .map(|(name, _)| name.clone())
            .collect(),
        ..Kept::default()
    }
}

/// Give link `name` the address `mac`. The address is read back rather than
/// the exit status trusted: when it did not take on a link that is up, the
/// driver may refuse to change a running device (`EBUSY`), so the link is taken
/// down for the change and brought up again, as NetworkManager does. A link
/// that is down is never brought up.
fn set_address(ip: &Path, sys_class_net: &Path, name: &str, mac: &str) {
    let set = ["link", "set", "dev", name, "address", mac];
    let _ = tools::run(ip, &set, IP_BUDGET);
    if !keeps_other_address(sys_class_net, name, mac) || !is_up(sys_class_net, name) {
        return;
    }
    let down = ["link", "set", "dev", name, "down"];
    let _ = tools::run(ip, &down, IP_BUDGET);
    let _ = tools::run(ip, &set, IP_BUDGET);
    let up = ["link", "set", "dev", name, "up"];
    let _ = tools::run(ip, &up, IP_BUDGET);
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

#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
