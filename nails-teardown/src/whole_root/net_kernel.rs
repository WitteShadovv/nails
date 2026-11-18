// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the network record and the way back ask of the kernel.
//!
//! Entry lists the decoy's policy-routing rules and nftables tables
//! ([`network_policy`](crate::whole_root::network_policy)), and the way back
//! deletes what the session added, sets the hardware addresses back and
//! deletes the session's links and Wi-Fi interfaces
//! ([`network`](crate::whole_root::network)). [`Netlink`] asks the running
//! kernel for all of it over netlink ([`crate::netlink`]), so no program
//! starts: entry runs on the decoy, where a program would read its file, its
//! libraries and its data files on the decoy disk. It asks nf_tables only
//! where nf_tables is in the kernel and nl80211 only where cfg80211 is, since
//! asking either otherwise makes the kernel load it, and the decoy's modprobe
//! reads its settings and the module's file to do so. A test gives a fake
//! kernel in its place.

use crate::netlink::{filter, route, wireless};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use crate::netlink::route::Rule;

/// An address family of the policy-routing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// Both, in the order the record keeps them.
    pub const ALL: [Self; 2] = [Self::V4, Self::V6];

    /// What its rules are called where they are unknown or left.
    pub fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4 rules",
            Family::V6 => "IPv6 rules",
        }
    }

    /// The family's name in a rule's description.
    pub fn name(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }

    /// The address family number netlink gives it.
    fn number(self) -> u8 {
        match self {
            Family::V4 => route::AF_INET,
            Family::V6 => route::AF_INET6,
        }
    }

    /// Whether `rule` is one of this family's.
    pub fn holds(self, rule: &Rule) -> bool {
        rule.family() == self.number()
    }
}

/// One nftables table: its family (as `nft` names it), its name, and the
/// handle the kernel gave it, which a table made again under the same name
/// does not share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    /// Its family: `ip`, `ip6`, `inet`, `arp`, `bridge` or `netdev`.
    pub family: String,
    /// Its name.
    pub name: String,
    /// Its handle.
    pub handle: u64,
}

/// The kernel's network state as the record and the way back read and change
/// it. A change reports nothing: the caller reads the state back.
pub trait NetKernel: std::fmt::Debug + Send + Sync {
    /// The policy-routing rules of `family`, `None` when they cannot be
    /// listed.
    fn rules(&self, family: Family) -> Option<Vec<Rule>>;
    /// Delete `rule`, as it was listed.
    fn delete_rule(&self, rule: &Rule);
    /// The nftables tables, none where nf_tables is not in the kernel, `None`
    /// when they cannot be listed or it cannot be told whether nf_tables is.
    fn tables(&self) -> Option<Vec<Table>>;
    /// Delete `table`, by its handle.
    fn delete_table(&self, table: &Table);
    /// Delete the link with interface index `index`.
    fn delete_link(&self, index: u32);
    /// Give the link with interface index `index` the hardware address `mac`.
    fn set_address(&self, index: u32, mac: &[u8]);
    /// Bring the link with interface index `index` up, or take it down.
    fn set_up(&self, index: u32, up: bool);
    /// Delete the Wi-Fi interface with interface index `index`.
    fn delete_wireless(&self, index: u32);
}

/// The default directory of the kernel's modules (`/sys/module`).
pub const SYS_MODULE: &str = "/sys/module";
/// The default list of the kernel's symbols (`/proc/kallsyms`).
pub const KALLSYMS: &str = "/proc/kallsyms";

/// The running kernel, over netlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Netlink {
    /// Where the kernel lists its modules ([`SYS_MODULE`]).
    pub sys_module: PathBuf,
    /// Where it lists its symbols ([`KALLSYMS`]).
    pub kallsyms: PathBuf,
}

impl Netlink {
    /// The running kernel, at its usual places.
    pub fn system() -> Self {
        Netlink {
            sys_module: PathBuf::from(SYS_MODULE),
            kallsyms: PathBuf::from(KALLSYMS),
        }
    }

    /// Whether nf_tables is in the kernel ([`filter::presence`]).
    fn nf_tables(&self) -> filter::Presence {
        filter::presence(&self.sys_module, &self.kallsyms)
    }
}

impl NetKernel for Netlink {
    fn rules(&self, family: Family) -> Option<Vec<Rule>> {
        route::rules(family.number()).ok()
    }

    fn delete_rule(&self, rule: &Rule) {
        let _ = route::delete_rule(rule);
    }

    fn tables(&self) -> Option<Vec<Table>> {
        match self.nf_tables() {
            filter::Presence::Absent => Some(Vec::new()),
            filter::Presence::Unknown => None,
            filter::Presence::Present => filter::tables()
                .ok()?
                .into_iter()
                .map(|listed| {
                    Some(Table {
                        family: filter::family_name(listed.family)?.to_string(),
                        name: listed.name,
                        handle: listed.handle,
                    })
                })
                .collect(),
        }
    }

    fn delete_table(&self, table: &Table) {
        if self.nf_tables() != filter::Presence::Present {
            return;
        }
        if let Some(family) = filter::family_number(&table.family) {
            let _ = filter::delete_table(family, table.handle);
        }
    }

    fn delete_link(&self, index: u32) {
        let _ = route::delete_link(index);
    }

    fn set_address(&self, index: u32, mac: &[u8]) {
        let _ = route::set_link_address(index, mac);
    }

    fn set_up(&self, index: u32, up: bool) {
        let _ = route::set_link_up(index, up);
    }

    fn delete_wireless(&self, index: u32) {
        let _ = wireless::delete_interface(&self.sys_module, index);
    }
}
