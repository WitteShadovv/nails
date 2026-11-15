// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's routing policy, firewall tables and network settings, recorded
//! at entry and put back on the way back.
//!
//! Software in the hidden session changes more of the kernel's network state
//! than its links. A WireGuard full tunnel (wg-quick, NetworkManager or a VPN
//! app) adds policy-routing rules and an nftables table; a VPN app that blocks
//! traffic outside its tunnel keeps a table of its own, which Mullvad leaves
//! loaded when it is stopped while connected; a container runtime or libvirt
//! adds firewall tables and turns forwarding on; a VPN app sets `arp_ignore`
//! and `src_valid_mark` for every device. None of it goes with the session's
//! links, a soft-reboot carries all of it into the decoy, and nothing on the
//! decoy resets it: anyone with a shell lists the rules with `ip rule` and
//! reads the settings below `/proc/sys/net`, root lists the tables, whose
//! names often name the provider, and a blocking table left loaded keeps the
//! decoy offline.
//!
//! So [the record](Policy) holds the decoy's rules of both address families,
//! each as the kernel lists it ([`Rule`]), its nftables tables with the handle
//! the kernel gave each (a table made again under the same name gets a new
//! handle, so it does not pass for the decoy's), and its network settings for
//! all devices and for new ones: `net.ipv4.ip_forward` and every key of
//! `net.ipv4.conf.all`, `net.ipv4.conf.default`, `net.ipv6.conf.all` and
//! `net.ipv6.conf.default` that every user can read and root can write. The
//! rules and tables are asked of the kernel itself ([`NetKernel`]), with no
//! program started; where nf_tables is not in the kernel there is no table,
//! and none is asked for, as the question would make the kernel load it. The
//! way back ([`Policy::restore`]) deletes every rule and table that was not
//! there at entry, reads them back, and writes back every setting that
//! differs, twice, since writing one setting can change another (turning
//! forwarding off turns `accept_redirects` on).
//!
//! A list entry could not read (a family the kernel refuses to list, or an
//! nf_tables of which it cannot be told whether it is in the kernel) is
//! unknown, and the way back leaves that part as the session leaves it:
//! without the decoy's list, a rule or table of the decoy's cannot be told from
//! the session's. A part the way back cannot list, before or after the
//! deletions, is unverified: the session's rules or tables may still be there,
//! and the transition powers off instead of returning, as it does for a rule
//! or table it could not delete. A rule or table the session deleted is not
//! made again, and what the session added inside a table the decoy already had
//! stays.
//!
//! Nothing here logs: a name written to `/dev/kmsg` would reach the decoy's
//! ring buffer.

use crate::whole_root::net_kernel::{Family, NetKernel, Rule, Table};
use crate::whole_root::network::Kept;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// The nftables families a table can be in.
const TABLE_FAMILIES: &[&str] = &["ip", "ip6", "inet", "arp", "bridge", "netdev"];

/// The settings below `/proc/sys` recorded one by one.
const SETTING_KEYS: &[&str] = &["net/ipv4/ip_forward"];

/// The directories below `/proc/sys` whose every key is recorded.
const SETTING_DIRS: &[&str] = &[
    "net/ipv4/conf/all",
    "net/ipv4/conf/default",
    "net/ipv6/conf/all",
    "net/ipv6/conf/default",
];

/// The mode bits a recorded setting has: written by root, read by every user.
/// A key only root may read (`stable_secret`) or no one may write
/// (`mc_forwarding`) is left out.
const SETTING_MODE: u32 = 0o204;

/// One network setting: its key, relative to `/proc/sys`, and its value
/// without the newline the kernel prints after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    key: PathBuf,
    value: String,
}

/// The decoy's routing policy, firewall tables and network settings at entry.
/// A list that could not be read is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Policy {
    rules_v4: Option<Vec<Rule>>,
    rules_v6: Option<Vec<Rule>>,
    tables: Option<Vec<Table>>,
    settings: Vec<Setting>,
}

impl Policy {
    /// Ask `kernel` for the rules and tables and read the settings below
    /// `proc_sys`.
    pub fn capture(kernel: &dyn NetKernel, proc_sys: &Path) -> Self {
        Policy {
            rules_v4: kernel.rules(Family::V4),
            rules_v6: kernel.rules(Family::V6),
            tables: kernel.tables(),
            settings: read_settings(proc_sys),
        }
    }

    /// Whether every part can be acted on: a rule of its list's family as the
    /// kernel lists one, a table in a known family, a setting below the
    /// recorded directories.
    pub fn is_valid(&self) -> bool {
        let rules = |family: Family, rules: &Option<Vec<Rule>>| {
            rules
                .iter()
                .flatten()
                .all(|rule| rule.is_valid() && family.holds(rule))
        };
        rules(Family::V4, &self.rules_v4)
            && rules(Family::V6, &self.rules_v6)
            && self.tables.iter().flatten().all(|table| {
                TABLE_FAMILIES.contains(&table.family.as_str()) && !table.name.is_empty()
            })
            && self
                .settings
                .iter()
                .all(|setting| is_setting_key(&setting.key))
    }

    /// Put the policy back: delete the rules and tables that were not there at
    /// entry, through `kernel`, and write back the settings below `proc_sys`
    /// that differ. What is still the session's afterwards goes into `kept`,
    /// with every part that entry could not read (`unknown`, left alone) and
    /// every part that cannot be listed now (`unverified`, not known to be the
    /// decoy's again).
    pub fn restore(&self, kernel: &dyn NetKernel, proc_sys: &Path, kept: &mut Kept) {
        for (family, recorded) in [(Family::V4, &self.rules_v4), (Family::V6, &self.rules_v6)] {
            match recorded {
                Some(recorded) => restore_rules(kernel, family, recorded, kept),
                None => kept.unknown.push(family.label()),
            }
        }
        match &self.tables {
            Some(recorded) => restore_tables(kernel, recorded, kept),
            None => kept.unknown.push("firewall tables"),
        }
        kept.settings = restore_settings(proc_sys, &self.settings);
    }
}

/// How a rule the way back could not delete is named.
fn describe(family: Family, rule: &Rule) -> String {
    format!(
        "{} rule {} (table {})",
        family.name(),
        rule.priority(),
        rule.table()
    )
}

/// Delete the rules of `family` that are not in `recorded`, then name in
/// `kept` the ones still there.
fn restore_rules(kernel: &dyn NetKernel, family: Family, recorded: &[Rule], kept: &mut Kept) {
    let Some(now) = kernel.rules(family) else {
        kept.unverified.push(family.label());
        return;
    };
    for rule in added(recorded, &now) {
        kernel.delete_rule(rule);
    }
    match kernel.rules(family) {
        Some(after) => kept.rules.extend(
            added(recorded, &after)
                .into_iter()
                .map(|rule| describe(family, rule)),
        ),
        None => kept.unverified.push(family.label()),
    }
}

/// Delete the tables that are not in `recorded`, by handle, then name in
/// `kept` the ones still there.
fn restore_tables(kernel: &dyn NetKernel, recorded: &[Table], kept: &mut Kept) {
    let Some(now) = kernel.tables() else {
        kept.unverified.push("firewall tables");
        return;
    };
    for table in added(recorded, &now) {
        kernel.delete_table(table);
    }
    match kernel.tables() {
        Some(after) => kept.tables.extend(
            added(recorded, &after)
                .into_iter()
                .map(|table| format!("{} {}", table.family, table.name)),
        ),
        None => kept.unverified.push("firewall tables"),
    }
}

/// The items of `now` that `recorded` does not account for, each recorded
/// item accounting for one equal item now.
fn added<'a, T: PartialEq>(recorded: &[T], now: &'a [T]) -> Vec<&'a T> {
    let mut unmatched: Vec<&T> = recorded.iter().collect();
    now.iter()
        .filter(
            |item| match unmatched.iter().position(|then| then == item) {
                Some(at) => {
                    unmatched.swap_remove(at);
                    false
                }
                None => true,
            },
        )
        .collect()
}

/// The settings below `proc_sys` that the record holds and that can be read
/// now: [`SETTING_KEYS`], then the keys of each of [`SETTING_DIRS`] in name
/// order.
fn read_settings(proc_sys: &Path) -> Vec<Setting> {
    let mut keys: Vec<PathBuf> = SETTING_KEYS.iter().map(PathBuf::from).collect();
    for dir in SETTING_DIRS {
        let Ok(entries) = std::fs::read_dir(proc_sys.join(dir)) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .filter(|entry| {
                entry.metadata().is_ok_and(|meta| {
                    meta.is_file() && meta.permissions().mode() & SETTING_MODE == SETTING_MODE
                })
            })
            .map(|entry| Path::new(dir).join(entry.file_name()))
            .collect();
        found.sort();
        keys.extend(found);
    }
    keys.into_iter()
        .filter_map(|key| {
            let value = read_value(&proc_sys.join(&key))?;
            Some(Setting { key, value })
        })
        .collect()
}

/// A setting's value without the newline the kernel prints after it, `None`
/// when it cannot be read.
fn read_value(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim_end_matches('\n').to_string())
}

/// Write back every setting that differs, in two passes; return the keys that
/// still differ.
fn restore_settings(proc_sys: &Path, settings: &[Setting]) -> Vec<String> {
    let differs = |setting: &&Setting| {
        read_value(&proc_sys.join(&setting.key)).as_deref() != Some(setting.value.as_str())
    };
    for _ in 0..2 {
        for setting in settings.iter().filter(differs) {
            let text = if setting.value.is_empty() {
                "\n"
            } else {
                setting.value.as_str()
            };
            let _ = std::fs::write(proc_sys.join(&setting.key), text);
        }
    }
    settings
        .iter()
        .filter(differs)
        .map(|setting| setting.key.display().to_string())
        .collect()
}

/// Whether `key` is one of [`SETTING_KEYS`] or a plain name in one of
/// [`SETTING_DIRS`].
fn is_setting_key(key: &Path) -> bool {
    let plain = key
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    plain
        && (SETTING_KEYS.iter().any(|known| key == Path::new(known))
            || key
                .parent()
                .is_some_and(|dir| SETTING_DIRS.iter().any(|known| dir == Path::new(known))))
}

#[cfg(test)]
#[path = "network_policy_tests.rs"]
mod tests;
