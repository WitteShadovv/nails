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
//! So [the record](Policy) holds the decoy's rules of both address families
//! (as `ip -N rule show` lists them), its nftables tables with the handle the
//! kernel gave each (as `nft -j list tables` lists them: a table made again
//! under the same name gets a new handle, so it does not pass for the decoy's)
//! and its network settings for all devices and for new ones:
//! `net.ipv4.ip_forward` and every key of `net.ipv4.conf.all`,
//! `net.ipv4.conf.default`, `net.ipv6.conf.all` and `net.ipv6.conf.default`
//! that every user can read and root can write. The way back
//! ([`Policy::restore`]) deletes every rule and table that was not there at
//! entry, reads them back, and writes back every setting that differs, twice,
//! since writing one setting can change another (turning forwarding off turns
//! `accept_redirects` on).
//!
//! A list entry could not read (no `ip` or `nft`, a tool that failed, output
//! that does not parse) is unknown, and the way back leaves that part as the
//! session leaves it: without the decoy's list, a rule or table of the decoy's
//! cannot be told from the session's. A rule or table the session deleted is
//! not made again, and what the session added inside a table the decoy already
//! had stays.
//!
//! Nothing here logs: a name written to `/dev/kmsg` would reach the decoy's
//! ring buffer.

use crate::whole_root::network::Kept;
use crate::whole_root::tools;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// How long one `ip` or `nft` call may take.
const TOOL_BUDGET: Duration = Duration::from_secs(3);

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

/// An address family of the policy-routing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// The `ip` option that selects it.
    fn option(self) -> &'static str {
        match self {
            Family::V4 => "-4",
            Family::V6 => "-6",
        }
    }

    /// What its rules are called where they are unknown.
    fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4 rules",
            Family::V6 => "IPv6 rules",
        }
    }
}

/// One policy-routing rule: its priority, and its selector and action as
/// `ip rule del` takes them back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    priority: u32,
    spec: Vec<String>,
}

/// One nftables table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    family: String,
    name: String,
    handle: u64,
}

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
    /// Read the rules with `ip`, the tables with `nft` and the settings below
    /// `proc_sys`; a part whose tool is `None` is unknown.
    pub fn capture(ip: Option<&Path>, nft: Option<&Path>, proc_sys: &Path) -> Self {
        Policy {
            rules_v4: ip.and_then(|ip| list_rules(ip, Family::V4)),
            rules_v6: ip.and_then(|ip| list_rules(ip, Family::V6)),
            tables: nft.and_then(list_tables),
            settings: read_settings(proc_sys),
        }
    }

    /// Whether every part can be acted on: a table in a known family, a
    /// setting below the recorded directories, a rule of plain words.
    pub fn is_valid(&self) -> bool {
        let words = |rule: &Rule| {
            rule.spec
                .iter()
                .all(|word| !word.is_empty() && !word.contains(char::is_whitespace))
        };
        self.rules_v4
            .iter()
            .chain(&self.rules_v6)
            .flatten()
            .all(words)
            && self.tables.iter().flatten().all(|table| {
                TABLE_FAMILIES.contains(&table.family.as_str()) && !table.name.is_empty()
            })
            && self
                .settings
                .iter()
                .all(|setting| is_setting_key(&setting.key))
    }

    /// Put the policy back: delete the rules and tables that were not there at
    /// entry with `ip` and `nft`, and write back the settings below `proc_sys`
    /// that differ. What is still the session's afterwards, and every part
    /// that could not be read at entry or now, goes into `kept`.
    pub fn restore(&self, ip: Option<&Path>, nft: Option<&Path>, proc_sys: &Path, kept: &mut Kept) {
        for (family, recorded) in [(Family::V4, &self.rules_v4), (Family::V6, &self.rules_v6)] {
            match (recorded, ip) {
                (Some(recorded), Some(ip)) => restore_rules(ip, family, recorded, kept),
                _ => kept.unknown.push(family.label()),
            }
        }
        match (&self.tables, nft) {
            (Some(recorded), Some(nft)) => restore_tables(nft, recorded, kept),
            _ => kept.unknown.push("firewall tables"),
        }
        kept.settings = restore_settings(proc_sys, &self.settings);
    }
}

/// The rules of `family` as `ip` lists them, `None` when it fails or prints
/// something else.
fn list_rules(ip: &Path, family: Family) -> Option<Vec<Rule>> {
    let text = tools::run_output(ip, &["-N", family.option(), "rule", "show"], TOOL_BUDGET)?;
    parse_rules(&text)
}

/// Parse `ip -N rule show` output, one rule per line (`32765:\tnot from all
/// fwmark 0xca6c lookup 51820`), into what `ip rule del` takes back: without
/// the flags it only prints (`[detached]` for an interface that is gone,
/// `[unresolved]` for a goto without its target), with `l3mdev` for the
/// `lookup [l3mdev-table]` it prints for one, and with the number for the
/// `ipproto-6` it prints in numeric mode.
fn parse_rules(text: &str) -> Option<Vec<Rule>> {
    let mut rules = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let (priority, rest) = line.split_once(':')?;
        let mut spec = Vec::new();
        let mut words = rest.split_whitespace().peekable();
        while let Some(word) = words.next() {
            match word {
                "[detached]" | "[unresolved]" => {}
                "lookup" if words.peek() == Some(&"[l3mdev-table]") => {
                    words.next();
                    spec.push("l3mdev".to_string());
                }
                "ipproto" => {
                    let proto = words.next()?;
                    spec.push(word.to_string());
                    spec.push(proto.strip_prefix("ipproto-").unwrap_or(proto).to_string());
                }
                _ => spec.push(word.to_string()),
            }
        }
        rules.push(Rule {
            priority: priority.trim().parse().ok()?,
            spec,
        });
    }
    Some(rules)
}

/// Delete the rules of `family` that are not in `recorded`, then name in
/// `kept` the ones still there.
fn restore_rules(ip: &Path, family: Family, recorded: &[Rule], kept: &mut Kept) {
    let Some(now) = list_rules(ip, family) else {
        kept.unknown.push(family.label());
        return;
    };
    for rule in added(recorded, &now) {
        let priority = rule.priority.to_string();
        let mut args = vec![family.option(), "rule", "del", "priority", &priority];
        args.extend(rule.spec.iter().map(String::as_str));
        let _ = tools::run(ip, &args, TOOL_BUDGET);
    }
    match list_rules(ip, family) {
        Some(after) => kept
            .rules
            .extend(added(recorded, &after).into_iter().map(|rule| {
                format!(
                    "{} {}: {}",
                    family.option(),
                    rule.priority,
                    rule.spec.join(" ")
                )
            })),
        None => kept.unknown.push(family.label()),
    }
}

/// The tables as `nft` lists them, `None` when it fails (as it does when it was
/// built without JSON) or prints something else.
fn list_tables(nft: &Path) -> Option<Vec<Table>> {
    let text = tools::run_output(nft, &["-j", "list", "tables"], TOOL_BUDGET)?;
    parse_tables(&text)
}

/// Parse `nft -j list tables` output: a `nftables` list of a `metainfo`
/// object and one `table` object (family, name, handle) per table.
fn parse_tables(json: &str) -> Option<Vec<Table>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut tables = Vec::new();
    for item in value.get("nftables")?.as_array()? {
        let Some(table) = item.get("table") else {
            continue;
        };
        let family = table.get("family")?.as_str()?;
        if !TABLE_FAMILIES.contains(&family) {
            return None;
        }
        tables.push(Table {
            family: family.to_string(),
            name: table.get("name")?.as_str()?.to_string(),
            handle: table.get("handle")?.as_u64()?,
        });
    }
    Some(tables)
}

/// Delete the tables that are not in `recorded`, by handle, then name in
/// `kept` the ones still there.
fn restore_tables(nft: &Path, recorded: &[Table], kept: &mut Kept) {
    let Some(now) = list_tables(nft) else {
        kept.unknown.push("firewall tables");
        return;
    };
    for table in added(recorded, &now) {
        let handle = table.handle.to_string();
        let args = ["delete", "table", table.family.as_str(), "handle", &handle];
        let _ = tools::run(nft, &args, TOOL_BUDGET);
    }
    match list_tables(nft) {
        Some(after) => kept.tables.extend(
            added(recorded, &after)
                .into_iter()
                .map(|table| format!("{} {}", table.family, table.name)),
        ),
        None => kept.unknown.push("firewall tables"),
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
