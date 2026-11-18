// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Policy-routing rules and links, over `NETLINK_ROUTE`.
//!
//! A rule is kept as the kernel lists it ([`Rule`]): its `fib_rule_hdr` and
//! its attributes. The same bytes are what `RTM_DELRULE` takes back, so a rule
//! is deleted as exactly the one listed, whatever selectors and action it has,
//! where `ip rule del` rebuilds them from the words `ip rule show` prints. A
//! link is named by its interface index.

use super::{F_ACK, F_DUMP, F_REQUEST, Message, Socket, attributes, find, u32_of};
use serde::{Deserialize, Serialize};
use std::io;

/// `RTM_DELLINK`.
const RTM_DELLINK: u16 = 17;
/// `RTM_NEWLINK`, which also changes an existing link.
const RTM_NEWLINK: u16 = 16;
/// `RTM_NEWRULE`, the type of each rule a list sends.
const RTM_NEWRULE: u16 = 32;
/// `RTM_DELRULE`.
const RTM_DELRULE: u16 = 33;
/// `RTM_GETRULE`.
const RTM_GETRULE: u16 = 34;

/// `IFLA_ADDRESS`: a link's hardware address.
const IFLA_ADDRESS: u16 = 1;
/// `FRA_PRIORITY`: a rule's priority.
const FRA_PRIORITY: u16 = 6;
/// `FRA_TABLE`: a rule's table, where it does not fit the header's byte.
const FRA_TABLE: u16 = 15;

/// The size of `struct fib_rule_hdr`.
const RULE_HEADER_LEN: usize = 12;
/// The size of `struct ifinfomsg`.
const LINK_HEADER_LEN: usize = 16;

/// `IFF_UP`, a link's administrative up flag.
const IFF_UP: u32 = 0x1;

/// The rule flags the kernel sets and clears by itself as other objects come
/// and go, which are not part of what the rule is: `FIB_RULE_UNRESOLVED` (a
/// goto whose target is gone), `FIB_RULE_IIF_DETACHED` and
/// `FIB_RULE_OIF_DETACHED` (an interface the rule names that is gone). `ip
/// rule show` prints them as `[unresolved]` and `[detached]`.
const TRANSIENT_FLAGS: u32 = 0x4 | 0x8 | 0x10;

/// `AF_INET`.
pub const AF_INET: u8 = 2;
/// `AF_INET6`.
pub const AF_INET6: u8 = 10;

/// One policy-routing rule, as the kernel lists it.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// The rule's `fib_rule_hdr`, then its attributes.
    body: Vec<u8>,
}

impl PartialEq for Rule {
    /// Two rules are the same when they list the same, but for the flags the
    /// kernel changes by itself ([`TRANSIENT_FLAGS`]).
    fn eq(&self, other: &Self) -> bool {
        self.lasting() == other.lasting()
    }
}

impl Rule {
    /// A rule from the body of a listed message; `None` when it is too short
    /// for its header or its attributes do not fill it.
    pub fn from_body(body: Vec<u8>) -> Option<Self> {
        let rule = Rule { body };
        rule.is_valid().then_some(rule)
    }

    /// Whether the body holds a whole header and attributes that fill the
    /// rest of it.
    pub fn is_valid(&self) -> bool {
        if self.body.len() < RULE_HEADER_LEN {
            return false;
        }
        let used: usize = attributes(&self.body, RULE_HEADER_LEN)
            .iter()
            .map(|(_, payload)| super::align(super::ATTR_HEADER_LEN + payload.len()))
            .sum();
        RULE_HEADER_LEN + used == self.body.len()
    }

    /// The body with the transient flags cleared.
    fn lasting(&self) -> Vec<u8> {
        let mut body = self.body.clone();
        if let Some(flags) = body.get_mut(8..12) {
            let value = u32::from_ne_bytes(flags.try_into().unwrap_or_default()) & !TRANSIENT_FLAGS;
            flags.copy_from_slice(&value.to_ne_bytes());
        }
        body
    }

    /// The address family (`AF_INET`, `AF_INET6`).
    pub fn family(&self) -> u8 {
        self.body.first().copied().unwrap_or_default()
    }

    /// The rule's priority.
    pub fn priority(&self) -> u32 {
        find(&attributes(&self.body, RULE_HEADER_LEN), FRA_PRIORITY)
            .and_then(u32_of)
            .unwrap_or(0)
    }

    /// The table the rule looks up.
    pub fn table(&self) -> u32 {
        find(&attributes(&self.body, RULE_HEADER_LEN), FRA_TABLE)
            .and_then(u32_of)
            .unwrap_or_else(|| u32::from(self.body.get(4).copied().unwrap_or_default()))
    }
}

/// The rules of `family` ([`AF_INET`], [`AF_INET6`]), in the kernel's order.
pub fn rules(family: u8) -> io::Result<Vec<Rule>> {
    let mut socket = Socket::open(None)?;
    let mut header = [0u8; RULE_HEADER_LEN];
    header[0] = family;
    let replies = socket.dump(&Message::new(RTM_GETRULE, F_REQUEST | F_DUMP, &header))?;
    replies
        .into_iter()
        .filter(|reply| reply.kind == RTM_NEWRULE)
        .map(|reply| {
            Rule::from_body(reply.body).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "a rule that does not parse")
            })
        })
        .collect()
}

/// Delete `rule`, given back as it was listed.
pub fn delete_rule(rule: &Rule) -> io::Result<()> {
    Socket::open(None)?.change(&Message::new(RTM_DELRULE, F_REQUEST | F_ACK, &rule.body))
}

/// A request about the link with interface index `index`, setting the flags
/// in `change` to those in `flags`.
fn link_message(kind: u16, index: u32, flags: u32, change: u32) -> Message {
    let mut header = [0u8; LINK_HEADER_LEN];
    header[4..8].copy_from_slice(&index.to_ne_bytes());
    header[8..12].copy_from_slice(&flags.to_ne_bytes());
    header[12..16].copy_from_slice(&change.to_ne_bytes());
    Message::new(kind, F_REQUEST | F_ACK, &header)
}

/// Delete the link with interface index `index`.
pub fn delete_link(index: u32) -> io::Result<()> {
    Socket::open(None)?.change(&link_message(RTM_DELLINK, index, 0, 0))
}

/// Give the link with interface index `index` the hardware address `mac`.
pub fn set_link_address(index: u32, mac: &[u8]) -> io::Result<()> {
    Socket::open(None)?.change(&link_message(RTM_NEWLINK, index, 0, 0).attr(IFLA_ADDRESS, mac))
}

/// Bring the link with interface index `index` up or take it down.
pub fn set_link_up(index: u32, up: bool) -> io::Result<()> {
    let flags = if up { IFF_UP } else { 0 };
    Socket::open(None)?.change(&link_message(RTM_NEWLINK, index, flags, IFF_UP))
}

/// A hardware address as the kernel prints it (`02:00:00:00:00:01`, lower-
/// or upper-case hex pairs separated by colons) as its bytes; `None` for
/// anything else.
pub fn parse_mac(text: &str) -> Option<Vec<u8>> {
    let bytes: Option<Vec<u8>> = text
        .split(':')
        .map(|pair| {
            (pair.len() == 2)
                .then(|| u8::from_str_radix(pair, 16).ok())
                .flatten()
        })
        .collect();
    bytes.filter(|bytes| !bytes.is_empty())
}

#[cfg(test)]
pub(crate) fn rule_for_tests(family: u8, priority: u32, table: u32, flags: u32) -> Rule {
    let mut header = [0u8; RULE_HEADER_LEN];
    header[0] = family;
    header[7] = 1; // FR_ACT_TO_TBL
    header[8..12].copy_from_slice(&flags.to_ne_bytes());
    let message = Message::new(0, 0, &header)
        .attr_u32(FRA_PRIORITY, priority)
        .attr_u32(FRA_TABLE, table);
    Rule {
        body: message.body_for_tests().to_vec(),
    }
}
