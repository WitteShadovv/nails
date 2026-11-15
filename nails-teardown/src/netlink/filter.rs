// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! nftables tables, over `NETLINK_NETFILTER`.
//!
//! A request to nf_tables, and the socket it goes through, makes the kernel
//! load nf_tables and nfnetlink when they are modules that are not loaded:
//! the kernel then starts the decoy's modprobe, which reads its settings and
//! the module files on the decoy disk, and the module stays loaded. So the
//! tables are asked for only where nf_tables is in the kernel already
//! ([`presence`]). Where it is not, there is no table to list: a table lives
//! in nf_tables.

use super::{F_ACK, F_DUMP, F_REQUEST, Message, Socket, attributes, find, str_of};
use rustix::net::netlink;
use std::io::{self, BufRead};
use std::path::Path;

/// The nftables subsystem of nfnetlink (`NFNL_SUBSYS_NFTABLES`).
const SUBSYS_NFTABLES: u16 = 10;
/// `NFT_MSG_NEWTABLE`, the type of each table a list sends.
const NFT_MSG_NEWTABLE: u16 = 0;
/// `NFT_MSG_GETTABLE`.
const NFT_MSG_GETTABLE: u16 = 1;
/// `NFT_MSG_DELTABLE`.
const NFT_MSG_DELTABLE: u16 = 2;
/// `NFNL_MSG_BATCH_BEGIN`.
const BATCH_BEGIN: u16 = 0x10;
/// `NFNL_MSG_BATCH_END`.
const BATCH_END: u16 = 0x11;
/// `NFTA_TABLE_NAME`.
const NFTA_TABLE_NAME: u16 = 1;
/// `NFTA_TABLE_HANDLE`, a 64-bit big-endian number.
const NFTA_TABLE_HANDLE: u16 = 4;

/// The families a table can be in, by the name `nft` gives each and its
/// number (`NFPROTO_*`).
pub const FAMILIES: [(&str, u8); 6] = [
    ("ip", 2),
    ("ip6", 10),
    ("inet", 1),
    ("arp", 3),
    ("bridge", 7),
    ("netdev", 5),
];

/// The name `nft` gives family number `number`.
pub fn family_name(number: u8) -> Option<&'static str> {
    FAMILIES
        .iter()
        .find(|(_, n)| *n == number)
        .map(|(name, _)| *name)
}

/// The number of family `name`.
pub fn family_number(name: &str) -> Option<u8> {
    FAMILIES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, number)| *number)
}

/// One table as the kernel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// Its family's number.
    pub family: u8,
    /// Its name.
    pub name: String,
    /// The handle the kernel gave it: a table made again under the same name
    /// gets a new one.
    pub handle: u64,
}

/// Whether nf_tables is in the running kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// It is: loaded as a module (its `/sys/module` directory is there) or
    /// built in (the kernel's symbols name one of its functions).
    Present,
    /// It is not, so there is no table: asking would load it.
    Absent,
    /// Neither can be read.
    Unknown,
}

/// A function nf_tables itself defines and exports, which the kernel's
/// symbol list names wherever nf_tables is in the kernel, built in or loaded.
const SYMBOL: &str = "nft_register_expr";

/// Whether nf_tables is in the kernel: its directory below `sys_module`
/// (`/sys/module`), or, for a kernel that has it built in and shows no such
/// directory, its function in the symbol list at `kallsyms`
/// (`/proc/kallsyms`). Reading these makes the kernel load nothing.
pub fn presence(sys_module: &Path, kallsyms: &Path) -> Presence {
    if super::module_present(sys_module, "nf_tables") {
        return Presence::Present;
    }
    let Ok(file) = std::fs::File::open(kallsyms) else {
        return Presence::Unknown;
    };
    let mut named = false;
    for line in io::BufReader::new(file).lines() {
        let Ok(line) = line else {
            return Presence::Unknown;
        };
        // `<address> <type> <name>[\t[<module>]]`
        if line.split_whitespace().nth(2) == Some(SYMBOL) {
            named = true;
            break;
        }
    }
    if named {
        Presence::Present
    } else {
        Presence::Absent
    }
}

/// The `nfgenmsg` header of a message to nf_tables about `family`.
fn header(family: u8, res_id: u16) -> [u8; 4] {
    let id = res_id.to_be_bytes();
    [family, 0, id[0], id[1]]
}

/// The message type of nf_tables message `message`.
fn kind(message: u16) -> u16 {
    (SUBSYS_NFTABLES << 8) | message
}

/// Every table, of every family. Call it only where [`presence`] says
/// nf_tables is in the kernel.
pub fn tables() -> io::Result<Vec<Listed>> {
    let mut socket = Socket::open(Some(netlink::NETFILTER))?;
    let request = Message::new(kind(NFT_MSG_GETTABLE), F_REQUEST | F_DUMP, &header(0, 0));
    let mut tables = Vec::new();
    for reply in socket.dump(&request)? {
        if reply.kind != kind(NFT_MSG_NEWTABLE) {
            continue;
        }
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "a table that does not parse");
        let attrs = attributes(&reply.body, 4);
        let name = find(&attrs, NFTA_TABLE_NAME)
            .and_then(str_of)
            .ok_or_else(invalid)?;
        let handle = find(&attrs, NFTA_TABLE_HANDLE)
            .and_then(|payload| payload.get(..8)?.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(invalid)?;
        tables.push(Listed {
            family: reply.body.first().copied().ok_or_else(invalid)?,
            name: name.to_string(),
            handle,
        });
    }
    Ok(tables)
}

/// Delete the table of `family` with `handle`, in a batch of its own as
/// nf_tables takes every change. Call it only where [`presence`] says
/// nf_tables is in the kernel.
pub fn delete_table(family: u8, handle: u64) -> io::Result<()> {
    let mut socket = Socket::open(Some(netlink::NETFILTER))?;
    let batch = header(0, SUBSYS_NFTABLES);
    let messages = [
        Message::new(BATCH_BEGIN, F_REQUEST, &batch),
        Message::new(
            kind(NFT_MSG_DELTABLE),
            F_REQUEST | F_ACK,
            &header(family, 0),
        )
        .attr(NFTA_TABLE_HANDLE, &handle.to_be_bytes()),
        Message::new(BATCH_END, F_REQUEST, &batch),
    ];
    socket.batch(&messages, 1)
}
