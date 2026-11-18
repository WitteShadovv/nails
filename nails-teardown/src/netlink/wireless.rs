// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wi-Fi interfaces, over nl80211.
//!
//! The kernel deletes a Wi-Fi interface only through its wireless
//! configuration interface, nl80211, a family of generic netlink. Asking the
//! generic netlink controller for a family that is not there makes the kernel
//! load the module that provides it, so nl80211 is asked for only where
//! cfg80211 is in the kernel: its `/sys/module` directory is there whenever
//! it is, loaded or built in, as it has parameters. A Wi-Fi interface lives in
//! cfg80211, so without it there is none to delete.

use super::{F_ACK, F_REQUEST, Message, Socket, attributes, find};
use rustix::net::netlink;
use std::io;
use std::path::Path;

/// The generic netlink controller's family (`GENL_ID_CTRL`).
const GENL_ID_CTRL: u16 = 16;
/// `CTRL_CMD_GETFAMILY`.
const CTRL_CMD_GETFAMILY: u8 = 3;
/// `CTRL_ATTR_FAMILY_ID`.
const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// `CTRL_ATTR_FAMILY_NAME`.
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
/// `NL80211_CMD_DEL_INTERFACE`.
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
/// `NL80211_ATTR_IFINDEX`.
const NL80211_ATTR_IFINDEX: u16 = 3;

/// The `genlmsghdr` of command `cmd`.
fn header(cmd: u8) -> [u8; 4] {
    [cmd, 1, 0, 0]
}

/// The number the controller gave family `name`.
fn family(socket: &mut Socket, name: &str) -> io::Result<u16> {
    let request = Message::new(GENL_ID_CTRL, F_REQUEST, &header(CTRL_CMD_GETFAMILY))
        .attr_str(CTRL_ATTR_FAMILY_NAME, name);
    let reply = socket.get(&request)?;
    find(&attributes(&reply.body, 4), CTRL_ATTR_FAMILY_ID)
        .and_then(|payload| Some(u16::from_ne_bytes(payload.get(..2)?.try_into().ok()?)))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no family number"))
}

/// Delete the Wi-Fi interface with interface index `index`. Without cfg80211
/// in the kernel (its directory below `sys_module`) nothing is asked, and
/// the interface is reported not found.
pub fn delete_interface(sys_module: &Path, index: u32) -> io::Result<()> {
    if !super::module_present(sys_module, "cfg80211") {
        return Err(io::ErrorKind::NotFound.into());
    }
    let mut socket = Socket::open(Some(netlink::GENERIC))?;
    let nl80211 = family(&mut socket, "nl80211")?;
    let request = Message::new(
        nl80211,
        F_REQUEST | F_ACK,
        &header(NL80211_CMD_DEL_INTERFACE),
    )
    .attr_u32(NL80211_ATTR_IFINDEX, index);
    socket.change(&request)
}
