// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's network configuration, asked over netlink.
//!
//! Entry records the decoy's network state and the way back puts it back
//! ([`crate::whole_root::network`]). Both ask the kernel itself, over the
//! netlink sockets that `ip`, `nft` and `iw` use, instead of starting those
//! programs: a program started on the decoy reads its own file, its libraries
//! and its data files there, and on a root mounted `relatime` each such read
//! can set an access time to the moment of the activation. The crate takes no
//! dependency beyond the ones its `boundary` test allows, so the few messages
//! are built and read here, over rustix's netlink sockets:
//!
//! - [`route`]: the policy-routing rules (list, delete), and a link's
//!   deletion, hardware address and up flag (`NETLINK_ROUTE`);
//! - [`filter`]: the nftables tables (list, delete), asked only where
//!   nf_tables is in the kernel, so that no request makes the kernel load it;
//! - [`wireless`]: a Wi-Fi interface's deletion (nl80211 over
//!   `NETLINK_GENERIC`), asked only where cfg80211 is in the kernel.
//!
//! A socket waits at most [`TIMEOUT`] for each reply, so a request costs at
//! most that long, as the bounded tool calls did.

pub mod filter;
pub mod route;
pub mod wireless;

use rustix::fd::OwnedFd;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::Timeout;
use rustix::net::{AddressFamily, Protocol, RecvFlags, SendFlags, SocketFlags, SocketType};
use std::io;
use std::time::Duration;

/// How long a socket waits for each reply.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// The size of a netlink message header (`struct nlmsghdr`).
const HEADER_LEN: usize = 16;
/// The size of an attribute header (`struct nlattr`).
const ATTR_HEADER_LEN: usize = 4;
/// The bits of an attribute's type that are flags, not the type
/// (`NLA_F_NESTED`, `NLA_F_NET_BYTEORDER`).
const ATTR_FLAGS: u16 = 0xc000;

/// A request (`NLM_F_REQUEST`).
pub const F_REQUEST: u16 = 0x1;
/// A reply that is one part of several (`NLM_F_MULTI`).
const F_MULTI: u16 = 0x2;
/// Ask for an acknowledgement (`NLM_F_ACK`).
pub const F_ACK: u16 = 0x4;
/// List every object (`NLM_F_DUMP`).
pub const F_DUMP: u16 = 0x300;

/// An error or an acknowledgement (`NLMSG_ERROR`).
const MSG_ERROR: u16 = 2;
/// The end of a list (`NLMSG_DONE`).
const MSG_DONE: u16 = 3;

/// The largest reply read at once: the kernel sends a list in parts of at most
/// 32 KiB.
const RECV_BUFFER: usize = 64 * 1024;

/// Round `len` up to the netlink alignment of four bytes.
const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// One message to send: its type, its flags and its body, a fixed header of
/// the message's family followed by attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    kind: u16,
    flags: u16,
    body: Vec<u8>,
}

impl Message {
    /// A message of `kind` with `flags` whose body starts with `header`.
    pub fn new(kind: u16, flags: u16, header: &[u8]) -> Self {
        let mut body = header.to_vec();
        body.resize(align(body.len()), 0);
        Message { kind, flags, body }
    }

    /// The message with attribute `kind` holding `payload` added.
    pub fn attr(mut self, kind: u16, payload: &[u8]) -> Self {
        let len = ATTR_HEADER_LEN + payload.len();
        let len16 = u16::try_from(len).unwrap_or(u16::MAX);
        self.body.extend_from_slice(&len16.to_ne_bytes());
        self.body.extend_from_slice(&kind.to_ne_bytes());
        self.body.extend_from_slice(payload);
        self.body.resize(align(self.body.len()), 0);
        self
    }

    /// The message with a 32-bit attribute in the host's byte order added.
    pub fn attr_u32(self, kind: u16, value: u32) -> Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    /// The message with a string attribute added, NUL-terminated as the
    /// kernel reads names.
    pub fn attr_str(self, kind: u16, value: &str) -> Self {
        let mut payload = value.as_bytes().to_vec();
        payload.push(0);
        self.attr(kind, &payload)
    }

    /// The body as it stands, for the tests of the families' messages.
    #[cfg(test)]
    pub(crate) fn body_for_tests(&self) -> &[u8] {
        &self.body
    }

    /// The message as it is sent, with sequence number `seq`.
    fn encode(&self, seq: u32) -> Vec<u8> {
        let len = u32::try_from(HEADER_LEN + self.body.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&self.kind.to_ne_bytes());
        out.extend_from_slice(&self.flags.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// One message the kernel sent back: its type and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The message type.
    pub kind: u16,
    /// The body: the family's fixed header, then the attributes.
    pub body: Vec<u8>,
}

/// One message read from a buffer the kernel filled.
struct Raw<'a> {
    kind: u16,
    flags: u16,
    seq: u32,
    body: &'a [u8],
}

/// The messages in `buf`, in order. A message whose length does not fit ends
/// the list.
fn messages(buf: &[u8]) -> Vec<Raw<'_>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + HEADER_LEN <= buf.len() {
        let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap_or_default()) as usize;
        if len < HEADER_LEN || at + len > buf.len() {
            break;
        }
        out.push(Raw {
            kind: u16::from_ne_bytes([buf[at + 4], buf[at + 5]]),
            flags: u16::from_ne_bytes([buf[at + 6], buf[at + 7]]),
            seq: u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap_or_default()),
            body: &buf[at + HEADER_LEN..at + len],
        });
        at += align(len);
    }
    out
}

/// The attributes of `body` after its fixed header of `header_len` bytes, as
/// type and payload, the type without its flag bits. An attribute whose length
/// does not fit ends the list.
pub fn attributes(body: &[u8], header_len: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = align(header_len);
    while at + ATTR_HEADER_LEN <= body.len() {
        let len = usize::from(u16::from_ne_bytes([body[at], body[at + 1]]));
        let kind = u16::from_ne_bytes([body[at + 2], body[at + 3]]) & !ATTR_FLAGS;
        if len < ATTR_HEADER_LEN || at + len > body.len() {
            break;
        }
        out.push((kind, &body[at + ATTR_HEADER_LEN..at + len]));
        at += align(len);
    }
    out
}

/// The payload of the first attribute of `kind` among `attrs`.
pub fn find<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs
        .iter()
        .find(|(found, _)| *found == kind)
        .map(|(_, payload)| *payload)
}

/// A 32-bit attribute in the host's byte order.
pub fn u32_of(payload: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(payload.get(..4)?.try_into().ok()?))
}

/// A NUL-terminated string attribute, without its NUL.
pub fn str_of(payload: &[u8]) -> Option<&str> {
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());
    std::str::from_utf8(&payload[..end]).ok()
}

/// What an `NLMSG_ERROR` or a list's `NLMSG_DONE` body says: `Ok` for an
/// acknowledgement or a list that ended well, the kernel's error otherwise.
fn status(body: &[u8]) -> io::Result<()> {
    let code = body
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_ne_bytes)
        .unwrap_or(0);
    if code < 0 {
        Err(io::Error::from_raw_os_error(-code))
    } else {
        Ok(())
    }
}

/// A netlink socket of one protocol.
#[derive(Debug)]
pub struct Socket {
    fd: OwnedFd,
    seq: u32,
}

impl Socket {
    /// Open a socket of `protocol` (`None` is `NETLINK_ROUTE`, whose number
    /// is 0) whose reads wait at most [`TIMEOUT`].
    pub fn open(protocol: Option<Protocol>) -> io::Result<Self> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            protocol,
        )?;
        rustix::net::sockopt::set_socket_timeout(&fd, Timeout::Recv, Some(TIMEOUT))?;
        Ok(Socket { fd, seq: 0 })
    }

    /// Send `messages` in one write, each with a sequence number of its own,
    /// and return them. An nftables batch is sent this way: the kernel takes
    /// its begin, its changes and its end as one transaction.
    fn send(&mut self, messages: &[Message]) -> io::Result<Vec<u32>> {
        let mut buf = Vec::new();
        let mut seqs = Vec::with_capacity(messages.len());
        for message in messages {
            self.seq = self.seq.wrapping_add(1);
            seqs.push(self.seq);
            buf.extend_from_slice(&message.encode(self.seq));
        }
        let kernel = SocketAddrNetlink::new(0, 0);
        rustix::net::sendto(&self.fd, &buf, SendFlags::empty(), &kernel)?;
        Ok(seqs)
    }

    /// Read what the kernel sends until `done` says the exchange ended,
    /// handing every message of one of `seqs` to it. A read that times out
    /// is an error.
    fn receive(
        &mut self,
        seqs: &[u32],
        mut done: impl FnMut(&Raw<'_>) -> io::Result<bool>,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; RECV_BUFFER];
        loop {
            let filled = match rustix::net::recv(&self.fd, &mut buf[..], RecvFlags::empty()) {
                Ok((_, 0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok((_, filled)) => filled.min(buf.len()),
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            };
            for message in messages(&buf[..filled]) {
                if seqs.contains(&message.seq) && done(&message)? {
                    return Ok(());
                }
            }
        }
    }

    /// Send a request that lists objects (`F_DUMP`) and collect every
    /// message of the list.
    pub fn dump(&mut self, request: &Message) -> io::Result<Vec<Reply>> {
        let seqs = self.send(std::slice::from_ref(request))?;
        let mut replies = Vec::new();
        self.receive(&seqs, |message| match message.kind {
            MSG_DONE => status(message.body).map(|()| true),
            MSG_ERROR => status(message.body).map(|()| true),
            kind => {
                replies.push(Reply {
                    kind,
                    body: message.body.to_vec(),
                });
                Ok(message.flags & F_MULTI == 0)
            }
        })?;
        Ok(replies)
    }

    /// Send a request that asks for one object and return the kernel's
    /// answer.
    pub fn get(&mut self, request: &Message) -> io::Result<Reply> {
        let seqs = self.send(std::slice::from_ref(request))?;
        let mut reply = None;
        self.receive(&seqs, |message| match message.kind {
            MSG_ERROR | MSG_DONE => status(message.body).map(|()| true),
            kind => {
                reply = Some(Reply {
                    kind,
                    body: message.body.to_vec(),
                });
                Ok(true)
            }
        })?;
        reply.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no answer"))
    }

    /// Send a request that changes something (`F_ACK`) and wait for the
    /// kernel's answer.
    pub fn change(&mut self, request: &Message) -> io::Result<()> {
        let seqs = self.send(std::slice::from_ref(request))?;
        self.receive(&seqs, |message| match message.kind {
            MSG_ERROR => status(message.body).map(|()| true),
            _ => Ok(false),
        })
    }

    /// Send `messages` as one write and wait for the answer to `acked`, the
    /// one among them that asked for an acknowledgement: the change of an
    /// nftables batch, between its begin and its end.
    pub fn batch(&mut self, messages: &[Message], acked: usize) -> io::Result<()> {
        let seqs = self.send(messages)?;
        let wanted = *seqs
            .get(acked)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no such message"))?;
        // An error of the begin or the end comes back under its own number.
        self.receive(&seqs, |message| match message.kind {
            MSG_ERROR if message.seq == wanted => status(message.body).map(|()| true),
            MSG_ERROR => status(message.body).map(|()| false),
            _ => Ok(false),
        })
    }
}

/// Whether `name` is in the running kernel: loaded as a module or built in
/// with something to show, its `/sys/module` directory there.
pub fn module_present(sys_module: &std::path::Path, name: &str) -> bool {
    std::fs::symlink_metadata(sys_module.join(name)).is_ok_and(|meta| meta.is_dir())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
