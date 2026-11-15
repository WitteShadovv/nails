// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a socket on a standard stream of a running daemon may lead, as PID
//! 1's socket table, `<root>/proc/1/net/unix`, shows it. The table is read
//! as the sssd check reads it ([`super::super::sssd`]): as bytes, and twice,
//! with what either read lists, since the kernel prints it a page at a time
//! and a socket closed between two pages can make it skip a line.
//!
//! The service manager connects a stream it sends to the journal before the
//! daemon runs, in its own network namespace, by a socket bound to no path,
//! so the table lists that socket as a connected local stream socket with no
//! path. The table does not name the socket at its other end. So such a
//! socket counts as one to the decoy's own journal, which the journal's own
//! check judges, unless the table also lists a socket of a journal
//! namespace, one bound in `/run/systemd/journal.<namespace>/`, whose
//! journal the decoy keeps on its disk or NAILS cannot tell whether it does:
//! a program can connect a daemon's stream to that namespace's socket
//! itself, as `systemd-cat --namespace=` does, without the mount of the
//! namespace that the service manager sets up for a unit
//! ([`super::namespace`]). Then NAILS cannot tell. A socket the table lists
//! otherwise, of another kind, or bound to a path, as the end a listening
//! program accepts is, or not at all, as one of another network namespace or
//! a network socket is, leaves NAILS unable to tell, and so does a table it
//! cannot read. A connected local stream socket with no path whose other
//! end a program other than journald holds, as the other end of a socket
//! pair is, counts as one to the journal all the same, though that program
//! may copy what it reads into a file: NAILS does not see that end.

use super::super::super::journald_storage::namespace_persistence_at;
use super::super::sssd::{SOCKET_TABLE, SOCKET_TABLE_HEADER};
use super::namespace::valid;
use super::options::{JournalFix, Log};
use super::streams::{Stream, listed};
use crate::Filesystem;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// How the path of a journal namespace's socket begins, before the
/// namespace's name.
const NAMESPACE_SOCKETS: &[u8] = b"/run/systemd/journal.";

/// The kind the table gives a stream socket (`SOCK_STREAM`).
const STREAM: &[u8] = b"0001";

/// The state the table gives a connected socket (`SS_CONNECTED`).
const CONNECTED: &[u8] = b"03";

/// What one read of PID 1's socket table lists.
#[derive(Debug, Default, PartialEq, Eq)]
struct Listed {
    /// The inodes of its connected stream sockets bound to no path.
    streams: BTreeSet<u64>,
    /// The journal namespaces it lists a socket of.
    namespaces: BTreeSet<String>,
}

impl Listed {
    /// What this read and `other`, another one, list together: a socket
    /// either lists.
    fn with(mut self, other: Listed) -> Listed {
        self.streams.extend(other.streams);
        self.namespaces.extend(other.namespaces);
        self
    }
}

/// What PID 1's socket table shows of where a daemon's socket may lead.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Sockets {
    /// The inodes of its connected stream sockets bound to no path.
    streams: BTreeSet<u64>,
    /// The journal namespaces it lists a socket of whose journal the decoy
    /// keeps on its disk, or NAILS cannot tell whether it does, each with
    /// what a finding says of it.
    doubtful: BTreeMap<String, String>,
}

/// What PID 1's socket table under `root` shows (see the [module
/// docs](self)).
///
/// # Errors
///
/// Why NAILS cannot read the table.
pub(super) fn read<F: Filesystem>(fs: &F, root: &Path) -> Result<Sockets, String> {
    let listed = read_once(fs, root)?.with(read_once(fs, root)?);
    let mut doubtful = BTreeMap::new();
    for namespace in &listed.namespaces {
        let said = match namespace_persistence_at(fs, root, namespace) {
            Ok(false) => continue,
            Ok(true) => format!(
                "the journal namespace {namespace}, which journald keeps on the decoy disk unless \
                 journald@{namespace}.conf sets Storage=volatile"
            ),
            Err(unread) => format!(
                "the journal namespace {namespace}, of which NAILS cannot tell where journald \
                 keeps it: {}",
                unread.with_advice()
            ),
        };
        doubtful.insert(namespace.clone(), said);
    }
    Ok(Sockets {
        streams: listed.streams,
        doubtful,
    })
}

/// What one read of PID 1's socket table under `root` lists.
///
/// # Errors
///
/// Why NAILS cannot read it: the read fails, or the table does not begin
/// with the header the kernel prints.
fn read_once<F: Filesystem>(fs: &F, root: &Path) -> Result<Listed, String> {
    let table = fs.read_file_bytes(&root.join(SOCKET_TABLE)).map_err(|e| {
        if e.io_kind() == Some(std::io::ErrorKind::PermissionDenied) {
            format!(
                "NAILS cannot read PID 1's socket table, /{SOCKET_TABLE}, which shows where it \
                 leads; run the command again with sudo"
            )
        } else {
            format!(
                "NAILS cannot read PID 1's socket table, /{SOCKET_TABLE}, which shows where it \
                 leads ({e})"
            )
        }
    })?;
    let mut lines = table.split(|&byte| byte == b'\n');
    if lines.next() != Some(SOCKET_TABLE_HEADER) {
        return Err(format!(
            "PID 1's socket table, /{SOCKET_TABLE}, does not begin with the header the kernel \
             prints"
        ));
    }
    let mut listed = Listed::default();
    for line in lines {
        let fields: Vec<&[u8]> = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect();
        // Num RefCount Protocol Flags Type St Inode, then the path of a
        // socket bound to one, which a space in it splits further.
        match fields.as_slice() {
            [_, _, _, _, kind, state, inode] => {
                if *kind == STREAM
                    && *state == CONNECTED
                    && let Some(inode) = std::str::from_utf8(inode)
                        .ok()
                        .and_then(|inode| inode.parse().ok())
                {
                    listed.streams.insert(inode);
                }
            }
            [_, _, _, _, _, _, _, path, ..] => listed.namespaces.extend(namespace_of(path)),
            _ => {}
        }
    }
    Ok(listed)
}

/// The journal namespace whose socket `path` is: one bound in
/// `/run/systemd/journal.<namespace>/`, for a name systemd takes.
fn namespace_of(path: &[u8]) -> Option<String> {
    let rest = path.strip_prefix(NAMESPACE_SOCKETS)?;
    let end = rest.iter().position(|&byte| byte == b'/')?;
    let name = std::str::from_utf8(&rest[..end]).ok()?;
    valid(name).then(|| name.to_string())
}

/// Where a socket on `stream` of a running daemon leads, `inode` being its
/// inode, by what PID 1's socket table shows, `sockets`, where the daemon's
/// own journal namespace keeps nothing on the decoy disk (see the [module
/// docs](self)).
pub(super) fn judge(sockets: &Result<Sockets, String>, stream: Stream, inode: u64) -> Log {
    let name = stream.name();
    let sockets = match sockets {
        Ok(sockets) => sockets,
        Err(why) => return Log::Unknown(format!("it logs to its {name}, a socket, and {why}")),
    };
    if !sockets.streams.contains(&inode) {
        return Log::Unknown(format!(
            "it logs to its {name}, a socket that PID 1's socket table does not list as a \
             connected local stream socket bound to no path, as one the service manager connects \
             to the journal is, so NAILS cannot tell where it leads"
        ));
    }
    if sockets.doubtful.is_empty() {
        return Log::NoFile;
    }
    let said: Vec<String> = sockets.doubtful.values().cloned().collect();
    Log::UntoldJournal {
        why: format!(
            "it logs to its {name}, a socket, which NAILS does not follow to the journal at its \
             other end, while PID 1's socket table lists a socket of {}",
            listed(&said)
        ),
        fix: JournalFix::Namespaces(sockets.doubtful.keys().cloned().collect()),
    }
}

#[cfg(test)]
#[path = "sockets_tests.rs"]
mod tests;
