// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The per-link state the service manager keeps below `/run`, copied at entry
//! and put back in place on the way back.
//!
//! NetworkManager keeps a state file per link below
//! `/run/NetworkManager/devices`, and every profile it holds only in memory
//! (one a session imports as temporary, and the ones it generates for links it
//! finds configured) as a keyfile below `/run/NetworkManager/system-connections`,
//! which it loads again when it starts. systemd-resolved keeps its per-link DNS
//! settings below `/run/systemd/resolve/netif`. All of it lies deeper than the
//! `/run` scrub reaches, so what the hidden session's services wrote there
//! would reach the decoy's services after the way back: a profile the session
//! kept in memory would be loaded, and could connect, in the decoy.
//!
//! So the record holds a copy of these directories ([`snapshot`]), with the
//! owner and mode of each entry, and the way back makes them what entry left
//! ([`restore`]): what the session added goes, what it changed is rewritten in
//! place, what it removed is made again, and an entry whose owner or mode
//! changed gets them back. A rewritten file keeps its inode and every directory
//! stays, so a service that owns its directory can still read and write its
//! state after the way back: systemd-resolved runs as its own user, owns
//! `netif` and writes its files there, and a `netif` made again by root would
//! leave it unable to load or save its per-link state. A directory the decoy
//! did not have goes whole. Sockets, FIFOs and devices are never copied or
//! touched.
//!
//! Nothing here logs: a name written to `/dev/kmsg` would reach the decoy's
//! ring buffer.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// The runtime-state directories, relative to a `/run` root, that the copy
/// holds and the way back makes what entry left them.
pub const RUN_DIRS: &[&str] = &[
    "NetworkManager/devices",
    "NetworkManager/system-connections",
    "systemd/resolve/netif",
];

/// How deep below a runtime-state directory the copy reaches (and the way back
/// looks).
const MAX_DEPTH: usize = 4;

/// The most file content the copy holds; a larger state is not copied.
const MAX_BYTES: usize = 1 << 20;

/// How often the copy is tried. NetworkManager writes a state file under a
/// temporary name and renames it into place, so a copy taken while it does
/// can meet a name that is gone by the time it reads it.
const ATTEMPTS: usize = 3;

/// The permission bits of a mode, without the file type.
const PERMISSION_BITS: u32 = 0o7777;

/// One copied entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Kind {
    Dir,
    File(Vec<u8>),
    Link(PathBuf),
}

/// A copied entry by its path relative to the `/run` root, with its owner and
/// permission bits; a parent sorts before its children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEntry {
    path: PathBuf,
    kind: Kind,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Copy the runtime-state directories of `run` below [`RUN_DIRS`], bounded in
/// depth and size. `None` when no attempt could read all of it (an entry that
/// cannot be read, or more than the size bound): the way back then leaves
/// these directories as the session leaves them.
pub fn snapshot(run: &Path) -> Option<Vec<RunEntry>> {
    retry(ATTEMPTS, || collect_all(run))
}

/// The result of the first of at most `attempts` calls of `attempt` that
/// succeeds.
fn retry<T>(attempts: usize, mut attempt: impl FnMut() -> std::io::Result<T>) -> Option<T> {
    (0..attempts).find_map(|_| attempt().ok())
}

fn collect_all(run: &Path) -> std::io::Result<Vec<RunEntry>> {
    let mut entries = Vec::new();
    let mut bytes = 0;
    for dir in RUN_DIRS {
        collect(run, Path::new(dir), 0, &mut entries, &mut bytes)?;
    }
    Ok(entries)
}

fn collect(
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
    let file_type = meta.file_type();
    let kind = if file_type.is_dir() {
        Kind::Dir
    } else if file_type.is_file() {
        let content = std::fs::read(&path)?;
        *bytes += content.len();
        if *bytes > MAX_BYTES {
            return Err(std::io::Error::other(
                "the runtime state is too large to copy",
            ));
        }
        Kind::File(content)
    } else if file_type.is_symlink() {
        Kind::Link(std::fs::read_link(&path)?)
    } else {
        return Ok(());
    };
    let is_dir = kind == Kind::Dir;
    entries.push(RunEntry {
        path: rel.to_path_buf(),
        kind,
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & PERMISSION_BITS,
    });
    if is_dir && depth < MAX_DEPTH {
        for child in std::fs::read_dir(&path)? {
            collect(
                run,
                &rel.join(child?.file_name()),
                depth + 1,
                entries,
                bytes,
            )?;
        }
    }
    Ok(())
}

/// Make the runtime-state directories of `run` what `entries` (a
/// [`snapshot`]) holds. See the module docs.
pub fn restore(run: &Path, entries: &[RunEntry]) {
    let recorded: BTreeMap<&Path, &RunEntry> = entries
        .iter()
        .map(|entry| (entry.path.as_path(), entry))
        .collect();
    for dir in RUN_DIRS {
        reconcile(run, Path::new(dir), 0, &recorded);
    }
    for entry in entries {
        let path = run.join(&entry.path);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if same_kind(&meta, &entry.kind) => keep_owner_and_mode(&path, &meta, entry),
            // Something the reconcile could not remove, or a socket: left.
            Ok(_) => {}
            Err(_) => create(&path, entry),
        }
    }
}

/// Make the entry at `rel` what `recorded` says: keep it, rewrite it in
/// place, or remove it (the caller then creates what is missing).
fn reconcile(run: &Path, rel: &Path, depth: usize, recorded: &BTreeMap<&Path, &RunEntry>) {
    let path = run.join(rel);
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return;
    };
    let kind = meta.file_type();
    if is_special(kind) {
        return;
    }
    match recorded.get(rel).map(|entry| &entry.kind) {
        Some(Kind::Dir) if kind.is_dir() => {
            if depth < MAX_DEPTH
                && let Ok(children) = std::fs::read_dir(&path)
            {
                for child in children.flatten() {
                    reconcile(run, &rel.join(child.file_name()), depth + 1, recorded);
                }
            }
        }
        Some(Kind::File(content)) if kind.is_file() => {
            if std::fs::read(&path).ok().as_ref() != Some(content) {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .and_then(|mut file| file.write_all(content));
            }
        }
        Some(Kind::Link(target)) if kind.is_symlink() => {
            if std::fs::read_link(&path).ok().as_ref() != Some(target) {
                let _ = std::fs::remove_file(&path);
            }
        }
        // The hidden session's, or of another kind than the decoy's.
        _ if kind.is_dir() => {
            let _ = std::fs::remove_dir_all(&path);
        }
        _ => {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Make an entry the reconcile found missing, with its recorded owner and
/// mode. A file is created private and opened up only once it has its owner.
fn create(path: &Path, entry: &RunEntry) {
    let made = create_parent(path).and_then(|()| match &entry.kind {
        Kind::Dir => std::fs::create_dir(path),
        Kind::File(content) => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut file| file.write_all(content)),
        Kind::Link(target) => std::os::unix::fs::symlink(target, path),
    });
    if made.is_ok() {
        let _ = std::os::unix::fs::lchown(path, Some(entry.uid), Some(entry.gid));
        if !matches!(entry.kind, Kind::Link(_)) {
            let _ = std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(entry.mode & PERMISSION_BITS),
            );
        }
    }
}

/// Give an entry that is there its recorded owner and permission bits where
/// they changed. A symbolic link has no mode of its own.
fn keep_owner_and_mode(path: &Path, meta: &Metadata, entry: &RunEntry) {
    if meta.uid() != entry.uid || meta.gid() != entry.gid {
        let _ = std::os::unix::fs::lchown(path, Some(entry.uid), Some(entry.gid));
    }
    if !meta.file_type().is_symlink()
        && meta.mode() & PERMISSION_BITS != entry.mode & PERMISSION_BITS
    {
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(entry.mode & PERMISSION_BITS),
        );
    }
}

fn same_kind(meta: &Metadata, kind: &Kind) -> bool {
    match kind {
        Kind::Dir => meta.is_dir(),
        Kind::File(_) => meta.is_file(),
        Kind::Link(_) => meta.file_type().is_symlink(),
    }
}

/// Create the parents of `path` that a record without them names.
fn create_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => std::fs::create_dir_all(parent),
        None => Ok(()),
    }
}

fn is_special(kind: std::fs::FileType) -> bool {
    kind.is_socket() || kind.is_fifo() || kind.is_block_device() || kind.is_char_device()
}

/// Whether every entry is a plain relative path at or below one of
/// [`RUN_DIRS`].
pub fn is_valid(entries: &[RunEntry]) -> bool {
    entries.iter().all(|entry| is_run_path(&entry.path))
}

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
#[path = "network_run_tests.rs"]
mod tests;
