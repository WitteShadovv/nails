// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's records in `/run` that its own start writes to disk.
//!
//! Some programs keep state in `/run` that another program turns into a file
//! on disk at every start. openresolv is the known case: each source of name
//! servers (NetworkManager, dhcpcd, a VPN client) hands its settings to
//! `resolvconf`, which keeps them as a record below `/run/resolvconf`;
//! NetworkManager leaves its record in place when it stops; and on NixOS the
//! decoy's `resolvconf.service` rebuilds `/etc/resolv.conf` on the decoy disk
//! from the records at every start, before NetworkManager runs. A record the
//! hidden session wrote, carried by the soft-reboot, would put the hidden name
//! servers and search domains there. The scrub cannot see it: the hidden
//! session rewrites the decoy's record under the same name, below the depth
//! the scrub lists.
//!
//! So the switch into the hidden session, after the decoy's own shutdown,
//! copies everything below these directories into the runtime directory
//! ([`save`]), and the way back puts that state back ([`restore`]): what the
//! hidden session added goes, and what it changed or removed gets the decoy's
//! content again. A file is rewritten in place, so it keeps its owner, mode
//! and ACLs. Without a copy the way back removes every record instead, and the
//! decoy's services register theirs again as they start. Sockets, FIFOs and
//! devices are never touched.
//!
//! Nothing here logs: a name written to `/dev/kmsg` would reach the decoy's
//! ring buffer.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

/// The record directories, below a `/run` root.
pub const RECORD_DIRS: &[&str] = &["resolvconf"];

/// How deep below a record directory the copy reaches (and the way back
/// looks).
const MAX_DEPTH: usize = 4;

/// The most file content the copy holds; a larger state is not copied.
const MAX_BYTES: usize = 1 << 20;

/// One entry below a record directory, as it was copied.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Dir,
    File(Vec<u8>),
    Link(PathBuf),
}

/// The copied entries by their path relative to the `/run` root; a parent
/// sorts before its children.
type Records = BTreeMap<PathBuf, Kind>;

/// Copy everything below the record directories of `run` to the file `to`
/// (private). A record directory that does not exist is copied as absent.
pub fn save(run: &Path, to: &Path) -> io::Result<()> {
    let mut records = Records::new();
    let mut bytes = 0;
    for dir in RECORD_DIRS {
        collect(run, Path::new(dir), 0, &mut records, &mut bytes)?;
    }
    crate::whole_root::plan::write_private_atomic(to, &encode(&records))
}

fn collect(
    run: &Path,
    rel: &Path,
    depth: usize,
    records: &mut Records,
    bytes: &mut usize,
) -> io::Result<()> {
    let path = run.join(rel);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let kind = meta.file_type();
    if kind.is_dir() {
        records.insert(rel.to_path_buf(), Kind::Dir);
        if depth < MAX_DEPTH {
            for child in std::fs::read_dir(&path)? {
                collect(
                    run,
                    &rel.join(child?.file_name()),
                    depth + 1,
                    records,
                    bytes,
                )?;
            }
        }
    } else if kind.is_file() {
        let content = std::fs::read(&path)?;
        *bytes += content.len();
        if *bytes > MAX_BYTES {
            return Err(io::Error::other("the records are too large to copy"));
        }
        records.insert(rel.to_path_buf(), Kind::File(content));
    } else if kind.is_symlink() {
        records.insert(rel.to_path_buf(), Kind::Link(std::fs::read_link(&path)?));
    }
    Ok(())
}

/// Put the record directories of `run` back to `saved`, the copy [`save`]
/// wrote; with no copy, or one that does not parse, remove every record.
pub fn restore(run: &Path, saved: Option<&[u8]>) {
    let Some(records) = saved.and_then(decode) else {
        for dir in RECORD_DIRS {
            clear(run, Path::new(dir), 0);
        }
        return;
    };
    for dir in RECORD_DIRS {
        reconcile(run, Path::new(dir), 0, &records);
    }
    for (rel, kind) in &records {
        let path = run.join(rel);
        if std::fs::symlink_metadata(&path).is_ok() {
            continue;
        }
        let _ = match kind {
            Kind::Dir => std::fs::create_dir(&path),
            Kind::File(content) => std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&path)
                .and_then(|mut file| file.write_all(content)),
            Kind::Link(target) => std::os::unix::fs::symlink(target, &path),
        };
    }
}

/// Make the entry at `rel` what `records` says: keep it, rewrite it in
/// place, or remove it (the caller then creates what is missing).
fn reconcile(run: &Path, rel: &Path, depth: usize, records: &Records) {
    let path = run.join(rel);
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return;
    };
    let kind = meta.file_type();
    if is_special(kind) {
        return;
    }
    match records.get(rel) {
        Some(Kind::Dir) if kind.is_dir() => {
            if depth < MAX_DEPTH
                && let Ok(children) = std::fs::read_dir(&path)
            {
                for child in children.flatten() {
                    reconcile(run, &rel.join(child.file_name()), depth + 1, records);
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

/// Remove every file and link below `rel`, keeping the directories.
fn clear(run: &Path, rel: &Path, depth: usize) {
    let path = run.join(rel);
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return;
    };
    if meta.is_dir() {
        if depth < MAX_DEPTH
            && let Ok(children) = std::fs::read_dir(&path)
        {
            for child in children.flatten() {
                clear(run, &rel.join(child.file_name()), depth + 1);
            }
        }
    } else if !is_special(meta.file_type()) {
        let _ = std::fs::remove_file(&path);
    }
}

fn is_special(kind: std::fs::FileType) -> bool {
    kind.is_socket() || kind.is_fifo() || kind.is_block_device() || kind.is_char_device()
}

/// The copy's format: per entry a tag (`d`, `f` or `l`), then the path and
/// the data (file content, link target, nothing for a directory), each as a
/// little-endian `u32` length and its bytes.
fn encode(records: &Records) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, kind) in records {
        let (tag, data): (u8, &[u8]) = match kind {
            Kind::Dir => (b'd', &[]),
            Kind::File(content) => (b'f', content),
            Kind::Link(target) => (b'l', target.as_os_str().as_bytes()),
        };
        out.push(tag);
        for part in [path.as_os_str().as_bytes(), data] {
            out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_le_bytes());
            out.extend_from_slice(part);
        }
    }
    out
}

/// Parse [`encode`] output; `None` for anything malformed, or for a path
/// that is not below a record directory.
fn decode(mut bytes: &[u8]) -> Option<Records> {
    let mut records = Records::new();
    while let Some((&tag, rest)) = bytes.split_first() {
        let (path, rest) = take(rest)?;
        let (data, rest) = take(rest)?;
        bytes = rest;
        let path = PathBuf::from(OsStr::from_bytes(path));
        if !is_record_path(&path) {
            return None;
        }
        let kind = match tag {
            b'd' => Kind::Dir,
            b'f' => Kind::File(data.to_vec()),
            b'l' => Kind::Link(PathBuf::from(OsStr::from_bytes(data))),
            _ => return None,
        };
        records.insert(path, kind);
    }
    Some(records)
}

fn take(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
    (rest.len() >= len).then(|| rest.split_at(len))
}

/// Whether `path` is a plain relative path below one of [`RECORD_DIRS`].
fn is_record_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(
        components.next(),
        Some(Component::Normal(first)) if RECORD_DIRS.iter().any(|dir| OsStr::new(dir) == first)
    ) && components.all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    /// A decoy `/run` with openresolv's records, as NixOS keeps them.
    fn decoy_run() -> tempfile::TempDir {
        let run = tempfile::tempdir().unwrap();
        let r = run.path();
        for dir in ["resolvconf/keys", "resolvconf/metrics"] {
            fs::create_dir_all(r.join(dir)).unwrap();
        }
        fs::write(
            r.join("resolvconf/keys/NetworkManager"),
            "# Generated by NetworkManager\nnameserver 10.0.2.3\n",
        )
        .unwrap();
        fs::write(r.join("resolvconf/keys/static"), "").unwrap();
        fs::write(r.join("resolvconf/metrics/0000001 static"), "").unwrap();
        run
    }

    fn saved(run: &Path) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let to = dir.path().join("copy");
        save(run, &to).unwrap();
        fs::read(&to).unwrap()
    }

    #[test]
    fn the_decoy_s_records_come_back_and_the_hidden_session_s_go() {
        let run = decoy_run();
        let r = run.path();
        let copy = saved(r);
        let key = r.join("resolvconf/keys/NetworkManager");
        let inode = fs::metadata(&key).unwrap().ino();
        // The hidden session: NetworkManager rewrites its record, a VPN adds
        // one, and a record and a metric go.
        fs::write(&key, "search hidden.example\nnameserver 10.213.77.53\n").unwrap();
        fs::write(
            r.join("resolvconf/keys/tun0.openvpn"),
            "nameserver 10.8.0.1\n",
        )
        .unwrap();
        fs::create_dir_all(r.join("resolvconf/private/x")).unwrap();
        fs::remove_file(r.join("resolvconf/keys/static")).unwrap();
        fs::remove_file(r.join("resolvconf/metrics/0000001 static")).unwrap();
        fs::write(r.join("resolvconf/metrics/0000002 tun0.openvpn"), "").unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            r.join("resolvconf/lock.sock"),
            rustix::fs::FileType::Socket,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        restore(r, Some(&copy));

        assert_eq!(
            fs::read_to_string(&key).unwrap(),
            "# Generated by NetworkManager\nnameserver 10.0.2.3\n"
        );
        assert_eq!(
            fs::metadata(&key).unwrap().ino(),
            inode,
            "rewritten in place"
        );
        for gone in [
            "resolvconf/keys/tun0.openvpn",
            "resolvconf/private",
            "resolvconf/metrics/0000002 tun0.openvpn",
        ] {
            assert!(fs::symlink_metadata(r.join(gone)).is_err(), "{gone}");
        }
        assert_eq!(
            fs::read_to_string(r.join("resolvconf/keys/static")).unwrap(),
            ""
        );
        assert!(r.join("resolvconf/metrics/0000001 static").is_file());
        assert!(
            fs::symlink_metadata(r.join("resolvconf/lock.sock")).is_ok(),
            "a socket is never touched"
        );
        assert_eq!(saved(r), copy, "the decoy's state, entry for entry");
    }

    #[test]
    fn records_the_decoy_did_not_have_are_removed_whole() {
        let run = tempfile::tempdir().unwrap();
        let r = run.path();
        let copy = saved(r);
        fs::create_dir_all(r.join("resolvconf/keys")).unwrap();
        fs::write(
            r.join("resolvconf/keys/NetworkManager"),
            "nameserver 10.213.77.53\n",
        )
        .unwrap();
        restore(r, Some(&copy));
        assert!(!r.join("resolvconf").exists());
    }

    #[test]
    fn without_a_trusted_copy_every_record_goes_and_the_directories_stay() {
        for copy in [
            None,
            Some(b"f\x04\x00\x00\x00../x\x00\x00\x00\x00".to_vec()),
            Some(b"f\xff\x00\x00\x00resolvconf".to_vec()),
            Some(b"q\x0a\x00\x00\x00resolvconf\x00\x00\x00\x00".to_vec()),
        ] {
            let run = decoy_run();
            let r = run.path();
            restore(r, copy.as_deref());
            assert!(r.join("resolvconf/keys").is_dir(), "{copy:?}");
            assert!(
                !r.join("resolvconf/keys/NetworkManager").exists(),
                "{copy:?}"
            );
            assert!(
                !r.join("resolvconf/metrics/0000001 static").exists(),
                "{copy:?}"
            );
        }
    }

    #[test]
    fn the_copy_round_trips_and_names_only_record_paths() {
        let run = decoy_run();
        let records = decode(&saved(run.path())).unwrap();
        assert_eq!(records.len(), 6);
        assert_eq!(
            records.get(Path::new("resolvconf/keys/static")),
            Some(&Kind::File(Vec::new()))
        );
        assert!(is_record_path(Path::new("resolvconf/keys/x")));
        for bad in ["/run/resolvconf", "resolvconf/../etc", "other/keys", ""] {
            assert!(!is_record_path(Path::new(bad)), "{bad}");
        }
    }
}
