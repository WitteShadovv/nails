// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the hidden session leaves in `/run`, and the scrub that removes it on
//! the way back.
//!
//! A soft-reboot carries `/run` into the next userspace. On the way back the
//! decoy would inherit everything the hidden session put there: logind state,
//! `utmp`, the runtime journal, stray files, and libmount's `utab` lines. The
//! scrub runs as the last userspace code before the switch, when every hidden
//! unit has stopped, and deletes:
//!
//! - the per-session state of units that are all stopped by now (the runtime
//!   journal, logind's sessions/users/seats/inhibitors, `utmp`) and the empty
//!   mountpoint directories of `/run/user/<uid>`. This state is deleted whole,
//!   whoever wrote it. The decoy's journald and the hidden one write the same
//!   files below `/run/log/journal/<machine-id>`, so on a volatile decoy the
//!   decoy's own records from before the entry go too (the activation's sudo
//!   line, the hidden build's progress, the decoy's shutdown). After the return
//!   the decoy journal starts at the switch, and since the kmsg cursor (below)
//!   lies past the kernel's boot records, it holds none of them either. A
//!   persistent journal keeps the decoy's records in `/var/log/journal`, which
//!   the scrub never touches;
//! - every entry up to two levels below `/run` (three below `/run/systemd`,
//!   where runtime unit files live) that is not in the snapshot. The entry
//!   takes it in the decoy before it adds anything to `/run`, and the switch
//!   into the hidden session narrows it to the entries the decoy's own
//!   shutdown left ([`Snapshot::still_present`]): the PID file of a decoy
//!   service, removed when the service stopped and written again by the
//!   hidden session's copy of it, goes too. A mount among them is detached
//!   first.
//!
//! It never touches a socket (PID 1 and the never-stopped socket units carry
//! them as fds bound to these inodes), `/run/udev` (the device database the
//! decoy's device units are rebuilt from: deleting it sent the spike's decoy
//! into emergency mode), `/run/credentials`, `/run/current-system`,
//! `/run/booted-system` or `/run/nextroot`. Deleting decoy state the next boot
//! relies on is what broke the spike's second run, hence the allowlist.
//!
//! The scrub then restores `utab` to the decoy's copy, and the caller writes the
//! kmsg cursor ([`next_kernel_seqnum`], [`write_kernel_seqnum`]) so the decoy
//! journald skips every kernel record of the hidden session, and every earlier
//! one with them. Nothing here logs: a name written to `/dev/kmsg` would reach
//! the decoy's ring buffer.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Top-level `/run` entries the snapshot and the scrub never look into.
const PRUNED: &[&str] = &[
    "nextroot",
    "udev",
    "credentials",
    "current-system",
    "booted-system",
];

/// Directories below `/run` whose children are the state of units that have
/// all stopped when the scrub runs. Every child goes, the decoy's included:
/// `log/journal` holds the decoy's runtime journal as well as the hidden
/// session's records, in the same files.
const SESSION_STATE_DIRS: &[&str] = &[
    "log/journal",
    "systemd/sessions",
    "systemd/users",
    "systemd/seats",
    "systemd/inhibit",
    "systemd/shutdown",
];

/// Files below `/run` that are per-session state.
const SESSION_STATE_FILES: &[&str] = &["utmp"];

/// The `/run` subtree listed one level deeper than the rest.
const DEEP_DIR: &str = "systemd";

/// The entries of a `/run` tree, as paths relative to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    entries: BTreeSet<OsString>,
}

impl Snapshot {
    /// List `run`: every entry up to two levels deep (three below
    /// `systemd/`), without crossing into another filesystem and without the
    /// pruned entries.
    pub fn take(run: &Path) -> Self {
        Self {
            entries: list(run).into_iter().collect(),
        }
    }

    /// Read a snapshot written with [`to_text`](Self::to_text); `None` when
    /// the file cannot be read.
    pub fn load(path: &Path) -> Option<Self> {
        std::fs::read(path).ok().map(|text| Self::from_text(&text))
    }

    /// Whether the snapshot holds `relative`.
    pub fn contains(&self, relative: &OsStr) -> bool {
        self.entries.contains(relative)
    }

    /// The entries that still exist below `run`. An entry whose lookup fails
    /// for any reason other than its absence stays, and so does every entry
    /// when `run` itself cannot be looked up: dropping an entry lets the scrub
    /// delete it, so only a certain absence counts.
    pub fn still_present(&self, run: &Path) -> Self {
        if std::fs::symlink_metadata(run).is_err() {
            return self.clone();
        }
        Self {
            entries: self
                .entries
                .iter()
                .filter(|entry| {
                    !matches!(
                        std::fs::symlink_metadata(run.join(entry)),
                        Err(e) if e.kind() == io::ErrorKind::NotFound
                    )
                })
                .cloned()
                .collect(),
        }
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The snapshot as text: one entry per line, `\` and newlines escaped.
    pub fn to_text(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in &self.entries {
            for &byte in entry.as_bytes() {
                match byte {
                    b'\\' => out.extend_from_slice(b"\\\\"),
                    b'\n' => out.extend_from_slice(b"\\n"),
                    other => out.push(other),
                }
            }
            out.push(b'\n');
        }
        out
    }

    /// Parse [`to_text`](Self::to_text) output.
    pub fn from_text(text: &[u8]) -> Self {
        let mut entries = BTreeSet::new();
        for line in text.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let mut bytes = Vec::with_capacity(line.len());
            let mut escaped = false;
            for &byte in line {
                match (escaped, byte) {
                    (false, b'\\') => escaped = true,
                    (true, b'n') => {
                        bytes.push(b'\n');
                        escaped = false;
                    }
                    (true, other) => {
                        bytes.push(other);
                        escaped = false;
                    }
                    (false, other) => bytes.push(other),
                }
            }
            entries.insert(OsString::from_vec(bytes));
        }
        Self { entries }
    }
}

/// The listing behind [`Snapshot::take`].
fn list(run: &Path) -> Vec<OsString> {
    let Ok(meta) = std::fs::symlink_metadata(run) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(run, Path::new(""), meta.dev(), 1, &mut out);
    out
}

fn max_depth(relative: &Path) -> usize {
    if relative.starts_with(DEEP_DIR) { 3 } else { 2 }
}

fn walk(run: &Path, relative: &Path, dev: u64, depth: usize, out: &mut Vec<OsString>) {
    let Ok(children) = std::fs::read_dir(run.join(relative)) else {
        return;
    };
    for child in children.flatten() {
        let name = child.file_name();
        if depth == 1 && PRUNED.iter().any(|p| OsStr::new(p) == name) {
            continue;
        }
        let rel = relative.join(&name);
        out.push(rel.clone().into_os_string());
        let Ok(meta) = child.metadata() else {
            continue;
        };
        // `metadata()` on a DirEntry does not follow symlinks.
        if meta.is_dir() && meta.dev() == dev && depth < max_depth(&rel) {
            walk(run, &rel, dev, depth + 1, out);
        }
    }
}

/// What the scrub did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScrubReport {
    /// Entries removed, relative to the `/run` root.
    pub removed: Vec<PathBuf>,
    /// Entries that could not be removed, with the error.
    pub failed: Vec<(PathBuf, String)>,
    /// Mounts detached because they sat on an entry being removed.
    pub detached: Vec<PathBuf>,
}

/// Remove from `run` the per-session state (the runtime journal among it,
/// whoever wrote it) and what else the hidden session added, judged against
/// `snapshot`.
///
/// `extra` names entries (relative to `run`) to remove even when the snapshot
/// holds them: the runtime directory of NAILS itself. `mount_points` is the
/// live mount table's mount points; a mount on or below a removed entry is
/// detached first. See the module docs for what is kept.
pub fn scrub(
    run: &Path,
    snapshot: &Snapshot,
    extra: &[&str],
    mount_points: &[PathBuf],
) -> ScrubReport {
    let mut report = ScrubReport::default();
    for dir in SESSION_STATE_DIRS {
        if let Ok(children) = std::fs::read_dir(run.join(dir)) {
            for child in children.flatten() {
                remove(
                    run,
                    &Path::new(dir).join(child.file_name()),
                    mount_points,
                    &mut report,
                );
            }
        }
    }
    for file in SESSION_STATE_FILES {
        remove(run, Path::new(file), mount_points, &mut report);
    }
    if let Ok(children) = std::fs::read_dir(run.join("user")) {
        for child in children.flatten() {
            // Only empty mountpoint directories: a populated one is a tmpfs
            // that is still mounted, which the switch drops anyway.
            let _ = std::fs::remove_dir(child.path());
        }
    }
    for entry in list(run) {
        let relative = PathBuf::from(&entry);
        let forced = extra.iter().any(|e| Path::new(e) == relative);
        if forced || !snapshot.contains(&entry) {
            remove(run, &relative, mount_points, &mut report);
        }
    }
    for name in extra {
        remove(run, Path::new(name), mount_points, &mut report);
    }
    report
}

/// Remove one entry, unless it is a socket or already gone.
fn remove(run: &Path, relative: &Path, mount_points: &[PathBuf], report: &mut ScrubReport) {
    let path = run.join(relative);
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return;
    };
    if meta.file_type().is_socket() {
        return;
    }
    if meta.is_dir() {
        for detached in crate::whole_root::nextroot::detach_under(&path, mount_points) {
            report.detached.push(detached);
        }
    }
    let result = if meta.is_dir() {
        std::fs::remove_dir_all(&path)
    } else {
        std::fs::remove_file(&path)
    };
    match result {
        Ok(()) => report.removed.push(relative.to_path_buf()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => report.failed.push((relative.to_path_buf(), e.to_string())),
    }
}

/// libmount's userspace mount table below a `/run` root.
pub const UTAB: &str = "mount/utab";

/// Restore `run/mount/utab` to `saved`, the decoy's copy taken at entry. Every
/// userspace start appends lines for its `x-*` mounts and mounts dropped by the
/// switch are never removed, so the hidden session's lines would otherwise
/// name hidden mount targets in the decoy's `/run`. A missing file stays
/// missing.
pub fn restore_utab(run: &Path, saved: &[u8]) -> io::Result<bool> {
    let path = run.join(UTAB);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(false);
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)?;
    file.write_all(saved)?;
    Ok(true)
}

/// The sequence number of one `/dev/kmsg` record (`prio,seq,ts,flags;text`).
pub fn record_seqnum(record: &[u8]) -> Option<u64> {
    let header = record.split(|&b| b == b';').next()?;
    let seq = header.split(|&b| b == b',').nth(1)?;
    std::str::from_utf8(seq).ok()?.parse().ok()
}

/// The highest sequence number in a buffer of kmsg records. A read of
/// `/dev/kmsg` returns one record; continuation lines start with a space.
fn highest_in(buffer: &[u8]) -> Option<u64> {
    buffer
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty() && line[0] != b' ')
        .filter_map(record_seqnum)
        .max()
}

/// One past the last record in the kernel ring buffer at `kmsg` (normally
/// `/dev/kmsg`), read without blocking. A read that returns `EPIPE` (the
/// record was overwritten while reading) is retried, so the cursor never comes
/// out too low. `None` when nothing could be read.
pub fn next_kernel_seqnum(kmsg: &Path) -> Option<u64> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(kmsg)
        .ok()?;
    let mut buffer = vec![0u8; 16 * 1024];
    let mut highest: Option<u64> = None;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(seq) = highest_in(&buffer[..n]) {
                    highest = Some(highest.map_or(seq, |h| h.max(seq)));
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    highest.map(|h| h + 1)
}

/// journald's kmsg cursor below a `/run` root.
pub const KERNEL_SEQNUM: &str = "systemd/journal/kernel-seqnum";

/// Write journald's kmsg cursor: the decoy journald skips every kernel record
/// whose sequence number is below `next`. journald maps the file as one
/// native-endian `u64`.
pub fn write_kernel_seqnum(run: &Path, next: u64) -> io::Result<()> {
    let path = run.join(KERNEL_SEQNUM);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(&path)?;
    file.write_all(&next.to_ne_bytes())?;
    file.set_len(8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn rel(s: &str) -> OsString {
        OsString::from(s)
    }

    /// A decoy `/run` the way a real one looks, two levels deep and more.
    fn decoy_run() -> tempfile::TempDir {
        let run = tempfile::tempdir().unwrap();
        let r = run.path();
        for dir in [
            "udev/data",
            "systemd/journal",
            "systemd/system",
            "systemd/sessions",
            "credentials/x",
            "log/journal",
            "mount",
            "user",
            "lock",
        ] {
            fs::create_dir_all(r.join(dir)).unwrap();
        }
        fs::write(r.join("udev/data/b8:0"), "E:ID=1").unwrap();
        fs::write(r.join("systemd/system/decoy.service"), "").unwrap();
        fs::write(r.join("mount/utab"), "ID=1 decoy\n").unwrap();
        fs::write(r.join("decoy-file"), "").unwrap();
        std::os::unix::fs::symlink("/nix/store/aaa", r.join("current-system")).unwrap();
        run
    }

    #[test]
    fn the_snapshot_lists_two_levels_three_below_systemd_and_skips_pruned_entries() {
        let run = decoy_run();
        fs::create_dir_all(run.path().join("lock/a/b/c")).unwrap();
        let snap = Snapshot::take(run.path());
        assert!(snap.contains(&rel("systemd/system/decoy.service")));
        assert!(snap.contains(&rel("lock/a")));
        assert!(!snap.contains(&rel("lock/a/b")));
        assert!(!snap.contains(&rel("udev")));
        assert!(!snap.contains(&rel("udev/data")));
        assert!(!snap.contains(&rel("current-system")));
        assert!(!snap.contains(&rel("credentials")));
    }

    #[test]
    fn the_snapshot_text_round_trips_awkward_names() {
        let run = tempfile::tempdir().unwrap();
        fs::write(run.path().join("a\nb"), "").unwrap();
        fs::write(run.path().join("back\\slash"), "").unwrap();
        fs::write(run.path().join(OsStr::from_bytes(b"bin\xff")), "").unwrap();
        let snap = Snapshot::take(run.path());
        assert_eq!(snap.len(), 3);
        assert_eq!(Snapshot::from_text(&snap.to_text()), snap);
    }

    #[test]
    fn the_scrub_removes_only_what_the_hidden_session_added() {
        let run = decoy_run();
        let r = run.path();
        let snap = Snapshot::take(r);
        // The hidden session.
        fs::write(r.join("hidden-probe"), "x").unwrap();
        fs::create_dir_all(r.join("probe-dir/nested")).unwrap();
        fs::write(r.join("probe-dir/nested/file"), "x").unwrap();
        fs::write(r.join("systemd/hidden-probe"), "x").unwrap();
        fs::create_dir_all(r.join("systemd/system/systemd-soft-reboot.service.d")).unwrap();
        fs::write(r.join("log/journal/probe"), "x").unwrap();
        fs::write(r.join("systemd/sessions/2"), "x").unwrap();
        fs::write(r.join("utmp"), "x").unwrap();
        fs::create_dir_all(r.join("user/1000")).unwrap();
        fs::write(r.join("udev/data/c1:1"), "hidden device").unwrap();
        fs::create_dir_all(r.join("overlay-runtime")).unwrap();
        fs::write(r.join("overlay-runtime/plan.json"), "{}").unwrap();
        // A socket inode, the way a carried socket unit leaves one (mknod needs
        // no privilege for a socket, unlike binding one in a sandbox).
        rustix::fs::mknodat(
            rustix::fs::CWD,
            r.join("hidden.sock"),
            rustix::fs::FileType::Socket,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();

        let report = scrub(r, &snap, &["overlay-runtime"], &[]);
        assert!(report.failed.is_empty(), "{:?}", report.failed);

        for gone in [
            "hidden-probe",
            "probe-dir",
            "systemd/hidden-probe",
            "systemd/system/systemd-soft-reboot.service.d",
            "log/journal/probe",
            "systemd/sessions/2",
            "utmp",
            "user/1000",
            "overlay-runtime",
        ] {
            assert!(!r.join(gone).exists(), "{gone} survived the scrub");
        }
        for kept in [
            "decoy-file",
            "systemd/system/decoy.service",
            "mount/utab",
            "udev/data/b8:0",
            "udev/data/c1:1",
            "credentials/x",
            "log/journal",
            "systemd/sessions",
            "user",
            "hidden.sock",
        ] {
            assert!(
                fs::symlink_metadata(r.join(kept)).is_ok(),
                "{kept} was removed"
            );
        }
        assert_eq!(
            fs::read_link(r.join("current-system")).unwrap(),
            Path::new("/nix/store/aaa")
        );
    }

    #[test]
    fn a_snapshot_narrowed_to_what_is_still_there_drops_only_the_entries_that_are_gone() {
        let run = decoy_run();
        let r = run.path();
        fs::create_dir_all(r.join("avahi-daemon")).unwrap();
        fs::write(r.join("avahi-daemon/pid"), "100").unwrap();
        let snap = Snapshot::take(r);
        // The decoy's own shutdown: the service removed its PID file.
        fs::remove_file(r.join("avahi-daemon/pid")).unwrap();
        let narrowed = snap.still_present(r);
        assert!(!narrowed.contains(&rel("avahi-daemon/pid")));
        assert!(narrowed.contains(&rel("avahi-daemon")));
        assert_eq!(narrowed.len(), snap.len() - 1);
        // Without the /run it was taken of, nothing counts as gone.
        assert_eq!(snap.still_present(&r.join("absent")), snap);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot");
        fs::write(&path, narrowed.to_text()).unwrap();
        assert_eq!(Snapshot::load(&path), Some(narrowed));
        assert_eq!(Snapshot::load(&dir.path().join("absent")), None);
    }

    #[test]
    fn a_user_runtime_dir_the_hidden_session_added_is_removed() {
        let run = decoy_run();
        let snap = Snapshot::take(run.path());
        fs::create_dir_all(run.path().join("user/1000/bus")).unwrap();
        let report = scrub(run.path(), &snap, &[], &[]);
        // Two levels deep and not in the snapshot: its tmpfs was not carried,
        // so what is left is the hidden session's.
        assert!(report.removed.contains(&PathBuf::from("user/1000")));
    }

    #[test]
    fn utab_is_restored_and_a_missing_one_stays_missing() {
        let run = decoy_run();
        fs::write(run.path().join(UTAB), "ID=1 decoy\nID=99 hidden\n").unwrap();
        assert!(restore_utab(run.path(), b"ID=1 decoy\n").unwrap());
        assert_eq!(
            fs::read_to_string(run.path().join(UTAB)).unwrap(),
            "ID=1 decoy\n"
        );
        let empty = tempfile::tempdir().unwrap();
        assert!(!restore_utab(empty.path(), b"x").unwrap());
        assert!(!empty.path().join(UTAB).exists());
    }

    #[test]
    fn kmsg_records_are_read_to_one_past_the_highest_sequence_number() {
        assert_eq!(record_seqnum(b"6,1234,5678,-;hello"), Some(1234));
        assert_eq!(record_seqnum(b"6,x,5678,-;hello"), None);
        assert_eq!(record_seqnum(b"garbage"), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kmsg");
        fs::write(
            &path,
            "6,10,1,-;first\n SUBSYSTEM=x\n4,12,2,c;second; with semicolon\n6,11,3,-;out of order\n",
        )
        .unwrap();
        assert_eq!(next_kernel_seqnum(&path), Some(13));
        fs::write(&path, "").unwrap();
        assert_eq!(next_kernel_seqnum(&path), None);
        assert_eq!(next_kernel_seqnum(&dir.path().join("absent")), None);
    }

    #[test]
    fn the_kmsg_cursor_is_one_native_endian_u64() {
        let run = tempfile::tempdir().unwrap();
        let path = run.path().join(KERNEL_SEQNUM);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, [0xffu8; 16]).unwrap();
        write_kernel_seqnum(run.path(), 0x0102_0304).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(u64::from_ne_bytes(bytes.try_into().unwrap()), 0x0102_0304);
    }
}
