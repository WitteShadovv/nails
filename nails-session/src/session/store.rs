// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keeping the hidden NixOS system on the hidden volume.
//!
//! The hidden toplevel is built into the next root's store, which is an
//! overlay over the decoy's: new paths land in the upper on the hidden volume,
//! but every path the hidden closure shares with the decoy is read from the
//! lower, while the hidden store database (copied up at the first build) keeps
//! listing it as valid. A decoy that garbage-collects or rebuilds between two
//! sessions can delete such a path, and the hidden system then fails to start
//! with nix none the wiser.
//!
//! So at every entry with a hidden NixOS system, after the build and before
//! the activation:
//!
//! 1. [`forget_vanished`] runs `nix-store --verify` against the next root's
//!    store, so paths the decoy deleted since the last session drop out of the
//!    hidden database and the build realises them again instead of trusting
//!    them (it runs before the build);
//! 2. [`keep_closure`] copies every path of the hidden toplevel's closure
//!    that is still read from the decoy store **up into the overlay's upper**,
//!    through the overlay itself: opening a file for writing, or changing a
//!    directory's or symlink's owner to the one it has, makes overlayfs copy
//!    it up whole, with its mode, owner and times. The lower is a read-only
//!    bind, so nothing is ever written to the decoy store. A record on the
//!    hidden volume lists the paths already kept, so a later entry copies
//!    only the paths that are new to the closure.
//!
//! Afterwards the hidden closure lives entirely on the hidden volume: a path
//! the decoy deletes later disappears from the lower only, and the copy in the
//! upper keeps serving it. The cost is the space and time of one copy of the
//! closure at the first entry (the whole system, several GB for a desktop),
//! and of the new paths at later ones. A separate store on the hidden volume
//! would cost more: it would need every build input copied in, the
//! evaluation's sources included, and a decoy binary cache to substitute from.

use crate::error::{NailsError, Result};
use crate::process::{ProcessCommand, ProcessRunner};
use nails_teardown::mountinfo::{MountEntry, parse_overlay_opts, top_mount_at};
use std::collections::BTreeSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long `nix-store --verify` may take before the entry goes on without it.
const VERIFY_BUDGET: Duration = Duration::from_secs(600);

/// Space kept free on the hidden volume beyond the copy itself, in bytes.
const SPACE_MARGIN: u64 = 64 * 1024 * 1024;

/// How often a long copy reports that it is still running.
const HEARTBEAT: Duration = Duration::from_secs(15);

/// What [`keep_closure`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeepReport {
    /// Paths in the closure.
    pub paths: usize,
    /// Paths that had to be copied up this time.
    pub copied: usize,
    /// Entries (files, directories, symlinks) copied up.
    pub files: usize,
    /// Bytes copied up (file sizes, rounded up to 4 KiB).
    pub bytes: u64,
    /// How long the check and the copy took.
    pub elapsed: Duration,
}

fn nix_store(store_root: &Path) -> ProcessCommand {
    ProcessCommand::caller_path("nix-store")
        .arg("--store")
        .arg(store_root)
        .allow_in_test_runtime()
}

/// Drop the paths that no longer exist from the next root's store database
/// (`nix-store --verify`, without checking contents). Best-effort: returns
/// whether it ran cleanly; a path that vanished while a present path still
/// refers to it is reported by nix and left alone.
pub fn forget_vanished(runner: &dyn ProcessRunner, store_root: &Path) -> bool {
    let command = nix_store(store_root)
        .arg("--verify")
        .deadline(VERIFY_BUDGET);
    crate::reporter::progress::detail("nixos_build", "checking the hidden store database");
    let started = Instant::now();
    let result = runner.run_text(&command);
    tracing::debug!(
        seconds = started.elapsed().as_secs_f64(),
        "hidden store database checked"
    );
    match result {
        Ok((true, _, _)) => true,
        Ok((false, _, stderr)) => {
            tracing::warn!(
                stderr = %stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | "),
                "the hidden store database lists paths that are gone"
            );
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not check the hidden store database");
            false
        }
    }
}

/// The closure of `system` in the next root's store.
pub fn closure(
    runner: &dyn ProcessRunner,
    store_root: &Path,
    system: &Path,
) -> Result<Vec<PathBuf>> {
    let command = nix_store(store_root)
        .args(["--query", "--requisites"])
        .arg(system);
    let (ok, stdout, stderr) = runner.run_text(&command)?;
    if !ok {
        return Err(NailsError::NixOSError(format!(
            "could not list the hidden system's store paths: {}",
            stderr.lines().last().unwrap_or("no output")
        )));
    }
    Ok(stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("/nix/store/"))
        .map(PathBuf::from)
        .collect())
}

/// The directory in an overlay's upper that holds the store of the next root
/// at `store_root`, or `None` when that store is not an overlay (then nothing
/// is read from the decoy and there is nothing to keep).
pub fn store_upper(mounts: &[MountEntry], store_root: &Path) -> Option<PathBuf> {
    let store = store_root.join("nix/store");
    let mount = store.ancestors().find_map(|at| top_mount_at(mounts, at))?;
    if mount.fstype != "overlay" {
        return None;
    }
    let upper = parse_overlay_opts(&mount.super_opts).upperdir?;
    let rest = store.strip_prefix(&mount.mount_point).ok()?;
    Some(upper.join(rest))
}

/// The paths already kept, from the record.
fn read_record(record: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(record)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

fn write_record(record: &Path, kept: &BTreeSet<String>) -> Result<()> {
    let mut text = String::new();
    for name in kept {
        text.push_str(name);
        text.push('\n');
    }
    if let Some(dir) = record.parent() {
        std::fs::create_dir_all(dir).map_err(|e| NailsError::io(dir, e))?;
    }
    nails_teardown::whole_root::plan::write_private_atomic(record, text.as_bytes())
        .map_err(|e| NailsError::io(record, e))
}

/// Whether `upper/<name>` holds the path itself (not a whiteout).
fn in_upper(upper: &Path, name: &str) -> bool {
    std::fs::symlink_metadata(upper.join(name))
        .is_ok_and(|m| !(m.file_type().is_char_device() && m.rdev() == 0))
}

fn round_up(size: u64) -> u64 {
    size.div_ceil(4096) * 4096
}

/// One copy-up: a regular file (with its size), or a directory or symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    File(PathBuf, u64),
    Attributes(PathBuf),
}

impl Item {
    fn bytes(&self) -> u64 {
        match self {
            Item::File(_, size) => round_up(*size),
            Item::Attributes(_) => 4096,
        }
    }

    /// Copy this entry (inside an overlay) up into the overlay's upper.
    fn copy_up(&self) -> std::io::Result<()> {
        match self {
            // Opening for writing copies the data up; nothing is written.
            Item::File(path, _) => std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc_flags())
                .open(path)
                .map(drop),
            // A directory or symlink is copied up by any attribute change,
            // and setting the owner it already has changes nothing else.
            Item::Attributes(path) => {
                let meta = std::fs::symlink_metadata(path)?;
                std::os::unix::fs::lchown(path, Some(meta.uid()), Some(meta.gid()))
            }
        }
    }
}

/// The copy-ups the tree at `merged` still needs: every entry without a
/// counterpart at `upper` (a directory already in the upper is still walked,
/// its children may not be).
fn pending(merged: &Path, upper: &Path, items: &mut Vec<Item>) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(merged)?;
    let copied = std::fs::symlink_metadata(upper).is_ok();
    if meta.is_file() {
        if !copied {
            items.push(Item::File(merged.to_path_buf(), meta.len()));
        }
        return Ok(());
    }
    if !copied {
        items.push(Item::Attributes(merged.to_path_buf()));
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(merged)? {
            let name = entry?.file_name();
            pending(&merged.join(&name), &upper.join(&name), items)?;
        }
    }
    Ok(())
}

/// How many copy-ups run at once. overlayfs syncs every file it copies up, so
/// one at a time waits on the disk for each file (several ms on an encrypted
/// SSD, far more in a VM); many at once share the filesystem's journal
/// commits, about ten times faster.
const WORKERS: usize = 64;

/// Why [`copy_all`] stopped before the end.
#[derive(Debug)]
enum CopyStop {
    /// A copy-up failed.
    Failed(PathBuf, std::io::Error),
    /// A SIGINT or SIGTERM asked to cancel the entry.
    Cancelled,
}

/// Run every copy-up on [`WORKERS`] threads, reporting progress every
/// [`HEARTBEAT`]. Stops at the first error, and on a cancel: the calling
/// thread asks [`crate::cancel`] between its progress checks, and the workers
/// finish the copy-ups they hold and take no more.
fn copy_all(items: &[Item]) -> std::result::Result<(), CopyStop> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    if crate::cancel::is_cancelled() {
        return Err(CopyStop::Cancelled);
    }
    let next = AtomicUsize::new(0);
    let finished = AtomicUsize::new(0);
    let copied_bytes = AtomicU64::new(0);
    let failure: Mutex<Option<(PathBuf, std::io::Error)>> = Mutex::new(None);
    let cancelled = AtomicBool::new(false);
    let total_bytes: u64 = items.iter().map(Item::bytes).sum();
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..WORKERS.min(items.len()) {
            scope.spawn(|| {
                loop {
                    let failed = cancelled.load(Ordering::Relaxed)
                        || failure.lock().map(|f| f.is_some()).unwrap_or(true);
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if failed || index >= items.len() {
                        break;
                    }
                    let item = &items[index];
                    if let Err(e) = item.copy_up() {
                        let path = match item {
                            Item::File(p, _) | Item::Attributes(p) => p.clone(),
                        };
                        if let Ok(mut slot) = failure.lock() {
                            slot.get_or_insert((path, e));
                        }
                    }
                    copied_bytes.fetch_add(item.bytes(), Ordering::Relaxed);
                    finished.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        let mut beat = Instant::now();
        while finished.load(Ordering::Relaxed) < items.len()
            && failure.lock().map(|f| f.is_none()).unwrap_or(false)
        {
            std::thread::sleep(Duration::from_millis(200));
            if crate::cancel::is_cancelled() {
                cancelled.store(true, Ordering::Relaxed);
                break;
            }
            if beat.elapsed() >= HEARTBEAT {
                beat = Instant::now();
                crate::reporter::progress::detail(
                    "nixos_build",
                    &format!(
                        "copied {} of {} MB of the hidden system ({} s)",
                        copied_bytes.load(Ordering::Relaxed) / (1024 * 1024),
                        total_bytes.div_ceil(1024 * 1024),
                        started.elapsed().as_secs()
                    ),
                );
            }
        }
    });
    if cancelled.into_inner() {
        return Err(CopyStop::Cancelled);
    }
    match failure.into_inner().ok().flatten() {
        Some((path, e)) => Err(CopyStop::Failed(path, e)),
        None => Ok(()),
    }
}

/// `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`: never follow a symlink, never block
/// on a special file, never take a terminal.
fn libc_flags() -> i32 {
    use rustix::fs::OFlags;
    (OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY).bits() as i32
}

/// Copy every path of `closure` that the next root at `store_root` still reads
/// from the decoy store up into the store overlay's upper on the hidden
/// volume. `record` lists the paths kept by earlier entries; `mounts` is the
/// live mount table. Refuses before copying anything when the hidden volume
/// lacks the space.
pub fn keep_closure(
    store_root: &Path,
    closure: &[PathBuf],
    record: &Path,
    mounts: &[MountEntry],
) -> Result<KeepReport> {
    let started = Instant::now();
    let mut report = KeepReport {
        paths: closure.len(),
        ..KeepReport::default()
    };
    let Some(upper) = store_upper(mounts, store_root) else {
        return Ok(report);
    };
    let merged = store_root.join("nix/store");
    let mut kept = read_record(record);
    let names: Vec<String> = closure
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect();
    let todo: Vec<&String> = names
        .iter()
        .filter(|name| !(kept.contains(*name) && in_upper(&upper, name)))
        .collect();
    if todo.is_empty() {
        return Ok(report);
    }
    crate::reporter::progress::detail(
        "nixos_build",
        &format!(
            "checking {} store paths of the hidden system on the hidden volume",
            todo.len()
        ),
    );
    let mut items = Vec::new();
    for name in &todo {
        let path = merged.join(name);
        if std::fs::symlink_metadata(&path).is_err() {
            return Err(NailsError::NixOSError(format!(
                "the hidden system needs /nix/store/{name}, which is gone from the store (the \
                 decoy deleted it before it was kept on the hidden volume); rebuild the hidden \
                 system with a binary cache, or reset its store with `discard /nix`"
            )));
        }
        pending(&path, &upper.join(name), &mut items).map_err(|e| NailsError::io(&path, e))?;
    }
    let needed: u64 = items.iter().map(Item::bytes).sum();
    let existing = upper
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(Path::new("/"));
    let stat = rustix::fs::statvfs(existing).map_err(|e| NailsError::io(existing, e.into()))?;
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    if needed.saturating_add(SPACE_MARGIN) > available {
        return Err(NailsError::InvalidState(format!(
            "keeping the hidden system on the hidden volume needs {} MB, and it has {} MB free",
            needed.div_ceil(1024 * 1024),
            available / (1024 * 1024)
        )));
    }
    if !items.is_empty() {
        crate::reporter::progress::detail(
            "nixos_build",
            &format!(
                "copying {} files ({} MB) of {} store paths onto the hidden volume",
                items.len(),
                needed.div_ceil(1024 * 1024),
                todo.len()
            ),
        );
    }
    match copy_all(&items) {
        Ok(()) => {}
        // What was copied up stays in the upper on the hidden volume; the
        // record is not written, so the next entry checks those paths again
        // and copies what is still missing.
        Err(CopyStop::Cancelled) => return Err(NailsError::Cancelled),
        Err(CopyStop::Failed(path, e)) => {
            return Err(NailsError::InvalidState(format!(
                "could not copy {} onto the hidden volume: {e}",
                path.display()
            )));
        }
    }
    kept.extend(todo.iter().map(|n| (*n).clone()));
    write_record(record, &kept)?;
    report.copied = todo.len();
    report.files = items.len();
    report.bytes = needed;
    report.elapsed = started.elapsed();
    crate::reporter::progress::detail(
        "nixos_build",
        &format!(
            "kept the hidden system on the hidden volume: {} files, {} MB in {} s",
            report.files,
            needed.div_ceil(1024 * 1024),
            report.elapsed.as_secs()
        ),
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::mountinfo::parse_mountinfo;

    #[test]
    fn the_store_upper_follows_the_overlay_that_holds_the_store() {
        // The store on the root overlay: the root upper's nix/store.
        let root = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda rw\n\
             2 1 0:40 / /run/nextroot rw - overlay overlay rw,lowerdir=/l,upperdir=/mnt/data/root/upper,workdir=/w\n",
        );
        assert_eq!(
            store_upper(&root, Path::new("/run/nextroot")),
            Some(PathBuf::from("/mnt/data/root/upper/nix/store"))
        );
        // A separate store overlay (a VM's store share, a separate /nix/store).
        let separate = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda rw\n\
             2 1 0:40 / /run/nextroot rw - overlay overlay rw,upperdir=/u,workdir=/w\n\
             3 2 0:41 / /run/nextroot/nix/store rw - overlay overlay rw,upperdir=/mnt/data/root/mounts/nix-store/upper,workdir=/w2\n",
        );
        assert_eq!(
            store_upper(&separate, Path::new("/run/nextroot")),
            Some(PathBuf::from("/mnt/data/root/mounts/nix-store/upper"))
        );
        // Not an overlay: nothing is read from the decoy.
        let plain = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/vda rw\n\
             2 1 8:3 / /run/nextroot rw - ext4 /dev/vdb rw\n",
        );
        assert_eq!(store_upper(&plain, Path::new("/run/nextroot")), None);
    }

    #[test]
    fn the_record_round_trips_and_ignores_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("sub/store-kept");
        assert!(read_record(&record).is_empty());
        let kept: BTreeSet<String> = ["b-two", "a-one"].iter().map(|s| s.to_string()).collect();
        write_record(&record, &kept).unwrap();
        assert_eq!(std::fs::read_to_string(&record).unwrap(), "a-one\nb-two\n");
        std::fs::write(&record, "a-one\n\n  b-two \n").unwrap();
        assert_eq!(read_record(&record), kept);
    }

    #[test]
    fn pending_copy_ups_cover_only_what_the_upper_lacks() {
        let merged = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let path = merged.path().join("abc-pkg");
        std::fs::create_dir_all(path.join("bin")).unwrap();
        std::fs::write(path.join("bin/tool"), vec![0u8; 5000]).unwrap();
        std::fs::write(path.join("small"), "x").unwrap();
        let up = upper.path().join("abc-pkg");
        let bytes = |items: &[Item]| items.iter().map(Item::bytes).sum::<u64>();
        // Nothing in the upper: two directories and two files (8 KiB + 4 KiB).
        let mut items = Vec::new();
        pending(&path, &up, &mut items).unwrap();
        assert_eq!(items.len(), 4);
        assert_eq!(bytes(&items), 4096 * 2 + 8192 + 4096);
        // The directories and the tool are in the upper already.
        std::fs::create_dir_all(up.join("bin")).unwrap();
        std::fs::write(up.join("bin/tool"), "").unwrap();
        let mut items = Vec::new();
        pending(&path, &up, &mut items).unwrap();
        assert_eq!(items, vec![Item::File(path.join("small"), 1)]);
    }

    #[test]
    fn a_cancel_stops_the_copy_before_it_takes_another_path() {
        let merged = tempfile::tempdir().unwrap();
        let path = merged.path().join("abc-pkg");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("file"), "x").unwrap();
        let items = vec![Item::File(path.join("file"), 1)];
        crate::cancel::testing::request();
        let result = copy_all(&items);
        crate::cancel::testing::reset();
        assert!(matches!(result, Err(CopyStop::Cancelled)), "{result:?}");
        assert!(copy_all(&items).is_ok());
        assert!(copy_all(&[]).is_ok());
    }

    #[test]
    fn a_cancelled_copy_keeps_no_record() {
        // A store overlay whose upper is a plain directory: the copy-up of a
        // plain file is an open for writing, which changes nothing.
        let root = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("nix/store/abc-pkg")).unwrap();
        std::fs::write(root.path().join("nix/store/abc-pkg/file"), "x").unwrap();
        let mounts = parse_mountinfo(&format!(
            "1 0 8:2 / / rw - ext4 /dev/vda rw\n             2 1 0:40 / {} rw - overlay overlay rw,lowerdir=/l,upperdir={},workdir=/w\n",
            root.path().display(),
            upper.path().display()
        ));
        let record = root.path().join("record");
        crate::cancel::testing::request();
        let result = keep_closure(
            root.path(),
            &[PathBuf::from("/nix/store/abc-pkg")],
            &record,
            &mounts,
        );
        crate::cancel::testing::reset();
        assert!(matches!(result, Err(NailsError::Cancelled)), "{result:?}");
        assert!(!record.exists());
    }

    #[test]
    fn a_whiteout_in_the_upper_is_not_a_kept_path() {
        let upper = tempfile::tempdir().unwrap();
        assert!(!in_upper(upper.path(), "abc-pkg"));
        std::fs::create_dir(upper.path().join("abc-pkg")).unwrap();
        assert!(in_upper(upper.path(), "abc-pkg"));
    }

    #[test]
    fn a_store_that_is_not_layered_needs_nothing_kept() {
        let mounts = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda rw\n");
        let dir = tempfile::tempdir().unwrap();
        let report = keep_closure(
            dir.path(),
            &[PathBuf::from("/nix/store/abc-pkg")],
            &dir.path().join("record"),
            &mounts,
        )
        .unwrap();
        assert_eq!(
            report,
            KeepReport {
                paths: 1,
                ..KeepReport::default()
            }
        );
        assert!(!dir.path().join("record").exists());
    }
}
