// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Upper-filesystem capability pre-flight check
//!
//! Validates that the hidden root can host an overlayfs *upper* (and *work*)
//! layer before any real overlay is mounted.

use super::super::{CheckResult, PreFlightCheck};
use crate::config::get_default_hidden_volume_root;
use crate::{Filesystem, Result};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::mount::{FsMountFlags, FsOpenFlags, MountAttrFlags};
use std::path::{Path, PathBuf};

/// The overlay-upper capability a probe could not confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingCapability {
    /// Setting/removing a `trusted.*` xattr on the upper directory failed.
    TrustedXattr,
    /// `readdir` reports `DT_UNKNOWN`, so overlayfs cannot read directory types.
    DirEntryType,
    /// The throwaway trial overlay, with its layers in the scratch directory,
    /// could not be mounted or used.
    TrialOverlay,
}

/// Outcome of the host probe.
#[derive(Debug)]
enum ProbeError {
    /// A specific overlay-upper capability is unavailable on the hidden root.
    Missing(MissingCapability),
    /// The probe scaffolding itself failed (scratch dir, syscall wiring). The
    /// check then fails closed because it cannot prove the backend is usable.
    Scaffold(std::io::Error),
    /// The kernel gave no filesystem context to mount the trial overlay
    /// detached (`fsopen(2)` failed: no root, a kernel before Linux 5.2, or a
    /// sandbox that blocks the call). The probe never mounts it where a mount
    /// table would show it instead, so it stops before writing anything and
    /// the check fails closed.
    NoDetachedMount(std::io::Error),
}

/// Pre-flight check that the hidden root can back an overlayfs upper layer.
///
/// # Security
///
/// Kernel overlayfs needs an upper filesystem that supports `trusted.*` (or
/// `user.*`) xattrs, returns a valid `d_type` from `readdir`, and can store
/// whiteouts. NFS, CIFS/SMB, 9p and most FUSE mounts, and FAT/exFAT/NTFS, cannot
/// be an overlay upper. The real overlays mount *after* the session kill, so an
/// unusable backend discovered then is discovered too late — the decoy session
/// is already gone. This check runs before the kill and proves the backend up
/// front, failing closed.
///
/// # How it probes
///
/// Everything happens inside a throwaway `.probe-<unique>` directory on the
/// hidden root, removed on every path; nothing outside it, and nothing on the
/// decoy, is ever touched. The probe sets and removes a `trusted.*` xattr,
/// confirms `readdir` reports a file type, and trial-mounts a self-contained
/// overlay (lower/upper/work all inside the scratch dir) that it exercises with
/// a new file and a whiteout.
///
/// The trial overlay is mounted detached, through the mount API
/// (`fsopen`/`fsconfig`/`fsmount`): the kernel hands back a file descriptor for
/// the mount and attaches it nowhere. No mount table lists it, so neither
/// systemd nor any other process sees a mount come and go (a mount in PID 1's
/// namespace could make systemd log a `.mount` unit for it, a line naming the
/// hidden root that a persistent decoy journal keeps), and closing the
/// descriptor dissolves it, also when the process dies. When the kernel cannot
/// mount it detached, the check fails closed before anything is written: the
/// probe never falls back to a mount the system could see.
///
/// # Portability
///
/// The probe reads and writes the real hidden root through direct syscalls, so
/// it makes no NixOS-specific assumptions and the forthcoming non-NixOS backends
/// reuse it unchanged.
#[derive(Debug, Clone)]
pub struct UpperFsCapabilityCheck {
    hidden_volume_root: PathBuf,
}

impl UpperFsCapabilityCheck {
    /// Create a new `UpperFsCapabilityCheck` with a custom hidden-root path.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl Default for UpperFsCapabilityCheck {
    /// Create the check with the default hidden-volume path.
    fn default() -> Self {
        Self {
            hidden_volume_root: PathBuf::from(get_default_hidden_volume_root()),
        }
    }
}

/// Pure seam: build the actionable `Fail` for a missing overlay-upper capability.
///
/// Kept free of syscalls so the backend-specific message is unit-tested without a
/// real kernel. `fstype` is the filesystem the hidden root is on, when the mount
/// table knows it.
fn classify(missing: MissingCapability, fstype: Option<&str>) -> CheckResult {
    let cause = match missing {
        MissingCapability::TrustedXattr => {
            "setting and removing a trusted xattr on the upper directory failed"
        }
        MissingCapability::DirEntryType => {
            "the upper directory does not report file types from readdir (d_type is DT_UNKNOWN)"
        }
        MissingCapability::TrialOverlay => {
            "a throwaway overlay with its layers on the hidden root could not be mounted or used"
        }
    };

    let detected = match fstype {
        Some(fs) => format!(" The hidden root is on a {fs} filesystem."),
        None => String::new(),
    };

    CheckResult::fail(format!(
        "The hidden root cannot host an overlayfs upper layer: {cause}.{detected} \
         Overlayfs needs a local Linux filesystem that supports trusted (or user) \
         xattrs, a valid readdir d_type, and whiteouts; NFS, CIFS/SMB, 9p, most \
         FUSE mounts, and FAT/exFAT/NTFS cannot provide these. Reformat or mount \
         the hidden volume as ext4, xfs, btrfs, or f2fs."
    ))
}

impl<F: Filesystem> PreFlightCheck<F> for UpperFsCapabilityCheck {
    fn name(&self) -> &'static str {
        "upper-fs-capability"
    }

    fn description(&self) -> &'static str {
        "Validates the hidden root can host an overlayfs upper layer (xattrs, d_type, whiteouts)"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // The probe creates a scratch directory *on the hidden root* and builds
        // its trial overlay from layers inside it, so it must never run against
        // a root that is not a positively attached volume: a probe on an
        // unmounted mount point would drop a `.probe-*` directory onto the decoy
        // disk, the exact forensic leak the attach gate exists to prevent. The
        // registry already short-circuits this check once the `hidden-volume`
        // check, which asks the same attach gate, fails. Asking the gate here
        // too keeps the probe safe however this check is run. A root the
        // operator accepted with `--allow-decoy-storage` is not probed either:
        // the gate without the override refuses it. The hidden-volume check
        // owns the operator message, so an unattached root is a silent skip,
        // not a second failure.
        match crate::hidden_root::HiddenRoot::verify_attached(fs, &self.hidden_volume_root, false)?
        {
            crate::hidden_root::AttachState::Attached => {}
            crate::hidden_root::AttachState::Unattached(reason) => {
                return Ok(CheckResult::skipped(format!(
                    "upper-fs capability not probed; the hidden root is not attached: {reason}"
                )));
            }
        }

        // The probe writes to the real hidden root and mounts an overlay from
        // it, so there is nothing to probe under a test binary. Skip it there,
        // like every other host-touching check, so mock-driven preflight tests
        // stay hermetic; a real deployment always runs the probe.
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(CheckResult::Pass(
                "Upper-fs capability check skipped under the test runtime".into(),
            ));
        }

        Ok(self.verdict(
            fs,
            probe_upper_capabilities(&self.hidden_volume_root, overlay_context()),
        ))
    }
}

impl UpperFsCapabilityCheck {
    /// The check result for a host probe `outcome`, naming the hidden root's
    /// filesystem from `fs` when a capability is missing. Split from `run`,
    /// whose probe the test runtime skips, so the mapping is tested on its own.
    fn verdict<F: Filesystem>(
        &self,
        fs: &F,
        outcome: std::result::Result<(), ProbeError>,
    ) -> CheckResult {
        match outcome {
            Ok(()) => CheckResult::Pass(format!(
                "Hidden root at {} can host an overlayfs upper layer",
                self.hidden_volume_root.display()
            )),
            Err(ProbeError::Missing(missing)) => {
                // Name the backend in the failure when the mount table knows it.
                let fstype = fs
                    .get_filesystem_type(&self.hidden_volume_root)
                    .ok()
                    .flatten();
                classify(missing, fstype.as_deref())
            }
            Err(ProbeError::Scaffold(e)) => CheckResult::fail(format!(
                "Could not verify the hidden root at {} can host an overlayfs upper layer ({e}). \
                 Ensure it is a mounted, writable, local Linux filesystem and retry.",
                self.hidden_volume_root.display()
            )),
            Err(ProbeError::NoDetachedMount(e)) => CheckResult::fail(format!(
                "Could not verify the hidden root at {} can host an overlayfs upper layer: the \
                 kernel refused to set up a detached trial overlay ({e}), and the probe never \
                 mounts one where a mount table would show it. Nothing was written. Run NAILS \
                 as root from a host shell, on Linux 5.2 or newer with overlayfs.",
                self.hidden_volume_root.display()
            )),
        }
    }
}

// ============================================================================
// Host probe (runs only on a real host; skipped under any test binary)
// ============================================================================

/// A filesystem context for the trial overlay, from `fsopen(2)`. A mount made
/// from it is detached: it enters no mount table unless it is attached, which
/// the probe never does.
fn overlay_context() -> std::io::Result<OwnedFd> {
    rustix::mount::fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).map_err(std::io::Error::from)
}

/// Probe that the hidden root can back an overlay upper/work dir.
///
/// `context` is the overlay context the trial mount is made from
/// ([`overlay_context`]). Without one the probe stops before it writes
/// anything, since it mounts the trial overlay detached or not at all. All I/O
/// then happens inside a throwaway `.probe-<unique>` directory on the hidden
/// root; nothing outside it is ever touched, and the scratch dir is removed on
/// every path.
fn probe_upper_capabilities(
    hidden_root: &Path,
    context: std::io::Result<OwnedFd>,
) -> std::result::Result<(), ProbeError> {
    let context = context.map_err(ProbeError::NoDetachedMount)?;
    let scratch = hidden_root.join(format!(".probe-{}", unique_suffix()));
    std::fs::create_dir(&scratch).map_err(ProbeError::Scaffold)?;

    let outcome = probe_in_scratch(&scratch, context);

    // Clean up on every path: a leftover probe dir would itself be a trace. A
    // failure to remove it is only surfaced when the probe otherwise passed, so
    // a real capability failure keeps its specific message. The trial overlay
    // is already gone: its descriptor closed inside `probe_in_scratch`.
    let cleanup = std::fs::remove_dir_all(&scratch);
    match outcome {
        Ok(()) => cleanup.map_err(ProbeError::Scaffold),
        Err(e) => Err(e),
    }
}

/// Run the three capability probes inside an already-created scratch dir.
fn probe_in_scratch(scratch: &Path, context: OwnedFd) -> std::result::Result<(), ProbeError> {
    // 1. Trusted xattrs on the upper directory.
    probe_trusted_xattr(scratch)?;

    // Lay out a self-contained overlay inside the scratch dir, with a file that
    // exists only in the lower layer, so deleting it through the overlay must
    // store a whiteout in the upper layer.
    let lower = scratch.join("lower");
    let upper = scratch.join("upper");
    let work = scratch.join("work");
    for dir in [&lower, &upper, &work] {
        std::fs::create_dir(dir).map_err(ProbeError::Scaffold)?;
    }
    std::fs::write(lower.join("seed"), b"seed").map_err(ProbeError::Scaffold)?;

    // 2. readdir d_type: the scratch dir now holds real sub-entries to classify.
    probe_dir_entry_type(scratch)?;

    // 3. Trial overlay, mounted detached, exercising a new file and a whiteout.
    // Dropping its descriptor at the end of this function dissolves it.
    let overlay = mount_trial_overlay(context, &lower, &upper, &work)?;
    exercise_mounted_overlay(overlay.as_fd())
}

/// Set then remove a `trusted.*` probe xattr on `dir`.
#[allow(unsafe_code)]
fn probe_trusted_xattr(dir: &Path) -> std::result::Result<(), ProbeError> {
    let c_dir = cstring(dir)?;
    let name = c"trusted.overlay.probe";
    let value = b"1";

    // SAFETY: `c_dir` and `name` are valid NUL-terminated C strings live for the
    // call, and `value`/len describe a valid byte buffer.
    let set = unsafe {
        nix::libc::lsetxattr(
            c_dir.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if set != 0 {
        return Err(ProbeError::Missing(MissingCapability::TrustedXattr));
    }

    // SAFETY: same invariants as the set call above.
    let removed = unsafe { nix::libc::lremovexattr(c_dir.as_ptr(), name.as_ptr()) };
    if removed != 0 {
        return Err(ProbeError::Missing(MissingCapability::TrustedXattr));
    }
    Ok(())
}

/// Confirm `readdir` on `dir` reports a concrete `d_type` for its entries.
///
/// A filesystem without `d_type` support returns `DT_UNKNOWN` for every entry
/// (including `.`/`..`); one that supports it reports a concrete type. Seeing any
/// known type is therefore a sufficient capability signal.
#[allow(unsafe_code)]
fn probe_dir_entry_type(dir: &Path) -> std::result::Result<(), ProbeError> {
    let c_dir = cstring(dir)?;

    // SAFETY: `c_dir` is a valid C string naming an existing directory.
    let handle = unsafe { nix::libc::opendir(c_dir.as_ptr()) };
    if handle.is_null() {
        return Err(ProbeError::Scaffold(std::io::Error::last_os_error()));
    }

    let mut saw_known_type = false;
    loop {
        // SAFETY: `handle` is a live `DIR*` from opendir that is not yet closed.
        let entry = unsafe { nix::libc::readdir(handle) };
        if entry.is_null() {
            break;
        }
        // SAFETY: readdir returned a non-null, correctly aligned `dirent`.
        let d_type = unsafe { (*entry).d_type };
        if d_type != nix::libc::DT_UNKNOWN {
            saw_known_type = true;
        }
    }

    // SAFETY: `handle` is still the live `DIR*` and is closed exactly once.
    unsafe {
        nix::libc::closedir(handle);
    }

    if saw_known_type {
        Ok(())
    } else {
        Err(ProbeError::Missing(MissingCapability::DirEntryType))
    }
}

/// Mount a self-contained overlay of `lower`, `upper` and `work`, detached,
/// from `context`, and return the descriptor of its root.
///
/// The mount is attached to no mount namespace, so no mount table ever lists
/// it; it lives as long as the returned descriptor, and dropping that
/// dissolves it.
fn mount_trial_overlay(
    context: OwnedFd,
    lower: &Path,
    upper: &Path,
    work: &Path,
) -> std::result::Result<OwnedFd, ProbeError> {
    // Exercise the exact options the real overlay mount uses, so the probe
    // proves the backend under the same pinned feature options.
    let params = nails_teardown::whole_root::nextroot::overlay_params(lower, upper, work)
        .map_err(ProbeError::Scaffold)?;

    // A refused option, superblock or mount is the common NFS/FUSE/FAT
    // verdict, so it is a Missing capability rather than a scaffolding error.
    let refused = |_| ProbeError::Missing(MissingCapability::TrialOverlay);
    for (key, value) in &params {
        rustix::mount::fsconfig_set_string(&context, *key, value.as_str()).map_err(refused)?;
    }
    rustix::mount::fsconfig_create(&context).map_err(refused)?;
    rustix::mount::fsmount(
        &context,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )
    .map_err(refused)
}

/// Create+delete a fresh file and delete the lower-only file through the
/// overlay whose root is `root`.
fn exercise_mounted_overlay(root: BorrowedFd<'_>) -> std::result::Result<(), ProbeError> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    let refused = |_| ProbeError::Missing(MissingCapability::TrialOverlay);

    let created = rustix::fs::openat(
        root,
        "probe-create",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(refused)?;
    let written = rustix::io::write(&created, b"x");
    drop(created);
    if written != Ok(1) {
        return Err(ProbeError::Missing(MissingCapability::TrialOverlay));
    }
    rustix::fs::unlinkat(root, "probe-create", AtFlags::empty()).map_err(refused)?;

    // Removing the lower-only file forces overlayfs to write a whiteout in the
    // upper layer; a backend that cannot store whiteouts fails here.
    rustix::fs::unlinkat(root, "seed", AtFlags::empty()).map_err(refused)?;
    Ok(())
}

/// Build a `CString` from a path for the libc calls.
fn cstring(path: &Path) -> std::result::Result<std::ffi::CString, ProbeError> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| ProbeError::Scaffold(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))
}

/// A per-invocation suffix for the scratch dir, from the pid and the clock.
///
/// It only needs to avoid collisions between NAILS runs, not be unpredictable.
fn unique_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests;
