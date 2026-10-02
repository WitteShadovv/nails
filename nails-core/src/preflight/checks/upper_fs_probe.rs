//! Upper-filesystem capability pre-flight check
//!
//! Validates that the hidden root can host an overlayfs *upper* (and *work*)
//! layer before any real overlay is mounted.

use super::super::{CheckResult, PreFlightCheck};
use crate::config::get_default_hidden_volume_root;
use crate::{Filesystem, Result};
use std::path::{Path, PathBuf};

/// The overlay-upper capability a probe could not confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingCapability {
    /// Setting/removing a `trusted.*` xattr on the upper directory failed.
    TrustedXattr,
    /// `readdir` reports `DT_UNKNOWN`, so overlayfs cannot read directory types.
    DirEntryType,
    /// A throwaway overlay mount over the scratch directory failed.
    TrialOverlay,
}

/// Outcome of the host probe.
enum ProbeError {
    /// A specific overlay-upper capability is unavailable on the hidden root.
    Missing(MissingCapability),
    /// The probe scaffolding itself failed (scratch dir, syscall wiring). The
    /// check then fails closed because it cannot prove the backend is usable.
    Scaffold(std::io::Error),
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
/// overlay (lower/upper/work/merged all inside the scratch dir) that it exercises
/// with a copy-up and a whiteout before unmounting.
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
        MissingCapability::TrialOverlay => "a throwaway overlay mount over the hidden root failed",
    };

    let detected = match fstype {
        Some(fs) => format!(" The hidden root is on a {fs} filesystem."),
        None => String::new(),
    };

    CheckResult::Fail(format!(
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

    fn run(&self, fs: &F) -> Result<CheckResult> {
        // The probe writes to and mounts over the real hidden root, so there is
        // nothing to probe under a test binary. Skip it there, like every other
        // host-touching check, so mock-driven preflight tests stay hermetic; a
        // real deployment always runs the probe.
        if crate::runtime_safety::should_skip_host_interaction() {
            return Ok(CheckResult::Pass(
                "Upper-fs capability check skipped under the test runtime".into(),
            ));
        }

        match probe_upper_capabilities(&self.hidden_volume_root) {
            Ok(()) => Ok(CheckResult::Pass(format!(
                "Hidden root at {} can host an overlayfs upper layer",
                self.hidden_volume_root.display()
            ))),
            Err(ProbeError::Missing(missing)) => {
                // Name the backend in the failure when the mount table knows it.
                let fstype = fs
                    .get_filesystem_type(&self.hidden_volume_root)
                    .ok()
                    .flatten();
                Ok(classify(missing, fstype.as_deref()))
            }
            Err(ProbeError::Scaffold(e)) => Ok(CheckResult::Fail(format!(
                "Could not verify the hidden root at {} can host an overlayfs upper layer ({e}). \
                 Ensure it is a mounted, writable, local Linux filesystem and retry.",
                self.hidden_volume_root.display()
            ))),
        }
    }
}

// ============================================================================
// Host probe (runs only on a real host; skipped under any test binary)
// ============================================================================

/// Probe that the hidden root can back an overlay upper/work dir.
///
/// All I/O happens inside a throwaway `.probe-<unique>` directory on the hidden
/// root; nothing outside it is ever touched, and the scratch dir is removed on
/// every path.
fn probe_upper_capabilities(hidden_root: &Path) -> std::result::Result<(), ProbeError> {
    let scratch = hidden_root.join(format!(".probe-{}", unique_suffix()));
    std::fs::create_dir(&scratch).map_err(ProbeError::Scaffold)?;

    let outcome = probe_in_scratch(&scratch);

    // Clean up on every path: a leftover probe dir would itself be a trace. A
    // failure to remove it is only surfaced when the probe otherwise passed, so
    // a real capability failure keeps its specific message.
    let cleanup = std::fs::remove_dir_all(&scratch);
    match outcome {
        Ok(()) => cleanup.map_err(ProbeError::Scaffold),
        Err(e) => Err(e),
    }
}

/// Run the three capability probes inside an already-created scratch dir.
fn probe_in_scratch(scratch: &Path) -> std::result::Result<(), ProbeError> {
    // 1. Trusted xattrs on the upper directory.
    probe_trusted_xattr(scratch)?;

    // Lay out a self-contained overlay inside the scratch dir.
    let lower = scratch.join("lower");
    let upper = scratch.join("upper");
    let work = scratch.join("work");
    let merged = scratch.join("merged");
    for dir in [&lower, &upper, &work, &merged] {
        std::fs::create_dir(dir).map_err(ProbeError::Scaffold)?;
    }

    // 2. readdir d_type: the scratch dir now holds real sub-entries to classify.
    probe_dir_entry_type(scratch)?;

    // 3. Trial overlay mount exercising a copy-up and a whiteout.
    probe_trial_overlay(&lower, &upper, &work, &merged)
}

/// Set then remove a `trusted.*` probe xattr on `dir`.
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

/// Trial-mount a self-contained overlay and exercise a copy-up and a whiteout.
fn probe_trial_overlay(
    lower: &Path,
    upper: &Path,
    work: &Path,
    merged: &Path,
) -> std::result::Result<(), ProbeError> {
    // A file that exists only in the lower layer, so deleting it through the
    // merged view must store a whiteout in the upper layer.
    std::fs::write(lower.join("seed"), b"seed").map_err(ProbeError::Scaffold)?;

    // Mirror the explicit options the real overlay mounts pass (see
    // `filesystem::real::mount_ops`): the trial must exercise the same mode.
    let options = format!(
        "lowerdir={},upperdir={},workdir={},index=off,metacopy=off,redirect_dir=off",
        lower.display(),
        upper.display(),
        work.display()
    );

    // A failed mount is the common NFS/FUSE/FAT verdict, so it is a Missing
    // capability rather than a scaffolding error.
    nix::mount::mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .map_err(|_| ProbeError::Missing(MissingCapability::TrialOverlay))?;

    // The overlay is mounted now; tear it down on every path below.
    let exercised = exercise_mounted_overlay(merged);
    let unmounted = nix::mount::umount2(merged, nix::mount::MntFlags::MNT_DETACH);

    exercised?;
    unmounted.map_err(|e| ProbeError::Scaffold(std::io::Error::from_raw_os_error(e as i32)))?;
    Ok(())
}

/// Create+delete a fresh file and delete the lower-only file through `merged`.
fn exercise_mounted_overlay(merged: &Path) -> std::result::Result<(), ProbeError> {
    let created = merged.join("probe-create");
    std::fs::write(&created, b"x")
        .map_err(|_| ProbeError::Missing(MissingCapability::TrialOverlay))?;
    std::fs::remove_file(&created)
        .map_err(|_| ProbeError::Missing(MissingCapability::TrialOverlay))?;

    // Removing the lower-only file forces overlayfs to write a whiteout in the
    // upper layer; a backend that cannot store whiteouts fails here.
    std::fs::remove_file(merged.join("seed"))
        .map_err(|_| ProbeError::Missing(MissingCapability::TrialOverlay))?;
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
mod tests {
    use super::*;
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    use crate::filesystem::MockFilesystem;

    #[test]
    fn default_uses_default_hidden_root() {
        let check = UpperFsCapabilityCheck::default();
        assert_eq!(
            check.hidden_volume_root,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
    }

    #[test]
    fn new_keeps_custom_root() {
        let custom = PathBuf::from("/custom/root");
        let check = UpperFsCapabilityCheck::new(custom.clone());
        assert_eq!(check.hidden_volume_root, custom);
    }

    #[test]
    fn clone_preserves_root() {
        let check = UpperFsCapabilityCheck::new(PathBuf::from("/a/b"));
        assert_eq!(check.clone().hidden_volume_root, check.hidden_volume_root);
    }

    #[test]
    fn trait_metadata_is_stable() {
        let check = UpperFsCapabilityCheck::default();
        assert_eq!(
            <UpperFsCapabilityCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "upper-fs-capability"
        );
        assert!(
            <UpperFsCapabilityCheck as PreFlightCheck<MockFilesystem>>::description(&check)
                .contains("overlayfs upper")
        );
    }

    #[test]
    fn runs_hermetically_under_test_runtime() {
        // The host probe is skipped under the test binary, so the check passes
        // against the mock without touching any real filesystem. This also keeps
        // the registry wiring compiled and exercised.
        let fs = MockFilesystem::new();
        let check = UpperFsCapabilityCheck::default();
        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert!(result.message().contains("skipped"));
    }

    #[test]
    fn classify_xattr_names_fstype_and_recommends_local_fs() {
        let result = classify(MissingCapability::TrustedXattr, Some("nfs"));
        assert!(result.is_fail());
        let message = result.message();
        assert!(message.contains("nfs"));
        assert!(message.contains("xattr"));
        assert!(message.contains("ext4"));
    }

    #[test]
    fn classify_trial_overlay_names_vfat() {
        let result = classify(MissingCapability::TrialOverlay, Some("vfat"));
        assert!(result.is_fail());
        let message = result.message();
        assert!(message.contains("vfat"));
        assert!(message.contains("overlay mount"));
    }

    #[test]
    fn classify_dtype_without_fstype_is_still_actionable() {
        let result = classify(MissingCapability::DirEntryType, None);
        assert!(result.is_fail());
        let message = result.message();
        assert!(message.contains("d_type") || message.contains("DT_UNKNOWN"));
        assert!(message.contains("ext4"));
        // No fstype known: the "on a <fs> filesystem" clause is omitted entirely.
        assert!(!message.contains("is on a"));
    }

    #[test]
    fn classify_lists_unsupported_remote_and_fat_backends() {
        let result = classify(MissingCapability::TrustedXattr, Some("cifs"));
        let message = result.message();
        assert!(message.contains("NFS"));
        assert!(message.contains("FUSE"));
        assert!(message.contains("FAT/exFAT/NTFS"));
    }
}
