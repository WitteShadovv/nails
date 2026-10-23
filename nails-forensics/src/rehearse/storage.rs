// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! When a raw plaintext scan of a decoy filesystem cannot be conclusive.
//!
//! Step three of a rehearsal reads the raw, decrypted decoy block devices and
//! searches them for the canary token in ASCII and UTF-16LE. That proves the
//! canary absent only where the filesystem stores file contents verbatim. Three
//! kinds of storage break that assumption:
//!
//! - **An explicit compress mount option.** btrfs, bcachefs and f2fs can be
//!   mounted to compress file contents (a `compress` option). A leaked canary is
//!   then on the disk in a form the plaintext matcher never sees, so a clean scan
//!   means nothing.
//! - **Copy-on-write.** btrfs, bcachefs and zfs can turn compression on per file
//!   or per subvolume (a subvolume property or `chattr +c`), invisibly to the
//!   mount options, so a decoy on one of them may compress the canary even with
//!   no compression shown at mount time.
//! - **f2fs made with compression.** f2fs compresses only on a filesystem made
//!   with its compression feature (`mkfs.f2fs -O compression`), and then only the
//!   files flagged for it (`chattr +c`, or an extension the mount's
//!   `compress_extension` names). A mounted f2fs with the feature always shows it
//!   among its mount options: the kernel prints `compress_algorithm=` and
//!   `compress_log_size=` for it whatever the mount asked for, so a mounted f2fs
//!   is judged by its options like the others. Without the feature the kernel
//!   refuses the flag and stores every file verbatim. An image or an unmounted
//!   device has no mount options, so there the superblock's feature flags
//!   decide.
//!
//! On such a decoy the rehearsal reports the device "not checked" rather than
//! clean. This module turns a filesystem's type and its per-superblock mount
//! options, or an f2fs superblock's feature, into that verdict; the scan carries
//! the reason on every device and the report never reads as clean when one is
//! present.

/// Why a raw plaintext scan of a filesystem cannot rule the canary out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanBlindSpot {
    /// The mount compresses file contents (a `compress` mount option), so a
    /// leaked canary may be stored compressed.
    Compressed,
    /// A copy-on-write filesystem that can compress file contents per file or
    /// subvolume, invisibly to the mount options.
    CopyOnWrite,
    /// An f2fs read offline whose superblock carries the compression feature,
    /// so it compresses the files flagged for it.
    CompressionCapable,
}

impl ScanBlindSpot {
    /// The reason shown with the device, explaining why a clean scan of it is
    /// not a clean result.
    pub fn reason(self) -> &'static str {
        match self {
            ScanBlindSpot::Compressed => {
                "the decoy filesystem compresses file contents, so a leaked canary may be stored \
                 compressed, which this raw plaintext scan cannot match"
            }
            ScanBlindSpot::CopyOnWrite => {
                "the decoy is on a copy-on-write filesystem that can compress file contents per \
                 file or subvolume, invisibly to the mount options, so this raw plaintext scan \
                 cannot prove the canary absent"
            }
            ScanBlindSpot::CompressionCapable => {
                "the decoy is an f2fs made with the compression feature, which compresses the \
                 contents of the files flagged for it, so this raw plaintext scan cannot prove \
                 the canary absent"
            }
        }
    }
}

/// Filesystems that are copy-on-write and can compress file contents per file
/// or subvolume, so a raw plaintext scan is never conclusive on them, whatever
/// their mount options show.
const COW_COMPRESSING_FORMATS: &[&str] = &["btrfs", "bcachefs", "zfs"];

/// Whether a per-superblock option string turns transparent compression on.
///
/// A token whose name begins with `compress` (btrfs `compress`/`compress-force`,
/// f2fs `compress_algorithm`/`compress_extension`/`compress_mode`) enables it,
/// unless its value explicitly disables it (`compress=no`). A `nocompress_*`
/// token does not, because its name does not begin with `compress`.
fn compression_is_on(super_opts: &str) -> bool {
    super_opts.split(',').any(|opt| {
        let (name, value) = opt.split_once('=').unwrap_or((opt, ""));
        name.starts_with("compress") && !matches!(value, "no" | "none" | "off")
    })
}

/// The blind spot a raw plaintext scan has on a filesystem of type `fstype`
/// mounted with per-superblock options `super_opts`, or `None` when a clean scan
/// of it is conclusive.
///
/// A copy-on-write, compression-capable filesystem (btrfs, bcachefs, zfs) is
/// never conclusive: it can compress a file invisibly to the mount options. A
/// mounted f2fs is a blind spot when its options show compression, which they
/// always do when the filesystem has the compression feature, and conclusive
/// otherwise; an f2fs read offline is judged by [`f2fs_image_blind_spot`].
/// Every other filesystem (ext4, xfs, vfat, …) stores file contents verbatim,
/// so a clean scan of it is a clean result — an `ext4` `chattr +c` flag, for
/// one, is recorded but never acted on.
pub fn scan_blind_spot(fstype: &str, super_opts: &str) -> Option<ScanBlindSpot> {
    let compressed = compression_is_on(super_opts);
    if COW_COMPRESSING_FORMATS.contains(&fstype) {
        return Some(if compressed {
            ScanBlindSpot::Compressed
        } else {
            ScanBlindSpot::CopyOnWrite
        });
    }
    (fstype == "f2fs" && compressed).then_some(ScanBlindSpot::Compressed)
}

/// The blind spot a raw plaintext scan has on an f2fs read offline, an image or
/// an unmounted device, from whether its superblock carries the compression
/// feature; `None` when it does not, and the f2fs stores every file verbatim.
pub fn f2fs_image_blind_spot(compression_feature: bool) -> Option<ScanBlindSpot> {
    compression_feature.then_some(ScanBlindSpot::CompressionCapable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_on_write_filesystem_is_never_conclusive() {
        // btrfs with no compression option is still a blind spot: compression
        // can be set per file or subvolume, which the mount options never show.
        assert_eq!(
            scan_blind_spot("btrfs", "rw,relatime,ssd,space_cache=v2"),
            Some(ScanBlindSpot::CopyOnWrite)
        );
        assert_eq!(
            scan_blind_spot("bcachefs", "rw,relatime"),
            Some(ScanBlindSpot::CopyOnWrite)
        );
        assert_eq!(
            scan_blind_spot("zfs", "rw,xattr,noacl"),
            Some(ScanBlindSpot::CopyOnWrite)
        );
    }

    #[test]
    fn an_explicit_compress_option_reads_as_compressed() {
        assert_eq!(
            scan_blind_spot("btrfs", "rw,compress=zstd:3,ssd"),
            Some(ScanBlindSpot::Compressed)
        );
        assert_eq!(
            scan_blind_spot("btrfs", "rw,compress-force=zstd"),
            Some(ScanBlindSpot::Compressed)
        );
        // A bare `compress` (btrfs's default algorithm) counts.
        assert_eq!(
            scan_blind_spot("btrfs", "rw,compress"),
            Some(ScanBlindSpot::Compressed)
        );
    }

    #[test]
    fn a_mounted_f2fs_is_judged_by_its_mount_options() {
        // The options a kernel prints for an f2fs made with the compression
        // feature, whatever the mount asked for: a blind spot.
        assert_eq!(
            scan_blind_spot(
                "f2fs",
                "rw,lazytime,background_gc=on,discard,compress_algorithm=lz4,\
                 compress_log_size=2,compress_mode=fs,alloc_mode=default"
            ),
            Some(ScanBlindSpot::Compressed)
        );
        assert_eq!(
            scan_blind_spot("f2fs", "rw,compress_algorithm=zstd:6,compress_extension=*"),
            Some(ScanBlindSpot::Compressed)
        );
        // Without the feature the kernel prints none of them and refuses the
        // chattr +c flag, so every file is stored verbatim.
        assert_eq!(
            scan_blind_spot(
                "f2fs",
                "rw,lazytime,background_gc=on,discard,no_heap,user_xattr,inline_xattr,acl,\
                 inline_data,inline_dentry,flush_merge,barrier,extent_cache,mode=adaptive,\
                 active_logs=6,alloc_mode=default,checkpoint_merge,fsync_mode=posix,\
                 memory=normal,errors=continue"
            ),
            None
        );
    }

    #[test]
    fn an_f2fs_read_offline_is_judged_by_its_compression_feature() {
        assert_eq!(
            f2fs_image_blind_spot(true),
            Some(ScanBlindSpot::CompressionCapable)
        );
        assert_eq!(f2fs_image_blind_spot(false), None);
        assert!(
            ScanBlindSpot::CompressionCapable
                .reason()
                .contains("compression feature")
        );
    }

    #[test]
    fn a_verbatim_filesystem_is_conclusive() {
        for fstype in ["ext4", "xfs", "vfat", "exfat", "overlay", "erofs"] {
            assert_eq!(scan_blind_spot(fstype, "rw,relatime"), None, "{fstype}");
        }
        // An ext4 `chattr +c` is stored but never acted on: the data stays
        // verbatim, so a clean scan is still a clean result.
        assert_eq!(scan_blind_spot("ext4", "rw,relatime"), None);
    }

    #[test]
    fn a_disabled_compress_option_is_not_compression() {
        // compress=no leaves a btrfs decoy a copy-on-write blind spot, not a
        // compressed one, and never flips a non-compressing filesystem.
        assert_eq!(
            scan_blind_spot("btrfs", "rw,compress=no"),
            Some(ScanBlindSpot::CopyOnWrite)
        );
        assert!(!compression_is_on("rw,nocompress_extension=zip,relatime"));
    }
}
