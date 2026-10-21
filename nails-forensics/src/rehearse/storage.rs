// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! When a raw plaintext scan of a decoy filesystem cannot be conclusive.
//!
//! Step three of a rehearsal reads the raw, decrypted decoy block devices and
//! searches them for the canary token in ASCII and UTF-16LE. That proves the
//! canary absent only where the filesystem stores file contents verbatim. Two
//! kinds of storage break that assumption:
//!
//! - **Compression.** btrfs, bcachefs and an f2fs mount with compression store
//!   file contents compressed. A leaked canary is then on the disk in a form the
//!   plaintext matcher never sees, so a clean scan means nothing.
//! - **Copy-on-write.** btrfs, bcachefs and zfs can turn compression on per file
//!   or per subvolume (a `compress` mount option, a subvolume property, or
//!   `chattr +c`), invisibly to the mount options, so a decoy on one of them may
//!   compress the canary even with no compression shown at mount time.
//!
//! On such a decoy the rehearsal reports the device "not checked" rather than
//! clean. This module turns a filesystem's type and its per-superblock mount
//! options into that verdict; the scan carries the reason on every device and
//! the report never reads as clean when one is present.

/// Why a raw plaintext scan of a filesystem cannot rule the canary out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanBlindSpot {
    /// The mount compresses file contents (a `compress` mount option), so a
    /// leaked canary may be stored compressed.
    Compressed,
    /// A copy-on-write filesystem that can compress file contents per file or
    /// subvolume, invisibly to the mount options.
    CopyOnWrite,
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
/// never conclusive: it can compress a file invisibly to the mount options. An
/// f2fs mount is a blind spot only when it enables compression, which f2fs needs
/// a mount option for. Every other filesystem (ext4, xfs, vfat, …) stores file
/// contents verbatim, so a clean scan of it is a clean result — an `ext4`
/// `chattr +c` flag, for one, is recorded but never acted on.
pub fn scan_blind_spot(fstype: &str, super_opts: &str) -> Option<ScanBlindSpot> {
    let compressed = compression_is_on(super_opts);
    if COW_COMPRESSING_FORMATS.contains(&fstype) {
        return Some(if compressed {
            ScanBlindSpot::Compressed
        } else {
            ScanBlindSpot::CopyOnWrite
        });
    }
    if fstype == "f2fs" && compressed {
        return Some(ScanBlindSpot::Compressed);
    }
    None
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
    fn f2fs_is_a_blind_spot_only_with_compression() {
        assert_eq!(
            scan_blind_spot("f2fs", "rw,relatime,background_gc=on"),
            None
        );
        assert_eq!(
            scan_blind_spot("f2fs", "rw,compress_algorithm=lz4,compress_extension=*"),
            Some(ScanBlindSpot::Compressed)
        );
        assert_eq!(
            scan_blind_spot("f2fs", "rw,compress_mode=fs"),
            Some(ScanBlindSpot::Compressed)
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
