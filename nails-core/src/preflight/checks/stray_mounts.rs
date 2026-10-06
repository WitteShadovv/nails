// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Warn about writable disk mounts that the session leaves on the decoy.
//!
//! The overlays cover the root directories NAILS targets, and the read-only
//! guard covers the base-OS trees. A second disk mounted at `/mnt/storage`, a
//! Windows partition, or a removable drive automounted under `/run/media` is
//! neither: it stays mounted read-write on its own block device for the whole
//! session, so anything the hidden session saves there (a download, a browser
//! cache pointed at it, a file manager's thumbnails) lands on a real disk next to
//! the decoy. This check lists such mounts before activation. It only warns: the
//! operator may need the mount, and only they know whether the session will
//! touch it.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::config::{Config, OverlayMode};
use crate::filesystem::Filesystem;
use crate::filesystem::mountinfo::{MountEntry, parse_mountinfo};
use crate::preflight::{CheckResult, PreFlightCheck};

/// The mount table.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// Kernel pseudo-trees whose mounts are never user storage.
const PSEUDO_TREES: &[&str] = &["/proc", "/sys", "/dev"];

/// Filesystem types that never hold data on a disk, even when their source
/// looks like a device path.
const VOLATILE_FSTYPES: &[&str] = &["tmpfs", "ramfs", "devtmpfs", "overlay", "squashfs"];

/// What the stray-mount scan excludes.
#[derive(Debug, Clone, Default)]
pub struct MountCoverage {
    /// Overlay targets; a mount at or below one is handled by the overlay
    /// (submounts are re-attached read-only or overlaid themselves).
    pub overlay_targets: Vec<PathBuf>,
    /// Trees the platform remounts read-only for the session (exact match only:
    /// a read-only bind of `/` does not make the disks mounted below it
    /// read-only).
    pub read_only_trees: Vec<PathBuf>,
    /// The hidden root; its mount and everything below it are the session's own.
    pub hidden_root: PathBuf,
    /// Files behind a loop device under the hidden root (a file container). The
    /// mount holding one must stay writable for the container to work, and the
    /// backend check already warns about it.
    pub container_files: Vec<PathBuf>,
}

/// Whether a mount is backed by a block device (a disk partition, a dm-crypt or
/// LVM mapping, a loop device, an ntfs-3g `fuseblk` mount).
fn block_backed(entry: &MountEntry) -> bool {
    if VOLATILE_FSTYPES.contains(&entry.fstype.as_str()) {
        return false;
    }
    let source = entry.source.to_string_lossy();
    // zram is RAM-backed even when it carries a filesystem.
    if source.starts_with("/dev/zram") {
        return false;
    }
    if source.starts_with("/dev/") {
        return true;
    }
    // A real block device has a non-zero major; btrfs subvolumes report an
    // anonymous 0:N device, which the source check above catches instead.
    entry
        .dev
        .split_once(':')
        .and_then(|(major, _)| major.parse::<u32>().ok())
        .is_some_and(|major| major != 0)
}

/// The writable, block-backed mounts the session would leave on disk.
///
/// The root mount itself is never reported (the overlays and the read-only guard
/// exist to cover it). When several entries share a mount point, the last one,
/// which is stacked on top and visible, decides.
pub fn stray_writable_mounts(entries: &[MountEntry], coverage: &MountCoverage) -> Vec<MountEntry> {
    let mut stray: Vec<MountEntry> = Vec::new();
    for entry in entries {
        // A later entry on the same mount point shadows an earlier one.
        stray.retain(|seen| seen.mount_point != entry.mount_point);

        let point = entry.mount_point.as_path();
        if point == Path::new("/")
            || entry.read_only()
            || !block_backed(entry)
            || PSEUDO_TREES.iter().any(|tree| point.starts_with(tree))
            || (!coverage.hidden_root.as_os_str().is_empty()
                && point.starts_with(&coverage.hidden_root))
            || coverage
                .overlay_targets
                .iter()
                .any(|target| point.starts_with(target))
            || coverage.read_only_trees.iter().any(|tree| tree == point)
        {
            continue;
        }
        stray.push(entry.clone());
    }

    // The mount that holds a file container must stay writable.
    stray.retain(|entry| {
        !coverage.container_files.iter().any(|file| {
            crate::preflight::checks::backend_detect::mount_containing(entries, file)
                .is_some_and(|host| host.mount_point == entry.mount_point)
        })
    });
    stray
}

/// Pre-flight check that warns about writable disk mounts left uncovered.
#[derive(Debug, Clone)]
pub struct StrayMountsCheck {
    config: Config,
}

impl StrayMountsCheck {
    /// Create the check for `config`.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn overlay_targets<F: Filesystem>(&self, fs: &F) -> Result<Vec<PathBuf>> {
        match self.config.overlay_mode {
            OverlayMode::Auto => crate::build_overlay_targets(fs, &self.config),
            OverlayMode::Explicit => Ok(self
                .config
                .overlays
                .iter()
                .map(|overlay| overlay.target.clone())
                .collect()),
        }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for StrayMountsCheck {
    fn name(&self) -> &'static str {
        "stray-mounts"
    }

    fn description(&self) -> &'static str {
        "Warns about writable disk mounts that are neither overlaid nor on the hidden volume"
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let Ok(content) = fs.read_file_content(Path::new(MOUNTINFO)) else {
            return Ok(CheckResult::Pass(format!(
                "Stray mount scan skipped: cannot read {MOUNTINFO}"
            )));
        };
        let entries = parse_mountinfo(&content);

        let hidden_root = self
            .config
            .hidden_volume_root
            .canonicalize()
            .unwrap_or_else(|_| self.config.hidden_volume_root.clone());
        let policy = crate::platform::detect_platform(fs)?.overlay_policy();
        let coverage = MountCoverage {
            overlay_targets: self.overlay_targets(fs)?,
            read_only_trees: policy.resolve_read_only(fs)?,
            container_files: crate::preflight::checks::backend_detect::hidden_root_backing_files(
                fs,
                &entries,
                &hidden_root,
            ),
            hidden_root,
        };

        let stray = stray_writable_mounts(&entries, &coverage);
        if stray.is_empty() {
            return Ok(CheckResult::Pass(
                "No writable disk mount is left outside the overlays and the hidden volume".into(),
            ));
        }

        let listed: Vec<String> = stray
            .iter()
            .map(|entry| {
                format!(
                    "{} ({} on {})",
                    entry.mount_point.display(),
                    entry.fstype,
                    entry.source.display()
                )
            })
            .collect();
        Ok(CheckResult::Warn(format!(
            "These disk mounts stay read-write on the decoy during the session, so anything \
             the hidden session writes there lands on a real disk: {}. Unmount them before \
             activating (sudo umount <path>), remount them read-only (sudo mount -o \
             remount,ro <path>), or add them as overlay targets; do not save hidden-session \
             files there.",
            listed.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    const TABLE: &str = "\
22 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw\n\
23 22 0:5 / /proc rw,nosuid shared:2 - proc proc rw\n\
24 22 0:6 / /dev rw,nosuid shared:3 - devtmpfs devtmpfs rw\n\
25 22 0:22 / /run rw,nosuid shared:4 - tmpfs tmpfs rw\n\
30 22 254:1 / /home rw,relatime shared:5 - ext4 /dev/mapper/home rw\n\
31 30 8:33 / /home/user/data rw,relatime shared:6 - ext4 /dev/sdc1 rw\n\
40 22 8:17 / /mnt/storage rw,relatime shared:7 - ext4 /dev/sdb1 rw\n\
41 22 0:40 / /mnt/windows rw,relatime shared:8 - fuseblk /dev/nvme0n1p3 rw,user_id=0\n\
42 25 8:49 / /run/media/user/USB rw,nosuid shared:9 - vfat /dev/sdd1 rw\n\
43 22 8:65 / /mnt/backup ro,relatime shared:10 - ext4 /dev/sde1 ro\n\
44 22 254:5 / /mnt/data rw,relatime shared:11 - ext4 /dev/mapper/hidden rw\n\
45 44 254:6 / /mnt/data/inner rw,relatime shared:12 - ext4 /dev/mapper/inner rw\n\
46 25 0:50 / /run/user/1000 rw,nosuid shared:13 - tmpfs tmpfs rw\n\
47 22 0:51 / /mnt/subvol rw,relatime shared:14 - btrfs /dev/sdf2 rw\n\
48 22 251:0 / /var/tmp rw,relatime shared:15 - ext4 /dev/zram0 rw\n";

    fn coverage() -> MountCoverage {
        MountCoverage {
            overlay_targets: vec![PathBuf::from("/home"), PathBuf::from("/var")],
            read_only_trees: vec![PathBuf::from("/")],
            hidden_root: PathBuf::from("/mnt/data"),
            container_files: Vec::new(),
        }
    }

    fn points(entries: &[MountEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| e.mount_point.display().to_string())
            .collect()
    }

    #[test]
    fn reports_only_uncovered_writable_disk_mounts() {
        let stray = stray_writable_mounts(&parse_mountinfo(TABLE), &coverage());
        assert_eq!(
            points(&stray),
            vec![
                "/mnt/storage",
                "/mnt/windows",
                "/run/media/user/USB",
                "/mnt/subvol"
            ]
        );
    }

    #[test]
    fn the_mount_holding_the_container_is_exempt() {
        let mut coverage = coverage();
        coverage.container_files = vec![PathBuf::from("/mnt/storage/vault.hc")];
        let stray = stray_writable_mounts(&parse_mountinfo(TABLE), &coverage);
        assert!(!points(&stray).contains(&"/mnt/storage".to_string()));
        assert!(points(&stray).contains(&"/mnt/windows".to_string()));
    }

    #[test]
    fn an_overlay_target_covers_its_own_mount() {
        let mut coverage = coverage();
        coverage.overlay_targets.push(PathBuf::from("/mnt/storage"));
        let stray = stray_writable_mounts(&parse_mountinfo(TABLE), &coverage);
        assert!(!points(&stray).contains(&"/mnt/storage".to_string()));
    }

    #[test]
    fn a_read_only_mount_stacked_on_top_hides_the_writable_one() {
        let table = "\
22 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw\n\
40 22 8:17 / /mnt/storage rw,relatime shared:7 - ext4 /dev/sdb1 rw\n\
50 40 8:17 / /mnt/storage ro,relatime shared:7 - ext4 /dev/sdb1 rw\n";
        assert!(stray_writable_mounts(&parse_mountinfo(table), &coverage()).is_empty());
    }

    #[test]
    fn check_warns_with_remediation_on_a_mock_host() {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=nixos\nVERSION_ID=\"24.11\"\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        fs.mock_set_path_type("/", PathKind::Dir);
        let roots = ["/home", "/etc", "/nix", "/var"];
        fs.mock_set_root_directories(roots.iter().map(PathBuf::from).collect());
        for root in roots {
            fs.mock_set_path_type(root, PathKind::Dir);
        }
        fs.mock_add_file(MOUNTINFO, TABLE);

        let config = Config {
            overlay_mode: OverlayMode::Auto,
            hidden_volume_root: PathBuf::from("/mnt/data"),
            ..Config::default()
        };
        let result = StrayMountsCheck::new(config).run(&fs).unwrap();
        assert!(result.is_warn(), "{}", result.message());
        let message = result.message();
        assert!(
            message.contains("/mnt/storage (ext4 on /dev/sdb1)"),
            "{message}"
        );
        assert!(message.contains("/run/media/user/USB"), "{message}");
        assert!(message.contains("remount,ro"), "{message}");
        assert!(!message.contains("/home/user/data"), "{message}");
    }

    #[test]
    fn check_passes_when_nothing_is_left_writable() {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/os-release", "ID=nixos\n");
        fs.mock_add_file("/proc/1/comm", "systemd");
        fs.mock_set_path_type("/", PathKind::Dir);
        fs.mock_add_file(
            MOUNTINFO,
            "22 1 254:0 / / rw,relatime shared:1 - ext4 /dev/mapper/root rw\n",
        );
        let result = StrayMountsCheck::new(Config::default()).run(&fs).unwrap();
        assert!(result.is_pass(), "{}", result.message());
    }
}
