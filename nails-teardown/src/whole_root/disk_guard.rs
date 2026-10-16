// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Disks the hidden session does not use, read-only for the session.
//!
//! The fstab policy covers every filesystem the decoy knows about at entry. A
//! disk the hidden session mounts itself (a USB drive automounted by udisks, a
//! manual `mount` of a decoy partition the policy masked, a Windows partition)
//! is a real disk. With `[session_mounts] read_only`, every such disk is made
//! read-only at the **block layer** (`BLKROSET`) for the session: the kernel
//! then refuses a read-write mount (`mount` falls back to read-only, udisks
//! mounts read-only) and a write through the device node fails, and nothing
//! the mount itself would write (a journal replay, a mount count) reaches the
//! disk. The decision is the same for disks present at entry and disks
//! attached later:
//!
//! - **a udev rule** in `/run/udev/rules.d`, installed by the entry transition
//!   so only the hidden udevd loads it, runs the RAM copy (`guard-device
//!   $devnode`) for every disk and partition the moment it appears, before
//!   udev announces it to udisks; the hidden boot's coldplug runs it for the
//!   disks present at entry;
//! - the session watcher sweeps all block devices on every poll, as a
//!   fallback.
//!
//! **Never guarded** ([`protected`]): the decoy root's device (the way back
//! mounts it read-write), the hidden backend, every device mounted inside the
//! hidden volume or at a policy target (the carried decoy filesystems, the
//! read-only ESP), all of their device-mapper and RAID members and the disks
//! they sit on, and every device without hardware below it (loop, device
//! mapper, md, zram).
//!
//! The devices set read-only are recorded in the runtime directory, and the
//! way back (the leave transition) makes exactly those writable again before
//! the switch, so the decoy finds its disks as it left them. A device that was
//! already read-only is never recorded. A root user in the hidden session can
//! always set a disk writable again (`blockdev --setrw`): this guards against
//! mistakes and automounts, not against intent.

use crate::mountinfo::MountEntry;
use crate::whole_root::plan::{Plan, PolicyMountKind};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The rule directory below `/run`.
pub const RULE_DIR: &str = "udev/rules.d";
/// The rule's file name (neutral).
pub const RULE_NAME: &str = "60-overlay-runtime.rules";
/// The argument the rule passes to the RAM copy, followed by the device node.
pub const GUARD_ARG: &str = "guard-device";
/// The record of devices set read-only, in the runtime directory.
pub const RECORD_NAME: &str = "read-only-devices";

/// A block device number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DevNum {
    /// Major number.
    pub major: u32,
    /// Minor number.
    pub minor: u32,
}

impl DevNum {
    /// Parse `major:minor`.
    pub fn parse(text: &str) -> Option<Self> {
        let (major, minor) = text.trim().split_once(':')?;
        Some(Self {
            major: major.parse().ok()?,
            minor: minor.parse().ok()?,
        })
    }

    /// From an `st_rdev` or `st_dev`.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            major: rustix::fs::major(raw),
            minor: rustix::fs::minor(raw),
        }
    }

    fn text(self) -> String {
        format!("{}:{}", self.major, self.minor)
    }
}

/// The rule text that runs `binary guard-device $devnode` for every disk and
/// partition as it appears or changes.
pub fn rule_text(binary: &Path) -> String {
    format!(
        "ACTION==\"add|change\", SUBSYSTEM==\"block\", ENV{{DEVTYPE}}==\"disk|partition\", \
         RUN+=\"{} {GUARD_ARG} $devnode\"\n",
        binary.display()
    )
}

/// Install the rule under `run` (normally `/run`).
pub fn install_rule(run: &Path, binary: &Path) -> io::Result<PathBuf> {
    let dir = run.join(RULE_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(RULE_NAME);
    crate::whole_root::plan::write_atomic_with_mode(
        &path,
        rule_text(binary).as_bytes(),
        crate::whole_root::plan::SERVICE_CONFIG_MODE,
    )?;
    Ok(path)
}

/// Remove the rule under `run`, and its directory when that is left empty.
pub fn remove_rule(run: &Path) {
    let dir = run.join(RULE_DIR);
    let _ = std::fs::remove_file(dir.join(RULE_NAME));
    let _ = std::fs::remove_dir(&dir);
}

/// The block device a path names, if it is one.
fn block_device(path: &Path) -> Option<DevNum> {
    let meta = std::fs::metadata(path).ok()?;
    meta.file_type()
        .is_block_device()
        .then(|| DevNum::from_raw(meta.rdev()))
}

/// The device a mount reads from: its source when that is a block device
/// (btrfs and fuseblk report an anonymous device number), else its device
/// number when that is not anonymous.
pub fn mount_device(mount: &MountEntry) -> Option<DevNum> {
    if mount.source.starts_with("/dev/")
        && let Some(dev) = block_device(&mount.source)
    {
        return Some(dev);
    }
    DevNum::parse(&mount.dev).filter(|d| d.major != 0)
}

/// Where sysfs describes block devices.
#[derive(Debug, Clone)]
pub struct Sysfs {
    /// The sysfs root, normally `/sys`.
    pub root: PathBuf,
}

impl Sysfs {
    /// The real `/sys`.
    pub fn system() -> Self {
        Self {
            root: PathBuf::from("/sys"),
        }
    }

    fn dir(&self, dev: DevNum) -> Option<PathBuf> {
        std::fs::canonicalize(self.root.join("dev/block").join(dev.text())).ok()
    }

    fn dev_in(dir: &Path) -> Option<DevNum> {
        DevNum::parse(&std::fs::read_to_string(dir.join("dev")).ok()?)
    }

    /// The disk a partition is on, or `None` for a whole disk.
    fn parent(&self, dev: DevNum) -> Option<DevNum> {
        let dir = self.dir(dev)?;
        if !dir.join("partition").exists() {
            return None;
        }
        Self::dev_in(dir.parent()?)
    }

    /// The devices this one is stacked on (device-mapper, md).
    fn slaves(&self, dev: DevNum) -> Vec<DevNum> {
        let Some(dir) = self.dir(dev) else {
            return Vec::new();
        };
        std::fs::read_dir(dir.join("slaves"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| Self::dev_in(&e.path()))
            .collect()
    }

    /// Whether hardware sits below the device (it, or its disk, has a
    /// `device` link): false for loop, device-mapper, md, zram and ram disks.
    pub fn is_hardware(&self, dev: DevNum) -> bool {
        let disk = self.parent(dev).unwrap_or(dev);
        self.dir(disk).is_some_and(|d| d.join("device").exists())
    }

    /// Whether the kernel reports the device read-only.
    pub fn is_read_only(&self, dev: DevNum) -> bool {
        self.dir(dev)
            .and_then(|d| std::fs::read_to_string(d.join("ro")).ok())
            .is_some_and(|ro| ro.trim() == "1")
    }

    /// Every block device: its number and kernel name.
    fn all(&self) -> Vec<(DevNum, String)> {
        std::fs::read_dir(self.root.join("class/block"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let dev = Self::dev_in(&e.path())?;
                Some((dev, e.file_name().to_string_lossy().into_owned()))
            })
            .collect()
    }
}

/// The devices the session must keep writable: what backs the decoy root, the
/// hidden backend, and every mount inside the hidden volume or at a policy
/// target, with everything they are stacked on and the disks below.
pub fn protected(plan: &Plan, mounts: &[MountEntry], sys: &Sysfs) -> BTreeSet<DevNum> {
    let policy: Vec<&Path> = plan
        .policy_mounts
        .iter()
        .filter(|m| m.kind != PolicyMountKind::HiddenVolume)
        .map(|m| m.target.as_path())
        .collect();
    let mut seeds: Vec<DevNum> = mounts
        .iter()
        .filter(|m| {
            m.mount_point.starts_with(&plan.hidden_root)
                || policy.contains(&m.mount_point.as_path())
        })
        .filter_map(mount_device)
        .collect();
    seeds.extend(block_device(&plan.decoy_root.source));
    seeds.extend(
        plan.backend
            .iter()
            .filter_map(|name| block_device(&Path::new("/dev/mapper").join(name))),
    );
    let mut done = BTreeSet::new();
    while let Some(dev) = seeds.pop() {
        if !done.insert(dev) {
            continue;
        }
        seeds.extend(sys.parent(dev));
        seeds.extend(sys.slaves(dev));
    }
    done
}

/// What [`guard`] did with one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guarded {
    /// Not a block device, or no hardware below it.
    Skipped,
    /// The session uses it: left writable.
    Protected,
    /// It was read-only already: left alone and not recorded.
    AlreadyReadOnly,
    /// Set read-only and recorded.
    SetReadOnly,
}

#[allow(unsafe_code)]
fn set_read_only(node: &Path, read_only: bool) -> io::Result<()> {
    use rustix::ioctl::{Setter, ioctl, opcode};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(node)?;
    // BLKROSET, `_IO(0x12, 93)`, takes a pointer to an int.
    // SAFETY: the opcode is BLKROSET and the kernel reads one c_int through
    // the pointer the Setter passes.
    unsafe {
        let set = Setter::<{ opcode::none(0x12, 93) }, libc::c_int>::new(i32::from(read_only));
        ioctl(&file, set)
    }
    .map_err(io::Error::from)
}

fn record(runtime_dir: &Path, dev: DevNum, node: &Path) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(runtime_dir.join(RECORD_NAME))?;
    file.write_all(format!("{} {}\n", dev.text(), node.display()).as_bytes())
}

/// Make the device at `node` read-only unless the session uses it. `mounts`
/// is the live mount table; `runtime_dir` holds the record.
pub fn guard(
    node: &Path,
    plan: &Plan,
    mounts: &[MountEntry],
    sys: &Sysfs,
    runtime_dir: &Path,
) -> io::Result<Guarded> {
    let Some(dev) = block_device(node) else {
        return Ok(Guarded::Skipped);
    };
    if !sys.is_hardware(dev) {
        return Ok(Guarded::Skipped);
    }
    if protected(plan, mounts, sys).contains(&dev) {
        return Ok(Guarded::Protected);
    }
    if sys.is_read_only(dev) {
        return Ok(Guarded::AlreadyReadOnly);
    }
    // Recorded first: a device set read-only must never be missing from the
    // record the way back reads.
    record(runtime_dir, dev, node)?;
    set_read_only(node, true)?;
    Ok(Guarded::SetReadOnly)
}

/// The device node of `name` from its `uevent` (`DEVNAME=`), else `/dev/<name>`.
fn node_of(sys: &Sysfs, name: &str) -> PathBuf {
    std::fs::read_to_string(sys.root.join("class/block").join(name).join("uevent"))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|l| {
                l.strip_prefix("DEVNAME=")
                    .map(|n| Path::new("/dev").join(n))
            })
        })
        .unwrap_or_else(|| Path::new("/dev").join(name))
}

/// Guard every block device (the watcher's fallback for a device the rule
/// missed). Returns the devices set read-only now.
pub fn sweep(plan: &Plan, mounts: &[MountEntry], sys: &Sysfs, runtime_dir: &Path) -> Vec<DevNum> {
    let mut set = Vec::new();
    for (dev, name) in sys.all() {
        let node = node_of(sys, &name);
        if block_device(&node) != Some(dev) {
            continue;
        }
        if let Ok(Guarded::SetReadOnly) = guard(&node, plan, mounts, sys, runtime_dir) {
            set.push(dev);
        }
    }
    set
}

/// The devices the record lists, each with the node it was set through.
pub fn recorded(runtime_dir: &Path) -> Vec<(DevNum, PathBuf)> {
    let text = std::fs::read_to_string(runtime_dir.join(RECORD_NAME)).unwrap_or_default();
    let mut seen = BTreeSet::new();
    text.lines()
        .filter_map(|line| {
            let (dev, node) = line.split_once(' ')?;
            let dev = DevNum::parse(dev)?;
            seen.insert(dev).then(|| (dev, PathBuf::from(node)))
        })
        .collect()
}

/// Make every recorded device writable again (the way back). Returns how many
/// were; a device that is gone is skipped.
pub fn release(runtime_dir: &Path) -> usize {
    recorded(runtime_dir)
        .into_iter()
        .filter(|(dev, node)| {
            let by_number = Path::new("/dev/block").join(dev.text());
            [node.as_path(), by_number.as_path()]
                .into_iter()
                .find(|n| block_device(n) == Some(*dev))
                .is_some_and(|n| set_read_only(n, false).is_ok())
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;
    use crate::whole_root::plan::{PolicyMount, sample};

    /// A fake sysfs: a disk `vda` (8:0) with partitions `vda1` (8:1, the
    /// ESP) and `vda2` (8:2), a second disk `vdb` (8:16) with `vdb1` (8:17),
    /// a USB disk `sdc` (8:32), a device-mapper device `dm-0` (253:0) on
    /// `vdb1`, and a loop device (7:0).
    fn sysfs() -> (tempfile::TempDir, Sysfs) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let devices = root.join("devices");
        let disk = |path: &str, dev: &str, hardware: bool| {
            let d = devices.join(path);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("dev"), format!("{dev}\n")).unwrap();
            std::fs::write(d.join("ro"), "0\n").unwrap();
            if hardware {
                std::fs::create_dir_all(d.join("device")).unwrap();
            }
            d
        };
        let part = |disk_dir: &Path, name: &str, dev: &str| {
            let d = disk_dir.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("dev"), format!("{dev}\n")).unwrap();
            std::fs::write(d.join("partition"), "1\n").unwrap();
            std::fs::write(d.join("ro"), "0\n").unwrap();
            d
        };
        let vda = disk("pci0/vda", "8:0", true);
        part(&vda, "vda1", "8:1");
        part(&vda, "vda2", "8:2");
        let vdb = disk("pci1/vdb", "8:16", true);
        part(&vdb, "vdb1", "8:17");
        disk("usb/sdc", "8:32", true);
        let dm = disk("virtual/dm-0", "253:0", false);
        std::fs::create_dir_all(dm.join("slaves")).unwrap();
        std::os::unix::fs::symlink(vdb.join("vdb1"), dm.join("slaves/vdb1")).unwrap();
        disk("virtual/loop0", "7:0", false);
        let by_dev = root.join("dev/block");
        std::fs::create_dir_all(&by_dev).unwrap();
        let class = root.join("class/block");
        std::fs::create_dir_all(&class).unwrap();
        for (dev, path) in [
            ("8:0", "pci0/vda"),
            ("8:1", "pci0/vda/vda1"),
            ("8:2", "pci0/vda/vda2"),
            ("8:16", "pci1/vdb"),
            ("8:17", "pci1/vdb/vdb1"),
            ("8:32", "usb/sdc"),
            ("253:0", "virtual/dm-0"),
            ("7:0", "virtual/loop0"),
        ] {
            std::os::unix::fs::symlink(devices.join(path), by_dev.join(dev)).unwrap();
            let name = Path::new(path).file_name().unwrap();
            std::os::unix::fs::symlink(devices.join(path), class.join(name)).unwrap();
        }
        let sys = Sysfs {
            root: root.to_path_buf(),
        };
        (dir, sys)
    }

    fn dev(text: &str) -> DevNum {
        DevNum::parse(text).unwrap()
    }

    #[test]
    fn device_numbers_parse_and_print() {
        assert_eq!(
            DevNum::parse("8:17"),
            Some(DevNum {
                major: 8,
                minor: 17
            })
        );
        assert_eq!(DevNum::parse(" 253:0\n").unwrap().text(), "253:0");
        assert_eq!(DevNum::parse("x:1"), None);
        assert_eq!(DevNum::parse("8"), None);
    }

    #[test]
    fn hardware_is_found_below_a_disk_or_its_partition_only() {
        let (_dir, sys) = sysfs();
        for hardware in ["8:0", "8:1", "8:17", "8:32"] {
            assert!(sys.is_hardware(dev(hardware)), "{hardware}");
        }
        for virtual_device in ["253:0", "7:0", "9:9"] {
            assert!(!sys.is_hardware(dev(virtual_device)), "{virtual_device}");
        }
        assert_eq!(sys.parent(dev("8:17")), Some(dev("8:16")));
        assert_eq!(sys.parent(dev("8:16")), None);
        assert_eq!(sys.slaves(dev("253:0")), vec![dev("8:17")]);
    }

    #[test]
    fn the_session_s_own_devices_are_protected_with_what_they_sit_on() {
        let (_dir, sys) = sysfs();
        let mut plan = sample();
        plan.hidden_root = PathBuf::from("/mnt/data");
        // A decoy root and backend that are not device nodes here: only the
        // mount table names devices.
        plan.decoy_root.source = PathBuf::from("/nonexistent/root");
        plan.backend = Vec::new();
        plan.policy_mounts = vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }];
        let mounts = parse_mountinfo(
            "1 0 0:30 / / rw - overlay overlay rw,upperdir=/u,workdir=/w\n\
             2 1 253:0 / /mnt/data rw - ext4 /nonexistent/mapper/data rw\n\
             3 1 8:1 / /boot ro - vfat /nonexistent/vda1 ro\n\
             4 1 8:32 / /media/usb rw - ext4 /nonexistent/sdc rw\n",
        );
        let protected = protected(&plan, &mounts, &sys);
        // The backend, its member and that member's disk; the ESP and its disk.
        for want in ["253:0", "8:17", "8:16", "8:1", "8:0"] {
            assert!(protected.contains(&dev(want)), "{want}: {protected:?}");
        }
        // A disk mounted elsewhere, and a sibling partition, are not.
        assert!(!protected.contains(&dev("8:32")));
        assert!(!protected.contains(&dev("8:2")));
    }

    #[test]
    fn the_rule_runs_the_ram_copy_for_every_disk_and_partition() {
        let text = rule_text(Path::new("/run/overlay-runtime/control"));
        assert!(text.contains("SUBSYSTEM==\"block\""), "{text}");
        assert!(text.contains("ENV{DEVTYPE}==\"disk|partition\""), "{text}");
        assert!(
            text.contains("RUN+=\"/run/overlay-runtime/control guard-device $devnode\""),
            "{text}"
        );
        assert!(!text.to_lowercase().contains("nails"));
        let run = tempfile::tempdir().unwrap();
        let path = install_rule(run.path(), Path::new("/x")).unwrap();
        assert_eq!(path, run.path().join(RULE_DIR).join(RULE_NAME));
        remove_rule(run.path());
        assert!(!path.exists());
        assert!(!run.path().join(RULE_DIR).exists());
    }

    #[test]
    fn the_record_lists_each_device_once() {
        let runtime = tempfile::tempdir().unwrap();
        assert!(recorded(runtime.path()).is_empty());
        record(runtime.path(), dev("8:32"), Path::new("/dev/sdc")).unwrap();
        record(runtime.path(), dev("8:33"), Path::new("/dev/sdc1")).unwrap();
        record(runtime.path(), dev("8:32"), Path::new("/dev/sdc")).unwrap();
        assert_eq!(
            recorded(runtime.path()),
            vec![
                (dev("8:32"), PathBuf::from("/dev/sdc")),
                (dev("8:33"), PathBuf::from("/dev/sdc1")),
            ]
        );
        // Nothing to release here: the nodes are not block devices.
        assert_eq!(release(runtime.path()), 0);
    }

    #[test]
    fn a_path_that_is_not_a_block_device_is_skipped() {
        let (_dir, sys) = sysfs();
        let runtime = tempfile::tempdir().unwrap();
        let outcome = guard(Path::new("/dev/null"), &sample(), &[], &sys, runtime.path()).unwrap();
        assert_eq!(outcome, Guarded::Skipped);
        assert!(recorded(runtime.path()).is_empty());
    }

    #[test]
    fn a_mount_reads_from_its_block_source_else_a_real_device_number() {
        let mounts = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /nonexistent/vda2 rw\n\
             2 1 0:44 / /data rw - btrfs /nonexistent/sdb rw\n\
             3 1 0:45 / /tmp rw - tmpfs tmpfs rw\n",
        );
        assert_eq!(mount_device(&mounts[0]), Some(dev("8:2")));
        assert_eq!(mount_device(&mounts[1]), None);
        assert_eq!(mount_device(&mounts[2]), None);
    }
}
