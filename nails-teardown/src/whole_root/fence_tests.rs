// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::mountinfo::parse_mountinfo;
use std::collections::BTreeMap;
use std::sync::Mutex;

fn dev(text: &str) -> DevNum {
    DevNum::parse(text).unwrap()
}

/// A fake sysfs:
///
/// - `vda` (252:0, virtio): `vda1` (252:1, the ESP), `vda2` (252:2) under the
///   decoy's LUKS `dm-0` (253:0) with its root LV `dm-2` (253:2) on top, and
///   `vda3` (252:3) under the hidden volume's LUKS `dm-1` (253:1), which has a
///   mapping `dm-3` (253:3) of its own on top;
/// - `sda` (8:0), a SCSI disk mounted whole at /srv, with `sg0` (21:0) and a
///   bsg node (247:0) below its hardware;
/// - `nvme0n1` (259:0) with `nvme0n1p1` (259:1) at /home, below the controller
///   `nvme0` (240:0) and its generic node `ng0n1` (241:0);
/// - `vdb` (252:16), a disk the decoy does not mount;
/// - `loop0` (7:0), bound to `backing` in the fake's directory.
struct Fake {
    dir: tempfile::TempDir,
    sys: Sysfs,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let devices = root.join("devices");
        let class = root.join("class/block");
        let by_dev = root.join("dev/block");
        std::fs::create_dir_all(&class).unwrap();
        std::fs::create_dir_all(&by_dev).unwrap();
        let node = |path: &Path, dev: &str| {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("dev"), format!("{dev}\n")).unwrap();
            std::fs::write(path.join("ro"), "0\n").unwrap();
        };
        let block = |rel: &str, dev: &str| {
            let d = devices.join(rel);
            node(&d, dev);
            std::os::unix::fs::symlink(&d, by_dev.join(dev)).unwrap();
            let name = Path::new(rel).file_name().unwrap();
            std::os::unix::fs::symlink(&d, class.join(name)).unwrap();
            std::os::unix::fs::symlink(root.join("class/block"), d.join("subsystem")).unwrap();
            d
        };
        let queue = |d: &Path| {
            std::fs::create_dir_all(d.join("queue")).unwrap();
            std::fs::write(d.join("queue/discard_max_bytes"), "2147450880\n").unwrap();
        };
        let partition = |d: &Path| std::fs::write(d.join("partition"), "1\n").unwrap();
        let link = |from: &Path, kind: &str, to: &Path| {
            std::fs::create_dir_all(from.join(kind)).unwrap();
            let name = to.file_name().unwrap();
            std::os::unix::fs::symlink(to, from.join(kind).join(name)).unwrap();
        };
        // Hardware.
        let virtio = devices.join("pci0/virtio1");
        std::fs::create_dir_all(&virtio).unwrap();
        let vda = block("pci0/virtio1/block/vda", "252:0");
        std::os::unix::fs::symlink(&virtio, vda.join("device")).unwrap();
        queue(&vda);
        let vda1 = block("pci0/virtio1/block/vda/vda1", "252:1");
        let vda2 = block("pci0/virtio1/block/vda/vda2", "252:2");
        let vda3 = block("pci0/virtio1/block/vda/vda3", "252:3");
        for p in [&vda1, &vda2, &vda3] {
            partition(p);
        }
        let scsi = devices.join("pci1/host0/target0:0:0/0:0:0:0");
        std::fs::create_dir_all(scsi.join("scsi_device/0:0:0:0")).unwrap();
        node(&scsi.join("scsi_generic/sg0"), "21:0");
        node(&scsi.join("bsg/0:0:0:0"), "247:0");
        let sda = block("pci1/host0/target0:0:0/0:0:0:0/block/sda", "8:0");
        std::os::unix::fs::symlink(&scsi, sda.join("device")).unwrap();
        queue(&sda);
        let ctrl = devices.join("pci2/nvme/nvme0");
        node(&ctrl, "240:0");
        node(&ctrl.join("ng0n1"), "241:0");
        let nvme = block("pci2/nvme/nvme0/nvme0n1", "259:0");
        std::os::unix::fs::symlink(&ctrl, nvme.join("device")).unwrap();
        queue(&nvme);
        let nvme_p1 = block("pci2/nvme/nvme0/nvme0n1/nvme0n1p1", "259:1");
        partition(&nvme_p1);
        let other = devices.join("pci3/virtio2");
        std::fs::create_dir_all(&other).unwrap();
        let vdb = block("pci3/virtio2/block/vdb", "252:16");
        std::os::unix::fs::symlink(&other, vdb.join("device")).unwrap();
        // Device mapper.
        let dm0 = block("virtual/block/dm-0", "253:0");
        let dm1 = block("virtual/block/dm-1", "253:1");
        let dm2 = block("virtual/block/dm-2", "253:2");
        let dm3 = block("virtual/block/dm-3", "253:3");
        for d in [&dm0, &dm1, &dm2, &dm3] {
            queue(d);
        }
        link(&dm0, "slaves", &vda2);
        link(&vda2, "holders", &dm0);
        link(&dm2, "slaves", &dm0);
        link(&dm0, "holders", &dm2);
        link(&dm1, "slaves", &vda3);
        link(&vda3, "holders", &dm1);
        link(&dm3, "slaves", &dm1);
        link(&dm1, "holders", &dm3);
        // A hidden LV (dm-4) and a swap LV (dm-5) in the decoy's VG on dm-0.
        let dm4 = block("virtual/block/dm-4", "253:4");
        let dm5 = block("virtual/block/dm-5", "253:5");
        queue(&dm4);
        queue(&dm5);
        link(&dm4, "slaves", &dm0);
        link(&dm0, "holders", &dm4);
        link(&dm5, "slaves", &dm0);
        link(&dm0, "holders", &dm5);
        // An NVMe multipath head (nvme1n1, 259:2) whose device is its virtual
        // subsystem, with one path through the controller nvme1 (240:1) and
        // its generic node (241:1).
        let subsys = devices.join("virtual/nvme-subsystem/nvme-subsys1");
        std::fs::create_dir_all(&subsys).unwrap();
        let head = block("virtual/nvme-subsystem/nvme-subsys1/nvme1n1", "259:2");
        std::os::unix::fs::symlink(&subsys, head.join("device")).unwrap();
        let ctrl1 = devices.join("pci4/nvme/nvme1");
        node(&ctrl1, "240:1");
        node(&ctrl1.join("ng1n1"), "241:1");
        let path = ctrl1.join("nvme1c1n1");
        std::fs::create_dir_all(&path).unwrap();
        std::os::unix::fs::symlink(&ctrl1, path.join("device")).unwrap();
        link(&head, "multipath", &path);
        // A btrfs over vdd and vde, two disks the decoy table mounts nowhere.
        let other2 = devices.join("pci5/virtio3");
        std::fs::create_dir_all(&other2).unwrap();
        let vdd = block("pci5/virtio3/block/vdd", "252:48");
        std::os::unix::fs::symlink(&other2, vdd.join("device")).unwrap();
        let other3 = devices.join("pci6/virtio4");
        std::fs::create_dir_all(&other3).unwrap();
        let vde = block("pci6/virtio4/block/vde", "252:64");
        std::os::unix::fs::symlink(&other3, vde.join("device")).unwrap();
        let btrfs = root.join("fs/btrfs/0aa6e2f4/devices");
        std::fs::create_dir_all(&btrfs).unwrap();
        std::os::unix::fs::symlink(&vdd, btrfs.join("vdd")).unwrap();
        std::os::unix::fs::symlink(&vde, btrfs.join("vde")).unwrap();
        // A loop device.
        let loop0 = block("virtual/block/loop0", "7:0");
        std::fs::create_dir_all(loop0.join("loop")).unwrap();
        std::fs::write(root.join("backing"), "").unwrap();
        std::fs::write(
            loop0.join("loop/backing_file"),
            format!("{}\n", root.join("backing").display()),
        )
        .unwrap();
        let sys = Sysfs {
            root: root.to_path_buf(),
        };
        Fake { dir, sys }
    }

    fn backing_dev(&self) -> String {
        let meta = std::fs::metadata(self.dir.path().join("backing")).unwrap();
        DevNum::from_raw(meta.dev()).text()
    }
}

/// The decoy's table at entry: the root LV, the ESP, /srv on the SCSI disk,
/// /home on the NVMe partition, the hidden volume at /mnt/data (on dm-1, or
/// another device when given), efivarfs and a tmpfs.
fn decoy_table(hidden: &str) -> Vec<MountEntry> {
    parse_mountinfo(&format!(
        "1 0 253:2 / / rw,relatime - ext4 /nonexistent/mapper/root rw\n\
         2 1 252:1 / /boot rw,relatime - vfat /nonexistent/vda1 rw,fmask=0077\n\
         3 1 8:0 / /srv rw - ext4 /nonexistent/sda rw\n\
         4 1 259:1 / /home rw - btrfs /nonexistent/nvme0n1p1 rw,subvol=/home\n\
         5 1 {hidden} / /mnt/data rw - ext4 /nonexistent/mapper/data rw\n\
         6 1 0:30 / /sys/firmware/efi/efivars rw - efivarfs efivarfs rw\n\
         7 1 0:31 / /tmp rw - tmpfs tmpfs rw\n"
    ))
}

#[test]
fn the_entry_records_the_disks_the_decoy_mounts_and_keeps_the_hidden_volume() {
    let fake = Fake::new();
    let spec = spec(
        &decoy_table("253:1"),
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    assert_eq!(
        spec.disks,
        vec![dev("8:0"), dev("252:0"), dev("259:0")],
        "the root's and the ESP's disk, the SCSI disk, the NVMe disk; not vdb"
    );
    assert_eq!(spec.kept_devices, vec![dev("253:1")]);
    assert_eq!(spec.kept_superblocks, vec!["253:1".to_string()]);
    assert!(spec.shared_superblocks.is_empty());
}

#[test]
fn at_the_switch_every_partition_and_decoy_mapping_is_fenced_but_the_hidden_volume() {
    let fake = Fake::new();
    let mounts = decoy_table("253:1");
    let spec = spec(
        &mounts,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    let targets = targets(&spec, &mounts, &fake.sys);
    let fenced: Vec<String> = targets.rules.block.iter().map(|d| d.text()).collect();
    for want in [
        "252:0", "252:1", "252:2", "252:3", "253:0", "253:2", "253:4", "253:5", "8:0", "259:0",
        "259:1",
    ] {
        assert!(fenced.contains(&want.to_string()), "{want}: {fenced:?}");
    }
    // The hidden volume's top device and what is stacked on it; disks the
    // decoy does not mount; the loop device.
    for kept in ["253:1", "253:3", "252:16", "7:0"] {
        assert!(!fenced.contains(&kept.to_string()), "{kept}: {fenced:?}");
    }
    assert_eq!(targets.devices.len(), targets.rules.block.len());
    let vda = targets
        .devices
        .iter()
        .find(|d| d.dev == dev("252:0"))
        .unwrap();
    assert_eq!(vda.node, PathBuf::from("/dev/vda"));
    assert_eq!(
        targets.rules.chars,
        vec![dev("21:0"), dev("240:0"), dev("241:0"), dev("247:0")]
    );
    assert!(targets.rules.sg);
    let queues: Vec<String> = targets
        .queues
        .iter()
        .map(|q| {
            q.strip_prefix(&fake.sys.root)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();
    assert_eq!(queues.len(), 7, "{queues:?}");
    assert!(queues.iter().all(|q| !q.contains("vda1")), "{queues:?}");
    let sbs: Vec<(&str, bool)> = targets
        .superblocks
        .iter()
        .map(|sb| (sb.sb_dev.as_str(), sb.device.is_some()))
        .collect();
    assert_eq!(
        sbs,
        vec![
            ("253:2", true),
            ("252:1", true),
            ("8:0", true),
            ("259:1", true),
            ("0:30", false)
        ]
    );
}

/// The decoy on LUKS with LVM (root LV dm-2, swap LV dm-5 on the LUKS dm-0),
/// and the hidden volume an LV of the same VG (dm-4) at /mnt/data.
fn hidden_lv_table() -> Vec<MountEntry> {
    parse_mountinfo(
        "1 0 253:2 / / rw - ext4 /nonexistent/mapper/root rw\n\
         2 1 252:1 / /boot rw - vfat /nonexistent/vda1 rw\n\
         3 1 253:4 / /mnt/data rw - ext4 /nonexistent/mapper/hidden rw\n",
    )
}

#[test]
fn a_hidden_lv_in_the_decoy_s_vg_leaves_the_decoy_s_luks_and_lvs_fenced() {
    let fake = Fake::new();
    let mounts = hidden_lv_table();
    let spec = spec(
        &mounts,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    assert_eq!(
        spec.kept_devices,
        vec![dev("253:4")],
        "only the hidden LV itself"
    );
    assert!(spec.shared_superblocks.is_empty());
    let targets = targets(&spec, &mounts, &fake.sys);
    let fenced: Vec<String> = targets.rules.block.iter().map(|d| d.text()).collect();
    for want in ["252:2", "253:0", "253:2", "253:5"] {
        assert!(fenced.contains(&want.to_string()), "{want}: {fenced:?}");
    }
    assert!(!fenced.contains(&"253:4".to_string()), "{fenced:?}");
    // The decoy root LV's superblock goes read-only, the hidden LV's does not.
    let sbs: Vec<&str> = targets
        .superblocks
        .iter()
        .map(|sb| sb.sb_dev.as_str())
        .collect();
    assert!(sbs.contains(&"253:2") && !sbs.contains(&"253:4"), "{sbs:?}");
    // A swap LV of the decoy's VG that is on refuses the fence.
    let kernel = Mock::default();
    kernel.state.lock().unwrap().swaps = vec![Swap::Device(dev("253:5"))];
    let error = apply(&targets, &kernel, Path::new("/s")).unwrap_err();
    assert_eq!(error.step, "swap");
}

#[test]
fn a_hidden_root_that_shares_a_decoy_filesystem_is_refused_at_activation() {
    let fake = Fake::new();
    // A folder (or btrfs subvolume) of the decoy root on its LUKS.
    let folder = parse_mountinfo(
        "1 0 253:2 / / rw - ext4 /nonexistent/mapper/root rw\n\
         2 1 252:1 / /boot rw - vfat /nonexistent/vda1 rw\n",
    );
    let folder_spec = spec(
        &folder,
        &[],
        Path::new("/"),
        Path::new("/nonexistent/folder"),
        &fake.sys,
    );
    assert!(
        folder_spec.kept_devices.is_empty(),
        "{:?}",
        folder_spec.kept_devices
    );
    assert_eq!(folder_spec.shared_superblocks, vec!["253:2".to_string()]);
    let fenced = targets(&folder_spec, &folder, &fake.sys);
    assert!(fenced.rules.block.contains(&dev("253:0")));
    assert!(fenced.rules.block.contains(&dev("253:2")));
    let error = check(folder_spec.clone(), &folder, &fake.sys, &Mock::default()).unwrap_err();
    assert!(
        error.contains("shares a filesystem with the decoy"),
        "{error}"
    );
    let runtime = tempfile::tempdir().unwrap();
    let at_switch = put_up(
        &folder_spec,
        &folder,
        &fake.sys,
        &Mock::default(),
        runtime.path(),
    );
    assert_eq!(at_switch.unwrap_err().step, "hidden storage");

    // A container file on a decoy filesystem, through a loop device.
    let backing = fake.backing_dev();
    let container = parse_mountinfo(&format!(
        "1 0 253:2 / / rw - ext4 /nonexistent/mapper/root rw\n\
         2 1 {backing} / /srv rw - ext4 /nonexistent/srv rw\n\
         3 1 7:0 / /mnt/data rw - ext4 /nonexistent/loop0 rw\n"
    ));
    let container_spec = spec(
        &container,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    assert_eq!(container_spec.kept_devices, vec![dev("7:0")]);
    // The fake's backing file lies where the test runs: on a disk, the decoy
    // mount of that filesystem is shared and refused; on a RAM filesystem
    // (tmpfs, as the distro suites keep the hidden root's file), which shows
    // no device, it is not the decoy's storage.
    if dev(&backing).major == 0 {
        assert!(container_spec.shared_superblocks.is_empty());
    } else {
        assert_eq!(container_spec.shared_superblocks, vec![backing]);
        let error = check(container_spec, &container, &fake.sys, &Mock::default()).unwrap_err();
        assert!(error.contains("container file"), "{error}");
    }
}

#[test]
fn only_mounts_below_the_decoy_root_count() {
    let fake = Fake::new();
    let spec = spec(
        &decoy_table("253:1"),
        &[],
        Path::new("/srv"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    assert_eq!(spec.disks, vec![dev("8:0")]);
}

#[test]
fn a_swap_partition_makes_its_disk_a_decoy_disk() {
    let fake = Fake::new();
    let spec = spec(
        &decoy_table("253:1"),
        &[Swap::Device(dev("252:16")), Swap::File("253:2".into())],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    assert!(spec.disks.contains(&dev("252:16")), "{:?}", spec.disks);
}

#[test]
fn every_device_of_a_multi_device_btrfs_is_a_decoy_disk() {
    let fake = Fake::new();
    let sys = &fake.sys;
    assert_eq!(
        sys.btrfs_devices(dev("252:48")),
        vec![dev("252:48"), dev("252:64")]
    );
    assert_eq!(sys.btrfs_devices(dev("252:16")), vec![dev("252:16")]);
    // A btrfs mount shows an anonymous device; its source names one member.
    let mounts = parse_mountinfo(
        "1 0 253:2 / / rw - ext4 /nonexistent/mapper/root rw\n\
         2 1 0:44 / /data rw - btrfs /nonexistent/vdd rw\n",
    );
    let spec = spec(&mounts, &[], Path::new("/"), Path::new("/mnt/data"), sys);
    // Both members are decoy disks, though the mount names one.
    for disk in ["252:48", "252:64"] {
        assert!(spec.disks.contains(&dev(disk)), "{disk}: {:?}", spec.disks);
    }
}

#[test]
fn an_nvme_multipath_head_is_a_disk_and_its_controllers_are_denied() {
    let fake = Fake::new();
    let mounts = parse_mountinfo("1 0 259:2 / / rw - ext4 /nonexistent/nvme1n1 rw\n");
    let spec = spec(
        &mounts,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    assert_eq!(spec.disks, vec![dev("259:2")]);
    let targets = targets(&spec, &mounts, &fake.sys);
    assert_eq!(targets.rules.chars, vec![dev("240:1"), dev("241:1")]);
}

#[test]
fn an_xfs_log_device_on_another_disk_makes_that_disk_a_decoy_disk() {
    let mount = parse_mountinfo("1 0 8:2 / / rw - xfs /nonexistent/x rw,logdev=/dev/null\n");
    // /dev/null is no block device: nothing is named.
    assert!(option_devices(&mount[0]).is_empty());
}

// ---------------------------------------------------------------------------

/// A kernel that keeps its state in memory and logs every change.
#[derive(Debug, Default)]
struct Mock {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    sb_ro: BTreeMap<String, bool>,
    dev_ro: BTreeMap<DevNum, bool>,
    discard: BTreeMap<PathBuf, u64>,
    program: Option<u32>,
    log: Vec<String>,
    fail: Option<String>,
    swaps: Vec<Swap>,
    /// A superblock that stays read-write whatever it is told.
    stuck: Option<String>,
    /// The pstore backend registered now.
    crash: Option<String>,
    /// Whether the EFI backend can be turned off.
    crash_unstoppable: bool,
    /// A crash log backend that stays registered whatever it is told.
    crash_stuck: bool,
    /// The rules the probe loaded.
    probed: Option<Rules>,
}

impl Mock {
    fn failing(at: &str) -> Self {
        let mock = Mock::default();
        mock.state.lock().unwrap().fail = Some(at.to_string());
        mock
    }

    fn check(&self, what: String) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.fail.as_deref() == Some(what.as_str()) {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        state.log.push(what);
        Ok(())
    }

    fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
}

impl FenceKernel for Mock {
    fn sync(&self) {
        self.state.lock().unwrap().log.push("sync".into());
    }
    fn swaps(&self) -> Vec<Swap> {
        self.state.lock().unwrap().swaps.clone()
    }
    fn reconfigure(&self, sb: &Superblock, _: &Path) -> io::Result<()> {
        self.check(format!("ro {}", sb.sb_dev))?;
        let mut state = self.state.lock().unwrap();
        if state.stuck.as_deref() != Some(sb.sb_dev.as_str()) {
            state.sb_ro.insert(sb.sb_dev.clone(), true);
        }
        Ok(())
    }
    fn superblock_read_only(&self, sb: &Superblock) -> Option<bool> {
        Some(
            *self
                .state
                .lock()
                .unwrap()
                .sb_ro
                .get(&sb.sb_dev)
                .unwrap_or(&false),
        )
    }
    fn device_read_only(&self, device: &Device) -> bool {
        *self
            .state
            .lock()
            .unwrap()
            .dev_ro
            .get(&device.dev)
            .unwrap_or(&false)
    }
    fn set_read_only(&self, device: &Device) -> io::Result<()> {
        self.check(format!("setro {}", device.dev.text()))?;
        self.state.lock().unwrap().dev_ro.insert(device.dev, true);
        Ok(())
    }
    fn discard_max(&self, queue: &Path) -> io::Result<u64> {
        Ok(*self
            .state
            .lock()
            .unwrap()
            .discard
            .get(queue)
            .unwrap_or(&512))
    }
    fn discard_off(&self, queue: &Path) -> io::Result<()> {
        self.check(format!("discard off {}", queue.display()))?;
        self.state.lock().unwrap().discard.insert(queue.into(), 0);
        Ok(())
    }
    fn attach(&self, rules: &Rules) -> io::Result<Program> {
        self.check(format!("attach {}", rules.block.len()))?;
        self.state.lock().unwrap().program = Some(7);
        Ok(Program {
            id: 7,
            tag: "abcd".into(),
        })
    }
    fn crash_log_backend(&self) -> Option<String> {
        self.state.lock().unwrap().crash.clone()
    }
    fn efi_crash_log_stoppable(&self) -> bool {
        !self.state.lock().unwrap().crash_unstoppable
    }
    fn stop_efi_crash_log(&self) -> io::Result<()> {
        self.check("stop crash log".into())?;
        let mut state = self.state.lock().unwrap();
        if !state.crash_stuck {
            state.crash = None;
        }
        Ok(())
    }
    fn probe(&self, rules: &Rules) -> io::Result<()> {
        self.check("probe".into())?;
        self.state.lock().unwrap().probed = Some(rules.clone());
        Ok(())
    }
}

fn sample_targets() -> Targets {
    let device = |d: &str, n: &str| Device {
        dev: dev(d),
        node: PathBuf::from(n),
    };
    Targets {
        superblocks: vec![
            Superblock {
                sb_dev: "252:2".into(),
                fstype: "ext4".into(),
                device: Some(device("252:2", "/dev/vda2")),
                read_write: true,
            },
            Superblock {
                sb_dev: "252:1".into(),
                fstype: "vfat".into(),
                device: Some(device("252:1", "/dev/vda1")),
                read_write: false,
            },
            Superblock {
                sb_dev: "0:30".into(),
                fstype: "efivarfs".into(),
                device: None,
                read_write: true,
            },
        ],
        devices: vec![
            device("252:0", "/dev/vda"),
            device("252:1", "/dev/vda1"),
            device("252:2", "/dev/vda2"),
        ],
        queues: vec![PathBuf::from("/q/vda"), PathBuf::from("/q/dm-0")],
        rules: Rules {
            block: vec![dev("252:0"), dev("252:1"), dev("252:2")],
            chars: Vec::new(),
            sg: false,
        },
    }
}

#[test]
fn the_fence_goes_up_filesystems_first_and_the_program_last() {
    let kernel = Mock::default();
    kernel
        .state
        .lock()
        .unwrap()
        .dev_ro
        .insert(dev("252:1"), true);
    kernel
        .state
        .lock()
        .unwrap()
        .discard
        .insert(PathBuf::from("/q/dm-0"), 0);
    apply(&sample_targets(), &kernel, Path::new("/scratch")).unwrap();
    assert_eq!(
        kernel.log(),
        vec![
            "sync",
            "ro 252:2",
            "ro 0:30",
            "setro 252:0",
            "setro 252:2",
            "discard off /q/vda",
            "attach 3",
        ]
    );
}

#[test]
fn a_step_that_fails_stops_the_fence_there_and_undoes_nothing() {
    for (step, done) in [
        ("ro 252:2", 1),
        ("ro 0:30", 2),
        ("setro 252:0", 3),
        ("setro 252:2", 5),
        ("discard off /q/vda", 6),
        ("attach 3", 8),
    ] {
        let kernel = Mock::failing(step);
        let error = apply(&sample_targets(), &kernel, Path::new("/s")).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("the decoy disk could not be made read-only")
        );
        // What went up stays up for the power-off: nothing is taken down.
        assert_eq!(kernel.log().len(), done, "{step}: {:?}", kernel.log());
        assert!(kernel.state.lock().unwrap().program.is_none(), "{step}");
    }
}

#[test]
fn a_filesystem_that_stays_read_write_refuses_the_fence() {
    let kernel = Mock::default();
    kernel.state.lock().unwrap().stuck = Some("252:2".into());
    let error = apply(&sample_targets(), &kernel, Path::new("/s")).unwrap_err();
    assert_eq!(error.step, "read-only filesystem");
    assert!(error.detail.contains("still reads read-write"), "{error}");
    assert!(!kernel.log().iter().any(|l| l.starts_with("setro")));
}

#[test]
fn a_busy_filesystem_says_what_to_do() {
    let kernel = Mock::failing("ro 252:2");
    let error = apply(&sample_targets(), &kernel, Path::new("/s")).unwrap_err();
    assert!(
        error.detail.contains("reboot the decoy and activate again"),
        "{error}"
    );
}

#[test]
fn swap_on_the_decoy_disk_refuses_the_fence_before_anything_changes() {
    for swap in [Swap::Device(dev("252:2")), Swap::File("252:2".into())] {
        let kernel = Mock::default();
        kernel.state.lock().unwrap().swaps = vec![Swap::Device(dev("251:0")), swap];
        let error = apply(&sample_targets(), &kernel, Path::new("/s")).unwrap_err();
        assert_eq!(error.step, "swap");
        assert_eq!(kernel.log(), vec!["sync"]);
    }
    let kernel = Mock::default();
    kernel.state.lock().unwrap().swaps = vec![Swap::Device(dev("251:0")), Swap::File("0:5".into())];
    assert!(apply(&sample_targets(), &kernel, Path::new("/s")).is_ok());
}

#[test]
fn a_superblock_no_mount_shows_counts_as_done_once_reconfigured() {
    #[derive(Debug, Default)]
    struct Unseen(Mock);
    impl FenceKernel for Unseen {
        fn sync(&self) {}
        fn swaps(&self) -> Vec<Swap> {
            Vec::new()
        }
        fn reconfigure(&self, sb: &Superblock, at: &Path) -> io::Result<()> {
            self.0.reconfigure(sb, at)
        }
        fn superblock_read_only(&self, _: &Superblock) -> Option<bool> {
            None
        }
        fn device_read_only(&self, d: &Device) -> bool {
            self.0.device_read_only(d)
        }
        fn set_read_only(&self, d: &Device) -> io::Result<()> {
            self.0.set_read_only(d)
        }
        fn discard_max(&self, q: &Path) -> io::Result<u64> {
            self.0.discard_max(q)
        }
        fn discard_off(&self, q: &Path) -> io::Result<()> {
            self.0.discard_off(q)
        }
        fn attach(&self, r: &Rules) -> io::Result<Program> {
            self.0.attach(r)
        }
        fn crash_log_backend(&self) -> Option<String> {
            None
        }
        fn efi_crash_log_stoppable(&self) -> bool {
            true
        }
        fn stop_efi_crash_log(&self) -> io::Result<()> {
            unreachable!("no backend")
        }
        fn probe(&self, _: &Rules) -> io::Result<()> {
            Ok(())
        }
    }
    let kernel = Unseen::default();
    assert!(apply(&sample_targets(), &kernel, Path::new("/s")).is_ok());
}

#[test]
fn the_crash_log_s_efi_backend_is_stopped_before_the_devices() {
    let kernel = Mock::default();
    kernel.state.lock().unwrap().crash = Some(EFI_CRASH_LOG.into());
    apply(&sample_targets(), &kernel, Path::new("/s")).unwrap();
    assert_eq!(kernel.crash_log_backend(), None);
    let log = kernel.log();
    let stop = log.iter().position(|l| l == "stop crash log").unwrap();
    let setro = log.iter().position(|l| l.starts_with("setro")).unwrap();
    assert!(stop < setro, "{log:?}");
}

#[test]
fn a_ram_crash_log_is_left_and_one_that_outlives_a_power_off_refuses_the_fence() {
    let kernel = Mock::default();
    kernel.state.lock().unwrap().crash = Some(RAM_CRASH_LOG.into());
    assert!(apply(&sample_targets(), &kernel, Path::new("/s")).is_ok());
    assert!(!kernel.log().contains(&"stop crash log".to_string()));

    for backend in ["erst", "pstore_blk", "mtdoops"] {
        let kernel = Mock::default();
        kernel.state.lock().unwrap().crash = Some(backend.into());
        let error = apply(&sample_targets(), &kernel, Path::new("/s")).unwrap_err();
        assert_eq!(error.step, "crash log");
        assert!(error.detail.contains(backend), "{error}");
    }
}

#[test]
fn an_efi_crash_log_that_stays_registered_refuses_the_fence() {
    let kernel = Mock::default();
    {
        let mut state = kernel.state.lock().unwrap();
        state.crash = Some(EFI_CRASH_LOG.into());
        state.crash_stuck = true;
    }
    let error = apply(&sample_targets(), &kernel, Path::new("/s")).unwrap_err();
    assert_eq!(error.step, "crash log");
    assert!(error.detail.contains("still keeps"), "{error}");
    assert!(kernel.state.lock().unwrap().program.is_none());
}

#[test]
fn the_switch_refuses_a_fence_with_no_decoy_disk() {
    let fake = Fake::new();
    let runtime = tempfile::tempdir().unwrap();
    let error = put_up(
        &FenceSpec::default(),
        &[],
        &fake.sys,
        &Mock::default(),
        runtime.path(),
    )
    .unwrap_err();
    assert_eq!(error.step, "decoy disks");
}

#[test]
fn the_switch_puts_the_fence_up_over_the_whole_decoy() {
    let fake = Fake::new();
    let mounts = decoy_table("253:1");
    let spec = spec(
        &mounts,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    let runtime = tempfile::tempdir().unwrap();
    let kernel = Mock::default();
    put_up(&spec, &mounts, &fake.sys, &kernel, runtime.path()).unwrap();
    let state = kernel.state.lock().unwrap();
    assert_eq!(state.sb_ro.len(), 5);
    assert_eq!(state.dev_ro.len(), 11);
    assert_eq!(state.program, Some(7));
}

#[test]
fn the_spec_reads_back_from_a_plan_written_without_its_newer_fields() {
    let spec: FenceSpec = serde_json::from_str(r#"{"disks":[{"major":8,"minor":0}]}"#).unwrap();
    assert_eq!(spec.disks, vec![dev("8:0")]);
    assert!(spec.kept_devices.is_empty() && spec.shared_superblocks.is_empty());
}

#[test]
fn activation_refuses_what_the_fence_cannot_cover_and_probes_the_real_program() {
    let fake = Fake::new();
    let mounts = decoy_table("253:1");
    let spec = spec(
        &mounts,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    let kernel = Mock::default();
    assert_eq!(
        check(spec.clone(), &mounts, &fake.sys, &kernel),
        Ok(spec.clone())
    );
    // The probe loads the program the switch would attach, not an empty one.
    let probed = kernel.state.lock().unwrap().probed.clone().unwrap();
    assert_eq!(probed, targets(&spec, &mounts, &fake.sys).rules);

    let none = check(FenceSpec::default(), &mounts, &fake.sys, &Mock::default()).unwrap_err();
    assert!(none.contains("no disk the decoy mounts"), "{none}");
    let denied = check(spec.clone(), &mounts, &fake.sys, &Mock::failing("probe")).unwrap_err();
    assert!(
        denied.contains("does not load the device program"),
        "{denied}"
    );
    for (backend, unstoppable) in [
        ("erst", false),
        ("pstore_blk", false),
        (EFI_CRASH_LOG, true),
    ] {
        let kernel = Mock::default();
        {
            let mut state = kernel.state.lock().unwrap();
            state.crash = Some(backend.into());
            state.crash_unstoppable = unstoppable;
        }
        let refused = check(spec.clone(), &mounts, &fake.sys, &kernel).unwrap_err();
        assert!(refused.contains(backend), "{refused}");
    }
    let kernel = Mock::default();
    kernel.state.lock().unwrap().crash = Some(EFI_CRASH_LOG.into());
    assert!(
        check(spec, &mounts, &fake.sys, &kernel).is_ok(),
        "a stoppable EFI log passes"
    );
}

#[test]
fn the_firmware_s_own_nodes_are_denied_where_they_exist() {
    let fake = Fake::new();
    let misc = fake.sys.root.join("class/misc/efi_test");
    std::fs::create_dir_all(&misc).unwrap();
    std::fs::write(misc.join("dev"), "10:120\n").unwrap();
    let mounts = decoy_table("253:1");
    let spec = spec(
        &mounts,
        &[],
        Path::new("/"),
        Path::new("/mnt/data"),
        &fake.sys,
    );
    let targets = targets(&spec, &mounts, &fake.sys);
    assert!(
        targets.rules.chars.contains(&dev("10:120")),
        "{:?}",
        targets.rules.chars
    );
}

#[test]
fn an_md_array_on_a_decoy_disk_is_refused_at_activation_and_at_the_switch() {
    let fake = Fake::new();
    let mounts = decoy_table("253:1");
    let at = |p: &str| spec(&mounts, &[], Path::new("/"), Path::new(p), &fake.sys);
    let spec = at("/mnt/data");
    assert!(check(spec.clone(), &mounts, &fake.sys, &Mock::default()).is_ok());
    // md0 (9:0) on the decoy's ESP partition vda1.
    let root = fake.sys.root.clone();
    let md0 = root.join("devices/virtual/block/md0");
    std::fs::create_dir_all(md0.join("md")).unwrap();
    std::fs::write(md0.join("dev"), "9:0\n").unwrap();
    std::os::unix::fs::symlink(&md0, root.join("dev/block/9:0")).unwrap();
    std::os::unix::fs::symlink(&md0, root.join("class/block/md0")).unwrap();
    let vda1 = root.join("devices/pci0/virtio1/block/vda/vda1");
    std::fs::create_dir_all(vda1.join("holders")).unwrap();
    std::os::unix::fs::symlink(&md0, vda1.join("holders/md0")).unwrap();
    let refused = check(spec.clone(), &mounts, &fake.sys, &Mock::default()).unwrap_err();
    assert!(refused.contains("md array md0"), "{refused}");
    let kernel = Mock::default();
    let run = tempfile::tempdir().unwrap();
    let at_switch = put_up(&spec, &mounts, &fake.sys, &kernel, run.path()).unwrap_err();
    assert!(at_switch.to_string().contains("md0"), "{at_switch}");
    assert!(
        kernel.state.lock().unwrap().log.is_empty(),
        "nothing of the fence goes up"
    );
}
