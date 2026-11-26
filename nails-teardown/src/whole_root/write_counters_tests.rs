// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// A fake sysfs: the decoy disk `vda` (252:0) with `vda1` (252:1, the ESP),
/// `vda2` (252:2, the root) and `vda3` (252:3); a USB disk `sdb` (8:16) with
/// `sdb1` (8:17); device-mapper devices added by each test; and every
/// counter at 0 until a test sets it.
struct Fake {
    _dir: tempfile::TempDir,
    sys: Sysfs,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake {
            sys: Sysfs {
                root: dir.path().to_path_buf(),
            },
            _dir: dir,
        };
        fake.disk("pci0/vda", "252:0", true);
        fake.part("pci0/vda", "vda1", "252:1");
        fake.part("pci0/vda", "vda2", "252:2");
        fake.part("pci0/vda", "vda3", "252:3");
        fake.disk("usb/sdb", "8:16", true);
        fake.part("usb/sdb", "sdb1", "8:17");
        fake
    }

    fn root(&self) -> &Path {
        &self.sys.root
    }

    fn link(&self, path: &str, dev: &str) {
        let target = self.root().join("devices").join(path);
        let by_dev = self.root().join("dev/block");
        let class = self.root().join("class/block");
        std::fs::create_dir_all(&by_dev).unwrap();
        std::fs::create_dir_all(&class).unwrap();
        std::os::unix::fs::symlink(&target, by_dev.join(dev)).unwrap();
        let name = Path::new(path).file_name().unwrap();
        std::os::unix::fs::symlink(&target, class.join(name)).unwrap();
        self.stat(dev, 0, 0);
    }

    fn disk(&self, path: &str, dev: &str, hardware: bool) {
        let d = self.root().join("devices").join(path);
        std::fs::create_dir_all(d.join("holders")).unwrap();
        std::fs::create_dir_all(d.join("slaves")).unwrap();
        std::fs::create_dir_all(d.join("queue")).unwrap();
        std::fs::write(d.join("queue/iostats"), "1\n").unwrap();
        std::fs::write(d.join("dev"), format!("{dev}\n")).unwrap();
        if hardware {
            std::fs::create_dir_all(d.join("device")).unwrap();
        }
        self.link(path, dev);
    }

    fn part(&self, disk: &str, name: &str, dev: &str) {
        let path = format!("{disk}/{name}");
        let d = self.root().join("devices").join(&path);
        std::fs::create_dir_all(d.join("holders")).unwrap();
        std::fs::write(d.join("dev"), format!("{dev}\n")).unwrap();
        std::fs::write(d.join("partition"), "1\n").unwrap();
        self.link(&path, dev);
    }

    /// A device-mapper device `name` (`dev`) stacked on `below`.
    fn dm(&self, name: &str, dev: &str, below: &[&str]) {
        let path = format!("virtual/block/{name}");
        self.disk(&path, dev, false);
        let d = self.root().join("devices").join(&path);
        for lower in below {
            let lower_dir =
                std::fs::canonicalize(self.root().join("dev/block").join(lower)).unwrap();
            let lower_name = lower_dir.file_name().unwrap().to_owned();
            std::os::unix::fs::symlink(&lower_dir, d.join("slaves").join(&lower_name)).unwrap();
            std::os::unix::fs::symlink(&d, lower_dir.join("holders").join(name)).unwrap();
        }
    }

    /// A loop device `name` (`dev`) over `file`.
    fn loop_dev(&self, name: &str, dev: &str, file: &str) {
        let path = format!("virtual/block/{name}");
        self.disk(&path, dev, false);
        let d = self.root().join("devices").join(&path).join("loop");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("backing_file"), format!("{file}\n")).unwrap();
    }

    /// Set the counters of `dev`: sectors written and discarded.
    fn stat(&self, dev: &str, written: u64, discarded: u64) {
        let dir = std::fs::canonicalize(self.root().join("dev/block").join(dev)).unwrap();
        std::fs::write(
            dir.join("stat"),
            format!("1 0 8 0 1 0 {written} 0 0 0 0 0 0 {discarded} 0 0 0\n"),
        )
        .unwrap();
    }
}

fn dev(text: &str) -> DevNum {
    DevNum::parse(text).unwrap()
}

fn no_file(_: &Path) -> Option<DevNum> {
    None
}

#[test]
fn the_counters_are_the_sectors_written_and_discarded() {
    let fake = Fake::new();
    fake.stat("252:2", 4096, 8);
    assert_eq!(sectors(&fake.sys, "252:2"), Some(4104));
    let dir = std::fs::canonicalize(fake.root().join("dev/block/252:1")).unwrap();
    std::fs::write(dir.join("stat"), "1 0 8 0 2 0 16 0 0 0 0\n").unwrap();
    assert_eq!(sectors(&fake.sys, "252:1"), Some(16));
    std::fs::write(dir.join("stat"), "1 0 x\n").unwrap();
    assert_eq!(sectors(&fake.sys, "252:1"), None);
    assert_eq!(sectors(&fake.sys, "9:9"), None);
}

#[test]
fn a_hidden_volume_on_another_disk_leaves_every_partition_of_the_decoy_disk_watched() {
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:17"]);
    let layout = layout_with(
        &[dev("253:0")],
        &[dev("252:2"), dev("252:1")],
        &fake.sys,
        &no_file,
    )
    .unwrap();
    assert_eq!(layout.disks.len(), 1);
    let disk = &layout.disks[0];
    assert_eq!((disk.name.as_str(), disk.dev.as_str()), ("vda", "252:0"));
    let names: Vec<&str> = disk.partitions.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["vda1", "vda2", "vda3"]);
    assert!(disk.allowed.is_empty());
}

#[test]
fn a_hidden_volume_on_a_partition_of_its_own_is_allowed_there_alone() {
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["252:3"]);
    let layout = layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file).unwrap();
    assert_eq!(layout.disks[0].allowed, ["252:3"]);
}

#[test]
fn a_hidden_volume_that_is_a_whole_disk_leaves_that_disk_unwatched() {
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:16"]);
    let layout = layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file).unwrap();
    let names: Vec<&str> = layout.disks.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["vda"]);
}

#[test]
fn a_hidden_volume_on_a_partition_the_decoy_also_uses_is_imprecise() {
    // A logical volume beside the decoy's root volume on the same partition.
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["252:2"]);
    fake.dm("dm-1", "253:1", &["252:2"]);
    assert_eq!(
        layout_with(&[dev("253:1")], &[dev("253:0")], &fake.sys, &no_file),
        Err(Imprecise::Shared("252:2".into()))
    );
    // A folder or subvolume of the decoy root (--allow-decoy-storage), on a
    // partition nothing is stacked on: only the decoy's own use of it tells.
    let plain = Fake::new();
    assert_eq!(
        layout_with(&[dev("252:2")], &[dev("252:2")], &plain.sys, &no_file),
        Err(Imprecise::Shared("252:2".into()))
    );
    // A partition another mapping outside the hidden stack holds.
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["252:3"]);
    fake.dm("dm-1", "253:1", &["252:3"]);
    assert_eq!(
        layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file),
        Err(Imprecise::Shared("252:3".into()))
    );
}

#[test]
fn a_hidden_volume_in_a_file_on_a_disk_is_imprecise_and_one_in_ram_is_not() {
    let fake = Fake::new();
    fake.loop_dev("loop0", "7:0", "/home/u/vault.img");
    fake.dm("dm-0", "253:0", &["7:0"]);
    let on_disk = |_: &Path| Some(dev("252:2"));
    assert_eq!(
        layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &on_disk),
        Err(Imprecise::File(PathBuf::from("/home/u/vault.img")))
    );
    let layout = layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file).unwrap();
    assert!(layout.disks[0].allowed.is_empty());
}

#[test]
fn no_hidden_device_and_an_unreadable_counter_are_imprecise() {
    let fake = Fake::new();
    assert_eq!(
        layout_with(&[], &[dev("252:2")], &fake.sys, &no_file),
        Err(Imprecise::NoDevice)
    );
    fake.dm("dm-0", "253:0", &["8:17"]);
    let dir = std::fs::canonicalize(fake.root().join("dev/block/252:3")).unwrap();
    std::fs::remove_file(dir.join("stat")).unwrap();
    assert_eq!(
        layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file),
        Err(Imprecise::Unreadable("252:3".into()))
    );
    for why in [
        Imprecise::NotCounted("252:0".into()),
        Imprecise::NothingToWatch,
        Imprecise::NoDevice,
        Imprecise::Shared("252:2".into()),
        Imprecise::File("/f".into()),
        Imprecise::Unreadable("252:3".into()),
    ] {
        assert!(!why.to_string().is_empty());
    }
}

/// The hidden volume on `vda3`, the decoy on `vda1` and `vda2`, with a baseline.
fn watched() -> (Fake, Layout, Baseline) {
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["252:3"]);
    fake.stat("252:0", 1000, 0);
    fake.stat("252:2", 900, 0);
    fake.stat("252:3", 100, 0);
    let layout = layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file).unwrap();
    let base = Baseline::take(&layout, &fake.sys).unwrap();
    (fake, layout, base)
}

#[test]
fn writes_to_the_hidden_partition_alone_are_no_violation() {
    let (fake, layout, base) = watched();
    assert!(check(&layout, &base, &fake.sys).is_empty());
    fake.stat("252:0", 1500, 0);
    fake.stat("252:3", 600, 0);
    assert!(check(&layout, &base, &fake.sys).is_empty());
}

#[test]
fn a_write_or_a_discard_on_a_decoy_partition_is_a_violation() {
    let (fake, layout, base) = watched();
    fake.stat("252:0", 1008, 0);
    fake.stat("252:2", 908, 0);
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["8 sectors written to vda2"]
    );
    let (fake, layout, base) = watched();
    fake.stat("252:0", 1000, 8);
    fake.stat("252:1", 0, 8);
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["8 sectors written to vda1"]
    );
}

#[test]
fn a_write_outside_every_partition_is_a_violation() {
    let (fake, layout, base) = watched();
    fake.stat("252:0", 1001, 0);
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["1 sectors written to vda outside its partitions"]
    );
    // A disk without partitions.
    let fake = Fake::new();
    fake.disk("pci2/vdc", "252:32", true);
    fake.dm("dm-0", "253:0", &["8:17"]);
    let layout = layout_with(&[dev("253:0")], &[dev("252:32")], &fake.sys, &no_file).unwrap();
    let base = Baseline::take(&layout, &fake.sys).unwrap();
    fake.stat("252:32", 4, 0);
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["4 sectors written to vdc"]
    );
}

#[test]
fn a_counter_that_goes_down_a_device_that_goes_and_a_new_partition_are_violations() {
    let (fake, layout, base) = watched();
    fake.stat("252:2", 10, 0);
    let found = check(&layout, &base, &fake.sys);
    assert!(
        found.iter().any(|l| l.contains("vda2 (252:2) went down")),
        "{found:?}"
    );
    let (fake, layout, base) = watched();
    let dir = std::fs::canonicalize(fake.root().join("dev/block/252:1")).unwrap();
    std::fs::remove_file(dir.join("stat")).unwrap();
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["the write counters of vda1 (252:1) cannot be read"]
    );
    let (fake, layout, base) = watched();
    fake.part("pci0/vda", "vda4", "252:4");
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["the partitions of vda changed"]
    );
    let mut short = base.clone();
    short.sectors.remove("252:3");
    let found = check(&layout, &short, &fake.sys);
    assert!(
        found
            .iter()
            .any(|l| l.contains("vda3 (252:3) has no baseline")),
        "{found:?}"
    );
}

#[test]
fn the_baseline_reads_back_and_a_missing_one_is_none() {
    let (fake, layout, base) = watched();
    let path = fake.root().join(BASELINE_NAME);
    base.save(&path).unwrap();
    assert_eq!(Baseline::load(&path), Some(base));
    assert_eq!(Baseline::load(&fake.root().join("none")), None);
    let dir = std::fs::canonicalize(fake.root().join("dev/block/252:2")).unwrap();
    std::fs::remove_file(dir.join("stat")).unwrap();
    assert_eq!(Baseline::take(&layout, &fake.sys), Err("252:2".to_string()));
}

#[test]
fn the_hidden_devices_are_the_mount_and_the_backend() {
    assert_eq!(hidden_devices(Some(dev("253:0")), &[]), [dev("253:0")]);
    assert!(hidden_devices(None, &["no-such-mapping-here".into()]).is_empty());
}

/// Set the kernel's I/O counting of the disk `dev` on or off.
fn count_io(fake: &Fake, dev: &str, on: bool) {
    let dir = std::fs::canonicalize(fake.root().join("dev/block").join(dev)).unwrap();
    std::fs::write(dir.join("queue/iostats"), if on { "1\n" } else { "0\n" }).unwrap();
}

#[test]
fn a_disk_whose_io_the_kernel_does_not_count_is_refused_and_turning_it_off_is_a_violation() {
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:17"]);
    count_io(&fake, "252:0", false);
    assert_eq!(
        layout_with(&[dev("253:0")], &[dev("252:2")], &fake.sys, &no_file),
        Err(Imprecise::NotCounted("252:0".into()))
    );
    let (fake, layout, base) = watched();
    count_io(&fake, "252:0", false);
    assert_eq!(
        check(&layout, &base, &fake.sys),
        ["the kernel no longer counts the I/O of vda (252:0)"]
    );
}

#[test]
fn a_decoy_on_no_watchable_disk_is_refused() {
    // The decoy mounts only a filesystem on no disk with hardware below it.
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:17"]);
    fake.loop_dev("loop1", "7:1", "/run/x.img");
    assert_eq!(
        layout_with(&[dev("253:0")], &[dev("7:1")], &fake.sys, &no_file),
        Err(Imprecise::NothingToWatch)
    );
}

#[test]
fn a_decoy_on_an_md_array_is_refused_as_writing_on_its_own() {
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:17"]);
    // md0 (9:0), mirrored on vda2 and vda3, holds the decoy root.
    fake.dm("md0", "9:0", &["252:2", "252:3"]);
    let md = std::fs::canonicalize(fake.root().join("dev/block/9:0")).unwrap();
    std::fs::create_dir_all(md.join("md")).unwrap();
    assert_eq!(
        layout_with(&[dev("253:0")], &[dev("9:0")], &fake.sys, &no_file),
        Err(Imprecise::WritesOnItsOwn("md0".into()))
    );
    // The hidden volume's own md array writes only to what it owns.
    let fake = Fake::new();
    fake.dm("md1", "9:1", &["8:17"]);
    let hidden_md = std::fs::canonicalize(fake.root().join("dev/block/9:1")).unwrap();
    std::fs::create_dir_all(hidden_md.join("md")).unwrap();
    assert!(layout_with(&[dev("9:1")], &[dev("252:2")], &fake.sys, &no_file).is_ok());
}

#[test]
fn a_decoy_device_the_counters_cannot_follow_to_a_disk_is_refused() {
    // nbd0 (43:0): no hardware, no loop file, nothing below it.
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:17"]);
    fake.disk("virtual/block/nbd0", "43:0", false);
    assert_eq!(
        layout_with(
            &[dev("253:0")],
            &[dev("252:2"), dev("43:0")],
            &fake.sys,
            &no_file
        ),
        Err(Imprecise::Unwatchable("nbd0".into()))
    );
    // A device sysfs does not list at all.
    assert_eq!(
        layout_with(
            &[dev("253:0")],
            &[dev("252:2"), dev("44:4")],
            &fake.sys,
            &no_file
        ),
        Err(Imprecise::Unwatchable("44:4".into()))
    );
    // A zram device and a RAM disk hold nothing of a disk.
    let fake = Fake::new();
    fake.dm("dm-0", "253:0", &["8:17"]);
    fake.disk("virtual/block/zram0", "251:0", false);
    fake.disk("virtual/block/ram1", "1:1", false);
    let layout = layout_with(
        &[dev("253:0")],
        &[dev("252:2"), dev("251:0"), dev("1:1")],
        &fake.sys,
        &no_file,
    )
    .unwrap();
    assert_eq!(layout.disks.len(), 1);
    assert!(in_ram("zram0") && in_ram("ram1") && !in_ram("ramx") && !in_ram("zram"));
    assert!(
        Imprecise::WritesOnItsOwn("md0".into())
            .to_string()
            .contains("md0")
    );
    assert!(
        Imprecise::Unwatchable("nbd0".into())
            .to_string()
            .contains("nbd0")
    );
}

#[test]
fn a_device_on_a_watched_disk_is_told_from_one_elsewhere() {
    let (fake, layout, _) = watched();
    fake.dm("dm-1", "253:1", &["252:2"]);
    assert!(on_watched_disk(&layout, &fake.sys, dev("252:2")));
    assert!(on_watched_disk(&layout, &fake.sys, dev("253:1")));
    assert!(on_watched_disk(&layout, &fake.sys, dev("252:0")));
    assert!(!on_watched_disk(&layout, &fake.sys, dev("8:17")));
}

#[test]
fn a_baseline_and_a_check_read_settled_counters() {
    let (fake, layout, base) = watched();
    assert_eq!(base.sectors.get("252:0"), Some(&1000));
    assert_eq!(base.sectors.len(), 4);
    let (read, agreed) = stable_read(&watched_devices(&layout), &fake.sys);
    assert!(agreed);
    assert_eq!(read.get("252:2"), Some(&Some(900)));
}

#[test]
fn a_file_lies_on_the_device_its_filesystem_shows() {
    // A kernel filesystem has no block device.
    assert_eq!(file_device(Path::new("/proc/self/stat")), None);
    assert_eq!(file_device(Path::new("/nonexistent/file")), None);
    // The test binary lies on a disk, unless the build keeps it in RAM.
    let exe = std::env::current_exe().unwrap();
    let raw = std::fs::metadata(&exe).unwrap().dev();
    let shown = DevNum::from_raw(raw);
    let expected = (shown.major != 0).then_some(shown);
    assert_eq!(file_device(&exe), expected);
}
