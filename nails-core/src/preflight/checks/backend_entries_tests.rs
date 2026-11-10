// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on mock decoys: a plain decoy on `nvme0n1p3`
//! and the hidden volume, an encrypted mapping `data` on the external `sdb`,
//! mounted at `/mnt`. The sysfs fixture follows the real layout: attributes
//! under `/sys/devices`, and `/sys/class/block/<name>` and `slaves/` entries
//! linking there.

use super::*;
use crate::filesystem::MockFilesystem;
use std::path::Path;

const NVME: &str = "/sys/devices/pci0/nvme/nvme0n1";
const P3: &str = "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p3";
const SDB: &str = "/sys/devices/pci0/usb/sdb";
const SDB1: &str = "/sys/devices/pci0/usb/sdb/sdb1";
const SDB2: &str = "/sys/devices/pci0/usb/sdb/sdb2";
const SDC: &str = "/sys/devices/pci0/usb/sdc";
const SDC1: &str = "/sys/devices/pci0/usb/sdc/sdc1";

struct Decoy {
    fs: MockFilesystem,
    class: Vec<PathBuf>,
}

impl Decoy {
    fn new(mountinfo: &str) -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(mountinfo);
        fs.mock_set_path_exists("/mnt", true);
        fs.mock_set_path_exists("/sys/class/block", true);
        Self {
            fs,
            class: Vec::new(),
        }
    }

    fn attr(&self, dir: &str, attribute: &str, value: &str) {
        self.fs
            .mock_set_file_content(&format!("{dir}/{attribute}"), &format!("{value}\n"));
    }

    fn link(&self, link: &str, target: &str) {
        self.fs
            .create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }

    fn device(mut self, dir: &str, name: &str, dev: &str, slaves: &[(&str, &str)]) -> Self {
        self.attr(dir, "dev", dev);
        self.attr(dir, "uevent", &format!("DEVNAME={name}"));
        let slave_dir = Path::new(dir).join("slaves");
        let mut entries = Vec::new();
        for (slave, target) in slaves {
            let path = slave_dir.join(slave);
            self.link(path.to_str().unwrap(), target);
            entries.push(path);
        }
        self.fs.mock_set_directory_contents(&slave_dir, entries);
        let class = format!("/sys/class/block/{name}");
        self.link(&class, dir);
        self.class.push(PathBuf::from(class));
        self.fs
            .mock_set_directory_contents(Path::new("/sys/class/block"), self.class.clone());
        self
    }

    fn partition(self, dir: &str, name: &str, dev: &str) -> Self {
        let decoy = self.device(dir, name, dev, &[]);
        decoy.attr(dir, "partition", "1");
        decoy
    }

    fn mapping(self, name: &str, dev: &str, dm: &str, below: (&str, &str)) -> Self {
        self.device_mapper(name, dev, dm, &format!("CRYPT-LUKS2-00-{dm}"), below)
    }

    /// An LVM logical volume `dm` in the volume group on `below`.
    fn lv(self, name: &str, dev: &str, dm: &str, below: (&str, &str)) -> Self {
        self.device_mapper(name, dev, dm, &format!("LVM-{dm}"), below)
    }

    fn device_mapper(
        self,
        name: &str,
        dev: &str,
        dm: &str,
        uuid: &str,
        below: (&str, &str),
    ) -> Self {
        let dir = format!("/sys/devices/virtual/block/{name}");
        let decoy = self.device(&dir, name, dev, &[below]);
        decoy.attr(&dir, "dm/name", dm);
        decoy.attr(&dir, "dm/uuid", uuid);
        decoy.link(&format!("/dev/mapper/{dm}"), &format!("/dev/{name}"));
        decoy
    }

    fn file(self, path: &str, text: &str) -> Self {
        self.fs.mock_set_file_content(path, text);
        self
    }

    fn run(&self) -> CheckResult {
        BackendEntriesCheck::new(PathBuf::from("/mnt"))
            .run(&self.fs)
            .unwrap()
    }
}

/// The decoy, with the hidden volume opened from the whole of `sdb`.
fn decoy() -> Decoy {
    Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 254:9 / /mnt rw - ext4 /dev/mapper/data rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .device(SDB, "sdb", "8:16", &[])
    .device(SDC, "sdc", "8:32", &[])
    .mapping("dm-9", "254:9", "data", ("sdb", SDB))
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n")
}

#[test]
fn a_decoy_without_entries_for_the_volume_passes() {
    let result = decoy().run();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn a_crypttab_line_that_opens_the_volume_fails() {
    let result = decoy()
        .file("/etc/crypttab", "data /dev/sdb none luks,noauto\n")
        .run();
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.contains("/etc/crypttab: 'data /dev/sdb'"),
        "{message}"
    );
    assert!(
        message.contains("it opens the volume at /mnt or a device it is stored on"),
        "{message}"
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
}

/// The decoy's root on md0p2 of an md mirror of two LUKS volumes its
/// crypttab opens at boot, and the hidden volume on md0p1 of the same array,
/// with `fstab` the decoy's fstab.
fn on_the_decoys_array(fstab: &str) -> Decoy {
    array_decoy("5 1 259:11 / /mnt rw - ext4 /dev/md0p1 rw\n", fstab)
}

/// The decoy's root on md0p2 of an md mirror of two LUKS volumes its
/// crypttab opens at boot, with `hidden` the mount line of the root and
/// `fstab` the decoy's fstab.
fn array_decoy(hidden: &str, fstab: &str) -> Decoy {
    let md0 = "/sys/devices/virtual/block/md0";
    Decoy::new(&format!("1 0 259:12 / / rw - ext4 /dev/md0p2 rw\n{hidden}"))
        .device(SDB, "sdb", "8:16", &[])
        .partition(SDB1, "sdb1", "8:17")
        .device(SDC, "sdc", "8:32", &[])
        .partition(SDC1, "sdc1", "8:33")
        .mapping("dm-20", "254:20", "leg0", ("sdb1", SDB1))
        .mapping("dm-21", "254:21", "leg1", ("sdc1", SDC1))
        .device(
            md0,
            "md0",
            "9:0",
            &[
                ("dm-20", "/sys/devices/virtual/block/dm-20"),
                ("dm-21", "/sys/devices/virtual/block/dm-21"),
            ],
        )
        .partition(&format!("{md0}/md0p1"), "md0p1", "259:11")
        .partition(&format!("{md0}/md0p2"), "md0p2", "259:12")
        .file("/etc/fstab", fstab)
        .file(
            "/etc/crypttab",
            "leg0 /dev/sdb1 none luks\nleg1 /dev/sdc1 none luks\n",
        )
}

/// The finding for the decoy's crypttab line `line` on the array, which its
/// own boot needs.
fn leg(line: &str) -> String {
    format!(
        "/etc/crypttab: '{line}' (it opens the volume at /mnt or a device it is stored on, and \
         the decoy's own boot needs it)"
    )
}

#[test]
fn a_line_the_decoys_own_boot_needs_says_to_move_the_hidden_root_instead() {
    // Removing the crypttab lines would break the decoy.
    let result = on_the_decoys_array("/dev/md0p2 / ext4 defaults 0 1\n").run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains(&leg("leg0 /dev/sdb1")),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
    assert_eq!(
        STORAGE_OF_ITS_OWN,
        "Do not remove a line the decoy's own boot needs: put the hidden root on storage of its \
         own instead."
    );
}

#[test]
fn the_decoys_line_for_the_filesystem_a_root_is_a_folder_of_is_never_to_be_removed() {
    // A folder of / bound at the root, which --allow-decoy-storage accepted:
    // the decoy's line for / names the root's device, and removing it would
    // break the decoy.
    let result = Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 259:3 /srv/x /mnt rw - ext4 /dev/nvme0n1p3 rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n")
    .run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains(
            "/etc/fstab: '/dev/nvme0n1p3 / ext4' (it mounts the filesystem the volume at /mnt \
             is part of, and the decoy's own boot needs it)"
        ),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
}

#[test]
fn lines_of_both_kinds_get_both_instructions() {
    // A noauto fstab line mounts md0p1 at /mnt for the hidden volume alone.
    // Once the hidden root moves, it is flagged no more and would stay
    // behind naming /mnt, so it still has to go.
    let result =
        on_the_decoys_array("/dev/md0p2 / ext4 defaults 0 1\n/dev/md0p1 /mnt ext4 noauto 0 0\n")
            .run();
    assert!(result.is_fail(), "{result:?}");
    for finding in [
        "/etc/fstab: '/dev/md0p1 /mnt ext4' (it mounts the volume at /mnt)".to_string(),
        leg("leg0 /dev/sdb1"),
        leg("leg1 /dev/sdc1"),
    ] {
        assert!(
            result.message().contains(&finding),
            "{finding}: {}",
            result.message()
        );
    }
    assert_eq!(result.remediation(), Some(REMOVE_AND_MOVE));
    assert_eq!(
        REMOVE_AND_MOVE,
        "Remove the lines only the hidden volume needs long before the next use, and open the \
         volume by hand each time. Do not remove a line the decoy's own boot needs: put the \
         hidden root on storage of its own instead."
    );
}

#[test]
fn a_tcrypt_hidden_line_for_the_volumes_drive_fails() {
    let result = decoy()
        .file(
            "/etc/crypttab",
            "vault /dev/sdb none tcrypt-hidden,noauto\n",
        )
        .run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("'vault /dev/sdb'"),
        "{}",
        result.message()
    );
}

#[test]
fn a_tcrypt_hidden_line_for_another_drive_passes() {
    let result = decoy()
        .file(
            "/etc/crypttab",
            "vault /dev/sdc none tcrypt-hidden,noauto\n",
        )
        .run();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn an_fstab_line_that_mounts_the_volume_fails() {
    let result = decoy()
        .file(
            "/etc/fstab",
            "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/mapper/data /mnt ext4 noauto 0 0\n",
        )
        .run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("/etc/fstab: '/dev/mapper/data /mnt ext4' (it mounts the volume at /mnt)"),
        "{}",
        result.message()
    );
}

#[test]
fn an_entry_for_another_device_passes() {
    let result = decoy()
        .file("/etc/crypttab", "backup /dev/sdc none luks,noauto\n")
        .run();
    assert!(result.is_pass(), "{result:?}");
}

#[test]
fn an_entry_for_the_outer_volume_of_the_same_drive_warns() {
    // The hidden volume opened from sdb2; the decoy opens a VeraCrypt volume
    // on sdb1 of the same drive.
    let decoy = Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 254:9 / /mnt rw - ext4 /dev/mapper/data rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .device(SDB, "sdb", "8:16", &[])
    .partition(SDB1, "sdb1", "8:17")
    .partition(SDB2, "sdb2", "8:18")
    .mapping("dm-9", "254:9", "data", ("sdb2", SDB2))
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n")
    .file("/etc/crypttab", "outer /dev/sdb1 none tcrypt,noauto\n");
    // Partitions know their disk through the parent directory.
    let result = decoy.run();
    assert!(result.is_warn(), "{result:?}");
    assert!(
        result
            .message()
            .contains("the decoy is configured to open storage on this drive"),
        "{}",
        result.message()
    );
}

#[test]
fn an_unreadable_crypttab_fails_and_asks_for_sudo() {
    let decoy = decoy();
    // It exists, but reading it fails, as a root-only file does.
    decoy.fs.mock_set_path_exists("/etc/crypttab", true);
    let result = decoy.run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("Could not read /etc/crypttab"),
        "{}",
        result.message()
    );
    assert_eq!(
        result.remediation(),
        Some("Run the command again with sudo.")
    );
}

#[test]
fn a_ram_root_or_a_folder_has_no_entries_to_find() {
    let ram = Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 0:50 / /mnt rw - tmpfs tmpfs rw\n",
    );
    ram.fs.mock_set_path_exists("/etc/crypttab", true);
    assert!(ram.run().is_pass());

    let folder = Decoy::new("1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n");
    assert!(folder.run().is_pass());
}

#[test]
fn it_depends_on_the_hidden_volume_and_is_named_backend_entries() {
    let check = BackendEntriesCheck::new(PathBuf::from("/mnt"));
    assert_eq!(
        <BackendEntriesCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "backend-entries"
    );
    assert!(
        <BackendEntriesCheck as PreFlightCheck<MockFilesystem>>::requires_hidden_volume(&check)
    );
}

// ------------------------------------------------------------------------
// A root that --allow-decoy-storage accepted on a filesystem the decoy uses
// ------------------------------------------------------------------------

/// A decoy whose block devices the mock renders from `table`, as each mount's
/// source and device number, with `fstab` and the root at `/mnt`.
fn rendered(table: &str, fstab: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt", true);
    fs.mock_set_writable("/mnt", true);
    fs.mock_set_mount_table(table);
    fs.mock_set_file_content("/etc/fstab", fstab);
    fs
}

/// The check of the root at `/mnt` on `fs`, with `allow`.
fn run_allowing(fs: &MockFilesystem, allow: Allow) -> CheckResult {
    BackendEntriesCheck::new(PathBuf::from("/mnt"))
        .allowing(allow)
        .run(fs)
        .unwrap()
}

/// The hidden-volume check of the root at `/mnt` on `fs`, with the flag.
fn hidden_volume_with_the_flag(fs: &MockFilesystem) -> CheckResult {
    crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
        .allowing(Allow::DecoyStorage)
        .run(fs)
        .unwrap()
}

/// A folder of `/` bound at the root.
const BIND_OF_ROOT: &str = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                            5 1 8:1 /srv/x /mnt rw - ext4 /dev/vda1 rw\n";

/// A btrfs subvolume beside the `/home` subvolume of the same filesystem.
const BESIDE_HOME: &str = "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
                           2 1 0:40 /home /home rw - btrfs /dev/vda2 rw,subvolid=257,subvol=/home\n\
                           5 1 0:40 /vault /mnt rw - btrfs /dev/vda2 rw,subvolid=300,subvol=/vault\n";

/// The pass of a root the flag accepted, which only the decoy's own line for
/// `place` names.
fn only_the_decoys_own_line(place: &str) -> String {
    format!(
        "No fstab or crypttab entry names the volume at /mnt other than the decoy's own line for \
         {place}, which mounts the filesystem that --allow-decoy-storage accepted it on"
    )
}

#[test]
fn with_the_flag_the_decoys_own_lines_for_slash_and_a_system_folder_are_no_finding() {
    // A bind of a folder of /, and a btrfs subvolume beside the fstab's
    // /home: the hidden-volume check passes each with the flag's warning,
    // and the decoy's line for / or /home mounts the filesystem the flag
    // accepted the root on.
    let home = "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs subvol=/home 0 0\n";
    for (table, fstab, place) in [
        (BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n", "/"),
        (BESIDE_HOME, home, "/home"),
    ] {
        let fs = rendered(table, fstab);
        let gate = hidden_volume_with_the_flag(&fs);
        assert!(gate.is_warn(), "{place}: {gate:?}");
        assert!(
            gate.message()
                .starts_with("--allow-decoy-storage: using /mnt although it is"),
            "{place}: {}",
            gate.message()
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{place}: {result:?}");
        assert_eq!(result.message(), only_the_decoys_own_line(place));
        // Without the flag nothing changes: the line is a finding, one the
        // decoy's own boot needs.
        let result = run_allowing(&fs, Allow::Nothing);
        assert!(result.is_fail(), "{place}: {result:?}");
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{place}");
    }
    // Lines for / and /home of that filesystem are named together, each
    // with its mount there.
    let fs = rendered(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:1 / /home rw - ext4 /dev/vda1 rw\n\
         5 1 8:1 /srv/x /mnt rw - ext4 /dev/vda1 rw\n",
        "/dev/vda1 / ext4 defaults 0 1\n/dev/vda1 /home ext4 defaults 0 2\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        "No fstab or crypttab entry names the volume at /mnt other than the decoy's own lines \
         for / and /home, which mount the filesystem that --allow-decoy-storage accepted it on"
    );
}

#[test]
fn with_the_flag_a_line_for_that_filesystem_at_any_other_folder_still_fails() {
    // The decoy mounts the btrfs top at /pool, a folder no system folder is:
    // its line may name the hidden drive's disk.
    let fs = rendered(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 0:40 / /pool rw - btrfs /dev/vda2 rw,subvolid=5,subvol=/\n\
         5 1 0:40 /vol /mnt rw - btrfs /dev/vda2 rw,subvolid=256,subvol=/vol\n",
        "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /pool btrfs defaults 0 0\n",
    );
    assert!(hidden_volume_with_the_flag(&fs).is_warn());
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains(
            "/etc/fstab: '/dev/vda2 /pool btrfs' (it mounts the filesystem the volume at /mnt is \
             part of, and the decoy's own boot needs it)"
        ),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
    // Beside a line for /home that the flag lets be, only the other line is
    // named: a noauto one, which the boot does not mount, is one to remove.
    let fs = rendered(
        BESIDE_HOME,
        "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs subvol=/home 0 0\n\
         /dev/vda2 /srv btrfs subvol=/vault,noauto 0 0\n",
    );
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("/etc/fstab: '/dev/vda2 /srv btrfs' (it mounts the volume at /mnt)"),
        "{}",
        result.message()
    );
    assert!(
        !result.message().contains("/home btrfs"),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
    // A crypttab line that would open a volume on the device the root is
    // mounted from makes no device the decoy's filesystem lies on: it still
    // fails, whether the boot opens it or not, and goes.
    for options in ["luks,noauto", "luks"] {
        let fs = rendered(BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n");
        fs.mock_set_file_content(
            "/etc/crypttab",
            &format!("vault /dev/vda1 none {options}\n"),
        );
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{options}: {result:?}");
        assert!(
            result.message().contains(
                "/etc/crypttab: 'vault /dev/vda1' (it opens the volume at /mnt or a device it is \
                 stored on)"
            ),
            "{options}: {}",
            result.message()
        );
        assert!(
            !result.message().contains("/etc/fstab"),
            "{options}: {}",
            result.message()
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{options}");
    }
}

#[test]
fn with_the_flag_a_root_whose_storage_cannot_be_judged_keeps_every_finding() {
    // The disk's kind cannot be read (no /proc/devices here), so the judge
    // does not place the root on the decoy's filesystem, and the line for /
    // stays a finding with the flag too.
    let decoy = Decoy::new(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         5 1 259:3 /srv/x /mnt rw - ext4 /dev/nvme0n1p3 rw\n",
    )
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .file("/etc/fstab", "/dev/nvme0n1p3 / ext4 defaults 0 1\n");
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
}

#[test]
fn a_root_that_is_the_whole_of_the_decoys_root_or_home_is_never_told_to_remove_its_line() {
    // The decoy's / on vda1, and its /home partition vda2, each mounted whole
    // at the root as well.
    let root = (
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         5 1 8:1 / /mnt rw - ext4 /dev/vda1 rw\n",
        "/dev/vda1 / ext4 defaults 0 1\n",
        "/",
    );
    let home = (
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:2 / /home rw - ext4 /dev/vda2 rw\n\
         5 1 8:2 / /mnt rw - ext4 /dev/vda2 rw\n",
        "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home ext4 defaults 0 2\n",
        "/home",
    );
    for (table, fstab, place) in [root, home] {
        let fs = rendered(table, fstab);
        // The gate refuses it without the flag, and says nothing of
        // removing the decoy's line for that folder.
        let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
            .run(&fs)
            .unwrap();
        assert!(gate.is_fail(), "{place}: {gate:?}");
        assert_eq!(
            gate.message(),
            format!(
                "/mnt is not a volume of its own: it is the filesystem this computer mounts at \
                 {place} per /etc/fstab"
            )
        );
        let hint = gate.remediation().unwrap();
        assert!(hint.starts_with("Setting up here"), "{place}: {hint}");
        assert!(!hint.contains("remove its line"), "{place}: {hint}");
        // With the flag the gate warns. The line mounts the volume itself,
        // no filesystem the root is part of, so backend-entries still fails
        // it, with the flag or without, and says to keep it, as the decoy's
        // own boot needs it.
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{place}");
        for allow in [Allow::DecoyStorage, Allow::Nothing] {
            let result = run_allowing(&fs, allow);
            assert!(result.is_fail(), "{place}: {result:?}");
            assert!(
                result
                    .message()
                    .contains("(it mounts the volume at /mnt, and the decoy's own boot needs it)"),
                "{place}: {}",
                result.message()
            );
            assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{place}");
        }
    }
}

/// The finding for the line `line` that mounts the volume at the root
/// itself, which the decoy's own boot needs.
fn mounts_the_volume(line: &str) -> String {
    format!(
        "/etc/fstab: '{line}' (it mounts the volume at /mnt, and the decoy's own boot needs it)"
    )
}

#[test]
fn with_the_flag_a_line_that_mounts_the_volume_itself_still_fails() {
    // A separate drive with a nofail line at a system folder, mounted at the
    // root alone, as one plugged in after the boot is: the gate takes it for
    // the decoy's storage, and with the flag it warns, but the line names the
    // volume itself. At /srv, /opt and /home it is one the boot needs, never
    // one to remove; at /backup it serves the volume alone, and goes.
    for (place, remediation) in [
        ("/srv", STORAGE_OF_ITS_OWN),
        ("/opt", STORAGE_OF_ITS_OWN),
        ("/home", STORAGE_OF_ITS_OWN),
        ("/backup", REMEDIATION),
    ] {
        let fs = rendered(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw
             5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw
",
            &format!(
                "/dev/vda1 / ext4 defaults 0 1
/dev/sdb1 {place} ext4 defaults,nofail 0 2
"
            ),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{place}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{place}: {result:?}");
        assert_eq!(result.remediation(), Some(remediation), "{place}");
    }
    // The same drive mounted at /srv by that line as well.
    let fs = rendered(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw
         2 1 8:17 / /srv rw - ext4 /dev/sdb1 rw
         5 1 8:17 / /mnt rw - ext4 /dev/sdb1 rw
",
        "/dev/vda1 / ext4 defaults 0 1
/dev/sdb1 /srv ext4 defaults,nofail 0 2
",
    );
    assert!(hidden_volume_with_the_flag(&fs).is_warn());
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains(&mounts_the_volume("/dev/sdb1 /srv ext4")),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));

    // A line that mounts the root's own subvolume at /srv, by its path or
    // its id, mounted there or not: only the line for /home is the decoy's
    // own.
    let at_srv = format!(
        "{BESIDE_HOME}6 1 0:40 /vault /srv rw - btrfs /dev/vda2 rw,subvolid=300,subvol=/vault
"
    );
    for table in [BESIDE_HOME, at_srv.as_str()] {
        for options in ["subvol=/vault", "subvolid=300"] {
            let fs = rendered(
                table,
                &format!(
                    "/dev/vda1 / ext4 defaults 0 1
/dev/vda2 /home btrfs subvol=/home 0 0
                     /dev/vda2 /srv btrfs {options} 0 0
"
                ),
            );
            assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{options}");
            let result = run_allowing(&fs, Allow::DecoyStorage);
            assert!(result.is_fail(), "{options}: {result:?}");
            let message = result.message();
            assert!(
                message.contains(&mounts_the_volume("/dev/vda2 /srv btrfs")),
                "{options}: {message}"
            );
            assert!(!message.contains("/home btrfs"), "{options}: {message}");
            assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{options}");
        }
    }
}

#[test]
fn with_the_flag_a_line_for_a_drive_whose_mount_is_not_there_still_fails() {
    // A folder of a separate drive bound at the root, while nothing mounts
    // the drive where its nofail line for a system folder would, as after it
    // was plugged in: nothing shows that the decoy uses the drive, and the
    // line may be the hidden drive's own. It mounts the filesystem the root
    // is part of, so the check says to keep it. Once the drive is mounted
    // there, the line is the decoy's own.
    let table = |mounts: &str| {
        format!(
            "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n{mounts}\
             5 1 8:17 /x /mnt rw - ext4 /dev/sdb1 rw\n"
        )
    };
    for place in ["/srv", "/opt", "/home"] {
        let fstab =
            format!("/dev/vda1 / ext4 defaults 0 1\n/dev/sdb1 {place} ext4 defaults,nofail 0 2\n");
        let fs = rendered(&table(""), &fstab);
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{place}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{place}: {result:?}");
        assert!(
            result.message().contains(&format!(
                "/etc/fstab: '/dev/sdb1 {place} ext4' (it mounts the filesystem the volume at \
                 /mnt is part of, and the decoy's own boot needs it)"
            )),
            "{place}: {}",
            result.message()
        );
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{place}");
        let mounted = table(&format!("2 1 8:17 / {place} rw - ext4 /dev/sdb1 rw\n"));
        let fs = rendered(&mounted, &fstab);
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{place}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_pass(), "{place}: {result:?}");
        assert_eq!(result.message(), only_the_decoys_own_line(place));
    }
}

#[test]
fn with_the_flag_a_line_whose_text_does_not_tell_what_btrfs_mounts_still_fails() {
    // A line for /srv beside the fstab's /home whose subvolume btrfs may read
    // otherwise than its text: two subvol= (btrfs takes the last, the root's
    // own here), with the /home subvolume mounted at /srv by hand too, two
    // subvolid=, or a .. in the path. Only the line for /home is the decoy's
    // own.
    let home_at_srv = format!(
        "{BESIDE_HOME}6 1 0:40 /home /srv rw - btrfs /dev/vda2 rw,subvolid=257,subvol=/home\n"
    );
    for (table, options) in [
        (BESIDE_HOME, "subvol=/home,subvol=/vault"),
        (home_at_srv.as_str(), "subvol=/home,subvol=/vault"),
        (BESIDE_HOME, "subvolid=257,subvolid=300"),
        (BESIDE_HOME, "subvol=/home/../vault"),
    ] {
        let fs = rendered(
            table,
            &format!(
                "/dev/vda1 / ext4 defaults 0 1\n/dev/vda2 /home btrfs subvol=/home 0 0\n\
                 /dev/vda2 /srv btrfs {options},nofail 0 0\n"
            ),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{options}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{options}: {result:?}");
        let message = result.message();
        assert!(
            message.contains(
                "/etc/fstab: '/dev/vda2 /srv btrfs' (it mounts the filesystem the volume at /mnt \
                 is part of, and the decoy's own boot needs it)"
            ),
            "{options}: {message}"
        );
        assert!(!message.contains("/home btrfs"), "{options}: {message}");
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{options}");
    }
}

#[test]
fn a_bind_line_that_mounts_the_volume_fails_with_the_flag_too() {
    // A bind of a folder of / at the root, which a bind line of the decoy's
    // fstab makes at every boot: with the flag the line for / is the decoy's
    // own, but the bind line mounts the volume itself, and goes.
    let fs = rendered(
        BIND_OF_ROOT,
        "/dev/vda1 / ext4 defaults 0 1\n/srv/x /mnt none bind 0 0\n",
    );
    assert!(hidden_volume_with_the_flag(&fs).is_warn());
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("/etc/fstab: '/srv/x /mnt none' (it mounts the volume at /mnt)"),
        "{}",
        result.message()
    );
    assert!(
        !result.message().contains("/dev/vda1 / ext4"),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
    // Without the flag the line for / is named too, and kept.
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(result.remediation(), Some(REMOVE_AND_MOVE));
    // A bind line for a folder of the volume of a drive of its own fails as
    // well: it mounts that folder at every boot the drive is there.
    let result = decoy()
        .file(
            "/etc/fstab",
            "/dev/nvme0n1p3 / ext4 defaults 0 1\n/mnt/web /srv/web none bind,nofail 0 0\n",
        )
        .run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains(
            "/etc/fstab: '/mnt/web /srv/web none' (it mounts a folder of the volume at /mnt)"
        ),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
}

/// What the check says after a line whose path cannot be told: it may name
/// the volume, and is stored on the decoy.
const STORED: &str = "Such an entry is stored on the decoy, where an examination reads it, and \
                      can open or mount the volume at boot.";

/// The finding for the line that reads `shown`, whose source or file
/// (`what`) lies where `why` says it cannot be told.
fn untold(shown: &str, what: &str, why: &str) -> String {
    format!("/etc/fstab: '{shown}' (where {what} lies cannot be told: {why})")
}

/// That the check of `fs` fails with `allow` naming only `finding`, a line
/// whose path cannot be told, and says to write it with its real path.
fn fails_as_untold(fs: &MockFilesystem, allow: Allow, finding: &str) {
    let result = run_allowing(fs, allow);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!("The decoy's configuration may name the volume at /mnt: {finding}. {STORED}")
    );
    assert_eq!(result.remediation(), Some(UNTOLD));
}

#[test]
fn a_bind_line_whose_source_holds_a_link_fails_with_the_flag_too() {
    // The bind line of the test above, written through a link to the root's
    // folder: the boot's mount follows the link, so the line binds the volume
    // at the root as its direct form does. NAILS follows no link: it fails
    // the line, with the flag too, names the link and says to write the line
    // with its real path. So does it for a relative link, a chain of links,
    // a link in a parent folder and a link to nothing, wherever they lead.
    // hidden-volume passes the root with the flag's warning, as for the
    // direct form.
    for (links, source, link) in [
        (&[("/srv/link", "/srv/x")][..], "/srv/link", "/srv/link"),
        (&[("/srv/link", "x")][..], "/srv/link", "/srv/link"),
        (
            &[("/srv/link", "/srv/chain"), ("/srv/chain", "../srv/x")][..],
            "/srv/link",
            "/srv/link",
        ),
        (&[("/data", "/srv")][..], "/data/x", "/data"),
        (
            &[("/srv/link", "/srv/nothing")][..],
            "/srv/link",
            "/srv/link",
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{source} /mnt none bind 0 0\n"),
        );
        for (link, target) in links {
            fs.create_symlink(Path::new(target), Path::new(link))
                .unwrap();
        }
        fs.mock_set_mount_root_error("/srv/nothing", std::io::ErrorKind::NotFound);
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{links:?}");
        let why = format!("{link} is a symbolic link, which NAILS does not follow");
        fails_as_untold(
            &fs,
            Allow::DecoyStorage,
            &untold(&format!("{source} /mnt none"), "its source", &why),
        );
    }
}

#[test]
fn a_line_whose_path_cannot_be_told_fails_without_the_flag_and_says_why() {
    // Without the flag the line for / is named first, which the decoy's own
    // boot needs, and the fix says what to do about each kind.
    let fs = rendered(
        BIND_OF_ROOT,
        "/dev/vda1 / ext4 defaults 0 1\n/srv/link /mnt none bind 0 0\n",
    );
    fs.create_symlink(Path::new("/srv/x"), Path::new("/srv/link"))
        .unwrap();
    let finding = untold(
        "/srv/link /mnt none",
        "its source",
        "/srv/link is a symbolic link, which NAILS does not follow",
    );
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_fail(), "{result:?}");
    let message = result.message();
    assert!(
        message.starts_with(
            "The decoy's configuration names the volume at /mnt: /etc/fstab: '/dev/vda1 / ext4' ("
        ),
        "{message}"
    );
    assert!(
        message.ends_with(&format!("). It may name it as well: {finding}. {STORED}")),
        "{message}"
    );
    assert_eq!(
        result.remediation(),
        Some(format!("{STORAGE_OF_ITS_OWN}\n{UNTOLD}").as_str())
    );
}

#[test]
fn a_swap_or_image_line_through_a_link_to_the_volumes_device_fails() {
    // The hidden volume is the mapping `data` (dm-9) on the whole of sdb,
    // at /mnt. A line that names its device mounts it, or swaps on it, at
    // boot, and fails. One whose path is a link to that device does the
    // same at boot, through the link, and fails as well, with no flag, as a
    // line whose path cannot be told.
    for line in [
        "/dev/mapper/data /media/x ext4 defaults,nofail 0 2",
        "/dev/mapper/data none swap sw 0 0",
    ] {
        let result = decoy()
            .file(
                "/etc/fstab",
                &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
            )
            .run();
        assert!(result.is_fail(), "{line}: {result:?}");
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
    }
    for (link, target, line, shown) in [
        (
            "/hidden.link",
            "/dev/mapper/data",
            "/hidden.link /media/x ext4 defaults,nofail 0 2",
            "/hidden.link /media/x ext4",
        ),
        (
            "/swap.link",
            "/dev/mapper/data",
            "/swap.link none swap sw 0 0",
            "/swap.link none swap",
        ),
        (
            "/swap.link",
            "/dev/sdb",
            "/swap.link none swap sw 0 0",
            "/swap.link none swap",
        ),
    ] {
        let decoy = decoy().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        decoy.link(link, target);
        let why = format!("{link} is a symbolic link, which NAILS does not follow");
        fails_as_untold(
            &decoy.fs,
            Allow::Nothing,
            &untold(shown, "the file it names", &why),
        );
    }
}

#[test]
fn a_swap_or_image_line_whose_path_is_a_device_node_fails() {
    // A device node outside /dev: swapon and mount use the device it is.
    for (line, shown) in [
        ("/srv/node none swap sw 0 0", "/srv/node none swap"),
        (
            "/srv/node /media/x ext4 defaults,nofail 0 2",
            "/srv/node /media/x ext4",
        ),
    ] {
        let decoy = decoy().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        decoy.fs.mock_set_device_node("/srv/node");
        fails_as_untold(
            &decoy.fs,
            Allow::Nothing,
            &untold(shown, "the file it names", "/srv/node is a device node"),
        );
    }
}

/// Why a line whose first field is no absolute path and no tag is not plain.
const RELATIVE: &str = "its first field is neither an absolute path nor a UUID=, LABEL=, \
                        PARTUUID=, PARTLABEL= or ID= tag";

/// The finding for the line that is not plain whose first three fields read
/// `shown`, for `reason`.
fn not_plain(shown: &str, reason: &str) -> String {
    format!("/etc/fstab: '{shown}' (NAILS reads only plain lines, and {reason})")
}

/// That the check of `fs` fails with `allow` naming only `finding`, a line
/// that is not plain, and says to write it plainly.
fn fails_as_not_plain(fs: &MockFilesystem, allow: Allow, finding: &str) {
    let result = run_allowing(fs, allow);
    assert!(result.is_fail(), "{result:?}");
    assert_eq!(
        result.message(),
        format!("The decoy's configuration may name the volume at /mnt: {finding}. {STORED}")
    );
    assert_eq!(result.remediation(), Some(UNPLAIN));
}

#[test]
fn a_swap_or_image_line_whose_path_is_not_absolute_fails_with_the_flag_too() {
    // swapon and mount look up such a path from the folder they run in: the
    // line is not plain, and NAILS reads no such line.
    for (line, shown) in [
        ("swapfile none swap sw 0 0", "swapfile none swap"),
        (
            "srv/img.raw /mnt/img ext4 loop 0 0",
            "srv/img.raw /mnt/img ext4",
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        fails_as_not_plain(&fs, Allow::DecoyStorage, &not_plain(shown, RELATIVE));
        let result = run_allowing(&fs, Allow::Nothing);
        assert!(result.is_fail(), "{line}: {result:?}");
        assert!(
            result.message().contains(&format!(
                "It may name it as well: {}",
                not_plain(shown, RELATIVE)
            )),
            "{line}: {}",
            result.message()
        );
        assert_eq!(
            result.remediation(),
            Some(format!("{STORAGE_OF_ITS_OWN}\n{UNPLAIN}").as_str()),
            "{line}"
        );
    }
}

#[test]
fn a_bind_line_below_a_folder_of_a_line_that_is_not_mounted_fails_with_the_flag_too() {
    // The fstab mounts vdc1 at /backup, at boot, by an automount or, for a
    // noauto line, once the bind line below it needs it (N1 to N3 of the
    // verify), but it is not mounted now: what /backup/link is then, a link
    // to /srv/x say, cannot be read.
    for options in ["noauto", "defaults,nofail", "noauto,x-systemd.automount"] {
        let fstab = format!(
            "/dev/vda1 / ext4 defaults 0 1\n/dev/vdc1 /backup ext4 {options} 0 2\n\
             /backup/link /mnt none bind 0 0\n"
        );
        let fs = rendered(BIND_OF_ROOT, &fstab);
        fs.mock_set_mount_root_error("/backup/link", std::io::ErrorKind::NotFound);
        let finding = untold(
            "/backup/link /mnt none",
            "its source",
            "a line of /etc/fstab mounts /backup, and that mount is not there now",
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{options}");
        fails_as_untold(&fs, Allow::DecoyStorage, &finding);
        let result = run_allowing(&fs, Allow::Nothing);
        assert!(
            result
                .message()
                .contains(&format!("It may name it as well: {finding}")),
            "{options}: {}",
            result.message()
        );
        // Once vdc1 is mounted at /backup, the place is read there: a link
        // is one, and a folder there is judged as it reads.
        let mounted = format!("{BIND_OF_ROOT}7 1 8:33 / /backup rw - ext4 /dev/vdc1 rw\n");
        let fs = rendered(&mounted, &fstab);
        fs.create_symlink(Path::new("/srv/x"), Path::new("/backup/link"))
            .unwrap();
        fails_as_untold(
            &fs,
            Allow::DecoyStorage,
            &untold(
                "/backup/link /mnt none",
                "its source",
                "/backup/link is a symbolic link, which NAILS does not follow",
            ),
        );
        let result = run_allowing(&rendered(&mounted, &fstab), Allow::DecoyStorage);
        assert!(result.is_pass(), "{options}: {result:?}");
        assert_eq!(result.message(), only_the_decoys_own_line("/"));
    }
}

#[test]
fn a_bind_line_of_any_type_or_with_netdev_fails_with_the_flag_too() {
    // mount binds whatever type a bind line gives, and `_netdev` only has
    // systemd mount it after the network: each of these binds the root's
    // folder at the root at every boot, as the plain line does (T1 to T4 of
    // the verify). hidden-volume passes the root with the flag's warning.
    for (line, shown) in [
        ("/srv/x /mnt tmpfs bind 0 0", "/srv/x /mnt tmpfs"),
        ("/srv/x /mnt none bind,_netdev 0 0", "/srv/x /mnt none"),
        ("/srv/x /mnt nfs bind 0 0", "/srv/x /mnt nfs"),
        ("/srv/x /mnt overlay rbind 0 0", "/srv/x /mnt overlay"),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{line}: {result:?}");
        assert_eq!(
            result.message(),
            format!(
                "The decoy's configuration names the volume at /mnt: /etc/fstab: '{shown}' (it \
                 mounts the volume at /mnt). {STORED}"
            ),
            "{line}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
    }
}

#[test]
fn a_line_for_the_volume_with_netdev_or_of_a_host_share_type_fails() {
    // The volume is the mapping `data` on the whole of sdb, at /mnt. A device
    // or swap line for it with `_netdev` mounts it, or swaps on it, after
    // the network, and a bind line from it of a host-share or overlay type
    // binds a folder of it (X1 to X4 of the verify).
    for (line, finding) in [
        (
            "/dev/mapper/data /media/x ext4 defaults,_netdev,nofail 0 0",
            "/etc/fstab: '/dev/mapper/data /media/x ext4' (it mounts the volume at /mnt)",
        ),
        (
            "/dev/mapper/data none swap sw,_netdev 0 0",
            "/etc/fstab: '/dev/mapper/data none swap' (it mounts the volume at /mnt)",
        ),
        (
            "/mnt/data /srv/d 9p bind,nofail 0 0",
            "/etc/fstab: '/mnt/data /srv/d 9p' (it mounts a folder of the volume at /mnt)",
        ),
        (
            "/mnt/data /srv/d overlay bind,nofail 0 0",
            "/etc/fstab: '/mnt/data /srv/d overlay' (it mounts a folder of the volume at /mnt)",
        ),
    ] {
        let result = decoy()
            .file(
                "/etc/fstab",
                &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
            )
            .run();
        assert!(result.is_fail(), "{line}: {result:?}");
        assert_eq!(
            result.message(),
            format!("The decoy's configuration names the volume at /mnt: {finding}. {STORED}"),
            "{line}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
    }
    // The gate refuses the volume the device line mounts at /media/x, as it
    // does without `_netdev`.
    let decoy = decoy().encrypted().file(
        "/etc/fstab",
        "/dev/nvme0n1p3 / ext4 defaults 0 1\n\
         /dev/mapper/data /media/x ext4 defaults,_netdev,nofail 0 0\n",
    );
    let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
        .run(&decoy.fs)
        .unwrap();
    assert!(gate.is_fail(), "{gate:?}");
    assert!(
        gate.message()
            .contains("it is the filesystem this computer mounts at /media/x per /etc/fstab"),
        "{}",
        gate.message()
    );
}

#[test]
fn a_line_that_is_not_plain_fails_with_the_flag_too() {
    // libmount reads `bin\144` as `bind` and `\162bind` as `rbind` (E1 and
    // E2 of the verify), and `/srv/\170` as `/srv/x`: each binds the root's
    // folder at the root at every boot. NAILS reads no such line, and says
    // to write it plainly. hidden-volume passes the root with the flag's
    // warning.
    for (line, shown, reason) in [
        (
            "/srv/x /mnt none bin\\144 0 0",
            "/srv/x /mnt none",
            "its options hold a backslash".to_string(),
        ),
        (
            "/srv/x /mnt none \\162bind 0 0",
            "/srv/x /mnt none",
            "its options hold a backslash".to_string(),
        ),
        (
            "/srv/\\170 /mnt none bind 0 0",
            "/srv/\\170 /mnt none",
            "its first field holds \\170, which is no escape of a space, a tab, a newline or a \
             backslash"
                .to_string(),
        ),
        (
            "srv/x /mnt none bind 0 0",
            "srv/x /mnt none",
            RELATIVE.to_string(),
        ),
        (
            "/srv/x /mnt none,ext4 bind 0 0",
            "/srv/x /mnt none,ext4",
            "its type is a list of types".to_string(),
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        fails_as_not_plain(&fs, Allow::DecoyStorage, &not_plain(shown, &reason));
    }
    // Without the flag, the line for / is named first, which the decoy's
    // own boot needs, and the fix says what to do about each kind.
    let fs = rendered(
        BIND_OF_ROOT,
        "/dev/vda1 / ext4 defaults 0 1\n/srv/x /mnt none bin\\144 0 0\n",
    );
    let result = run_allowing(&fs, Allow::Nothing);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().ends_with(&format!(
            "It may name it as well: {}. {STORED}",
            not_plain("/srv/x /mnt none", "its options hold a backslash")
        )),
        "{}",
        result.message()
    );
    assert_eq!(
        result.remediation(),
        Some(format!("{STORAGE_OF_ITS_OWN}\n{UNPLAIN}").as_str())
    );
}

#[test]
fn a_relative_device_or_a_list_of_types_fails_without_the_flag() {
    // The volume is the mapping `data` (dm-9) on the whole of sdb, at /mnt.
    // libmount looks a relative first field up from /, where systemd runs
    // mount, so each of these mounts the volume at boot (R1 to R4 of the
    // verify) and fails, while the gate, which reads no such line, passes the
    // volume.
    for (line, shown, reason) in [
        (
            "dev/mapper/data /media/x ext4 nofail 0 0",
            "dev/mapper/data /media/x ext4",
            RELATIVE.to_string(),
        ),
        (
            "dev/mapper/data /media/x ntfs-3g nofail,x-systemd.automount 0 0",
            "dev/mapper/data /media/x ntfs-3g",
            RELATIVE.to_string(),
        ),
        (
            "dev/mapper/data /media/x ext4,xfs nofail 0 0",
            "dev/mapper/data /media/x ext4,xfs",
            format!("its type is a list of types and {RELATIVE}"),
        ),
        (
            "dev/dm-9 /media/x cramfs nofail 0 0",
            "dev/dm-9 /media/x cramfs",
            RELATIVE.to_string(),
        ),
    ] {
        let decoy = decoy().encrypted().file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{line}\n"),
        );
        decoy.fs.mock_set_device_node("/dev/dm-9");
        fails_as_not_plain(&decoy.fs, Allow::Nothing, &not_plain(shown, &reason));
        let gate = crate::preflight::HiddenVolumeCheck::new(PathBuf::from("/mnt"))
            .run(&decoy.fs)
            .unwrap();
        assert!(gate.is_pass(), "{line}: {gate:?}");
    }
}

#[test]
fn a_swap_or_image_file_in_the_roots_folder_fails_with_the_flag_too() {
    // A swap file or an image file in the folder of / bound at the root lies
    // in the volume: the decoy swaps on it, or mounts it, at every boot (F1
    // to F3 of the verify), as a bind line from there mounts it.
    for (line, shown) in [
        (
            "/srv/x/swapfile none swap sw 0 0",
            "/srv/x/swapfile none swap",
        ),
        (
            "/srv/x/disk.img /media/i ext4 loop,nofail 0 0",
            "/srv/x/disk.img /media/i ext4",
        ),
        (
            "/srv/x/disk.img /media/i ext4 nofail 0 0",
            "/srv/x/disk.img /media/i ext4",
        ),
    ] {
        let fs = rendered(
            BIND_OF_ROOT,
            &format!("/dev/vda1 / ext4 defaults 0 1\n{line}\n"),
        );
        assert!(hidden_volume_with_the_flag(&fs).is_warn(), "{line}");
        let result = run_allowing(&fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{line}: {result:?}");
        assert_eq!(
            result.message(),
            format!(
                "The decoy's configuration names the volume at /mnt: /etc/fstab: '{shown}' (the \
                 file it names lies in the volume at /mnt). {STORED}"
            ),
            "{line}"
        );
        assert_eq!(result.remediation(), Some(REMEDIATION), "{line}");
    }
}

#[test]
fn plain_lines_that_name_no_part_of_the_volume_pass() {
    // Lines of filesystems whose first field names no local path, a bind,
    // swap file or image beside the root's folder, a noauto drive below which
    // no path is read, and escapes of a space in a path: the flag lets the
    // line for / be, and nothing else names the volume.
    let lines = "tmpfs /tmp tmpfs mode=1777,nosuid 0 0\n\
                 none /dev/shm tmpfs defaults 0 0\n\
                 server:/export /net nfs4 _netdev 0 0\n\
                 //server/share /media/s cifs credentials=/etc/cifs,_netdev 0 0\n\
                 mybucket /media/s3 fuse.s3fs _netdev,allow_other 0 0\n\
                 store /nix/.ro-store 9p trans=virtio,version=9p2000.L 0 0\n\
                 overlay /srv/o overlay lowerdir=/srv/y,upperdir=/var/u,workdir=/var/w 0 0\n\
                 rpool/data /data zfs defaults 0 0\n\
                 /srv/y /srv/b none bind 0 0\n\
                 /srv/y/swapfile none swap sw 0 0\n\
                 /srv/y/disk.img /media/i ext4 loop,nofail 0 0\n\
                 UUID=b2 /backup ext4 noauto 0 2\n\
                 /dev/vdb1 /media/My\\040Disk ntfs-3g noauto,user 0 0\n";
    let fs = rendered(
        BIND_OF_ROOT,
        &format!("/dev/vda1 / ext4 defaults 0 1\n{lines}"),
    );
    assert!(hidden_volume_with_the_flag(&fs).is_warn());
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(result.message(), only_the_decoys_own_line("/"));
    // So for a volume of its own, with no flag.
    let result = decoy()
        .file(
            "/etc/fstab",
            &format!("/dev/nvme0n1p3 / ext4 defaults 0 1\n{lines}"),
        )
        .run();
    assert!(result.is_pass(), "{result:?}");
}

/// What the mock lists in `/proc/devices` for the encrypted decoys.
const PROC_DEVICES: &str =
    "Character devices:\n  1 mem\n\nBlock devices:\n  8 sd\n259 blkext\n254 device-mapper\n";

/// Where sysfs keeps the LUKS volume the encrypted decoys' storage lies on.
const DM0: &str = "/sys/devices/virtual/block/dm-0";

impl Decoy {
    /// The decoy with the hidden root's mount point writable and the
    /// drivers of its disks listed.
    fn encrypted(self) -> Self {
        let decoy = self.file("/proc/devices", PROC_DEVICES);
        decoy.fs.mock_set_writable("/mnt", true);
        decoy
    }
}

/// Debian's encrypted ext4 root without LVM, whose crypttab opens the LUKS
/// volume its / lies on with `options`, and `root`, a folder of / or `/`
/// itself, mounted at the root.
fn encrypted_decoy_with(root: &str, options: &str) -> Decoy {
    Decoy::new(&format!(
        "1 0 254:0 / / rw - ext4 /dev/mapper/cryptroot rw\n\
         5 1 254:0 {root} /mnt rw - ext4 /dev/mapper/cryptroot rw\n"
    ))
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .mapping("dm-0", "254:0", "cryptroot", ("nvme0n1p3", P3))
    .file("/etc/fstab", "/dev/mapper/cryptroot / ext4 defaults 0 1\n")
    .file(
        "/etc/crypttab",
        &format!("cryptroot /dev/nvme0n1p3 none {options}\n"),
    )
    .encrypted()
}

/// The encrypted decoy, with a bind of a folder of / at the root.
fn encrypted_decoy() -> Decoy {
    encrypted_decoy_with("/srv/x", "luks,discard")
}

/// The finding for the encrypted decoy's crypttab line, which its own boot
/// needs.
const CRYPTROOT: &str = "/etc/crypttab: 'cryptroot /dev/nvme0n1p3' (it opens the volume at /mnt \
                         or a device it is stored on, and the decoy's own boot needs it)";

/// The pass of a root the flag accepted, which only the decoy's own fstab
/// lines for `places` and its crypttab line `line` name.
fn only_the_decoys_own_lines(places: &str, line: &str) -> String {
    format!(
        "No fstab or crypttab entry names the volume at /mnt other than the decoy's own {places} \
         and its crypttab line '{line}', which unlock and mount the filesystem that \
         --allow-decoy-storage accepted it on"
    )
}

/// The flag lets the lines in `fs` be, with the hidden-volume check's
/// warning, and `pass` is the pass of backend-entries; without the flag the
/// check fails each of `findings` and says to keep them.
fn passes_with_the_flag_only(fs: &MockFilesystem, pass: &str, findings: &[&str]) {
    let gate = hidden_volume_with_the_flag(fs);
    assert!(gate.is_warn(), "{pass}: {gate:?}");
    assert!(
        gate.message()
            .starts_with("--allow-decoy-storage: using /mnt although it is"),
        "{pass}: {}",
        gate.message()
    );
    let result = run_allowing(fs, Allow::DecoyStorage);
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(result.message(), pass);
    let result = run_allowing(fs, Allow::Nothing);
    assert!(result.is_fail(), "{result:?}");
    for finding in findings {
        assert!(
            result.message().contains(finding),
            "{finding}: {}",
            result.message()
        );
    }
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{pass}");
}

#[test]
fn on_an_encrypted_decoy_the_flag_lets_the_crypttab_line_for_its_root_be() {
    // A bind of a folder of /: the crypttab line opens the volume the
    // decoy's root lies on. With the flag it is the decoy's own line, as its
    // line for / is, and the check passes. Without it both lines are named,
    // and both are kept: the decoy's boot needs them.
    passes_with_the_flag_only(
        &encrypted_decoy().fs,
        &only_the_decoys_own_lines("line for /", "cryptroot /dev/nvme0n1p3"),
        &[
            CRYPTROOT,
            "/etc/fstab: '/dev/mapper/cryptroot / ext4' (it mounts the filesystem the volume at \
             /mnt is part of, and the decoy's own boot needs it)",
        ],
    );
    // With no line for / in the fstab, the decoy's mount of that filesystem
    // at / makes the crypttab line its own all the same.
    let decoy = encrypted_decoy().file("/etc/fstab", "");
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert_eq!(
        result.message(),
        "No fstab or crypttab entry names the volume at /mnt other than the decoy's own crypttab \
         line 'cryptroot /dev/nvme0n1p3', which unlocks the filesystem that \
         --allow-decoy-storage accepted it on"
    );
}

#[test]
fn with_the_flag_a_noauto_crypttab_line_or_one_for_a_whole_root_still_fails() {
    // A noauto line, which the boot does not open, and every line for the
    // decoy's whole / mounted at the root, which name the volume itself:
    // the check says to keep them, as the decoy's own boot needs them.
    for (root, options) in [("/srv/x", "luks,noauto"), ("/", "luks,discard")] {
        let decoy = encrypted_decoy_with(root, options);
        assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn(), "{root}");
        let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{root}: {result:?}");
        assert!(
            result.message().contains(CRYPTROOT),
            "{root}: {}",
            result.message()
        );
        assert_eq!(
            result.message().contains("/etc/fstab"),
            root == "/",
            "{root}: {}",
            result.message()
        );
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN), "{root}");
    }
}

#[test]
fn on_a_decoy_whose_root_lies_in_the_hidden_volume_of_a_container_its_line_is_kept() {
    // The encrypted decoy's root in the hidden volume of a VeraCrypt
    // container its crypttab opens, and a bind of a folder of / at the root:
    // the line opens the hidden volume of a container, which the flag never
    // lets be, but the decoy's own boot needs it, so the check says to keep
    // it, with the flag or without.
    let decoy = encrypted_decoy_with("/srv/x", "tcrypt-hidden");
    assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn());
    for allow in [Allow::DecoyStorage, Allow::Nothing] {
        let result = run_allowing(&decoy.fs, allow);
        assert!(result.is_fail(), "{result:?}");
        assert!(
            result.message().contains(
                "/etc/crypttab: 'cryptroot /dev/nvme0n1p3' (it opens the hidden volume of a \
                 TrueCrypt or VeraCrypt container, and the decoy's own boot needs it)"
            ),
            "{}",
            result.message()
        );
        assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
    }
}

#[test]
fn on_lvm_on_luks_the_flag_lets_the_crypttab_line_be() {
    // The decoy's / on the logical volume vg-root in the LUKS volume its
    // crypttab opens, with the swap on another logical volume or in a file
    // on /, and a bind of a folder of / at the root.
    for swap in [
        "/dev/mapper/vg-swap none swap sw 0 0\n",
        "/swap.img none swap sw 0 0\n",
    ] {
        let decoy = Decoy::new(
            "1 0 254:1 / / rw - ext4 /dev/mapper/vg-root rw\n\
             5 1 254:1 /srv/x /mnt rw - ext4 /dev/mapper/vg-root rw\n",
        )
        .device(NVME, "nvme0n1", "259:0", &[])
        .partition(P3, "nvme0n1p3", "259:3")
        .mapping("dm-0", "254:0", "nvme0n1p3_crypt", ("nvme0n1p3", P3))
        .lv("dm-1", "254:1", "vg-root", ("dm-0", DM0))
        .lv("dm-2", "254:2", "vg-swap", ("dm-0", DM0))
        .file(
            "/etc/fstab",
            &format!("/dev/mapper/vg-root / ext4 defaults 0 1\n{swap}"),
        )
        .file(
            "/etc/crypttab",
            "nvme0n1p3_crypt /dev/nvme0n1p3 none luks,discard\n",
        )
        .encrypted();
        passes_with_the_flag_only(
            &decoy.fs,
            &only_the_decoys_own_lines("line for /", "nvme0n1p3_crypt /dev/nvme0n1p3"),
            &[
                "/etc/crypttab: 'nvme0n1p3_crypt /dev/nvme0n1p3' (it opens the volume at /mnt or a \
               device it is stored on, and the decoy's own boot needs it)",
            ],
        );
    }
}

#[test]
fn on_fedoras_btrfs_on_luks_the_flag_lets_the_crypttab_line_be() {
    // btrfs on LUKS with root and home subvolumes, and a subvolume beside
    // /home or a folder of /home at the root.
    for (root, options) in [
        ("/vault", "subvolid=300,subvol=/vault"),
        ("/home/u/vault", "subvolid=257,subvol=/home"),
    ] {
        let decoy = Decoy::new(&format!(
            "1 0 0:35 /root / rw - btrfs /dev/mapper/luks-f1 rw,subvolid=256,subvol=/root\n\
             2 1 0:35 /home /home rw - btrfs /dev/mapper/luks-f1 rw,subvolid=257,subvol=/home\n\
             5 1 0:35 {root} /mnt rw - btrfs /dev/mapper/luks-f1 rw,{options}\n"
        ))
        .device(NVME, "nvme0n1", "259:0", &[])
        .partition(P3, "nvme0n1p3", "259:3")
        .mapping("dm-0", "254:0", "luks-f1", ("nvme0n1p3", P3))
        .file(
            "/etc/fstab",
            "/dev/mapper/luks-f1 / btrfs subvol=root,compress=zstd:1 0 0\n\
             /dev/mapper/luks-f1 /home btrfs subvol=home,compress=zstd:1 0 0\n",
        )
        .file("/etc/crypttab", "luks-f1 /dev/nvme0n1p3 none discard\n")
        .encrypted();
        passes_with_the_flag_only(
            &decoy.fs,
            &only_the_decoys_own_lines("lines for / and /home", "luks-f1 /dev/nvme0n1p3"),
            &[
                "/etc/crypttab: 'luks-f1 /dev/nvme0n1p3' (it opens the volume at /mnt or a device it \
               is stored on, and the decoy's own boot needs it)",
            ],
        );
    }
}

/// A LUKS volume on the external sdb that the decoy's crypttab opens and its
/// fstab mounts at `place`, with `mounts` the mount lines of it.
fn luks_drive(place: &str, mounts: &str) -> Decoy {
    Decoy::new(&format!(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n{mounts}"
    ))
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .device(SDB, "sdb", "8:16", &[])
    .mapping("dm-9", "254:9", "data", ("sdb", SDB))
    .file(
        "/etc/fstab",
        &format!(
            "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/mapper/data {place} ext4 defaults,nofail 0 2\n"
        ),
    )
    .file("/etc/crypttab", "data /dev/sdb none luks,nofail\n")
    .encrypted()
}

/// The finding for the crypttab line of the LUKS drive, with `needed` what
/// the check adds when the decoy's own boot needs it.
fn luks_drive_line(needed: &str) -> String {
    format!(
        "/etc/crypttab: 'data /dev/sdb' (it opens the volume at /mnt or a device it is stored \
         on{needed})"
    )
}

#[test]
fn the_flag_lets_the_crypttab_line_of_a_drive_the_decoy_mounts_at_srv_be_but_not_at_backup() {
    let needed = ", and the decoy's own boot needs it";
    // A folder of the drive bound at the root, while the decoy's line
    // mounts the drive at /srv: both lines are the decoy's own for /srv.
    let mounted = |place: &str| {
        format!(
            "2 1 254:9 / {place} rw - ext4 /dev/mapper/data rw\n\
             5 1 254:9 /x /mnt rw - ext4 /dev/mapper/data rw\n"
        )
    };
    passes_with_the_flag_only(
        &luks_drive("/srv", &mounted("/srv")).fs,
        &only_the_decoys_own_lines("line for /srv", "data /dev/sdb"),
        &[luks_drive_line(needed).as_str()],
    );
    // At /backup, a folder no system folder is, both still fail with the
    // flag: the line may name the hidden drive's disk. The decoy's boot needs
    // both, and the check says to keep them.
    let decoy = luks_drive("/backup", &mounted("/backup"));
    assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn());
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    for finding in [
        luks_drive_line(needed),
        "/etc/fstab: '/dev/mapper/data /backup ext4' (it mounts the filesystem the volume at \
         /mnt is part of, and the decoy's own boot needs it)"
            .to_string(),
    ] {
        assert!(
            result.message().contains(&finding),
            "{finding}: {}",
            result.message()
        );
    }
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
    // A folder of the drive bound at the root while the drive is mounted
    // nowhere else, as after it was plugged in: nothing shows that the decoy
    // uses it, so with the flag both lines still fail at /srv, and the check
    // says to keep them.
    let decoy = luks_drive("/srv", "5 1 254:9 /x /mnt rw - ext4 /dev/mapper/data rw\n");
    assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn());
    let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    for finding in [
        luks_drive_line(needed),
        "/etc/fstab: '/dev/mapper/data /srv ext4' (it mounts the filesystem the volume at /mnt \
         is part of, and the decoy's own boot needs it)"
            .to_string(),
    ] {
        assert!(
            result.message().contains(&finding),
            "{finding}: {}",
            result.message()
        );
    }
    assert_eq!(result.remediation(), Some(STORAGE_OF_ITS_OWN));
    // The whole drive at the root, as one plugged in after the boot is: each
    // line names the volume itself, so both fail with the flag, at /srv as
    // lines the decoy's boot needs, and at /backup as ones to remove.
    for (place, why, remediation) in [
        ("/srv", needed, STORAGE_OF_ITS_OWN),
        ("/backup", "", REMEDIATION),
    ] {
        let decoy = luks_drive(place, "5 1 254:9 / /mnt rw - ext4 /dev/mapper/data rw\n");
        assert!(hidden_volume_with_the_flag(&decoy.fs).is_warn(), "{place}");
        let result = run_allowing(&decoy.fs, Allow::DecoyStorage);
        assert!(result.is_fail(), "{place}: {result:?}");
        assert!(
            result.message().contains(&luks_drive_line(why)),
            "{place}: {}",
            result.message()
        );
        assert_eq!(result.remediation(), Some(remediation), "{place}");
    }
}

#[test]
fn the_flag_lets_the_crypttab_lines_of_the_array_the_decoys_root_is_on_be() {
    // A bind of a folder of / on md0p2 of the mirror: the boot opens both
    // legs to assemble the array, and each line is the decoy's own, as the
    // line for / is. With no line for / in the fstab, the decoy's mount of
    // that filesystem at / makes them its own all the same.
    let bind = "5 1 259:12 /srv/x /mnt rw - ext4 /dev/md0p2 rw\n";
    let legs = "crypttab lines 'leg0 /dev/sdb1' and 'leg1 /dev/sdc1'";
    for (fstab, own, does) in [
        (
            "/dev/md0p2 / ext4 defaults 0 1\n",
            format!("line for / and its {legs}"),
            "unlock and mount",
        ),
        ("", legs.to_string(), "unlock"),
    ] {
        passes_with_the_flag_only(
            &array_decoy(bind, fstab).encrypted().fs,
            &format!(
                "No fstab or crypttab entry names the volume at /mnt other than the decoy's own \
                 {own}, which {does} the filesystem that --allow-decoy-storage accepted it on"
            ),
            &[
                leg("leg0 /dev/sdb1").as_str(),
                leg("leg1 /dev/sdc1").as_str(),
            ],
        );
    }
}
