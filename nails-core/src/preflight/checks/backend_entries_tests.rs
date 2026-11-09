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
        let dir = format!("/sys/devices/virtual/block/{name}");
        let decoy = self.device(&dir, name, dev, &[below]);
        decoy.attr(&dir, "dm/name", dm);
        decoy.attr(&dir, "dm/uuid", &format!("CRYPT-LUKS2-00-{dm}"));
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
    let md0 = "/sys/devices/virtual/block/md0";
    Decoy::new(
        "1 0 259:12 / / rw - ext4 /dev/md0p2 rw\n\
         5 1 259:11 / /mnt rw - ext4 /dev/md0p1 rw\n",
    )
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
    // Lines for / and /home of that filesystem are named together.
    let fs = rendered(
        "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n\
         2 1 8:1 /home /home rw - ext4 /dev/vda1 rw\n\
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
            .contains("/etc/fstab: '/dev/vda2 /srv btrfs' (it mounts the filesystem"),
        "{}",
        result.message()
    );
    assert!(
        !result.message().contains("/home btrfs"),
        "{}",
        result.message()
    );
    assert_eq!(result.remediation(), Some(REMEDIATION));
    // The flag covers no crypttab line.
    let fs = rendered(BIND_OF_ROOT, "/dev/vda1 / ext4 defaults 0 1\n");
    fs.mock_set_file_content("/etc/crypttab", "vault /dev/vda1 none luks,noauto\n");
    let result = run_allowing(&fs, Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("/etc/crypttab: 'vault /dev/vda1'"),
        "{}",
        result.message()
    );
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
