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
const DM9: &str = "/sys/devices/virtual/block/dm-9";

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
        let decoy = self.device(DM9, name, dev, &[below]);
        decoy.attr(DM9, "dm/name", dm);
        decoy.attr(DM9, "dm/uuid", &format!("CRYPT-LUKS2-00-{dm}"));
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

#[test]
fn a_tcrypt_hidden_line_fails() {
    let result = decoy()
        .file(
            "/etc/crypttab",
            "vault /dev/sdc none tcrypt-hidden,noauto\n",
        )
        .run();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result.message().contains("'vault /dev/sdc'"),
        "{}",
        result.message()
    );
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
