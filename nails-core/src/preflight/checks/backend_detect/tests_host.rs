// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mock host the tests of the backend checks build. The decoy is on
//! `nvme0n1`: its root on the LUKS mapping `dm-0` of `nvme0n1p3`, its
//! `/home` on the LUKS mapping `dm-1` of `nvme0n1p4`. Each test mounts the
//! hidden root at `/mnt/data` on a stack of its own. The sysfs fixture
//! follows the real layout: attributes under `/sys/devices`, and
//! `/sys/class/block/<name>`, `/sys/dev/block/<major:minor>`,
//! `/sys/block/<name>`, `slaves/` and `holders/` entries linking there.

use crate::Filesystem;
use crate::filesystem::MockFilesystem;
use std::collections::BTreeMap;
use std::path::Path;

/// Where every test mounts the hidden root.
pub(super) const ROOT: &str = "/mnt/data";

/// A mock host, built one device at a time, bottom first.
pub(super) struct Host {
    pub(super) fs: MockFilesystem,
    /// The sysfs directory of each device, by kernel name.
    dirs: BTreeMap<String, String>,
    /// The devices built on each device, by kernel name.
    holders: BTreeMap<String, Vec<String>>,
}

impl Host {
    /// The decoy, with the hidden root mounted from `source`, a filesystem of
    /// type `fstype` on the device `dev` (`major:minor`).
    pub(super) fn new(dev: &str, fstype: &str, source: &str) -> Self {
        Self::with_mounts(&format!(
            "40 1 {dev} / {ROOT} rw,relatime - {fstype} {source} rw\n"
        ))
    }

    /// The decoy, with `mounts` added to its mount table.
    pub(super) fn with_mounts(mounts: &str) -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(&format!(
            "1 0 254:0 / / rw,relatime - ext4 /dev/mapper/root rw\n\
             2 1 254:1 / /home rw,relatime - ext4 /dev/mapper/home rw\n{mounts}"
        ));
        fs.mock_set_path_exists("/sys/class/block", true);
        let host = Self {
            fs,
            dirs: BTreeMap::new(),
            holders: BTreeMap::new(),
        };
        host.disk("nvme0n1", "259:0")
            .partition_at("nvme0n1p3", "259:3", "nvme0n1", 3, 1_050_624)
            .partition_at("nvme0n1p4", "259:4", "nvme0n1", 4, 105_908_224)
            .mapping(
                "dm-0",
                "254:0",
                "root",
                "CRYPT-LUKS2-0011-root",
                &["nvme0n1p3"],
            )
            .mapping(
                "dm-1",
                "254:1",
                "home",
                "CRYPT-LUKS2-2233-home",
                &["nvme0n1p4"],
            )
            .file(
                "/etc/fstab",
                "/dev/mapper/root / ext4 defaults 0 1\n/dev/mapper/home /home ext4 defaults 0 2\n",
            )
    }

    /// Set the sysfs attribute `attribute` of the device in `dir`.
    pub(super) fn attr(&self, dir: &str, attribute: &str, value: &str) {
        self.fs
            .mock_set_file_content(&format!("{dir}/{attribute}"), &format!("{value}\n"));
    }

    /// A symbolic link at `link` to `target`.
    pub(super) fn link(&self, link: &str, target: &str) {
        self.fs
            .create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }

    /// The sysfs directory of the device `name`.
    pub(super) fn dir(&self, name: &str) -> &str {
        &self.dirs[name]
    }

    /// A device `name`, numbered `dev`, in `dir`, built on `slaves`.
    pub(super) fn device(mut self, dir: &str, name: &str, dev: &str, slaves: &[&str]) -> Self {
        self.attr(dir, "dev", dev);
        self.attr(dir, "uevent", &format!("DEVNAME={name}"));
        let slave_dir = Path::new(dir).join("slaves");
        let mut entries = Vec::new();
        for slave in slaves {
            let entry = slave_dir.join(slave);
            self.link(entry.to_str().unwrap(), &self.dirs[*slave]);
            entries.push(entry);
            self.holders
                .entry((*slave).to_string())
                .or_default()
                .push(name.to_string());
            let holders_dir = Path::new(&self.dirs[*slave]).join("holders");
            let mut holder_entries = Vec::new();
            for holder in &self.holders[*slave] {
                let entry = holders_dir.join(holder);
                let target = if holder == name {
                    dir
                } else {
                    &self.dirs[holder]
                };
                self.link(entry.to_str().unwrap(), target);
                holder_entries.push(entry);
            }
            self.fs
                .mock_set_directory_contents(&holders_dir, holder_entries);
        }
        self.fs.mock_set_directory_contents(&slave_dir, entries);
        self.link(&format!("/sys/class/block/{name}"), dir);
        self.link(&format!("/sys/dev/block/{dev}"), dir);
        self.link(&format!("/sys/block/{name}"), dir);
        self.dirs.insert(name.to_string(), dir.to_string());
        for listing in ["/sys/class/block", "/sys/block"] {
            let entries = self
                .dirs
                .keys()
                .map(|known| Path::new(listing).join(known))
                .collect();
            self.fs
                .mock_set_directory_contents(Path::new(listing), entries);
        }
        self
    }

    /// A whole disk.
    pub(super) fn disk(self, name: &str, dev: &str) -> Self {
        self.device(&format!("/sys/devices/pci0/{name}"), name, dev, &[])
    }

    /// A partition of `disk`, numbered 1, with no start.
    pub(super) fn partition(self, name: &str, dev: &str, disk: &str) -> Self {
        let dir = format!("{}/{name}", self.dirs[disk]);
        let host = self.device(&dir, name, dev, &[]);
        host.attr(&dir, "partition", "1");
        host
    }

    /// Partition `number` of `disk`, from the 512-byte sector `start` on.
    pub(super) fn partition_at(
        self,
        name: &str,
        dev: &str,
        disk: &str,
        number: u32,
        start: u64,
    ) -> Self {
        let dir = format!("{}/{name}", self.dirs[disk]);
        let host = self.device(&dir, name, dev, &[]);
        host.attr(&dir, "partition", &number.to_string());
        host.attr(&dir, "start", &start.to_string());
        host
    }

    /// A device-mapper device with the name `dm` and the uuid `uuid`.
    pub(super) fn mapping(
        self,
        name: &str,
        dev: &str,
        dm: &str,
        uuid: &str,
        slaves: &[&str],
    ) -> Self {
        let dir = format!("/sys/devices/virtual/block/{name}");
        let host = self.device(&dir, name, dev, slaves);
        host.attr(&dir, "dm/name", dm);
        host.attr(&dir, "dm/uuid", uuid);
        host.link(&format!("/dev/mapper/{dm}"), &format!("/dev/{name}"));
        host
    }

    /// A LUKS2 mapping named `dm`.
    pub(super) fn luks(self, name: &str, dev: &str, dm: &str, slaves: &[&str]) -> Self {
        self.mapping(name, dev, dm, &format!("CRYPT-LUKS2-4455-{dm}"), slaves)
    }

    /// A loop device bound to `backing`, a file or a device node.
    pub(super) fn loop_device(self, name: &str, dev: &str, backing: &str) -> Self {
        let dir = format!("/sys/devices/virtual/block/{name}");
        let host = self.device(&dir, name, dev, &[]);
        host.attr(&dir, "loop/backing_file", backing);
        host
    }

    /// A loop device bound to `backing` from the byte `offset` on.
    pub(super) fn loop_at(self, name: &str, dev: &str, backing: &str, offset: u64) -> Self {
        let host = self.loop_device(name, dev, backing);
        host.attr(host.dir(name), "loop/offset", &offset.to_string());
        host
    }

    /// The kernel holds the device `name` read-only.
    pub(super) fn read_only(self, name: &str) -> Self {
        self.attr(self.dir(name), "ro", "1");
        self
    }

    /// `path` is a file on the filesystem of the device `major:minor`, as
    /// `stat` reports it.
    pub(super) fn file_on(self, path: &str, major: u32, minor: u32) -> Self {
        self.fs
            .mock_set_device_id(Path::new(path), rustix::fs::makedev(major, minor));
        self
    }

    /// A file at `path` holding `text`.
    pub(super) fn file(self, path: &str, text: &str) -> Self {
        self.fs.mock_set_file_content(path, text);
        self
    }

    /// One btrfs filesystem on `members`, as `/sys/fs/btrfs/<fsid>/devices`
    /// lists them.
    pub(super) fn btrfs(self, members: &[&str]) -> Self {
        let fsid = Path::new("/sys/fs/btrfs/0a1b2c3d-0000-4000-8000-000000000009");
        self.fs
            .mock_set_directory_contents(Path::new("/sys/fs/btrfs"), vec![fsid.to_path_buf()]);
        let devices = fsid.join("devices");
        let mut entries = Vec::new();
        for member in members {
            let entry = devices.join(member);
            self.link(entry.to_str().unwrap(), &self.dirs[*member]);
            entries.push(entry);
        }
        self.fs.mock_set_directory_contents(&devices, entries);
        self
    }

    /// The loop driver records the file of the loop device `name` on the
    /// filesystem of the device `major:minor`, as root can read it.
    pub(super) fn recorded(self, name: &str, major: u32, minor: u32) -> Self {
        self.fs.mock_set_loop_backing_device(
            &Path::new("/dev").join(name),
            rustix::fs::makedev(major, minor),
        );
        self
    }
}
