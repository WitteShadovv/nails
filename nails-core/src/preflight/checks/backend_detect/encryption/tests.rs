// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-encryption check on mock hosts. The decoy is on `nvme0n1`: its
//! root on the LUKS mapping `dm-0` of `nvme0n1p3`, its `/home` on the LUKS
//! mapping `dm-1` of `nvme0n1p4`. Each test mounts the hidden root at
//! `/mnt/data` on a stack of its own. The sysfs fixture follows the real
//! layout: attributes under `/sys/devices`, and `/sys/class/block/<name>`,
//! `/sys/dev/block/<major:minor>`, `/sys/block/<name>` and `slaves/` entries
//! linking there.

use super::*;
use crate::filesystem::MockFilesystem;

const ROOT: &str = "/mnt/data";

/// A mock host, built one device at a time, bottom first.
struct Host {
    fs: MockFilesystem,
    /// The sysfs directory of each device, by kernel name.
    dirs: BTreeMap<String, String>,
}

impl Host {
    /// The decoy, with the hidden root mounted from `source`, a filesystem of
    /// type `fstype` on the device `dev` (`major:minor`).
    fn new(dev: &str, fstype: &str, source: &str) -> Self {
        Self::with_mounts(&format!(
            "40 1 {dev} / {ROOT} rw,relatime - {fstype} {source} rw\n"
        ))
    }

    /// The decoy, with `mounts` added to its mount table.
    fn with_mounts(mounts: &str) -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(&format!(
            "1 0 254:0 / / rw,relatime - ext4 /dev/mapper/root rw\n\
             2 1 254:1 / /home rw,relatime - ext4 /dev/mapper/home rw\n{mounts}"
        ));
        fs.mock_set_path_exists("/sys/class/block", true);
        let host = Self {
            fs,
            dirs: BTreeMap::new(),
        };
        host.disk("nvme0n1", "259:0")
            .partition("nvme0n1p3", "259:3", "nvme0n1")
            .partition("nvme0n1p4", "259:4", "nvme0n1")
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

    fn attr(&self, dir: &str, attribute: &str, value: &str) {
        self.fs
            .mock_set_file_content(&format!("{dir}/{attribute}"), &format!("{value}\n"));
    }

    fn link(&self, link: &str, target: &str) {
        self.fs
            .create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }

    /// A device `name`, numbered `dev`, in `dir`, built on `slaves`.
    fn device(mut self, dir: &str, name: &str, dev: &str, slaves: &[&str]) -> Self {
        self.attr(dir, "dev", dev);
        self.attr(dir, "uevent", &format!("DEVNAME={name}"));
        let slave_dir = Path::new(dir).join("slaves");
        let mut entries = Vec::new();
        for slave in slaves {
            let entry = slave_dir.join(slave);
            self.link(entry.to_str().unwrap(), &self.dirs[*slave]);
            entries.push(entry);
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

    fn disk(self, name: &str, dev: &str) -> Self {
        self.device(&format!("/sys/devices/pci0/{name}"), name, dev, &[])
    }

    fn partition(self, name: &str, dev: &str, disk: &str) -> Self {
        let dir = format!("{}/{name}", self.dirs[disk]);
        let host = self.device(&dir, name, dev, &[]);
        host.attr(&dir, "partition", "1");
        host
    }

    /// A device-mapper device with the name `dm` and the uuid `uuid`.
    fn mapping(self, name: &str, dev: &str, dm: &str, uuid: &str, slaves: &[&str]) -> Self {
        let dir = format!("/sys/devices/virtual/block/{name}");
        let host = self.device(&dir, name, dev, slaves);
        host.attr(&dir, "dm/name", dm);
        host.attr(&dir, "dm/uuid", uuid);
        host.link(&format!("/dev/mapper/{dm}"), &format!("/dev/{name}"));
        host
    }

    /// A LUKS2 mapping named `dm`.
    fn luks(self, name: &str, dev: &str, dm: &str, slaves: &[&str]) -> Self {
        self.mapping(name, dev, dm, &format!("CRYPT-LUKS2-4455-{dm}"), slaves)
    }

    /// A loop device bound to `backing`, a file or a device node.
    fn loop_device(self, name: &str, dev: &str, backing: &str) -> Self {
        let dir = format!("/sys/devices/virtual/block/{name}");
        let host = self.device(&dir, name, dev, &[]);
        host.attr(&dir, "loop/backing_file", backing);
        host
    }

    /// `path` is a file on the filesystem of the device `major:minor`, as
    /// `stat` reports it.
    fn file_on(self, path: &str, major: u32, minor: u32) -> Self {
        self.fs
            .mock_set_device_id(Path::new(path), rustix::fs::makedev(major, minor));
        self
    }

    fn file(self, path: &str, text: &str) -> Self {
        self.fs.mock_set_file_content(path, text);
        self
    }

    /// One btrfs filesystem on `members`, as `/sys/fs/btrfs/<fsid>/devices`
    /// lists them.
    fn btrfs(self, members: &[&str]) -> Self {
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
    fn recorded(self, name: &str, major: u32, minor: u32) -> Self {
        self.fs.mock_set_loop_backing_device(
            &Path::new("/dev").join(name),
            rustix::fs::makedev(major, minor),
        );
        self
    }

    fn run(&self) -> CheckResult {
        BackendEncryptionCheck::new(PathBuf::from(ROOT))
            .run(&self.fs)
            .unwrap()
    }
}

/// The hidden root on `uuid`, the mapping `dm-9` named `data` of the
/// external disk `sdb`.
fn external(uuid: &str) -> Host {
    Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .mapping("dm-9", "254:9", "data", uuid, &["sdb"])
}

fn assert_pass(result: &CheckResult, layers: &str) {
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        format!("The hidden root at {ROOT} has encryption of its own: {layers}")
    );
}

/// The warning's sentence, without the fix on its own line.
fn warning(result: &CheckResult) -> &str {
    assert!(result.is_warn(), "{result:?}");
    result.message().lines().next().unwrap_or_default()
}

/// Its fix, on its own line.
fn fix(result: &CheckResult) -> &str {
    result.message().lines().nth(1).unwrap_or_default()
}

// ------------------------------------------------------------------------
// Encryption of its own
// ------------------------------------------------------------------------

#[test]
fn luks_on_an_external_disk_passes() {
    assert_pass(
        &external("CRYPT-LUKS2-6677-data").run(),
        "LUKS mapping dm-9",
    );
}

#[test]
fn every_encrypting_cryptsetup_type_passes() {
    for (kind, label) in [
        ("TCRYPT", "VeraCrypt/TrueCrypt (tcrypt)"),
        ("LUKS1", "LUKS"),
        ("PLAIN", "plain dm-crypt"),
        ("LOOPAES", "dm-crypt (LOOPAES)"),
        ("BITLK", "dm-crypt (BITLK)"),
        ("FVAULT2", "dm-crypt (FVAULT2)"),
    ] {
        let result = external(&format!("CRYPT-{kind}-data")).run();
        assert_pass(&result, &format!("{label} mapping dm-9"));
    }
}

#[test]
fn a_cascade_passes_on_its_topmost_layer() {
    // cryptsetup opens a VeraCrypt cascade as a TCRYPT mapping over one
    // SUBDEV mapping per further cipher.
    let result = Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .mapping("dm-8", "254:8", "data_1", "CRYPT-SUBDEV-data_1", &["sdb"])
        .mapping("dm-9", "254:9", "data", "CRYPT-TCRYPT-data", &["dm-8"])
        .run();
    assert_pass(&result, "VeraCrypt/TrueCrypt (tcrypt) mapping dm-9");

    // A SUBDEV layer counts on its own, too.
    let result = Host::new("254:9", "ext4", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .mapping("dm-9", "254:9", "data_1", "CRYPT-SUBDEV-data_1", &["sdb"])
        .run();
    assert_pass(&result, "dm-crypt (SUBDEV) mapping dm-9");
}

#[test]
fn a_mapping_the_veracrypt_application_made_passes() {
    // The application names its mappings veracrypt<N>, and veracrypt<N>_<k>
    // for the further ciphers of a cascade, with no uuid.
    let result = Host::new("254:9", "ext4", "/dev/mapper/veracrypt1")
        .disk("sdb", "8:16")
        .mapping("dm-8", "254:8", "veracrypt1_0", "", &["sdb"])
        .mapping("dm-9", "254:9", "veracrypt1", "", &["dm-8"])
        .run();
    assert_pass(&result, "VeraCrypt mapping dm-9");
}

#[test]
fn a_loop_over_an_encrypted_mapping_passes() {
    let result = Host::new("7:0", "ext4", "/dev/loop0")
        .disk("sdb", "8:16")
        .luks("dm-5", "254:5", "vault", &["sdb"])
        .loop_device("loop0", "7:0", "/dev/mapper/vault")
        .run();
    assert_pass(&result, "LUKS mapping dm-5");
}

#[test]
fn an_image_file_on_an_encrypted_external_stick_passes() {
    let result = Host::with_mounts(
        "30 1 254:6 / /media/stick rw - ext4 /dev/mapper/stick rw\n\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    )
    .disk("sdc", "8:32")
    .partition("sdc1", "8:33", "sdc")
    .luks("dm-6", "254:6", "stick", &["sdc1"])
    .loop_device("loop0", "7:0", "/media/stick/vault.img")
    .file_on("/media/stick/vault.img", 254, 6)
    .run();
    assert_pass(&result, "LUKS mapping dm-6");
}

#[test]
fn a_luks_volume_inside_the_decoys_encrypted_volume_group_passes() {
    // Its own LUKS layer comes first, on the way down to the decoy's.
    let result = Host::new("254:4", "ext4", "/dev/mapper/vault")
        .mapping("dm-3", "254:3", "vg-vault", "LVM-a1b2-vault", &["dm-0"])
        .luks("dm-4", "254:4", "vault", &["dm-3"])
        .run();
    assert_pass(&result, "LUKS mapping dm-4");
}

#[test]
fn every_leg_of_a_mirror_needs_encryption_of_its_own() {
    // An md mirror of sdb through LUKS and of sdc, through LUKS or not.
    let mirror = |second_encrypted: bool| {
        let host = Host::new("9:0", "ext4", "/dev/md0")
            .disk("sdb", "8:16")
            .disk("sdc", "8:32")
            .luks("dm-7", "254:7", "leg0", &["sdb"]);
        let (host, second) = if second_encrypted {
            (host.luks("dm-8", "254:8", "leg1", &["sdc"]), "dm-8")
        } else {
            (host, "sdc")
        };
        host.device(
            "/sys/devices/virtual/block/md0",
            "md0",
            "9:0",
            &["dm-7", second],
        )
        .run()
    };
    assert_pass(&mirror(true), "LUKS mapping dm-7, LUKS mapping dm-8");

    let result = mirror(false);
    assert_eq!(
        warning(&result),
        format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc: anyone who can read sdc, or a \
             copy of it, can read the hidden root's files."
        )
    );
}

#[test]
fn a_btrfs_root_is_followed_through_its_source() {
    // btrfs reports an anonymous device number for its mount.
    let result = Host::new("0:52", "btrfs", "/dev/mapper/data")
        .disk("sdb", "8:16")
        .luks("dm-9", "254:9", "data", &["sdb"])
        .run();
    assert_pass(&result, "LUKS mapping dm-9");
}

// ------------------------------------------------------------------------
// No encryption
// ------------------------------------------------------------------------

#[test]
fn plain_ext4_on_a_partition_warns_with_the_fix() {
    let result = Host::new("8:17", "ext4", "/dev/sdb1")
        .disk("sdb", "8:16")
        .partition("sdb1", "8:17", "sdb")
        .run();
    assert_eq!(
        warning(&result),
        format!(
            "Nothing encrypts the hidden root at {ROOT} on sdb1: anyone who can read sdb1, or a \
             copy of it, can read the hidden root's files."
        )
    );
    assert_eq!(fix(&result), FIX);
}

#[test]
fn integrity_or_verity_alone_encrypts_nothing() {
    for uuid in ["CRYPT-INTEGRITY-data", "CRYPT-VERITY-0a1b-data"] {
        let result = external(uuid).run();
        assert!(
            warning(&result).starts_with(&format!(
                "Nothing encrypts the hidden root at {ROOT} on sdb:"
            )),
            "{uuid}: {result:?}"
        );
    }
}

#[test]
fn a_logical_volume_spanning_an_encrypted_and_a_plain_disk_warns() {
    let result = Host::new("254:9", "ext4", "/dev/mapper/vg-data")
        .disk("sdb", "8:16")
        .disk("sdc", "8:32")
        .luks("dm-7", "254:7", "pv0", &["sdb"])
        .mapping(
            "dm-9",
            "254:9",
            "vg-data",
            "LVM-c3d4-data",
            &["dm-7", "sdc"],
        )
        .run();
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc:"
        )),
        "{result:?}"
    );
}

#[test]
fn a_plain_image_on_an_unencrypted_disk_names_that_disk() {
    let result = Host::with_mounts(
        "30 1 8:33 / /media/stick rw - ext4 /dev/sdc1 rw\n\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    )
    .disk("sdc", "8:32")
    .partition("sdc1", "8:33", "sdc")
    .loop_device("loop0", "7:0", "/media/stick/vault.img")
    .file_on("/media/stick/vault.img", 8, 33)
    .run();
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc1:"
        )),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// Only the decoy's own encryption
// ------------------------------------------------------------------------

#[test]
fn a_plain_image_on_the_decoys_encrypted_home_warns() {
    let result = Host::new("7:0", "ext4", "/dev/loop0")
        .loop_device("loop0", "7:0", "/home/alice/photos.img")
        .file_on("/home/alice/photos.img", 254, 1)
        .run();
    assert_eq!(
        warning(&result),
        format!(
            "The only encryption under the hidden root at {ROOT} is the decoy's own: LUKS mapping \
             dm-1, which also holds the decoy's filesystem at /home. Whoever can unlock the decoy \
             can read the hidden root's files."
        )
    );
    assert_eq!(fix(&result), FIX);
}

#[test]
fn a_logical_volume_in_the_decoys_encrypted_volume_group_warns() {
    let result = Host::new("254:3", "ext4", "/dev/mapper/vg-vault")
        .mapping("dm-3", "254:3", "vg-vault", "LVM-a1b2-vault", &["dm-0"])
        .run();
    assert!(
        warning(&result).contains(
            "is the decoy's own: LUKS mapping dm-0, which also holds the decoy's filesystem at /."
        ),
        "{result:?}"
    );
}

#[test]
fn an_encrypted_volume_the_decoys_crypttab_opens_is_the_decoys() {
    // The decoy opens a backup drive by hand through its crypttab, and the
    // hidden root is a plain image on it.
    let result = Host::with_mounts(
        "30 1 254:5 / /srv/backup rw - ext4 /dev/mapper/backup rw\n\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    )
    .disk("sdc", "8:32")
    .luks("dm-5", "254:5", "backup", &["sdc"])
    .loop_device("loop0", "7:0", "/srv/backup/disk.raw")
    .file_on("/srv/backup/disk.raw", 254, 5)
    .file("/etc/crypttab", "backup /dev/sdc none luks,noauto\n")
    .run();
    assert!(
        warning(&result).contains(
            "is the decoy's own: LUKS mapping dm-5, which also holds the volume the decoy's \
             /etc/crypttab opens as backup."
        ),
        "{result:?}"
    );
}

#[test]
fn the_decoys_entry_for_the_hidden_volume_is_no_claim_on_it() {
    // The line opens the hidden root's own device: backend-entries refuses
    // it, and it makes that encryption no more the decoy's.
    let result = external("CRYPT-LUKS2-6677-data")
        .file("/etc/crypttab", "data /dev/sdb none luks,noauto\n")
        .run();
    assert_pass(&result, "LUKS mapping dm-9");
}

#[test]
fn the_claims_name_what_the_decoys_layer_holds() {
    assert_eq!(
        holds_phrase(&Claimed::Mount(PathBuf::from("/home"))),
        "the decoy's filesystem at /home"
    );
    assert_eq!(
        holds_phrase(&Claimed::Swap("/dev/sda2".to_string())),
        "the decoy's swap"
    );
    assert_eq!(
        holds_phrase(&Claimed::Encrypted("backup".to_string())),
        "the volume the decoy's /etc/crypttab opens as backup"
    );
}

// ------------------------------------------------------------------------
// Stacks the check cannot judge
// ------------------------------------------------------------------------

#[test]
fn a_zfs_dataset_cannot_be_confirmed() {
    let result = Host::new("0:61", "zfs", "tank/data").run();
    assert_eq!(
        warning(&result),
        format!(
            "Could not confirm that the hidden root at {ROOT} is encrypted: its zfs filesystem \
             shows no block device to follow."
        )
    );
    assert_eq!(fix(&result), UNKNOWN_FIX);
}

#[test]
fn a_mapping_of_an_unknown_kind_cannot_be_confirmed() {
    let result = external("mpath-3600508b400105e21").run();
    assert!(
        warning(&result).contains(
            "dm-9 is a device-mapper device of a kind the check does not know, and the check \
             never reads a mapping's table"
        ),
        "{result:?}"
    );
    let result = external("CRYPT-NEWKIND-data").run();
    assert!(
        warning(&result).contains(
            "dm-9 is a cryptsetup mapping of type NEWKIND, which the check does not know"
        ),
        "{result:?}"
    );
}

#[test]
fn a_mapping_of_an_unknown_kind_over_encryption_of_its_own_passes() {
    let result = Host::new("254:9", "ext4", "/dev/mapper/mp")
        .disk("sdb", "8:16")
        .luks("dm-7", "254:7", "inner", &["sdb"])
        .mapping("dm-9", "254:9", "mp", "mpath-3600508b4", &["dm-7"])
        .run();
    assert_pass(&result, "LUKS mapping dm-7");
}

#[test]
fn a_loop_file_the_walk_cannot_place_cannot_be_confirmed() {
    let result = Host::with_mounts(
        "25 1 0:25 / /run rw - tmpfs tmpfs rw\n\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    )
    .loop_device("loop0", "7:0", "/run/blk/data.img")
    .file_on("/run/blk/data.img", 0, 25)
    .run();
    assert!(
        warning(&result).ends_with(
            "loop device loop0 reads /run/blk/data.img, which the check cannot follow to a disk."
        ),
        "{result:?}"
    );

    // With LUKS over the loop device, the hidden root is encrypted anyway.
    let result = Host::with_mounts(
        "25 1 0:25 / /run rw - tmpfs tmpfs rw\n\
         40 1 254:9 / /mnt/data rw - ext4 /dev/mapper/data rw\n",
    )
    .loop_device("loop0", "7:0", "/run/blk/data.img")
    .luks("dm-9", "254:9", "data", &["loop0"])
    .run();
    assert_pass(&result, "LUKS mapping dm-9");
}

#[test]
fn a_stack_deeper_than_the_walk_reads_cannot_be_confirmed() {
    // Twenty logical volumes, each on the one before, on a plain disk.
    let mut host = Host::new("254:120", "ext4", "/dev/mapper/lv20").disk("sdb", "8:16");
    let mut below = "sdb".to_string();
    for level in 1..=20 {
        let name = format!("dm-{}", 100 + level);
        host = host.mapping(
            &name,
            &format!("254:{}", 100 + level),
            &format!("lv{level}"),
            &format!("LVM-{level}"),
            &[&below],
        );
        below = name;
    }
    let result = host.run();
    assert!(
        warning(&result)
            .contains("the stack under it holds more devices than the check reads (16 below any one device, 64 in all)"),
        "{result:?}"
    );
}

#[test]
fn an_unreadable_crypttab_keeps_encryption_from_being_confirmed() {
    let host = external("CRYPT-LUKS2-6677-data");
    // It exists, but reading it fails, as a root-only file does.
    host.fs.mock_set_path_exists("/etc/crypttab", true);
    let result = host.run();
    assert_eq!(
        warning(&result),
        format!(
            "Could not confirm that the hidden root at {ROOT} is encrypted: /etc/crypttab could \
             not be read, so whether the decoy opens that encryption itself cannot be told."
        )
    );
    // A stack with no encryption warns as such: nothing the file says changes that.
    let host = Host::new("8:16", "ext4", "/dev/sdb").disk("sdb", "8:16");
    host.fs.mock_set_path_exists("/etc/crypttab", true);
    assert!(
        warning(&host.run()).starts_with("Nothing encrypts"),
        "{:?}",
        host.run()
    );
}

#[test]
fn an_unreadable_mount_table_cannot_be_confirmed() {
    let fs = MockFilesystem::new();
    fs.mock_set_mount_table_error("EACCES");
    let result = BackendEncryptionCheck::new(PathBuf::from(ROOT))
        .run(&fs)
        .unwrap();
    assert!(
        warning(&result).ends_with("is encrypted: the mount table cannot be read."),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// Several ways down
// ------------------------------------------------------------------------

#[test]
fn of_two_plain_ways_the_first_is_named() {
    let result = Host::new("254:9", "ext4", "/dev/mapper/vg-data")
        .disk("sdb", "8:16")
        .disk("sdc", "8:32")
        .mapping("dm-9", "254:9", "vg-data", "LVM-c3d4-data", &["sdb", "sdc"])
        .run();
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdb:"
        )),
        "{result:?}"
    );
}

#[test]
fn the_most_serious_way_is_the_one_reported() {
    // A logical volume spread over some of: the decoy's own LUKS mapping
    // dm-0, a device of a kind the check does not know, a plain disk.
    let spread = |slaves: &[&str]| {
        Host::new("254:9", "ext4", "/dev/mapper/vg-data")
            .disk("sdc", "8:32")
            .disk("sdd", "8:48")
            .mapping("dm-7", "254:7", "mp", "mpath-36005", &["sdd"])
            .mapping("dm-9", "254:9", "vg-data", "LVM-c3d4-data", slaves)
            .run()
    };
    // A plain disk comes before the decoy's own encryption and a doubt.
    let result = spread(&["dm-0", "dm-7", "sdc"]);
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc:"
        )),
        "{result:?}"
    );
    // The decoy's own encryption comes before a doubt.
    let result = spread(&["dm-0", "dm-7"]);
    assert!(
        warning(&result).contains("is the decoy's own: LUKS mapping dm-0"),
        "{result:?}"
    );
    let result = spread(&["dm-7"]);
    assert!(
        warning(&result).contains("dm-7 is a device-mapper device of a kind"),
        "{result:?}"
    );
}

#[test]
fn a_mapping_of_an_unknown_kind_over_the_decoys_encryption_cannot_be_confirmed() {
    // Whether the device in between encrypts cannot be told, so the decoy's
    // encryption may not be all there is.
    let result = Host::new("254:9", "ext4", "/dev/mapper/mp")
        .mapping("dm-9", "254:9", "mp", "mpath-3600508b4", &["dm-0"])
        .run();
    assert!(
        warning(&result).contains("dm-9 is a device-mapper device of a kind"),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// Filesystems of several devices
// ------------------------------------------------------------------------

#[test]
fn a_btrfs_filesystem_needs_encryption_of_its_own_on_each_device() {
    // btrfs on dm-9 (LUKS on sdb) and sdc, through LUKS or not.
    let spread = |second_encrypted: bool| {
        let host = Host::new("0:52", "btrfs", "/dev/mapper/data")
            .disk("sdb", "8:16")
            .disk("sdc", "8:32")
            .luks("dm-9", "254:9", "data", &["sdb"]);
        let (host, second) = if second_encrypted {
            (host.luks("dm-8", "254:8", "data2", &["sdc"]), "dm-8")
        } else {
            (host, "sdc")
        };
        host.btrfs(&["dm-9", second]).run()
    };
    assert_pass(&spread(true), "LUKS mapping dm-8, LUKS mapping dm-9");
    let result = spread(false);
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc:"
        )),
        "{result:?}"
    );
}

#[test]
fn a_bcachefs_filesystem_is_followed_into_each_device_its_source_names() {
    // bcachefs shows the number of its first device and names them all in
    // its source.
    let result = Host::new("254:9", "bcachefs", "/dev/mapper/data:/dev/sdc")
        .disk("sdb", "8:16")
        .disk("sdc", "8:32")
        .luks("dm-9", "254:9", "data", &["sdb"])
        .run();
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc:"
        )),
        "{result:?}"
    );
}

#[test]
fn an_image_file_on_a_btrfs_filesystem_of_several_devices_needs_each_encrypted() {
    let result = Host::with_mounts(
        "30 1 0:60 / /srv rw - btrfs /dev/mapper/pool rw\n\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    )
    .disk("sdb", "8:16")
    .disk("sdc", "8:32")
    .luks("dm-7", "254:7", "pool", &["sdb"])
    .btrfs(&["dm-7", "sdc"])
    .loop_device("loop0", "7:0", "/srv/vm/box.img")
    .run();
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc:"
        )),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// A volume of the decoy's crypttab under another name
// ------------------------------------------------------------------------

/// The decoy's crypttab opens sdc as `backup`; it was opened as `media`
/// (dm-5, a tcrypt mapping over `below`), and the hidden root is a plain
/// image on it.
fn crypttab_volume_under_another_name(below: &[&str], host: Host) -> CheckResult {
    host.mapping("dm-5", "254:5", "media", "CRYPT-TCRYPT-media", below)
        .loop_device("loop0", "7:0", "/srv/backup/disk.raw")
        .file_on("/srv/backup/disk.raw", 254, 5)
        .file("/etc/crypttab", "backup /dev/sdc none tcrypt,noauto\n")
        .run()
}

#[test]
fn a_volume_the_decoys_crypttab_opens_is_the_decoys_under_any_name() {
    let mounts = "30 1 254:5 / /srv/backup rw - ext4 /dev/mapper/media rw\n\
                  40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n";
    let result =
        crypttab_volume_under_another_name(&["sdc"], Host::with_mounts(mounts).disk("sdc", "8:32"));
    assert!(
        warning(&result).contains(
            "is the decoy's own: VeraCrypt/TrueCrypt (tcrypt) mapping dm-5, which also holds the \
             volume the decoy's /etc/crypttab opens as backup."
        ),
        "{result:?}"
    );

    // The same past the inner cipher of a cascade.
    let cascade = Host::with_mounts(mounts).disk("sdc", "8:32").mapping(
        "dm-4",
        "254:4",
        "media_1",
        "CRYPT-SUBDEV-media_1",
        &["sdc"],
    );
    let result = crypttab_volume_under_another_name(&["dm-4"], cascade);
    assert!(
        warning(&result).contains("is the decoy's own: VeraCrypt/TrueCrypt (tcrypt) mapping dm-5"),
        "{result:?}"
    );
}

#[test]
fn encryption_of_its_own_over_the_decoys_crypttab_volume_passes() {
    // The decoy's crypttab opens sdc as `backup` (dm-5), and a LUKS volume
    // with a key of its own (dm-9) lies on that mapping.
    let result = Host::with_mounts(
        "30 1 254:9 / /srv/inner rw - ext4 /dev/mapper/inner rw\n\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n",
    )
    .disk("sdc", "8:32")
    .luks("dm-5", "254:5", "backup", &["sdc"])
    .luks("dm-9", "254:9", "inner", &["dm-5"])
    .loop_device("loop0", "7:0", "/srv/inner/disk.raw")
    .file_on("/srv/inner/disk.raw", 254, 9)
    .file("/etc/crypttab", "backup /dev/sdc none luks,noauto\n")
    .run();
    assert_pass(&result, "LUKS mapping dm-9");
}

// ------------------------------------------------------------------------
// Where the loop driver records a loop device's file
// ------------------------------------------------------------------------

/// An image on the plain stick sdc1 (`8:33`) at `/media/stick`, with
/// `extra` mount lines, through loop0 at the hidden root.
fn image_on_a_stick(extra: &str) -> Host {
    Host::with_mounts(&format!(
        "30 1 8:33 / /media/stick rw - ext4 /dev/sdc1 rw\n{extra}\
         40 1 7:0 / /mnt/data rw - ext4 /dev/loop0 rw\n"
    ))
    .disk("sdc", "8:32")
    .partition("sdc1", "8:33", "sdc")
    .disk("sdd", "8:48")
    .luks("dm-6", "254:6", "other", &["sdd"])
    .loop_device("loop0", "7:0", "/media/stick/vault.img")
}

#[test]
fn a_loop_file_is_followed_where_the_loop_driver_records_it() {
    let result = image_on_a_stick("").recorded("loop0", 8, 33).run();
    assert!(
        warning(&result).starts_with(&format!(
            "Nothing encrypts the hidden root at {ROOT} on sdc1:"
        )),
        "{result:?}"
    );
}

#[test]
fn a_loop_file_whose_path_leads_elsewhere_than_its_record_cannot_be_confirmed() {
    // An encrypted volume mounted over /media/stick later leads the path
    // into it, while the loop driver still records the stick.
    let result = image_on_a_stick("31 30 254:6 / /media/stick rw - ext4 /dev/mapper/other rw\n")
        .recorded("loop0", 8, 33)
        .run();
    assert!(
        warning(&result).ends_with(
            "loop device loop0 reads /media/stick/vault.img, which its path now places on another \
             filesystem than the one the loop driver recorded for it."
        ),
        "{result:?}"
    );
}

#[test]
fn a_loop_file_recorded_on_a_filesystem_mounted_nowhere_cannot_be_confirmed() {
    let result = image_on_a_stick("").recorded("loop0", 8, 99).run();
    assert!(
        warning(&result).ends_with(
            "loop device loop0 reads /media/stick/vault.img, whose filesystem, as the loop \
             driver recorded it, is not mounted here."
        ),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// Partitions and devices whose storage sysfs does not show
// ------------------------------------------------------------------------

#[test]
fn a_partition_of_a_loop_device_over_luks_passes() {
    // losetup -P: the partition's data lies where the loop device keeps its
    // own.
    let result = Host::new("259:8", "ext4", "/dev/loop0p1")
        .disk("sdb", "8:16")
        .luks("dm-5", "254:5", "vault", &["sdb"])
        .loop_device("loop0", "7:0", "/dev/mapper/vault")
        .partition("loop0p1", "259:8", "loop0")
        .run();
    assert_pass(&result, "LUKS mapping dm-5");
}

#[test]
fn a_partition_of_a_mirror_of_two_encrypted_disks_passes() {
    let result = Host::new("259:12", "ext4", "/dev/md0p1")
        .disk("sdb", "8:16")
        .disk("sdc", "8:32")
        .luks("dm-7", "254:7", "leg0", &["sdb"])
        .luks("dm-8", "254:8", "leg1", &["sdc"])
        .device(
            "/sys/devices/virtual/block/md0",
            "md0",
            "9:0",
            &["dm-7", "dm-8"],
        )
        .partition("md0p1", "259:12", "md0")
        .run();
    assert_pass(&result, "LUKS mapping dm-7, LUKS mapping dm-8");
}

#[test]
fn a_device_that_keeps_its_data_out_of_sight_cannot_be_confirmed() {
    for (name, dev, kind) in [
        ("zd0", "230:0", "a ZFS volume"),
        ("nbd0", "43:0", "a network block device"),
        ("ublkb0", "259:9", "a userspace block device"),
        ("zram0", "252:0", "a compressed RAM disk"),
    ] {
        let result = Host::new(dev, "ext4", &format!("/dev/{name}"))
            .disk(name, dev)
            .run();
        assert!(
            warning(&result).ends_with(&format!(
                "{name} is {kind}, which keeps its data where the check cannot follow."
            )),
            "{name}: {result:?}"
        );
    }
    // A partition of a ZFS volume, as a virtual machine's disk has.
    let result = Host::new("230:1", "ext4", "/dev/zd0p1")
        .disk("zd0", "230:0")
        .partition("zd0p1", "230:1", "zd0")
        .run();
    assert!(
        warning(&result)
            .ends_with("zd0 is a ZFS volume, which keeps its data where the check cannot follow."),
        "{result:?}"
    );
}

// ------------------------------------------------------------------------
// RAM, a folder and the check itself
// ------------------------------------------------------------------------

#[test]
fn a_root_in_ram_warns_that_nothing_survives_a_power_off() {
    for fstype in ["tmpfs", "ramfs"] {
        let result = Host::new("0:50", fstype, fstype).run();
        assert_eq!(
            warning(&result),
            format!(
                "The hidden root at {ROOT} is a {fstype}, held in RAM: nothing on it survives a \
                 power-off or a reboot."
            )
        );
        assert_eq!(fix(&result), RAM_FIX);
    }
}

#[test]
fn a_root_that_is_no_mount_point_is_skipped() {
    let result = Host::with_mounts("").run();
    assert!(result.is_pass(), "{result:?}");
    assert_eq!(
        result.message(),
        format!("Encryption check skipped: nothing is mounted at {ROOT}")
    );
}

#[test]
fn the_check_is_named_needs_the_hidden_volume_and_defaults_to_its_root() {
    let check = BackendEncryptionCheck::default();
    assert_eq!(
        check.hidden_volume_root,
        PathBuf::from(crate::config::DEFAULT_HIDDEN_VOLUME_ROOT)
    );
    assert_eq!(
        <BackendEncryptionCheck as PreFlightCheck<MockFilesystem>>::name(&check),
        "backend-encryption"
    );
    assert_eq!(
        <BackendEncryptionCheck as PreFlightCheck<MockFilesystem>>::description(&check),
        "Warns when the hidden root's storage has no encryption of its own"
    );
    assert!(
        <BackendEncryptionCheck as PreFlightCheck<MockFilesystem>>::requires_hidden_volume(&check)
    );
}
