// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check on a stock NixOS install whose `/` and `/home` lie on one
//! filesystem, with the hidden root in a btrfs subvolume or a folder of it,
//! which `--allow-decoy-storage` accepts: the `hardware-configuration.nix`
//! that `nixos-generate-config` writes names that filesystem's device, and
//! passes with the flag, while it fails without it.
//!
//! The machine is a mock with sysfs laid out as the kernel lays it out (each
//! device's attributes in its own directory under `/sys/devices`, linked from
//! `/sys/class/block` and `/sys/dev/block`), udev's records and links, and
//! the fstab NixOS generates, so the attach gate's judge and the scan both
//! read it as on a real install.

use super::*;
use crate::filesystem::MockFilesystem;
use crate::nixos::config::ReferenceKind;
use std::path::Path;

/// The drivers' major numbers, as `/proc/devices` lists them in a virtual
/// machine with a virtio disk.
const PROC_DEVICES: &str = "Character devices:\n  1 mem\n  4 tty\n\n\
                            Block devices:\n  7 loop\n  8 sd\n  9 md\n 11 sr\n\
                            252 virtblk\n253 device-mapper\n259 blkext\n";

const VDA: &str = "/sys/devices/pci0000:00/0000:00:04.0/virtio2/block/vda";
const VDA1: &str = "/sys/devices/pci0000:00/0000:00:04.0/virtio2/block/vda/vda1";
const VDA2: &str = "/sys/devices/pci0000:00/0000:00:04.0/virtio2/block/vda/vda2";

/// The root's filesystem's uuid, as udev and `hardware-configuration.nix`
/// give it.
const ROOT_UUID: &str = "4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f";
/// The ESP's uuid.
const BOOT_UUID: &str = "1A2B-3C4D";
/// The root partition's GPT uuid.
const ROOT_PARTUUID: &str = "8e7d6c5b-4a39-4281-a0b1-c2d3e4f5a6b7";

/// A NixOS machine, built one device at a time.
struct Machine {
    fs: MockFilesystem,
    class: Vec<PathBuf>,
    links: Vec<(String, String)>,
}

impl Machine {
    /// A machine whose mount table is `mountinfo` and whose generated fstab
    /// is `fstab`, with the virtio disk vda: its ESP vda1 (252:1) and its
    /// root partition vda2 (252:2).
    fn new(mountinfo: &str, fstab: &str) -> Self {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_table(mountinfo);
        fs.mock_set_file_content("/proc/self/mountinfo", mountinfo);
        fs.mock_set_path_exists("/mnt/vault", true);
        fs.mock_set_path_exists("/sys/class/block", true);
        fs.mock_set_file_content("/proc/devices", PROC_DEVICES);
        fs.mock_set_file_content("/etc/fstab", fstab);
        let mut machine = Self {
            fs,
            class: Vec::new(),
            links: Vec::new(),
        };
        machine.device(VDA, "vda", "252:0", "DEVTYPE=disk", &[]);
        machine.device(VDA1, "vda1", "252:1", "DEVTYPE=partition\nPARTN=1", &[]);
        machine.device(
            VDA2,
            "vda2",
            "252:2",
            &format!("DEVTYPE=partition\nPARTN=2\nPARTUUID={ROOT_PARTUUID}"),
            &[],
        );
        for dir in [VDA1, VDA2] {
            machine
                .fs
                .mock_set_file_content(&format!("{dir}/partition"), "1\n");
        }
        machine.udev(
            "252:1",
            &format!(
                "S:disk/by-uuid/{BOOT_UUID}\nS:disk/by-path/pci-0000:00:04.0-part1\n\
                 S:disk/by-partlabel/ESP\nE:ID_FS_UUID={BOOT_UUID}\nE:ID_FS_TYPE=vfat\n\
                 E:ID_PART_ENTRY_NAME=ESP\n"
            ),
        );
        machine.udev(
            "252:2",
            &format!(
                "S:disk/by-uuid/{ROOT_UUID}\nS:disk/by-label/nixos\n\
                 S:disk/by-partuuid/{ROOT_PARTUUID}\nS:disk/by-path/pci-0000:00:04.0-part2\n\
                 S:disk/by-partlabel/primary\nE:ID_FS_UUID={ROOT_UUID}\nE:ID_FS_LABEL=nixos\n\
                 E:ID_FS_LABEL_ENC=nixos\nE:ID_PART_ENTRY_UUID={ROOT_PARTUUID}\n\
                 E:ID_PART_ENTRY_NAME=primary\n"
            ),
        );
        machine.dev_disk(&[
            (&format!("/dev/disk/by-uuid/{BOOT_UUID}"), "/dev/vda1"),
            (&format!("/dev/disk/by-uuid/{ROOT_UUID}"), "/dev/vda2"),
            ("/dev/disk/by-label/nixos", "/dev/vda2"),
            (
                &format!("/dev/disk/by-partuuid/{ROOT_PARTUUID}"),
                "/dev/vda2",
            ),
            ("/dev/disk/by-partlabel/ESP", "/dev/vda1"),
            ("/dev/disk/by-partlabel/primary", "/dev/vda2"),
        ]);
        machine
    }

    /// The device `name` (`dev`) at `dir`, with `uevent`, listed in
    /// `/sys/class/block` and `/sys/dev/block`, its node in `/dev`, and the
    /// devices at `holders` built on it.
    fn device(&mut self, dir: &str, name: &str, dev: &str, uevent: &str, holders: &[&str]) {
        self.fs
            .mock_set_file_content(&format!("{dir}/dev"), &format!("{dev}\n"));
        self.fs.mock_set_file_content(
            &format!("{dir}/uevent"),
            &format!("DEVNAME={name}\n{uevent}\n"),
        );
        self.fs
            .mock_set_directory_contents(&Path::new(dir).join("slaves"), Vec::new());
        let holder_dir = Path::new(dir).join("holders");
        let mut entries = Vec::new();
        for holder in holders {
            let link = holder_dir.join(Path::new(holder).file_name().unwrap());
            self.link(link.to_str().unwrap(), holder);
            entries.push(link);
        }
        self.fs.mock_set_directory_contents(&holder_dir, entries);
        let class = format!("/sys/class/block/{name}");
        self.link(&class, dir);
        self.link(&format!("/sys/dev/block/{dev}"), dir);
        self.fs.mock_set_device_node(&format!("/dev/{name}"));
        self.class.push(PathBuf::from(class));
        self.fs
            .mock_set_directory_contents(Path::new("/sys/class/block"), self.class.clone());
    }

    fn link(&self, link: &str, target: &str) {
        self.fs
            .create_symlink(Path::new(target), Path::new(link))
            .unwrap();
    }

    /// udev's record of the device `dev`.
    fn udev(&self, dev: &str, record: &str) {
        self.fs
            .mock_set_file_content(&format!("/run/udev/data/b{dev}"), record);
    }

    /// The `/dev/disk` links, each to a device node, with their directories.
    fn dev_disk(&mut self, links: &[(&str, &str)]) {
        for (link, node) in links {
            self.link(link, node);
            self.links.push(((*link).to_string(), (*node).to_string()));
        }
        let mut dirs: Vec<PathBuf> = Vec::new();
        for (link, _) in &self.links {
            let dir = Path::new(link).parent().unwrap().to_path_buf();
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        for dir in &dirs {
            let entries = self
                .links
                .iter()
                .map(|(link, _)| PathBuf::from(link))
                .filter(|link| link.parent() == Some(dir.as_path()))
                .collect();
            self.fs.mock_set_directory_contents(dir, entries);
        }
        self.fs
            .mock_set_directory_contents(Path::new("/dev/disk"), dirs);
    }

    /// vda2 holds a btrfs filesystem.
    fn btrfs(&self) {
        let fsid = Path::new("/sys/fs/btrfs").join(ROOT_UUID);
        self.fs
            .mock_set_directory_contents(Path::new("/sys/fs/btrfs"), vec![fsid.clone()]);
        let member = fsid.join("devices/vda2");
        self.link(member.to_str().unwrap(), VDA2);
        self.fs
            .mock_set_directory_contents(&fsid.join("devices"), vec![member]);
    }

    /// `/etc/nixos` holds `files`.
    fn nixos(&self, files: &[(&str, &str)]) {
        let mut paths = Vec::new();
        for (path, content) in files {
            self.fs.mock_set_file_content(path, content);
            paths.push(Path::new(*path));
        }
        self.fs
            .mock_set_files_with_pattern("/etc/nixos", ".nix", &paths);
    }

    /// The check of the root at `/mnt/vault`, with `allow`.
    fn check(&self, allow: Allow) -> CheckResult {
        SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/vault"))
            .allowing(allow)
            .run(&self.fs)
            .unwrap()
    }
}

/// The `hardware-configuration.nix` that `nixos-generate-config` writes for
/// `/` and `/home` as the btrfs subvolumes `@` and `@home` of vda2, and the
/// ESP at `/boot`.
fn btrfs_hardware_configuration() -> String {
    format!(
        "# Do not modify this file!  It was generated by 'nixos-generate-config'\n\
         # and may be overwritten by future invocations.  Please make changes\n\
         # to /etc/nixos/configuration.nix instead.\n\
         {{ config, lib, pkgs, modulesPath, ... }}:\n\
         \n\
         {{\n\
         \x20 imports =\n\
         \x20   [ (modulesPath + \"/profiles/qemu-guest.nix\")\n\
         \x20   ];\n\
         \n\
         \x20 boot.initrd.availableKernelModules = [ \"ahci\" \"xhci_pci\" \"virtio_pci\" \"sr_mod\" \"virtio_blk\" ];\n\
         \x20 boot.initrd.kernelModules = [ ];\n\
         \x20 boot.kernelModules = [ \"kvm-intel\" ];\n\
         \x20 boot.extraModulePackages = [ ];\n\
         \n\
         \x20 fileSystems.\"/\" =\n\
         \x20   {{ device = \"/dev/disk/by-uuid/{ROOT_UUID}\";\n\
         \x20     fsType = \"btrfs\";\n\
         \x20     options = [ \"subvol=@\" ];\n\
         \x20   }};\n\
         \n\
         \x20 fileSystems.\"/home\" =\n\
         \x20   {{ device = \"/dev/disk/by-uuid/{ROOT_UUID}\";\n\
         \x20     fsType = \"btrfs\";\n\
         \x20     options = [ \"subvol=@home\" ];\n\
         \x20   }};\n\
         \n\
         \x20 fileSystems.\"/boot\" =\n\
         \x20   {{ device = \"/dev/disk/by-uuid/{BOOT_UUID}\";\n\
         \x20     fsType = \"vfat\";\n\
         \x20     options = [ \"fmask=0077\" \"dmask=0077\" ];\n\
         \x20   }};\n\
         \n\
         \x20 swapDevices = [ ];\n\
         \n\
         \x20 networking.useDHCP = lib.mkDefault true;\n\
         \x20 nixpkgs.hostPlatform = lib.mkDefault \"x86_64-linux\";\n\
         \x20 hardware.cpu.intel.updateMicrocode = lib.mkDefault config.hardware.enableRedistributableFirmware;\n\
         }}\n"
    )
}

/// A stock `configuration.nix`, which names no device.
const CONFIGURATION: &str = "{ config, pkgs, ... }:\n\
                             {\n\
                             \x20 imports = [ ./hardware-configuration.nix ];\n\
                             \x20 boot.loader.systemd-boot.enable = true;\n\
                             \x20 boot.loader.efi.canTouchEfiVariables = true;\n\
                             \x20 networking.hostName = \"nixos\";\n\
                             \x20 system.stateVersion = \"25.11\";\n\
                             }\n";

/// The mount table of the btrfs install, with the subvolume `@vault` (id
/// 258) at the hidden root: NixOS mounts `@` at `/`, binds `/nix/store`
/// read-only, and mounts `@home` at `/home` and the ESP at `/boot`.
fn btrfs_mounts(vault: &str) -> String {
    format!(
        "22 1 0:31 /@ / rw,relatime shared:1 - btrfs /dev/vda2 rw,space_cache=v2,subvolid=256,subvol=/@\n\
         23 22 0:31 /@/nix/store /nix/store ro,relatime shared:2 - btrfs /dev/vda2 rw,space_cache=v2,subvolid=256,subvol=/@\n\
         45 22 0:31 /@home /home rw,relatime shared:3 - btrfs /dev/vda2 rw,space_cache=v2,subvolid=257,subvol=/@home\n\
         46 22 252:1 / /boot rw,relatime shared:4 - vfat /dev/vda1 rw,fmask=0077,dmask=0077\n\
         {vault}"
    )
}

/// The fstab NixOS generates from that `hardware-configuration.nix`.
fn btrfs_fstab() -> String {
    format!(
        "# This is a generated file.  Do not edit!\n\
         #\n\
         # To make changes, edit the fileSystems and swapDevices NixOS options\n\
         # in your /etc/nixos/configuration.nix file.\n\
         #\n\
         # <file system> <mount point>   <type>  <options>       <dump>  <pass>\n\
         \n\
         # Filesystems.\n\
         /dev/disk/by-uuid/{ROOT_UUID} / btrfs subvol=@ 0 0\n\
         /dev/disk/by-uuid/{ROOT_UUID} /home btrfs subvol=@home 0 0\n\
         /dev/disk/by-uuid/{BOOT_UUID} /boot vfat fmask=0077,dmask=0077 0 2\n\
         \n\
         \n\
         # Swap devices.\n"
    )
}

/// The stock btrfs install with `@vault` at the hidden root, and `files` in
/// `/etc/nixos` beside the stock ones.
fn btrfs_install(files: &[(&str, &str)]) -> Machine {
    let machine = Machine::new(
        &btrfs_mounts(
            "60 22 0:31 /@vault /mnt/vault rw,relatime shared:5 - btrfs /dev/vda2 \
             rw,space_cache=v2,subvolid=258,subvol=/@vault\n",
        ),
        &btrfs_fstab(),
    );
    machine.btrfs();
    let hardware = btrfs_hardware_configuration();
    let mut all = vec![
        ("/etc/nixos/configuration.nix", CONFIGURATION),
        ("/etc/nixos/hardware-configuration.nix", hardware.as_str()),
    ];
    all.extend_from_slice(files);
    machine.nixos(&all);
    machine
}

#[test]
fn a_stock_btrfs_install_with_the_root_in_a_subvolume_passes_with_the_flag() {
    let machine = btrfs_install(&[]);
    let without = machine.check(Allow::Nothing);
    assert_eq!(
        without,
        CheckResult::fail_with(
            format!(
                "The decoy's /etc/nixos names the hidden environment: \
                 /etc/nixos/hardware-configuration.nix, line 17: \
                 '/dev/disk/by-uuid/{ROOT_UUID}' ({}). An examination of the decoy reads this \
                 file. One more line does too.",
                ReferenceKind::Storage.reason()
            ),
            ReferenceKind::Storage.remedy(),
        )
    );
    assert_eq!(
        machine.check(Allow::DecoyStorage),
        CheckResult::Pass(
            "The 2 .nix files under /etc/nixos name nothing of the hidden environment other \
             than the device of the filesystem that --allow-decoy-storage accepted the hidden \
             root on, which the decoy mounts itself (2 lines name that device)"
                .to_string()
        )
    );
}

#[test]
fn with_the_flag_every_name_of_the_installs_device_passes() {
    for line in [
        "fileSystems.\"/data\".device = \"/dev/vda2\";",
        "fileSystems.\"/data\".device = \"/dev/disk/by-label/nixos\";",
        "fileSystems.\"/data\".label = \"nixos\";",
        "# LABEL=nixos",
        "# UUID=4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f",
        "fileSystems.\"/data\".device = \"/dev/disk/by-partuuid/8e7d6c5b-4a39-4281-a0b1-c2d3e4f5a6b7\";",
        "# PARTUUID=8e7d6c5b-4a39-4281-a0b1-c2d3e4f5a6b7",
        "fileSystems.\"/data\".device = \"/dev/disk/by-partlabel/primary\";",
        "# PARTLABEL=primary",
        "fileSystems.\"/data\".device = \"/dev/disk/by-path/pci-0000:00:04.0-part2\";",
        "boot.resumeDevice = \"/dev/block/252:2\";",
        "services.udev.extraRules = ''KERNEL==\"vda2\", OPTIONS+=\"watch\"'';",
    ] {
        let content = format!("{{\n  {line}\n}}\n");
        let machine = btrfs_install(&[("/etc/nixos/extra.nix", &content)]);
        assert!(
            machine.check(Allow::Nothing).is_fail(),
            "{line}: {:?}",
            machine.check(Allow::Nothing)
        );
        let with = machine.check(Allow::DecoyStorage);
        assert!(with.is_pass(), "{line}: {with:?}");
        assert!(
            with.message().ends_with("(3 lines name that device)"),
            "{line}: {with:?}"
        );
    }
}

#[test]
fn with_the_flag_the_roots_own_names_still_refuse() {
    for (line, text, kind) in [
        ("x = /mnt/vault;", "/mnt/vault", ReferenceKind::MountPoint),
        (
            "fileSystems.\"/data\".options = [ \"subvol=@vault\" ];",
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/data\".options = [ \"subvolid=258\" ];",
            "258",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/mnt/vault\".device = \"/dev/disk/by-uuid/4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f\";",
            "/mnt/vault",
            ReferenceKind::MountPoint,
        ),
        (
            "services.nails.enable = true;",
            "nails",
            ReferenceKind::ToolName,
        ),
    ] {
        let content = format!("{{\n  {line}\n}}\n");
        let machine = btrfs_install(&[("/etc/nixos/extra.nix", &content)]);
        let result = machine.check(Allow::DecoyStorage);
        assert!(result.is_fail(), "{line}: {result:?}");
        assert!(
            result.message().contains(&format!(
                "/etc/nixos/extra.nix, line 2: '{text}' ({})",
                kind.reason()
            )),
            "{line}: {result:?}"
        );
    }
}

/// A place that may name the storage and cannot be read, a device of the
/// install's filesystem among them, still refuses with the flag.
#[test]
fn with_the_flag_a_name_nails_cannot_read_still_refuses() {
    let machine = btrfs_install(&[]);
    machine
        .fs
        .mock_set_lookup_error("/run/udev/data/b252:2", std::io::ErrorKind::Other);
    let result = machine.check(Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("NAILS cannot read /run/udev/data/b252:2"),
        "{result:?}"
    );
}

/// The judge cannot read its inputs: nothing is the decoy's own, and the
/// install's names refuse as without the flag.
#[test]
fn with_the_flag_a_root_the_judge_cannot_place_lets_nothing_be() {
    let machine = btrfs_install(&[]);
    machine
        .fs
        .mock_set_lookup_error("/etc/fstab", std::io::ErrorKind::PermissionDenied);
    let result = machine.check(Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains(&format!("'/dev/disk/by-uuid/{ROOT_UUID}'")),
        "{result:?}"
    );
}

/// The `hardware-configuration.nix` of an ext4 install whose `/` holds
/// `/home`, and its fstab.
fn ext4_install(vault: &str) -> Machine {
    let mounts = format!(
        "22 1 252:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw\n\
         23 22 252:2 /nix/store /nix/store ro,relatime shared:2 - ext4 /dev/vda2 rw\n\
         46 22 252:1 / /boot rw,relatime shared:4 - vfat /dev/vda1 rw,fmask=0077,dmask=0077\n\
         {vault}"
    );
    let fstab = format!(
        "# This is a generated file.  Do not edit!\n\
         # Filesystems.\n\
         /dev/disk/by-uuid/{ROOT_UUID} / ext4 defaults 0 1\n\
         /dev/disk/by-uuid/{BOOT_UUID} /boot vfat fmask=0077,dmask=0077 0 2\n"
    );
    let machine = Machine::new(&mounts, &fstab);
    let hardware = format!(
        "{{ config, lib, pkgs, modulesPath, ... }}:\n\
         {{\n\
         \x20 fileSystems.\"/\" =\n\
         \x20   {{ device = \"/dev/disk/by-uuid/{ROOT_UUID}\";\n\
         \x20     fsType = \"ext4\";\n\
         \x20   }};\n\
         \x20 fileSystems.\"/boot\" =\n\
         \x20   {{ device = \"/dev/disk/by-uuid/{BOOT_UUID}\";\n\
         \x20     fsType = \"vfat\";\n\
         \x20   }};\n\
         \x20 swapDevices = [ ];\n\
         }}\n"
    );
    machine.nixos(&[
        ("/etc/nixos/configuration.nix", CONFIGURATION),
        ("/etc/nixos/hardware-configuration.nix", &hardware),
    ]);
    machine
}

#[test]
fn a_stock_ext4_install_with_the_root_in_a_folder_of_slash_passes_with_the_flag() {
    let machine = ext4_install(
        "60 22 252:2 /home/alice/vault /mnt/vault rw,relatime shared:5 - ext4 /dev/vda2 rw\n",
    );
    assert!(machine.check(Allow::Nothing).is_fail());
    let with = machine.check(Allow::DecoyStorage);
    assert_eq!(
        with,
        CheckResult::Pass(
            "The 2 .nix files under /etc/nixos name nothing of the hidden environment other \
             than the device of the filesystem that --allow-decoy-storage accepted the hidden \
             root on, which the decoy mounts itself (1 line names that device)"
                .to_string()
        )
    );
    // The folder the root is, as / shows it, still refuses.
    machine.nixos(&[(
        "/etc/nixos/configuration.nix",
        "{ services.syncthing.dataDir = \"/home/alice/vault\"; }",
    )]);
    let result = machine.check(Allow::DecoyStorage);
    assert!(
        result.message().contains(&format!(
            "'/home/alice/vault' ({})",
            ReferenceKind::RootPlace.reason()
        )),
        "{result:?}"
    );
}

/// The whole of a filesystem at the root, or a volume of its own, lets
/// nothing be: its names refuse with the flag as without it.
#[test]
fn with_the_flag_a_root_that_is_no_folder_or_subvolume_of_the_decoys_filesystem_lets_nothing_be() {
    // The whole ext4 at the root as well.
    let machine =
        ext4_install("60 22 252:2 / /mnt/vault rw,relatime shared:5 - ext4 /dev/vda2 rw\n");
    let result = machine.check(Allow::DecoyStorage);
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains(&format!("'/dev/disk/by-uuid/{ROOT_UUID}'")),
        "{result:?}"
    );
}
