// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The check on a stock NixOS install whose `/` and `/home` lie on one
//! filesystem, with the hidden root in a btrfs subvolume or a folder of it,
//! which `--allow-decoy-storage` accepts. The `hardware-configuration.nix`
//! that `nixos-generate-config` writes names that filesystem's device, and
//! the check refuses it, as it does for any other root: the flag does not
//! reach this check. The fix says why.
//!
//! The machine is a mock with sysfs laid out as the kernel lays it out (each
//! device's attributes in its own directory under `/sys/devices`, linked from
//! `/sys/class/block` and `/sys/dev/block`), udev's records and links, and
//! the fstab NixOS generates, so the attach gate's judge and the scan both
//! read it as on a real install.

use super::*;
use crate::filesystem::MockFilesystem;
use crate::nixos::config::{PLACED_DEVICE_REMEDY, ReferenceKind};
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

    /// The check of the root at `/mnt/vault`.
    fn check(&self) -> CheckResult {
        SuspiciousNailsReferenceCheck::new(PathBuf::from("/mnt/vault"))
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

/// The refusal of a stock install's line 17 (or `line` of
/// `hardware-configuration.nix`), which names the device of `/`, with the fix
/// that says why the flag does not let it be.
fn refuses_the_stock_device(result: &CheckResult, line: usize, more: &str) {
    assert_eq!(
        *result,
        CheckResult::fail_with(
            format!(
                "The decoy's /etc/nixos names the hidden environment: \
                 /etc/nixos/hardware-configuration.nix, line {line}: \
                 '/dev/disk/by-uuid/{ROOT_UUID}' ({}). An examination of the decoy reads this \
                 file.{more}",
                ReferenceKind::Storage.reason()
            ),
            PLACED_DEVICE_REMEDY,
        )
    );
}

/// The stock btrfs install, with the root in a subvolume beside `@` and
/// `@home`: `hardware-configuration.nix` names the device of `/` and
/// `/home`, and the check refuses it, with the fix for a placed root.
#[test]
fn a_stock_btrfs_install_with_the_root_in_a_subvolume_refuses_and_says_why() {
    let machine = btrfs_install(&[]);
    refuses_the_stock_device(&machine.check(), 17, " One more line does too.");
}

/// The stock ext4 install, with the root in a folder of `/`.
#[test]
fn a_stock_ext4_install_with_the_root_in_a_folder_of_slash_refuses_and_says_why() {
    let machine = ext4_install(
        "60 22 252:2 /home/alice/vault /mnt/vault rw,relatime shared:5 - ext4 /dev/vda2 rw\n",
    );
    refuses_the_stock_device(&machine.check(), 4, "");
}

/// The check NixOS's config layer registers for the commands that take
/// `--allow-decoy-storage` is built from the hidden root alone, so the flag
/// cannot reach it, and it refuses the stock install as the check does.
#[test]
fn the_check_the_nixos_layer_registers_refuses_the_stock_install() {
    let machine = btrfs_install(&[]);
    let gate = crate::platform::ConfigLayer::<MockFilesystem>::base_reference_check(
        &crate::platform::NixOsConfigLayer,
        Path::new("/mnt/vault"),
    );
    refuses_the_stock_device(
        &gate.run(&machine.fs).unwrap(),
        17,
        " One more line does too.",
    );
}

/// The fix for a placed root says why only for a name of a device; for a
/// root on storage of its own the fix is the one for any root.
#[test]
fn the_fix_for_a_placed_root_names_the_flag_only_for_a_device() {
    let machine = btrfs_install(&[]);
    let result = machine.check();
    let fix = result.remediation().unwrap_or_default();
    assert!(fix.contains("--allow-decoy-storage does not make this check pass such a line"));
    assert!(fix.contains("keep the hidden root on storage of its own"));
    machine.nixos(&[(
        "/etc/nixos/configuration.nix",
        "{\n  services.x.dataDir = \"/mnt/vault\";\n}\n",
    )]);
    let result = machine.check();
    assert_eq!(
        result.remediation(),
        Some(ReferenceKind::MountPoint.remedy()),
        "{result:?}"
    );
}

/// Each name of the install's device, as the device or label of an entry
/// for a system folder, refuses on its own line.
#[test]
fn every_name_of_the_installs_device_refuses_in_an_entry_for_a_system_folder() {
    for line in [
        "fileSystems.\"/srv\".device = \"/dev/vda2\";",
        "fileSystems.\"/srv\".device = \"/dev/disk/by-label/nixos\";",
        "fileSystems.\"/srv\".label = \"nixos\";",
        "fileSystems.\"/srv\".device = \"LABEL=nixos\";",
        "fileSystems.\"/srv\".device = \"UUID=4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f\";",
        "fileSystems.\"/srv\".device = \"/dev/disk/by-partuuid/8e7d6c5b-4a39-4281-a0b1-c2d3e4f5a6b7\";",
        "fileSystems.\"/srv\".device = \"PARTUUID=8e7d6c5b-4a39-4281-a0b1-c2d3e4f5a6b7\";",
        "fileSystems.\"/srv\".device = \"/dev/disk/by-partlabel/primary\";",
        "fileSystems.\"/srv\".device = \"PARTLABEL=primary\";",
        "fileSystems.\"/srv\".device = \"/dev/disk/by-path/pci-0000:00:04.0-part2\";",
        "fileSystems.\"/var/lib/docker\".device = \"/dev/block/252:2\";",
        "fileSystems.\"/.snapshots\" = { device = \"/dev/vda2\"; options = [ \"subvol=@snapshots\" ]; };",
    ] {
        let machine = btrfs_install(&[]);
        machine.nixos(&[("/etc/nixos/extra.nix", &format!("{{\n  {line}\n}}\n"))]);
        let result = machine.check();
        assert!(result.is_fail(), "{line}: {result:?}");
        assert!(
            result.message().contains("/etc/nixos/extra.nix, line 2: '"),
            "{line}: {result:?}"
        );
        assert_eq!(
            result.remediation(),
            Some(PLACED_DEVICE_REMEDY),
            "{line}: {result:?}"
        );
    }
}

/// The install's device named anywhere else fails as well: an entry for a
/// folder that is no system folder (the filesystem's top mounted for a
/// backup tool, say), the resume device, a udev rule, a comment, a
/// deduplicating service.
#[test]
fn the_installs_device_elsewhere_refuses() {
    for (line, text) in [
        (
            "fileSystems.\"/btr_pool\" = { device = \"/dev/disk/by-uuid/4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; };",
            "/dev/disk/by-uuid/4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f",
        ),
        (
            "fileSystems.\"/data\".device = \"/dev/disk/by-label/nixos\";",
            "/dev/disk/by-label/nixos",
        ),
        (
            "boot.resumeDevice = \"/dev/block/252:2\";",
            "/dev/block/252:2",
        ),
        (
            "services.udev.extraRules = ''KERNEL==\"vda2\", OPTIONS+=\"watch\"'';",
            "vda2",
        ),
        ("# LABEL=nixos", "nixos"),
        (
            "services.beesd.filesystems.root.spec = \"UUID=4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f\";",
            "4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f",
        ),
    ] {
        let content = format!("{{\n  {line}\n}}\n");
        let machine = btrfs_install(&[("/etc/nixos/extra.nix", &content)]);
        let result = machine.check();
        assert!(result.is_fail(), "{line}: {result:?}");
        assert!(
            result
                .message()
                .contains(&format!("/etc/nixos/extra.nix, line 2: '{text}'")),
            "{line}: {result:?}"
        );
    }
}
/// The root's mount point, its subvolume however a line reaches it, by
/// `subvol=` in any spelling, by `subvolid=` in any base, or through a mount
/// of the filesystem's top that only the configuration makes, a backup
/// tool's settings for it, and NAILS fail, each on its own line.
#[test]
fn the_roots_own_names_refuse() {
    const DEVICE: &str = "/dev/disk/by-uuid/4b1c9e2d-7f3a-4e8b-9c1d-2a3b4c5d6e7f";
    let top = format!(
        "fileSystems.\"/btr_pool\" = {{ device = \"{DEVICE}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};"
    );
    let cases = [
        ("x = /mnt/vault;".to_string(), "/mnt/vault", ReferenceKind::MountPoint),
        (
            "fileSystems.\"/data\".options = [ \"subvol=@vault\" ];".to_string(),
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/home\".options = [ \"subvol=//@vault\" ];".to_string(),
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/srv\".options = [ \"subvol=./@vault\" ];".to_string(),
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/srv\".options = [ \"subvol=@home/../@vault\" ];".to_string(),
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/data\".options = [ \"subvolid=258\" ];".to_string(),
            "subvolid=258",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/srv\".options = [ \"subvolid=0x102\" ];".to_string(),
            "subvolid=0x102",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/data\" = { device = \"/btr_pool/@vault\"; options = [ \"bind\" ]; };".to_string(),
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "services.btrbk.instances.daily.settings.volume.\"/btr_pool\".subvolume.\"@vault\" = { };".to_string(),
            "@vault",
            ReferenceKind::RootPlace,
        ),
        (
            "fileSystems.\"/mnt/vault\".options = [ \"bind\" ];".to_string(),
            "/mnt/vault",
            ReferenceKind::MountPoint,
        ),
        (
            "services.nails.enable = true;".to_string(),
            "nails",
            ReferenceKind::ToolName,
        ),
    ];
    for (line, text, kind) in cases {
        let content = format!("{{\n  {line}\n}}\n");
        let machine = btrfs_install(&[("/etc/nixos/extra.nix", &content)]);
        let result = machine.check();
        assert!(result.is_fail(), "{line}: {result:?}");
        assert!(
            result.message().contains(&format!(
                "/etc/nixos/extra.nix, line 2: '{text}' ({})",
                kind.reason()
            )),
            "{line}: {result:?}"
        );
    }
    // The top mounted by a line of its own and the subvolume reached
    // through it on the next: the first fails by the device, the second by
    // the subvolume's name, and the stock file's two lines by the device.
    let content = format!(
        "{{\n  {top}\n  services.btrbk.instances.daily.settings.volume.\"/btr_pool\".subvolume.\"@vault\" = {{ }};\n}}\n"
    );
    let machine = btrfs_install(&[("/etc/nixos/extra.nix", &content)]);
    let result = machine.check();
    assert!(
        result
            .message()
            .contains(&format!("/etc/nixos/extra.nix, line 2: '{DEVICE}'"))
            && result.message().contains("3 more lines do too."),
        "{result:?}"
    );
}
/// A place that may name the storage and cannot be read, a device of the
/// install's filesystem among them, refuses where no line names it.
#[test]
fn a_name_nails_cannot_read_refuses() {
    let machine = btrfs_install(&[]);
    machine.nixos(&[("/etc/nixos/configuration.nix", CONFIGURATION)]);
    machine
        .fs
        .mock_set_lookup_error("/run/udev/data/b252:2", std::io::ErrorKind::Other);
    let result = machine.check();
    assert!(result.is_fail(), "{result:?}");
    assert!(
        result
            .message()
            .contains("NAILS cannot read /run/udev/data/b252:2"),
        "{result:?}"
    );
}
/// The attach gate looks the hidden root up through the automount guard: a
/// root behind an automount point that nothing is mounted on is never
/// looked up, so the check mounts nothing there.
#[test]
fn a_root_behind_an_automount_point_is_never_looked_up() {
    let fs = MockFilesystem::new();
    let file = Path::new("/etc/nixos/configuration.nix");
    fs.mock_set_file_content(
        file.to_str().unwrap(),
        "{ fileSystems.\"/\".device = \"/dev/vda1\"; }",
    );
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &[file]);
    let mountinfo = "1 0 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n\
                     30 1 0:50 / /srv rw,relatime - autofs systemd-1 \
                     rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=100\n";
    fs.mock_set_mount_table(mountinfo);
    fs.mock_set_file_content("/proc/self/mountinfo", mountinfo);
    fs.mock_clear_lookups();
    let result = SuspiciousNailsReferenceCheck::new(PathBuf::from("/srv/vault"))
        .run(&fs)
        .unwrap();
    let behind: Vec<PathBuf> = fs
        .mock_lookups()
        .into_iter()
        .filter(|path| path.starts_with("/srv"))
        .collect();
    assert!(behind.is_empty(), "{behind:?}");
    assert!(result.is_pass(), "{result:?}");
}

/// `content` with `@DEV@` and `{dev}` forms filled in: the device of `/`.
fn with_device(content: &str) -> String {
    content.replace("@DEV@", &format!("/dev/disk/by-uuid/{ROOT_UUID}"))
}

/// Whether `content` names the install's device or its label itself.
fn names_the_device(content: &str) -> bool {
    content.contains(ROOT_UUID) || content.contains("\"nixos\"")
}

/// The check of the btrfs install with `content` in `/etc/nixos/extra.nix`
/// beside the stock files, and with it alone there.
fn btrfs_with(content: &str) -> (CheckResult, CheckResult) {
    let machine = btrfs_install(&[("/etc/nixos/extra.nix", content)]);
    let stock = machine.check();
    machine.nixos(&[("/etc/nixos/extra.nix", content)]);
    (stock, machine.check())
}

/// The check of the ext4 install with `content` in `/etc/nixos/extra.nix`
/// beside the stock files, and with it alone there.
fn ext4_with(content: &str) -> (CheckResult, CheckResult) {
    let machine = ext4_install(
        "60 22 252:2 /home/alice/vault /mnt/vault rw,relatime shared:5 - ext4 /dev/vda2 rw\n",
    );
    let config = machine
        .fs
        .read_file_content(Path::new("/etc/nixos/configuration.nix"))
        .unwrap();
    let hardware = machine
        .fs
        .read_file_content(Path::new("/etc/nixos/hardware-configuration.nix"))
        .unwrap();
    machine.nixos(&[
        ("/etc/nixos/configuration.nix", &config),
        ("/etc/nixos/hardware-configuration.nix", &hardware),
        ("/etc/nixos/extra.nix", content),
    ]);
    let stock = machine.check();
    machine.nixos(&[("/etc/nixos/extra.nix", content)]);
    (stock, machine.check())
}

/// That `id` refuses beside the stock files, and on its own where it names
/// the install's device, on a line of its own file.
fn assert_refuses(id: &str, content: &str, (stock, alone): (CheckResult, CheckResult)) {
    assert!(stock.is_fail(), "{id}: {stock:?}");
    if names_the_device(content) {
        assert!(alone.is_fail(), "{id}: {alone:?}");
        assert!(
            alone.message().contains("/etc/nixos/extra.nix, line "),
            "{id}: {alone:?}"
        );
    }
}

/// Every config through which an earlier version of this check let the
/// decoy's own device names pass with `--allow-decoy-storage` refuses now:
/// beside the stock files, and on its own wherever it names the device
/// itself.
#[test]
fn every_config_that_passed_with_the_flag_before_refuses() {
    for (id, content) in BTRFS_PROBES {
        let content = with_device(content);
        assert_refuses(id, &content, btrfs_with(&content));
    }
    for (id, content) in EXT4_PROBES {
        let content = with_device(content);
        assert_refuses(id, &content, ext4_with(&content));
    }
    for (id, lines) in btrfs_forms() {
        let content = format!("{{\n{lines}\n}}\n");
        assert_refuses(id, &content, btrfs_with(&content));
    }
    for (id, lines) in ext4_forms() {
        let content = format!("{{\n{lines}\n}}\n");
        assert_refuses(id, &content, ext4_with(&content));
    }
}

/// Configs that earlier versions of this check let pass with
/// `--allow-decoy-storage` on the btrfs install, while NixOS applies each to
/// the decoy's own entry: `@DEV@` stands for the device of `/` and `/home`.
const BTRFS_PROBES: &[(&str, &str)] = &[
    ("c00-empty", "{ }\n"),
    (
        "c01-plain-srv",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"subvol=@srv\" ]; };\n}\n",
    ),
    (
        "c02-join-inline",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ (\"subvol=@va\" + \"ult\") ]; };\n}\n",
    ),
    (
        "c03-join-split",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "c04-plain-vault",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"subvol=@vault\" ]; };\n}\n",
    ),
    (
        "c05-plain-needed",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; neededForBoot = true; options = [ \"subvol=@srv\" \"compress=zstd\" ]; };\n}\n",
    ),
    (
        "v01-bc-quote-inline",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; }; /* a 5\" disk */ fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v02-bc-quote-line",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  /* a 5\" disk */\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v03-bc-indq-line",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  /* write '' for two quotes */\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v04-prime-ident",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  y = let a'' = 1; in a'';\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v05-cr-comment",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; }; # old disk\r  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v06-esc-folder",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  fileSystems.\"/\\srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v07-esc-fs-attr",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  \"file\\Systems\".\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v08-interp-folder",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  fileSystems.${\"/srv\"}.options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v09-interp-fs-attr",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  ${\"fileSystems\"}.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v10-esc-options-attr",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  fileSystems.\"/srv\".\"opt\\ions\" = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v11-let-module",
        "let\n  m = { fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ]; };\nin\n{\n  imports = [ m ];\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n}\n",
    ),
    (
        "v12-true-shadow",
        "let true = [ (\"subvol=@va\" + \"ult\") ]; in\n{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = true; };\n}\n",
    ),
    (
        "v13-octal-subvol",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"subvol=@va\\\\165lt\" ]; };\n}\n",
    ),
    (
        "v14-octal-xmount",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"X-mount.subdir=@va\\\\165lt\" ]; };\n}\n",
    ),
    (
        "v15-octal-subvolid",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"subvolid=\\\\06258\" ]; };\n}\n",
    ),
    (
        "v16-uri-prime",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  y = http://example.org/a'';\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v17-octal-bind-data",
        "{\n  fileSystems.\"/var/lib/pool\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; };\n  fileSystems.\"/data\" = { device = \"/var/lib/pool/@va\\\\165lt\"; fsType = \"none\"; options = [ \"bind\" ]; };\n}\n",
    ),
    (
        "v18-let-module-mkmerge",
        "{ lib, ... }:\nlet\n  m = { fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ]; };\nin\n{\n  config = lib.mkMerge [ m { fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; }; } ];\n}\n",
    ),
    (
        "v19-bc-after-token",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  y = true/* a 5\" disk */;\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v20-bc-in-interp",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  y = \"${ /* a 5\" disk */ \"x\" }\";\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v21-select-prime",
        "{\n  fileSystems.\"/srv\" = { device = \"@DEV@\"; fsType = \"btrfs\"; };\n  y = { a'' = 1; }.a'';\n  fileSystems.\"/srv\".options = [ (\"subvol=@va\" + \"ult\") ];\n}\n",
    ),
    (
        "v22-esc-luks-attr",
        "{\n  boot.initrd.luks.devices.x.device = \"@DEV@\";\n  boot.initrd.luks.\"dev\\ices\".x.keyFile = \"/var/lib/pool/@va\" + \"ult\";\n}\n",
    ),
    (
        "v23-let-module-device-bind",
        "let\n  m = { fileSystems.\"/srv\".device = \"/var/lib/pool/@va\" + \"ult\"; };\nin\n{\n  imports = [ m ];\n  fileSystems.\"/var/lib/pool\" = { device = \"@DEV@\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; };\n  fileSystems.\"/srv\".options = [ \"bind\" ];\n}\n",
    ),
];

/// The same on the ext4 install, whose root is the folder `home/alice/vault`
/// of `/`.
const EXT4_PROBES: &[(&str, &str)] = &[
    ("e00-empty", "{ }\n"),
    (
        "e01-octal-bind-srv",
        "{\n  fileSystems.\"/srv\" = { device = \"/home/alice/va\\\\165lt\"; fsType = \"none\"; options = [ \"bind\" ]; };\n}\n",
    ),
    (
        "e02-plain-bind-srv",
        "{\n  fileSystems.\"/srv\" = { device = \"/home/alice/vault\"; fsType = \"none\"; options = [ \"bind\" ]; };\n}\n",
    ),
    (
        "e03-bc-quote-bind",
        "{\n  fileSystems.\"/srv\" = { fsType = \"none\"; options = [ \"bind\" ]; };\n  /* a 5\" disk */\n  fileSystems.\"/srv\".device = \"/home/alice/va\" + \"ult\";\n}\n",
    ),
    (
        "e04-join-bind-srv",
        "{\n  fileSystems.\"/srv\" = { fsType = \"none\"; options = [ \"bind\" ]; };\n  fileSystems.\"/srv\".device = \"/home/alice/va\" + \"ult\";\n}\n",
    ),
];

/// The device of `/` and `/home` on the btrfs install.
fn device() -> String {
    format!("/dev/disk/by-uuid/{ROOT_UUID}")
}

/// An entry for `/srv` on the install's device with `options`, on one line.
fn entry(options: &str) -> String {
    let dev = device();
    format!(
        "  fileSystems.\"/srv\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ {options} ]; }};"
    )
}

/// The same entry over several lines, as `nixos-generate-config` writes it.
fn multiline(options: &str) -> String {
    let dev = device();
    format!(
        "  fileSystems.\"/srv\" =\n    {{ device = \"{dev}\";\n      fsType = \"btrfs\";\n      options = [ {options} ];\n    }};"
    )
}

/// Entries for the btrfs install that earlier versions of this check let
/// pass with `--allow-decoy-storage`, or that test the edges of that, each
/// as lines of one set: escapes, joins behind brackets, functions, `let`,
/// references, comments and attribute paths written otherwise.
fn btrfs_forms() -> Vec<(&'static str, String)> {
    [btrfs_forms_1(), btrfs_forms_2(), btrfs_forms_3()].concat()
}

/// Part 1 of [`btrfs_forms`].
fn btrfs_forms_1() -> Vec<(&'static str, String)> {
    let dev = device();
    vec![
        ("baseline-stock", String::new()),
        ("own-srv-subvol-home", entry("\"subvol=@home\"")),
        ("N-subvol-literal", entry("\"subvol=@vault\"")),
        ("N-subvol-upper", entry("\"subvol=@VAULT\"")),
        ("N-subvolid-258", entry("\"subvolid=258\"")),
        ("N-subvolid-0x0102", entry("\"subvolid=0x0102\"")),
        ("N-subvolid-0402", entry("\"subvolid=0402\"")),
        ("N-subvolid-plus", entry("\"subvolid=+258\"")),
        ("N-subvolid-nl", entry("\"subvolid=258\\n\"")),
        ("N-subvolid-in-list", entry("\"compress=zstd,subvolid=258\"")),
        ("N-subvol-in-list", entry("\"subvol=@vault,compress=zstd\"")),
        ("N-subvol-interp", entry("\"subvol=@v${\"\"}ault\"")),
        ("N-subvol-concat-list", entry("\"compress=zstd\" ] ++ [ \"subvol=@vault\"")),
        ("N-subvol-map", entry("(map (s: \"subvol=\" + s) [ \"@vault\" ])")),
        ("N-indented", entry("''subvol=@vault''")),
        ("N-xmount-subdir", entry("\"X-mount.subdir=@vault\"")),
        ("N-multiline-subvol", multiline("\"subvol=@vault\"")),
        ("E-escape-subvol", entry("\"subvol=@v\\ault\"")),
        ("E-escape-subvol-slash", entry("\"subvol=/@v\\ault\"")),
        ("E-escape-subvol-at", entry("\"subvol=\\@vault\"")),
        ("E-escape-subvolid", entry("\"subvolid=2\\58\"")),
        ("E-escape-subvolid-hex", entry("\"subvolid=0x1\\02\"")),
        ("E-escape-xmount", entry("\"X-mount.subdir=@v\\ault\"")),
        ("E-escape-multiline", multiline("\"subvol=@v\\ault\"")),
        ("E-indented-escape", entry("''subvol=@v''\\ault''")),
        ("E-concat-subvol", entry("(\"subvol=@va\" + \"ult\")")),
        ("E-concat-subvolid", entry("(\"subvolid=25\" + \"8\")")),
        ("E-concatsep", entry("(lib.concatStrings [ \"subvol=@va\" \"ult\" ])")),
        (
            "E-home-escape",
            format!(
                "  fileSystems.\"/home\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvol=@v\\ault\" ]; }};"
            ),
        ),
        (
            "E-var-escape",
            format!(
                "  fileSystems.\"/var/lib/x\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvol=@v\\ault\" ]; }};"
            ),
        ),
        (
            "T-top-var-literal-bind",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/data\" = {{ device = \"/var/lib/pool/@vault\"; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "T-top-var-concat-bind",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/data\" = {{ device = \"/var/lib/pool/@va\" + \"ult\"; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "T-top-var-escape-bind",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/data\" = {{ device = \"/var/lib/pool/@v\\ault\"; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "T-top-var-alone",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};"
            ),
        ),
        (
            "T-top-var-btrbk-wildcard",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  services.btrbk.instances.d.settings.volume.\"/var/lib/pool\".subvolume = \"*\";"
            ),
        ),
        (
            "T-inherit-device-top",
            "  fileSystems.\"/btr_pool\" = { inherit (config.fileSystems.\"/\") device fsType; options = [ \"subvolid=5\" ]; };".to_string(),
        ),
        (
            "B-device-interp",
            "  fileSystems.\"/srv\".device = \"/dev/disk/by-uuid/${uuid}\";".to_string(),
        ),
        (
            "B-device-concat-srv",
            "  fileSystems.\"/srv\" = { device = \"/var/lib/pool/@va\" + \"ult\"; options = [ \"bind\" ]; };".to_string(),
        ),
        ("B-xmount-concat", entry("(\"X-mount.subdir=@va\" + \"ult\")")),
        ("B-subvolid-plus-number", entry("(\"subvolid=2\" + toString 58)")),
        ("M-unit", "  systemd.services.x.after = [ \"mnt-vault.mount\" ];".to_string()),
        ("M-dot", "  x = \"/mnt/./vault\";".to_string()),
        ("M-dslash", "  x = \"/mnt//vault/y\";".to_string()),
    ]
}

/// Part 2 of [`btrfs_forms`].
fn btrfs_forms_2() -> Vec<(&'static str, String)> {
    let dev = device();
    vec![
        (
            "M-own-place-mountpoint",
            format!("  fileSystems.\"/mnt/vault\".device = \"{dev}\";"),
        ),
        (
            "C-comment-in-entry",
            format!(
                "  fileSystems.\"/srv\" = {{ device = \"{dev}\"; # was /dev/vda2\n    fsType = \"btrfs\"; options = [ \"subvol=@srv\" ]; }};"
            ),
        ),
        (
            "C-trailing-comment-plain",
            format!(
                "  fileSystems.\"/srv\" = {{ device = \"{dev}\"; # the disk\n    fsType = \"btrfs\"; options = [ \"subvol=@srv\" ]; }};"
            ),
        ),
        (
            "U-uppercase-filesystems",
            format!("  filesystems.\"/srv\".device = \"{dev}\";"),
        ),
        (
            "L-label-swap",
            "  swapDevices = [ { label = \"nixos\"; } ];".to_string(),
        ),
        (
            "L-label-own",
            "  fileSystems.\"/srv\".label = \"nixos\";".to_string(),
        ),
        (
            "P-interp-in-device",
            format!("  fileSystems.\"/srv\".device = \"{dev}${{\"/../@vault\"}}\";"),
        ),
        (
            "P-dotdot-system",
            format!("  fileSystems.\"/var/../mnt/x\".device = \"{dev}\";"),
        ),
        (
            "P-trailing-slash-system",
            format!("  fileSystems.\"/home/\".device = \"{dev}\";"),
        ),
        (
            "P-double-slash-system",
            format!("  fileSystems.\"//home\".device = \"{dev}\";"),
        ),
        (
            "P-mkforce",
            format!("  fileSystems.\"/home\".device = lib.mkForce \"{dev}\";"),
        ),
        (
            "P-let-binding",
            format!("  fileSystems.\"/home\".device = let d = \"{dev}\"; in d;"),
        ),
        (
            "P-list-form",
            format!("  fileSystems = [ {{ mountPoint = \"/home\"; device = \"{dev}\"; }} ];"),
        ),
        ("P-resume", format!("  boot.resumeDevice = \"{dev}\";")),
        (
            "P-kernel-param",
            format!("  boot.kernelParams = [ \"resume={dev}\" ];"),
        ),
        (
            "P-luks-entry-other-attr",
            format!("  boot.initrd.luks.devices.x.header = \"{dev}\";"),
        ),
        (
            "P-luks-device-own",
            format!("  boot.initrd.luks.devices.x.device = \"{dev}\";"),
        ),
        (
            "P-luks-keyfile",
            format!("  boot.initrd.luks.devices.x.keyFile = \"{dev}\";"),
        ),
        (
            "P-filesystems-depends",
            format!("  fileSystems.\"/srv\".depends = [ \"{dev}\" ];"),
        ),
        (
            "P-encrypted-blkdev",
            format!("  fileSystems.\"/srv\".encrypted.blkDev = \"{dev}\";"),
        ),
        (
            "P-device-and-other",
            format!(
                "  fileSystems.\"/srv\".device = \"{dev}\"; boot.resumeDevice = \"/dev/vda2\";"
            ),
        ),
        (
            "P-two-entries-one-line",
            format!(
                "  fileSystems.\"/srv\".device = \"{dev}\"; fileSystems.\"/data\".device = \"{dev}\";"
            ),
        ),
        (
            "P-string-continues-next-line",
            format!("  fileSystems.\"/srv\".device = \"{dev}\n\";"),
        ),
        (
            "P-indented-device",
            format!("  fileSystems.\"/srv\".device = ''{dev}'';"),
        ),
        (
            "P-indented-multiline-device",
            format!("  fileSystems.\"/srv\".device = ''\n    {dev}\n  '';"),
        ),
        (
            "P-nested-attrs",
            format!("  fileSystems = {{ \"/srv\" = {{ device = \"{dev}\"; }}; }};"),
        ),
        (
            "P-rec-attrs",
            format!("  fileSystems = rec {{ \"/srv\" = {{ device = \"{dev}\"; }}; }};"),
        ),
        (
            "P-with-lib",
            format!(
                "  fileSystems = with lib; {{ \"/srv\" = {{ device = mkForce \"{dev}\"; }}; }};"
            ),
        ),
        (
            "P-mkmerge",
            format!("  fileSystems = lib.mkMerge [ {{ \"/srv\".device = \"{dev}\"; }} ];"),
        ),
        (
            "P-mkif",
            format!("  fileSystems = lib.mkIf true {{ \"/srv\".device = \"{dev}\"; }};"),
        ),
        (
            "P-config-prefix",
            format!("  config.fileSystems.\"/srv\".device = \"{dev}\";"),
        ),
        (
            "P-mkif-nested-other",
            format!("  services.x = lib.mkIf true {{ fileSystems.\"/srv\".device = \"{dev}\"; }};"),
        ),
        (
            "P-attr-interp",
            format!("  fileSystems.\"${{\"/srv\"}}\".device = \"{dev}\";"),
        ),
        ("X-paren-subvol", entry("((\"subvol=@va\") + \"ult\")")),
        ("X-paren-subvolid", entry("((\"subvolid=25\") + \"8\")")),
        (
            "X-paren-xmount",
            entry("((\"X-mount.subdir=@va\") + \"ult\")"),
        ),
        (
            "X-ifthen-subvol",
            entry("((if true then \"subvol=@va\" else \"x\") + \"ult\")"),
        ),
        ("X-plus-newline", entry("(\"subvol=@va\"\n      + \"ult\")")),
        (
            "X-plus-comment-line",
            entry("(\"subvol=@va\" # part\n      + \"ult\")"),
        ),
        (
            "X-plus-block-comment",
            entry("(\"subvol=@va\" /* part */ + \"ult\")"),
        ),
        ("X-plus-nospace", entry("(\"subvol=@va\"+\"ult\")")),
        ("X-plus-var", entry("(\"subvol=@va\" + rest)")),
        ("X-plus-escape-first", entry("(\"subvol=@v\\a\" + \"ult\")")),
    ]
}

/// Part 3 of [`btrfs_forms`].
fn btrfs_forms_3() -> Vec<(&'static str, String)> {
    let dev = device();
    vec![
        ("X-escape-key", entry("(\"sub\\vol=@va\" + \"ult\")")),
        ("X-escape-eq", entry("\"subvol\\=@vault\"")),
        ("X-escape-slash", entry("\"subvol=\\/@vault\"")),
        ("X-escape-subvolid-octal", entry("\"subvolid=04\\02\"")),
        ("X-escape-subvolid-key", entry("\"subvol\\id=258\"")),
        ("X-escape-xmount-key", entry("\"X-mount.sub\\dir=@vault\"")),
        ("X-indented-dollar-escape", entry("''subvol=@va''${\"ult\"}''")),
        ("X-indented-plus", entry("(''subvol=@va'' + ''ult'')")),
        ("X-interp-inner-plus", entry("\"${\"subvol=@va\" + \"ult\"}\"")),
        ("X-comment-escape", "  # options = [ \"subvol=@v\\ault\" ];".to_string()),
        ("X-comment-plus", "  # options = [ (\"subvol=@va\" + \"ult\") ];".to_string()),
        ("X-prose-escape", "  # the old @v\\ault subvolume".to_string()),
        (
            "X-btrbk-attr-escape",
            "  services.btrbk.instances.x.settings.volume.\"/btr_pool\".subvolume.\"@v\\ault\" = { };".to_string(),
        ),
        (
            "X-btrbk-attr-interp-plus",
            "  services.btrbk.instances.x.settings.volume.\"/btr_pool\".subvolume.${\"@va\" + \"ult\"} = { };".to_string(),
        ),
        ("X-substring", entry("(builtins.substring 0 13 \"subvol=@vaultx\")")),
        ("X-replace", entry("(builtins.replaceStrings [ \"X\" ] [ \"a\" ] \"subvol=@vXult\")")),
        ("X-fskey-escape-srv", format!("  fileSystems.\"/s\\rv\".device = \"{dev}\";")),
        ("X-fskey-escape-home", format!("  fileSystems.\"/h\\ome\".device = \"{dev}\";")),
        ("X-fskey-escape-root", format!("  fileSystems.\"/mnt/v\\ault\".device = \"{dev}\";")),
        ("X-own-device-escape", format!("  fileSystems.\"/srv\".device = \"{}\";", dev.replacen("4b1c", "4b1\\c", 1))),
        ("X-resume-escape", format!("  boot.resumeDevice = \"{}\";", dev.replacen("4b1c", "4b1\\c", 1))),
        ("X-own-label-paren", "  fileSystems.\"/srv\".label = (\"nix\") + \"os\";".to_string()),
        ("X-own-label-paren-var", "  fileSystems.\"/srv\".label = (\"nix\") + os;".to_string()),
        (
            "X-paren-device-top-str",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/srv\" = {{ device = (\"/var/lib/pool/@va\") + \"ult\"; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "X-paren-device-top-var",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/srv\" = {{ device = (\"/var/lib/pool/@va\") + rest; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "X-concat-device-top-own",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/srv\" = {{ device = lib.concatStrings [ \"/var/lib/pool/@va\" \"ult\" ]; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "X-paren-after-own",
            format!(
                "  fileSystems.\"/var/lib/pool\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; options = [ \"subvolid=5\" ]; }};\n  fileSystems.\"/srv\" = {{ device = rest + (\"ult\"); options = [ \"bind\" ]; }};"
            ),
        ),
        ("X-paren-subvol-after", entry("(rest + (\"ult\"))")),
        (
            "X-device-from-other-own",
            "  fileSystems.\"/srv\" = { device = config.fileSystems.\"/\".device; fsType = \"btrfs\"; options = [ \"subvol=@srv\" ]; };".to_string(),
        ),
        (
            "X-let-own-path",
            format!("  x = let fileSystems.\"/srv\".device = \"{dev}\"; in 1;"),
        ),
        (
            "R3-luks-keyfile-join",
            format!("  boot.initrd.luks.devices.x = {{ device = \"{dev}\"; keyFile = \"/var/lib/pool/@va\" + \"ult\"; }};"),
        ),
        (
            "R3-luks-device-join",
            format!("  boot.initrd.luks.devices.x.device = \"{dev}\" + \"x\";"),
        ),
        ("R3-comment-entry", format!("  # fileSystems.\"/srv\".device = \"{dev}\";")),
        (
            "R3-mkforce-set",
            format!("  fileSystems = lib.mkForce {{ \"/srv\".device = \"{dev}\"; }};"),
        ),
        (
            "R3-true-in-options",
            format!("  fileSystems.\"/srv\" = {{ device = \"{dev}\"; options = [ true ]; }};"),
        ),
        (
            "R3-plain-needed-for-boot",
            format!("  fileSystems.\"/srv\" = {{ device = \"{dev}\"; fsType = \"btrfs\"; neededForBoot = true; options = [ \"subvol=@srv\" ]; }};"),
        ),
        (
            "R3-plain-comment-in-list",
            format!("  fileSystems.\"/srv\" = {{ device = \"{dev}\"; options = [\n    \"subvol=@srv\" # (srv)\n  ]; }};"),
        ),
        (
            "R3-with-entry",
            format!("  fileSystems.\"/srv\" = with lib; {{ device = \"{dev}\"; }};"),
        ),
        (
            "R3-let-block-set",
            format!("  x = let y = {{ fileSystems.\"/srv\".device = \"{dev}\"; }}; in y;"),
        ),
        (
            "R3-call-around-entry",
            format!("  services.x = f {{ fileSystems.\"/srv\".device = \"{dev}\"; }};"),
        ),
        (
            "R3-indented-device",
            format!("  fileSystems.\"/srv\".device = ''{dev}'';"),
        ),

    ]
}

/// The same for the ext4 install, each as lines of one set.
fn ext4_forms() -> Vec<(&'static str, String)> {
    let dev = format!("/dev/disk/by-uuid/{ROOT_UUID}");
    vec![
        ("baseline", String::new()),
        ("F-folder", "  x = \"/home/alice/vault\";".to_string()),
        ("F-folder-escape", "  x = \"/home/alice/va\\ult\";".to_string()),
        (
            "F-bind-system-escape",
            "  fileSystems.\"/srv\" = { device = \"/home/alice/va\\ult\"; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "F-top-var-concat-bind",
            format!(
                "  fileSystems.\"/var/lib/rootfs\" = {{ device = \"{dev}\"; fsType = \"ext4\"; }};\n  fileSystems.\"/data\" = {{ device = \"/var/lib/rootfs/home/alice/va\" + \"ult\"; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "F-top-var-literal-bind",
            format!(
                "  fileSystems.\"/var/lib/rootfs\" = {{ device = \"{dev}\"; fsType = \"ext4\"; }};\n  fileSystems.\"/data\" = {{ device = \"/var/lib/rootfs/home/alice/vault\"; options = [ \"bind\" ]; }};"
            ),
        ),
        (
            "F-top-var-alone",
            format!("  fileSystems.\"/var/lib/rootfs\" = {{ device = \"{dev}\"; fsType = \"ext4\"; }};"),
        ),
        (
            "F-srv-own",
            format!("  fileSystems.\"/srv\" = {{ device = \"{dev}\"; fsType = \"ext4\"; }};"),
        ),

        (
            "XF-paren-device-own-str",
            "  fileSystems.\"/srv\" = { device = (\"/home/alice/va\") + \"ult\"; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-paren-device-own-var",
            "  fileSystems.\"/srv\" = { device = (\"/home/alice/va\") + rest; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-pathlit-interp-own",
            "  fileSystems.\"/srv\" = { device = toString /home/alice/va${\"ult\"}; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-concat-own",
            "  fileSystems.\"/srv\" = { device = lib.concatStrings [ \"/home/alice/va\" \"ult\" ]; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-escape-own",
            "  fileSystems.\"/srv\" = { device = \"/home/alice/va\\ult\"; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-indented-escape-own",
            "  fileSystems.\"/srv\" = { device = ''/home/alice/va''\\ult''; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-plus-own",
            "  fileSystems.\"/srv\" = { device = \"/home/alice/va\" + \"ult\"; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-dotdot",
            "  fileSystems.\"/data\" = { device = \"/home/alice/../alice/vault\"; options = [ \"bind\" ]; };".to_string(),
        ),
        (
            "XF-escape-slash",
            "  x = \"/home/alice\\/vault\";".to_string(),
        ),
        (
            "XF-mountpoint-escape",
            "  x = \"/mnt/v\\ault\";".to_string(),
        ),
        (
            "XF-mountunit-escape",
            "  x = \"mnt-v\\ault.mount\";".to_string(),
        ),
    ]
}
