// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The GPT partition types that systemd acts on by their type alone.
//!
//! systemd-gpt-auto-generator runs at every boot and looks at the partitions
//! of the disk the root file system is on (systemd-gpt-auto-generator(8), the
//! UAPI.2 Discoverable Partitions Specification). By its GPT type it mounts
//! the first partition of the `/home`, `/srv`, `/var` and `/var/tmp` types at
//! that folder, when no fstab line mounts the folder and the folder is empty
//! (`/var` only when the partition's uuid is the one the machine ID gives
//! it), and asks for the passphrase first when such a partition is a LUKS
//! volume; it uses every partition of the swap type as swap; it mounts an
//! extended boot loader partition at `/boot` and the EFI system partition the
//! boot loader started from at `/boot` or `/efi` on first access; and in the
//! initrd, when the kernel command line names no root, it takes a root
//! partition of the machine's architecture from the disk of that EFI system
//! partition. The no-auto attribute flag ([`NO_AUTO`]) keeps it from using a
//! partition of any of these types but swap and the EFI system partition.

use serde::Serialize;

/// What systemd uses a partition of a type it discovers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutoRole {
    /// The root file system, of x86-64 or 64-bit ARM.
    Root,
    /// `/home`.
    Home,
    /// `/srv`.
    Srv,
    /// `/var`.
    Var,
    /// `/var/tmp`.
    VarTmp,
    /// Swap.
    Swap,
    /// The EFI system partition.
    Esp,
    /// The extended boot loader partition (XBOOTLDR).
    Xbootldr,
}

impl AutoRole {
    /// Whether the no-auto flag keeps systemd from using a partition of this
    /// type: it does for every type but swap and the EFI system partition.
    pub fn honours_no_auto(self) -> bool {
        !matches!(self, AutoRole::Swap | AutoRole::Esp)
    }

    /// The folder systemd mounts a partition of this type at; `None` for
    /// swap, and for the EFI system partition, which goes to `/boot` or to
    /// `/efi` by whether an extended boot loader partition takes `/boot`.
    pub fn mount_point(self) -> Option<&'static str> {
        match self {
            AutoRole::Root => Some("/"),
            AutoRole::Home => Some("/home"),
            AutoRole::Srv => Some("/srv"),
            AutoRole::Var => Some("/var"),
            AutoRole::VarTmp => Some("/var/tmp"),
            AutoRole::Xbootldr => Some("/boot"),
            AutoRole::Swap | AutoRole::Esp => None,
        }
    }

    /// The kind of partition the type makes, for a sentence: `a /srv
    /// partition`, `a swap partition`, `an EFI system partition`.
    pub fn describe(self) -> &'static str {
        match self {
            AutoRole::Root => "a root partition",
            AutoRole::Home => "a /home partition",
            AutoRole::Srv => "a /srv partition",
            AutoRole::Var => "a /var partition",
            AutoRole::VarTmp => "a /var/tmp partition",
            AutoRole::Swap => "a swap partition",
            AutoRole::Esp => "an EFI system partition",
            AutoRole::Xbootldr => "an extended boot loader partition",
        }
    }
}

/// The no-auto attribute flag of a GPT entry (bit 63).
pub const NO_AUTO: u64 = 1 << 63;

/// The generic type of a Linux filesystem, which systemd discovers nothing
/// by.
pub const LINUX_FILESYSTEM: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

/// The GPT types systemd discovers, in the text form
/// [`Partition::type_id`](super::Partition::type_id) holds, with the role of
/// each.
pub const AUTO_DISCOVERED_TYPES: &[(&str, AutoRole)] = &[
    ("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", AutoRole::Root),
    ("B921B045-1DF0-41C3-AF44-4C6F280D3FAE", AutoRole::Root),
    ("933AC7E1-2EB4-4F13-B844-0E14E2AEF915", AutoRole::Home),
    ("3B8F8425-20E0-4F3B-907F-1A25A76F98E8", AutoRole::Srv),
    ("4D21B016-B534-45C2-A9FB-5C16E091FD2D", AutoRole::Var),
    ("7EC6F557-3BC5-4ACA-B293-16EF5DF639D1", AutoRole::VarTmp),
    ("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", AutoRole::Swap),
    ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", AutoRole::Esp),
    ("BC13C2FF-59E6-4262-A352-B275FD6F7172", AutoRole::Xbootldr),
];

/// The role systemd gives a partition of the GPT type `type_id`, written in
/// either case (udev writes types in lower case); `None` for a type it does
/// not discover.
pub fn auto_discovery_role(type_id: &str) -> Option<AutoRole> {
    AUTO_DISCOVERED_TYPES
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(type_id.trim()))
        .map(|(_, role)| *role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_discovered_type_has_its_role_in_either_case() {
        for (type_id, role) in AUTO_DISCOVERED_TYPES {
            assert_eq!(auto_discovery_role(type_id), Some(*role), "{type_id}");
            assert_eq!(
                auto_discovery_role(&type_id.to_lowercase()),
                Some(*role),
                "{type_id}"
            );
        }
        assert_eq!(
            auto_discovery_role("3b8f8425-20e0-4f3b-907f-1a25a76f98e8\n"),
            Some(AutoRole::Srv)
        );
    }

    #[test]
    fn the_generic_type_and_other_types_have_no_role() {
        for type_id in [
            LINUX_FILESYSTEM,
            // Microsoft basic data, Linux LUKS, Linux LVM.
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
            "CA7D7CCB-63ED-4C53-861C-1742536059CC",
            "E6D6D379-F507-44C2-A23C-238F2A3DF928",
            "0x83",
            "",
        ] {
            assert_eq!(auto_discovery_role(type_id), None, "{type_id}");
        }
    }

    #[test]
    fn no_auto_holds_for_every_role_but_swap_and_the_efi_system_partition() {
        let honoured: Vec<AutoRole> = AUTO_DISCOVERED_TYPES
            .iter()
            .map(|(_, role)| *role)
            .filter(|role| role.honours_no_auto())
            .collect();
        assert_eq!(
            honoured,
            [
                AutoRole::Root,
                AutoRole::Root,
                AutoRole::Home,
                AutoRole::Srv,
                AutoRole::Var,
                AutoRole::VarTmp,
                AutoRole::Xbootldr,
            ]
        );
        assert_eq!(NO_AUTO, 0x8000_0000_0000_0000);
    }

    #[test]
    fn each_role_but_swap_and_the_efi_system_partition_has_one_folder() {
        for (role, point) in [
            (AutoRole::Root, Some("/")),
            (AutoRole::Home, Some("/home")),
            (AutoRole::Srv, Some("/srv")),
            (AutoRole::Var, Some("/var")),
            (AutoRole::VarTmp, Some("/var/tmp")),
            (AutoRole::Swap, None),
            (AutoRole::Esp, None),
            (AutoRole::Xbootldr, Some("/boot")),
        ] {
            assert_eq!(role.mount_point(), point, "{role:?}");
        }
    }

    #[test]
    fn each_role_names_its_kind_of_partition() {
        for (role, kind) in [
            (AutoRole::Root, "a root partition"),
            (AutoRole::Home, "a /home partition"),
            (AutoRole::Srv, "a /srv partition"),
            (AutoRole::Var, "a /var partition"),
            (AutoRole::VarTmp, "a /var/tmp partition"),
            (AutoRole::Swap, "a swap partition"),
            (AutoRole::Esp, "an EFI system partition"),
            (AutoRole::Xbootldr, "an extended boot loader partition"),
        ] {
            assert_eq!(role.describe(), kind, "{role:?}");
        }
    }
}
