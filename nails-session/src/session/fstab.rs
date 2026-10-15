// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/fstab` as the hidden systemd will read it, and systemd's unit names.
//!
//! The hidden root runs the decoy's own fstab (or, on NixOS, the hidden
//! toplevel's). `systemd-fstab-generator` turns every entry into a `.mount` or
//! `.swap` unit, so the session policy ([`super::policy`]) needs the same view
//! of it, plus the unit names it would generate, to overlay, bind or mask each
//! entry before the switch. The parser is [`nails_base::fstab`], re-exported
//! here; the unit names are the session's own.

use std::path::{Path, PathBuf};

pub use nails_base::fstab::{FstabEntry, escape_path, parse_fstab, spec_device};

/// The `.mount` unit for a mount point.
pub fn mount_unit(path: &Path) -> String {
    format!("{}.mount", escape_path(path))
}

/// The `.automount` unit for a mount point.
pub fn automount_unit(path: &Path) -> String {
    format!("{}.automount", escape_path(path))
}

/// The `.swap` unit for a swap spec, when it names a device or file.
pub fn swap_unit(spec: &str) -> Option<String> {
    let path = spec_device(spec).or_else(|| spec.starts_with('/').then(|| PathBuf::from(spec)))?;
    Some(format!("{}.swap", escape_path(&path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_named_the_way_systemd_names_them() {
        assert_eq!(mount_unit(Path::new("/")), "-.mount");
        assert_eq!(mount_unit(Path::new("/boot/efi")), "boot-efi.mount");
        assert_eq!(mount_unit(Path::new("/home/")), "home.mount");
        assert_eq!(
            mount_unit(Path::new("/mnt/my-disk")),
            "mnt-my\\x2ddisk.mount"
        );
        assert_eq!(
            mount_unit(Path::new("/mnt/My Disk")),
            "mnt-My\\x20Disk.mount"
        );
        assert_eq!(mount_unit(Path::new("/.snapshots")), "\\x2esnapshots.mount");
        assert_eq!(automount_unit(Path::new("/srv/x")), "srv-x.automount");
        assert_eq!(swap_unit("/dev/vda3").as_deref(), Some("dev-vda3.swap"));
        assert_eq!(
            swap_unit("UUID=0a-1b").as_deref(),
            Some("dev-disk-by\\x2duuid-0a\\x2d1b.swap")
        );
        assert_eq!(swap_unit("/swapfile").as_deref(), Some("swapfile.swap"));
        assert_eq!(swap_unit("none"), None);
    }
}
