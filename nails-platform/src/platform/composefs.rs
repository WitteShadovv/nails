// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Refuse composefs-native hosts, even without `/run/ostree-booted`.
//!
//! A conventional ostree boot writes `/run/ostree-booted`, which detection
//! already refuses. A sealed composefs image (bootc, and Fedora Atomic on some
//! boot paths) need not, so this looks for the other marks of a read-only
//! composefs root: the composefs runtime directory, and the kernel command line
//! that put the image at the root. Such a host is refused before detection looks
//! at the family, because NAILS cannot overlay an immutable system.

use std::path::Path;

use crate::filesystem::Filesystem;

/// The kernel command line of the running host.
const CMDLINE: &str = "/proc/cmdline";
/// The composefs runtime directory, present on a composefs-native boot.
const COMPOSEFS_RUN: &str = "/run/composefs";

/// `Some(reason)` when the host boots from a sealed composefs / ostree image,
/// `None` otherwise. Every read is tolerant of absence.
pub(crate) fn composefs_refusal<F: Filesystem>(fs: &F) -> Option<String> {
    let marked = fs.path_exists(Path::new(COMPOSEFS_RUN)).unwrap_or(false)
        || fs
            .read_file_content(Path::new(CMDLINE))
            .ok()
            .is_some_and(|cmdline| cmdline_marks_composefs(&cmdline));
    marked.then(reason)
}

/// Whether the kernel command line puts a composefs or ostree image at the root.
///
/// Matches an `ostree=`, `composefs=` or `composefs.digest=` argument, and a
/// `root=composefs:…` or `root=transient:composefs=…` root source.
fn cmdline_marks_composefs(cmdline: &str) -> bool {
    cmdline.split_whitespace().any(|token| {
        let (key, value) = token.split_once('=').unwrap_or((token, ""));
        match key {
            "ostree" | "composefs" | "composefs.digest" => true,
            "root" => value.starts_with("composefs:") || value.starts_with("transient:composefs="),
            _ => false,
        }
    })
}

/// The documented refusal for a composefs-native host.
fn reason() -> String {
    "this host boots from a sealed composefs image (an ostree or composefs \
     root); NAILS cannot overlay an immutable system. Use a conventional \
     mutable installation."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::{MockFilesystem, PathKind};

    #[test]
    fn a_plain_host_is_not_marked() {
        assert_eq!(composefs_refusal(&MockFilesystem::new()), None);
        let fs = MockFilesystem::new();
        fs.mock_set_file_content(
            CMDLINE,
            "BOOT_IMAGE=/vmlinuz root=/dev/sda2 ro quiet splash\n",
        );
        assert_eq!(composefs_refusal(&fs), None);
    }

    #[test]
    fn the_composefs_runtime_directory_refuses() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type(COMPOSEFS_RUN, PathKind::Dir);
        assert!(composefs_refusal(&fs).is_some());
    }

    #[test]
    fn a_composefs_or_ostree_cmdline_refuses() {
        for cmdline in [
            "root=/dev/vda3 ostree=/ostree/boot.1/fedora/abc/0 rw",
            "composefs=f00dcafe root=/dev/mapper/root",
            "composefs.digest=abcd1234 rw quiet",
            "root=composefs:fedora/x86_64 rw",
            "root=transient:composefs=fedora rw",
        ] {
            let fs = MockFilesystem::new();
            fs.mock_set_file_content(CMDLINE, cmdline);
            assert!(composefs_refusal(&fs).is_some(), "{cmdline}");
        }
    }

    #[test]
    fn a_bare_root_device_is_not_a_composefs_source() {
        // A normal `root=` by device or tag must not be mistaken for composefs.
        for cmdline in [
            "root=UUID=1234-5678 rw",
            "root=/dev/nvme0n1p2 rw",
            "root=LABEL=root rw",
        ] {
            let fs = MockFilesystem::new();
            fs.mock_set_file_content(CMDLINE, cmdline);
            assert_eq!(composefs_refusal(&fs), None, "{cmdline}");
        }
    }

    proptest::proptest! {
        /// The command-line scan is total: no bytes make it panic.
        #[test]
        fn cmdline_scan_never_panics(text in "\\PC{0,400}") {
            let _ = cmdline_marks_composefs(&text);
        }
    }
}
