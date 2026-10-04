// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount-table guard for shell integration writes.
//!
//! Before writing a shell rc block or an XDG autostart entry into a user's home
//! directory, the shell integration confirms that the home actually sits on a
//! NAILS overlay. If the home is on the decoy disk (for example when `/home` is
//! excluded or omitted in explicit overlay mode) the integration files would
//! persist on the real filesystem, so the writes are skipped instead.
//!
//! This parser is deliberately small and self-contained: it reads a single
//! `/proc/self/mountinfo` snapshot passed in by the caller and answers one
//! question without touching the filesystem (no `canonicalize`, no blocking on
//! dead mounts).

use std::path::Path;

/// Return `true` when `target` is covered by an `overlay` mount whose
/// `upperdir` lives under `hidden_root`.
///
/// The covering mount is the one whose mount point is the longest path-prefix of
/// `target`; later `mountinfo` lines win ties because a later mount shadows an
/// earlier one at the same point.
pub fn path_on_hidden_overlay(mountinfo: &str, target: &Path, hidden_root: &Path) -> bool {
    // (components in the matching mount point, whether it is a hidden overlay)
    let mut best: Option<(usize, bool)> = None;

    for line in mountinfo.lines() {
        // Optional fields between the mount point and the fs type are terminated
        // by a standalone " - " separator.
        let Some(sep) = line.find(" - ") else {
            continue;
        };
        let (pre, post) = line.split_at(sep);

        let pre_fields: Vec<&str> = pre.split_whitespace().collect();
        // Field index 4 is the mount point (man 5 proc, mountinfo).
        if pre_fields.len() < 5 {
            continue;
        }
        let mount_point_raw = octal_unescape(pre_fields[4]);
        let mount_point = Path::new(&mount_point_raw);

        if !target.starts_with(mount_point) {
            continue;
        }

        // Skip the leading " - " (3 bytes) then read fs type and super options.
        let post_fields: Vec<&str> = post[3..].split_whitespace().collect();
        let fs_type = post_fields.first().copied().unwrap_or("");
        let super_options = post_fields.get(2).copied().unwrap_or("");

        let is_hidden_overlay = fs_type == "overlay" && upperdir_under(super_options, hidden_root);

        let len = mount_point.components().count();
        match best {
            Some((best_len, _)) if len < best_len => {}
            _ => best = Some((len, is_hidden_overlay)),
        }
    }

    best.map(|(_, hidden)| hidden).unwrap_or(false)
}

/// Return `true` when the overlay super options carry an `upperdir=` whose path
/// is under `hidden_root`.
fn upperdir_under(super_options: &str, hidden_root: &Path) -> bool {
    for opt in super_options.split(',') {
        if let Some(value) = opt.strip_prefix("upperdir=") {
            let upper = octal_unescape(value);
            return Path::new(&upper).starts_with(hidden_root);
        }
    }
    false
}

/// Decode the kernel's octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash) that appear in `mountinfo` paths and option values.
fn octal_unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 4 <= bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| b.is_ascii_digit() && *b <= b'7')
        {
            let code = (u16::from(bytes[i + 1] - b'0') << 6)
                | (u16::from(bytes[i + 2] - b'0') << 3)
                | u16::from(bytes[i + 3] - b'0');
            out.push(code as u8);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const HIDDEN: &str = "/mnt/hidden-volume";

    fn home_overlay_line(upperdir: &str) -> String {
        format!(
            "40 1 0:40 / /home rw,relatime shared:1 - overlay overlay \
             rw,lowerdir=/home,upperdir={upperdir},workdir=/mnt/hidden-volume/.work/home"
        )
    }

    #[test]
    fn overlay_with_upperdir_under_hidden_root_matches() {
        let mi = home_overlay_line("/mnt/hidden-volume/home");
        assert!(path_on_hidden_overlay(
            &mi,
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }

    #[test]
    fn overlay_with_upperdir_elsewhere_does_not_match() {
        let mi = home_overlay_line("/var/tmp/other/home");
        assert!(!path_on_hidden_overlay(
            &mi,
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }

    #[test]
    fn non_overlay_filesystem_does_not_match() {
        let mi = "40 1 8:2 / /home rw,relatime - ext4 /dev/sda2 rw";
        assert!(!path_on_hidden_overlay(
            mi,
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }

    #[test]
    fn longest_prefix_wins_over_root_mount() {
        // Root is a plain ext4 mount; /home is the hidden overlay. The longer
        // mount point must be selected even though it appears after root.
        let mi = format!(
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n{}",
            home_overlay_line("/mnt/hidden-volume/home")
        );
        assert!(path_on_hidden_overlay(
            &mi,
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }

    #[test]
    fn later_line_shadows_earlier_at_same_point() {
        // An earlier hidden overlay at /home is shadowed by a later plain mount
        // at the same point; the guard must report the live (last) one.
        let mi = format!(
            "{}\n50 1 8:3 / /home rw,relatime - ext4 /dev/sdb1 rw",
            home_overlay_line("/mnt/hidden-volume/home")
        );
        assert!(!path_on_hidden_overlay(
            &mi,
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }

    #[test]
    fn octal_escaped_space_in_mount_point_and_upperdir_is_decoded() {
        let hidden = "/mnt/hidden volume";
        let mi = "40 1 0:40 / /home rw,relatime - overlay overlay \
                  rw,lowerdir=/home,upperdir=/mnt/hidden\\040volume/home,workdir=/w"
            .replace("/home rw", "/ho\\040me rw"); // mount point with a space
        // target lives under the space-containing mount point and the upperdir is
        // under the space-containing hidden root.
        assert!(path_on_hidden_overlay(
            &mi,
            Path::new("/ho me/testuser"),
            Path::new(hidden)
        ));
    }

    #[test]
    fn no_covering_mount_returns_false() {
        let mi = "40 1 0:40 / /srv rw,relatime - overlay overlay \
                  rw,lowerdir=/srv,upperdir=/mnt/hidden-volume/srv,workdir=/w";
        assert!(!path_on_hidden_overlay(
            mi,
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }

    #[test]
    fn empty_or_malformed_mountinfo_returns_false() {
        assert!(!path_on_hidden_overlay(
            "",
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
        assert!(!path_on_hidden_overlay(
            "garbage line without separator",
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
        // Separator present but too few pre-fields.
        assert!(!path_on_hidden_overlay(
            "1 2 - overlay overlay rw,upperdir=/mnt/hidden-volume/home",
            Path::new("/home/testuser"),
            Path::new(HIDDEN)
        ));
    }
}
