// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What an offline scan cannot read because it is not mounted under the
//! root: the mount points of the decoy's fstab and the homes of its login
//! accounts that hold nothing there.

use super::deep_scan::is_login_shell;
use super::*;
use nails_base::fstab::parse_fstab;

/// The decoy's table of the filesystems it mounts, read under the root.
const FSTAB_FILE: &str = "/etc/fstab";

impl<F: Filesystem> Verifier<F> {
    /// The places of the decoy system an offline scan cannot read, because
    /// what the decoy mounts there is not mounted under the root: each mount
    /// point of the decoy's `/etc/fstab` that is missing or empty there, and
    /// each home of a login account of its `/etc/passwd` that is, outside
    /// those mount points. A btrfs decoy scanned by its system subvolume alone
    /// misses its `@home` this way, and on archinstall its `@log`.
    ///
    /// Read as the root itself is ([`Self::refuse_a_root_with_nothing_to_scan`]):
    /// the two files with `O_NOATIME`, each place with `lstat` and `stat`, and
    /// a folder with an `O_NOATIME` listing. No link is followed, so a fstab
    /// that is a link, as NixOS's is, is not read, and a place that cannot be
    /// looked at is left out.
    pub(super) fn unmounted_areas(&self) -> Vec<String> {
        let mut mount_points = self.fstab_mount_points();
        mount_points.sort();
        mount_points.dedup();
        let mut unmounted: Vec<PathBuf> = Vec::new();
        let mut areas = Vec::new();
        for point in mount_points {
            if !unmounted.iter().any(|seen| point.starts_with(seen)) && self.holds_nothing(&point) {
                areas.push(format!(
                    "{}, which the decoy's /etc/fstab mounts (missing or empty under the root: \
                     mount it there before the scan)",
                    point.display()
                ));
                unmounted.push(point);
            }
        }
        for (user, home) in self.login_homes() {
            if !unmounted.iter().any(|seen| home.starts_with(seen)) && self.holds_nothing(&home) {
                areas.push(format!(
                    "{}, the home of {user} in the decoy's /etc/passwd (missing or empty under \
                     the root: mount what holds it there before the scan)",
                    home.display()
                ));
            }
        }
        areas
    }

    /// The mount points of the filesystems the decoy's fstab mounts from a
    /// disk: neither `/` itself, swap, a filesystem in RAM or the kernel, a
    /// host share nor a network filesystem.
    fn fstab_mount_points(&self) -> Vec<PathBuf> {
        let Some(text) = self.read_unlinked(Path::new(FSTAB_FILE)) else {
            return Vec::new();
        };
        parse_fstab(&text)
            .into_iter()
            .filter(|entry| {
                entry.file.is_absolute()
                    && entry.file != Path::new("/")
                    && !entry.is_swap()
                    && !entry.is_virtual()
                    && !entry.is_host_share()
                    && !entry.is_network()
            })
            .map(|entry| entry.file)
            .collect()
    }

    /// The login accounts of the decoy's `/etc/passwd` (from
    /// [`FIRST_LOGIN_UID`] on, with a login shell) and their homes.
    fn login_homes(&self) -> Vec<(String, PathBuf)> {
        let Some(text) = self.read_unlinked(Path::new(PASSWD_FILE)) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                let [user, _, uid, _, _, home, shell] = fields[..] else {
                    return None;
                };
                let login = uid.parse::<u32>().is_ok_and(|uid| uid >= FIRST_LOGIN_UID)
                    && is_login_shell(shell)
                    && home.starts_with('/');
                login.then(|| (user.to_string(), PathBuf::from(home)))
            })
            .collect()
    }

    /// The text of the decoy's file at `path`, read under the root unless it
    /// is a link, which could lead out of the image.
    fn read_unlinked(&self, path: &Path) -> Option<String> {
        let file = self.rebase(path);
        if !matches!(self.filesystem.is_symlink(&file), Ok(false)) {
            return None;
        }
        self.filesystem.read_file_content(&file).ok()
    }

    /// Whether the decoy's place `path` is missing under the root or an empty
    /// folder there. A link is not followed, and answers no.
    fn holds_nothing(&self, path: &Path) -> bool {
        let place = self.rebase(path);
        if !matches!(self.filesystem.is_symlink(&place), Ok(false)) {
            return false;
        }
        match self.filesystem.inode(&place) {
            Ok(None) => true,
            Ok(Some(_)) => {
                matches!(self.filesystem.is_directory(&place), Ok(true))
                    && self
                        .filesystem
                        .list_directory(&place)
                        .is_ok_and(|entries| entries.is_empty())
            }
            Err(_) => false,
        }
    }
}
