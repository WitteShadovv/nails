// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The offline root itself: a root with nothing to scan is refused.

use super::*;
use crate::NailsError;
use nails_base::error::OfflineRootProblem;
use std::io::ErrorKind;

impl<F: Filesystem> Verifier<F> {
    /// Refuse an offline `root` that holds nothing to scan, before any check
    /// reads below it.
    ///
    /// Every check of an offline scan looks for a path under the root, so a
    /// root that does not exist, is not a folder or is empty finds nothing,
    /// and its clean verdict would be read as the image's. An empty folder is
    /// also what a mount point looks like when the image was never mounted on
    /// it. Whether a filesystem is mounted at the root is not asked: a copy of
    /// the decoy's files, or a subvolume of an image mounted from its top
    /// level, is scanned as a mounted image is.
    ///
    /// The root may be the decoy's own disk, so it is only looked up with
    /// `stat` and listed with `O_NOATIME` ([`Filesystem::list_directory`]),
    /// like every other read of an offline scan: nothing is written, and no
    /// access time moves wherever the kernel grants `O_NOATIME`, as it always
    /// does to root. A lookup or a listing that fails for any other reason
    /// than a missing path is an error, so the scan does not run then either.
    pub(super) fn refuse_a_root_with_nothing_to_scan(&self, root: &Path) -> Result<()> {
        let problem = match self.filesystem.inode(root) {
            Ok(None) => OfflineRootProblem::Missing,
            // A file on the way to the root: nothing can be at the path.
            Err(error) if error.io_kind() == Some(ErrorKind::NotADirectory) => {
                OfflineRootProblem::Missing
            }
            Err(error) => return Err(error),
            Ok(Some(_)) if !self.filesystem.is_directory(root)? => OfflineRootProblem::NotAFolder,
            Ok(Some(_)) if self.filesystem.list_directory(root)?.is_empty() => {
                OfflineRootProblem::Empty
            }
            Ok(Some(_)) => return Ok(()),
        };
        Err(NailsError::RefusedOfflineRoot {
            root: root.to_path_buf(),
            problem,
        })
    }
}
