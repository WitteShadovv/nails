// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the NAILS fuzz targets share: splitting one input into the files a
//! target stages, an in-memory disk image, and the reference models the
//! targets compare NAILS with. Each model follows the C or C++ source of the
//! program NAILS has to agree with, function by function, so a disagreement
//! points at NAILS or at a model line that can be checked against that
//! source.

pub mod display_managers;
pub mod gkeyfile;
pub mod image;
pub mod kconfig;
pub mod kernel;
pub mod libmount;
pub mod systemd;
pub mod systemd_conf;

/// `data` split at its first `n - 1` NUL bytes into at most `n` parts, each
/// decoded as UTF-8 with invalid sequences replaced. A target that reads
/// several files takes them from one input this way, so a seed can be a plain
/// text file and a mutation can still reach every part.
pub fn parts(data: &[u8], n: usize) -> Vec<String> {
    data.splitn(n, |&byte| byte == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}
