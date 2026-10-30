// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! How pacman names the packages of its local database, written from
//! libalpm's `_alpm_splitname()` (lib/libalpm/util.c, pacman 6.0.2, as it
//! still is): `local_db_populate()` hands it each entry of
//! `/var/lib/pacman/local` and leaves out an entry it cannot split.

/// `_alpm_splitname()` of the C string `target`: the name and the version,
/// or `None` where it returns -1. The string ends at its first NUL, as
/// `strlen()` has it. The two loops walk back from the end while `*pkgver`
/// is neither a NUL nor a hyphen; where the C code would walk off the start
/// of the string (no hyphen left, which a name a directory listing gives
/// never reaches past its own start), the model stops and refuses.
pub fn splitname(target: &[u8]) -> Option<(&[u8], &[u8])> {
    let target = &target[..target
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(target.len())];

    // Remove anything trailing a '/'.
    let end = target
        .iter()
        .position(|&byte| byte == b'/')
        .unwrap_or(target.len());

    // Find the beginning of the version string by doing two iterations of
    // the same loop to lop off two hyphens.
    let back = |mut pkgver: usize| -> Option<usize> {
        while target[pkgver] != b'-' {
            pkgver = pkgver.checked_sub(1)?;
        }
        Some(pkgver)
    };
    let pkgver = back(end.checked_sub(1)?)?;
    let pkgver = back(pkgver.checked_sub(1)?)?;
    if pkgver == 0 {
        return None;
    }
    Some((&target[..pkgver], &target[pkgver + 1..end]))
}
