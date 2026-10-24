// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's persona in the hidden root, put in place at entry.
//!
//! - **fresh-home**: the operator's home is an opaque directory in the upper
//!   that covers it (`trusted.overlay.opaque=y`), so none of the decoy home
//!   shows through. It is created once, at the first entry; after that it is
//!   the hidden home and is left as it is.
//! - **masks**: each inherited decoy autostart entry and user unit named in
//!   `[persona] mask_inherited` gets a `Hidden=true` override or a `/dev/null`
//!   mask, written through the next root's home before `/run` is bound in, so
//!   it lands in the upper and never on the decoy. Every path below the home
//!   is resolved inside the next root, as the hidden root will resolve it: an
//!   absolute symlink (a `/home` or `~/.config` linked elsewhere) never leads
//!   a mask onto the decoy disk. A name the inventory does not list is masked
//!   as well, judged by its suffix, so a directory the inventory does not read
//!   never drops a requested mask.

use crate::config::{PersonaConfig, PersonaMode};
use crate::error::{NailsError, Result};
use crate::filesystem::RealFilesystem;
use crate::persona::{MaskKind, PersonaSource, collect_inherited_persona};
use crate::target_user::TargetUser;
use nails_teardown::whole_root::nextroot;
use rustix::fs::{AtFlags, Mode, OFlags};
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The overlay xattr that hides the lower layers below a directory.
const OPAQUE_XATTR: &str = "trusted.overlay.opaque";

/// The `Hidden=true` override that masks an autostart entry of the same name.
const AUTOSTART_MASK: &str = "[Desktop Entry]\nType=Application\nHidden=true\n";

fn io(path: &Path, e: std::io::Error) -> NailsError {
    NailsError::io(path, e)
}

/// The directory in `upper` that becomes `home` in the merged view, created
/// opaque when it does not exist yet. Missing parents take the mode and owner
/// of the decoy's directories (`decoy` maps a path to the decoy's copy), since
/// an overlay directory takes its attributes from the upper. Returns whether
/// it was created.
pub fn prepare_fresh_home(
    upper_home: &Path,
    decoy_home: &Path,
    operator: &TargetUser,
) -> Result<bool> {
    if upper_home.symlink_metadata().is_ok() {
        return Ok(false);
    }
    if let Some(parent) = upper_home.parent() {
        create_parents_like(parent, decoy_home.parent())?;
    }
    std::fs::create_dir(upper_home).map_err(|e| io(upper_home, e))?;
    let mode = std::fs::metadata(decoy_home).map_or(0o700, |m| m.mode() & 0o7777);
    std::fs::set_permissions(upper_home, std::fs::Permissions::from_mode(mode))
        .map_err(|e| io(upper_home, e))?;
    std::os::unix::fs::chown(upper_home, Some(operator.uid), Some(operator.gid))
        .map_err(|e| io(upper_home, e))?;
    if let Err(e) = rustix::fs::setxattr(
        upper_home,
        OPAQUE_XATTR,
        b"y",
        rustix::fs::XattrFlags::empty(),
    ) {
        // A plain directory here would let the decoy home show through at
        // every later entry: never leave one behind.
        let _ = std::fs::remove_dir(upper_home);
        return Err(io(upper_home, e.into()));
    }
    Ok(true)
}

/// Create `dir` and its missing parents, each with the mode and owner of the
/// matching decoy directory when there is one.
fn create_parents_like(dir: &Path, like: Option<&Path>) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_parents_like(parent, like.and_then(Path::parent))?;
    }
    std::fs::create_dir(dir).map_err(|e| io(dir, e))?;
    if let Some(meta) = like.and_then(|l| std::fs::metadata(l).ok()) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(meta.mode() & 0o7777))
            .map_err(|e| io(dir, e))?;
        std::os::unix::fs::chown(dir, Some(meta.uid()), Some(meta.gid()))
            .map_err(|e| io(dir, e))?;
    }
    Ok(())
}

/// Reads the paths below the next root the way the hidden root will resolve
/// them, through [`nextroot`]'s in-root lookups; any other path is the running
/// system's. An absolute symlink in the operator's home (`~/.config` linked
/// to a dotfiles directory) then reads the copy the hidden session sees,
/// through the overlay's read-only lower, never the decoy's directory itself.
struct InNextRoot<'a> {
    root: &'a Path,
}

impl InNextRoot<'_> {
    /// `path` relative to the next root, when it lies below it.
    fn below<'p>(&self, path: &'p Path) -> Option<&'p Path> {
        path.strip_prefix(self.root).ok()
    }
}

impl PersonaSource for InNextRoot<'_> {
    fn entries(&self, dir: &Path) -> Vec<PathBuf> {
        match self.below(dir) {
            Some(rel) => nextroot::list_in_root(self.root, rel)
                .unwrap_or_default()
                .into_iter()
                .map(|name| dir.join(name))
                .collect(),
            None => RealFilesystem.entries(dir),
        }
    }

    fn text(&self, path: &Path) -> Option<String> {
        match self.below(path) {
            Some(rel) => nextroot::read_in_root(self.root, rel)
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            None => RealFilesystem.text(path),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        match self.below(path) {
            Some(rel) => nextroot::exists_in_root(self.root, rel),
            None => RealFilesystem.exists(path),
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        match self.below(path) {
            Some(rel) => nextroot::is_file_in_root(self.root, rel),
            None => RealFilesystem.is_file(path),
        }
    }
}

/// The directory `rel` below the operator's `home` in the next root `root`,
/// resolved and created there ([`nextroot::create_dir_all_in_root`]); each
/// directory it creates is the operator's.
fn operator_dir(
    root: &Path,
    home: &Path,
    rel: &str,
    operator: &TargetUser,
) -> std::io::Result<OwnedFd> {
    nextroot::create_dir_all_in_root(root, &home.join(rel), &mut |parent, name| {
        chown_entry(parent, name, operator)
    })
}

/// Give the entry `name` in `dir` to the operator, without following it.
fn chown_entry(
    dir: impl AsFd,
    name: impl rustix::path::Arg,
    operator: &TargetUser,
) -> std::io::Result<()> {
    rustix::fs::chownat(
        dir,
        name,
        Some(rustix::fs::Uid::from_raw(operator.uid)),
        Some(rustix::fs::Gid::from_raw(operator.gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(std::io::Error::from)
}

fn write_autostart_mask(
    root: &Path,
    home: &Path,
    name: &str,
    operator: &TargetUser,
) -> std::io::Result<PathBuf> {
    let dir = operator_dir(root, home, ".config/autostart", operator)?;
    let file = format!("{name}.desktop");
    let _ = rustix::fs::unlinkat(&dir, file.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        &dir,
        file.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )?;
    let mut mask = std::fs::File::from(fd);
    mask.write_all(AUTOSTART_MASK.as_bytes())?;
    rustix::fs::fchmod(&mask, Mode::from_raw_mode(0o644))?;
    std::os::unix::fs::fchown(&mask, Some(operator.uid), Some(operator.gid))?;
    Ok(home.join(".config/autostart").join(file))
}

fn write_unit_mask(
    root: &Path,
    home: &Path,
    unit: &str,
    operator: &TargetUser,
) -> std::io::Result<PathBuf> {
    let dir = operator_dir(root, home, ".config/systemd/user", operator)?;
    let _ = rustix::fs::unlinkat(&dir, unit, AtFlags::empty());
    rustix::fs::symlinkat("/dev/null", &dir, unit)?;
    chown_entry(&dir, unit, operator)?;
    Ok(home.join(".config/systemd/user").join(unit))
}

/// Write the masks `persona` asks for into the operator's home inside the
/// next root `root`: one for every maskable inherited entry it names, and one
/// for every name it lists that the inventory does not (see
/// [`PersonaInventory::mask_targets`](crate::persona::PersonaInventory::mask_targets)).
/// Every path below the home is resolved as the hidden root resolves it
/// ([`nextroot`]), so a mask lands in the upper even when the decoy's `/home`
/// or `~/.config` is an absolute symlink. Best-effort per entry: a mask that
/// cannot be written is skipped with a warning. Returns the masks written, as
/// the hidden root names them.
pub fn write_masks(root: &Path, persona: &PersonaConfig, operator: &TargetUser) -> Vec<PathBuf> {
    let home = operator.passwd_home();
    if persona.mask_inherited.is_empty() || nextroot::open_dir_in_root(root, home).is_err() {
        return Vec::new();
    }
    let fresh = persona.mode == PersonaMode::FreshHome;
    let in_root_home = root.join(home.strip_prefix("/").unwrap_or(home));
    let inventory =
        collect_inherited_persona(&InNextRoot { root }, &in_root_home, &operator.name, fresh);
    inventory
        .mask_targets(persona)
        .into_iter()
        .filter_map(|target| {
            let written = match target.kind {
                MaskKind::Autostart => write_autostart_mask(root, home, &target.name, operator),
                MaskKind::Unit => write_unit_mask(root, home, &target.name, operator),
            };
            written
                .inspect_err(|e| {
                    tracing::warn!(entry = %target.name, error = %e, "Could not mask an inherited entry");
                })
                .ok()
        })
        .collect()
}

#[cfg(test)]
#[path = "persona_tests.rs"]
mod tests;
