// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's persona in the hidden root, put in place at entry.
//!
//! - **fresh-home**: the operator's home is an opaque directory in the upper
//!   that covers it (`trusted.overlay.opaque=y`), so none of the decoy home
//!   shows through. It is created once, at the first entry; after that it is
//!   the hidden home and is left as it is. The home and the directories on the
//!   way to it are looked up and made inside that upper without following a
//!   link: a hidden session may have put one there (a `/home` replaced by a
//!   link to `/var/home`), and followed, it could lead the new home, with its
//!   mode, owner and opaque attribute, out of the upper onto the decoy disk.
//!   A link, or anything else that is not a directory, on the way to the home
//!   refuses the entry.
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
use rustix::fs::{AtFlags, FileType, Gid, Mode, OFlags, Uid, XattrFlags};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// The overlay xattr that hides the lower layers below a directory.
const OPAQUE_XATTR: &str = "trusted.overlay.opaque";

/// How a directory on the way to the fresh home is opened in the one above
/// it: the directory itself, for its attributes only. A symlink is not
/// followed, and it or a file there fails the open with `ENOTDIR`.
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// The `Hidden=true` override that masks an autostart entry of the same name.
const AUTOSTART_MASK: &str = "[Desktop Entry]\nType=Application\nHidden=true\n";

fn io(path: &Path, e: std::io::Error) -> NailsError {
    NailsError::io(path, e)
}

/// Make `upper_home`, the operator's home in the upper that covers it, an
/// opaque directory when nothing stands there yet, and say whether it was
/// made. `decoy_home` is the home on the decoy that it covers.
///
/// Below the root of the upper, `upper_home` names the path `decoy_home` has
/// below the root of the decoy filesystem the home lives on, so the two paths
/// end alike, and each directory on the way to one stands for the directory at
/// the same place on the way to the other. The way down starts where they
/// part, at the root of the upper (or at a directory above it whose name the
/// decoy's path shares as well); the path above that resolves as it does for
/// the overlay. From there down each directory is opened in the one above it
/// without following a link, and one that is missing is made there with the
/// mode and owner of the decoy directory it stands for, where there is one,
/// since an overlay directory takes its attributes from the upper. A link, or
/// anything else that is not a directory, on the way refuses the entry with
/// nothing made through it or below it, so the home is never made outside the
/// upper.
///
/// Whatever already stands at the home is left as it is and never followed:
/// the home an earlier entry made, or what a hidden session put in its place.
/// A new home takes the opaque attribute, then the mode of the decoy's home
/// (`0700` without one) and the operator as its owner; one that cannot take
/// all three is removed again.
pub fn prepare_fresh_home(
    upper_home: &Path,
    decoy_home: &Path,
    operator: &TargetUser,
) -> Result<bool> {
    let way = Way::new(upper_home, decoy_home)?;
    let parent = create_parents_like(&way)?;
    match rustix::fs::statat(&parent, way.home, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => return Ok(false),
        Err(Errno::NOENT) => {}
        Err(errno) => return Err(io(upper_home, errno.into())),
    }
    let mode = std::fs::metadata(decoy_home).map_or(0o700, |meta| permissions(&meta));
    rustix::fs::mkdirat(&parent, way.home, Mode::from_raw_mode(0o700))
        .map_err(|errno| io(upper_home, errno.into()))?;
    if let Err(errno) = make_opaque_home(&parent, way.home, mode, operator) {
        // A plain directory here would let the decoy home show through at
        // every later entry: never leave one behind.
        let _ = rustix::fs::unlinkat(&parent, way.home, AtFlags::REMOVEDIR);
        return Err(io(upper_home, errno.into()));
    }
    Ok(true)
}

/// The permission bits of `meta`, which `chmod` sets: its mode without the
/// file type.
fn permissions(meta: &std::fs::Metadata) -> u32 {
    meta.mode() & 0o7777
}

/// Give the directory `name`, just made in `parent`, the opaque attribute,
/// then `mode` and the operator as its owner, through a descriptor opened
/// without following a link.
fn make_opaque_home(
    parent: &OwnedFd,
    name: &OsStr,
    mode: u32,
    operator: &TargetUser,
) -> rustix::io::Result<()> {
    let home = rustix::fs::openat(parent, name, DIRECTORY, Mode::empty())?;
    rustix::fs::fsetxattr(&home, OPAQUE_XATTR, b"y", XattrFlags::empty())?;
    rustix::fs::fchmod(&home, Mode::from_raw_mode(mode))?;
    rustix::fs::fchown(
        &home,
        Some(Uid::from_raw(operator.uid)),
        Some(Gid::from_raw(operator.gid)),
    )
}

/// The way down to a fresh home (see [`prepare_fresh_home`]).
#[derive(Debug)]
struct Way<'a> {
    /// The directory the way starts from, reached by its path: the one above
    /// the root of the upper.
    base: &'a Path,
    /// The decoy directory `base` stands for, where there is one.
    base_like: Option<&'a Path>,
    /// From the root of the upper down to the parent of the home.
    parents: Vec<Step<'a>>,
    /// The name of the home in its parent.
    home: &'a OsStr,
}

/// A directory on the way to a fresh home, made when it is missing.
#[derive(Debug, PartialEq, Eq)]
struct Step<'a> {
    /// Its name in the directory above it.
    name: &'a OsStr,
    /// Its path, for the errors.
    path: PathBuf,
    /// The decoy directory it stands for, where there is one.
    like: Option<&'a Path>,
}

impl<'a> Way<'a> {
    /// The way to `upper_home`, found where it and `decoy_home` part.
    fn new(upper_home: &'a Path, decoy_home: &'a Path) -> Result<Self> {
        // The plain names at the end of the path, the home first.
        let names: Vec<&OsStr> = trailing_names(upper_home).collect();
        let shared = names
            .iter()
            .zip(trailing_names(decoy_home))
            .take_while(|(upper, decoy)| **upper == *decoy)
            .count();
        // The names the two share lie below the root of the upper, and the
        // name above them is that root itself.
        let walked = names.len().min(shared + 1);
        let (Some(&home), Some(base)) = (names.first(), upper_home.ancestors().nth(walked)) else {
            return Err(NailsError::InvalidState(format!(
                "{} names no directory to make the fresh home in",
                upper_home.display()
            )));
        };
        let base = if base.as_os_str().is_empty() {
            Path::new(".")
        } else {
            base
        };
        let mut path = base.to_path_buf();
        let parents = names[1..walked]
            .iter()
            .rev()
            .enumerate()
            .map(|(depth, &name)| {
                path.push(name);
                Step {
                    name,
                    path: path.clone(),
                    like: decoy_home.ancestors().nth(walked - 1 - depth),
                }
            })
            .collect();
        Ok(Self {
            base,
            base_like: decoy_home.ancestors().nth(walked),
            parents,
            home,
        })
    }
}

/// The plain names at the end of `path`, the last one first.
fn trailing_names(path: &Path) -> impl Iterator<Item = &OsStr> {
    path.components()
        .rev()
        .map_while(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
}

/// Make the directories on the way to the home that do not exist, each with
/// the mode and owner of the decoy directory it stands for when there is one,
/// and open the last of them, the home's parent. Above the root of the upper
/// they are made by their paths ([`create_dir_all_like`]), as the overlay
/// resolves the path of its upper; from the root of the upper down each is
/// opened, or made, in the one above it, without following a link
/// ([`enter_or_make`]).
fn create_parents_like(way: &Way<'_>) -> Result<OwnedFd> {
    create_dir_all_like(way.base, way.base_like)?;
    let mut dir = rustix::fs::open(
        way.base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|errno| io(way.base, errno.into()))?;
    for step in &way.parents {
        dir = enter_or_make(&dir, step)?;
    }
    Ok(dir)
}

/// Create `dir` and its missing parents by their paths, each with the mode and
/// owner of the matching decoy directory when there is one: the directories
/// above the root of an upper, which belong to no overlay.
fn create_dir_all_like(dir: &Path, like: Option<&Path>) -> Result<()> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_dir_all_like(parent, like.and_then(Path::parent))?;
    }
    std::fs::create_dir(dir).map_err(|e| io(dir, e))?;
    if let Some(meta) = like.and_then(|l| std::fs::metadata(l).ok()) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(permissions(&meta)))
            .map_err(|e| io(dir, e))?;
        std::os::unix::fs::chown(dir, Some(meta.uid()), Some(meta.gid()))
            .map_err(|e| io(dir, e))?;
    }
    Ok(())
}

/// The directory `step` in `dir`, opened there without following a link, and
/// made there first when it does not exist, with the mode and owner of the
/// decoy directory it stands for when there is one. A link, or anything else
/// that is not a directory, refuses the entry ([`not_a_directory`]).
fn enter_or_make(dir: &OwnedFd, step: &Step<'_>) -> Result<OwnedFd> {
    match rustix::fs::openat(dir, step.name, DIRECTORY, Mode::empty()) {
        Ok(found) => return Ok(found),
        Err(Errno::NOENT) => {}
        Err(errno) => return Err(not_a_directory(dir, step, errno)),
    }
    // Something that took the name since the lookup is judged by the open
    // below, and keeps its attributes.
    let made = match rustix::fs::mkdirat(dir, step.name, Mode::from_raw_mode(0o777)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(errno) => return Err(io(&step.path, errno.into())),
    };
    let opened = rustix::fs::openat(dir, step.name, DIRECTORY, Mode::empty())
        .map_err(|errno| not_a_directory(dir, step, errno))?;
    if made && let Some(meta) = step.like.and_then(|like| std::fs::metadata(like).ok()) {
        rustix::fs::fchmod(&opened, Mode::from_raw_mode(permissions(&meta)))
            .map_err(|errno| io(&step.path, errno.into()))?;
        rustix::fs::fchown(
            &opened,
            Some(Uid::from_raw(meta.uid())),
            Some(Gid::from_raw(meta.gid())),
        )
        .map_err(|errno| io(&step.path, errno.into()))?;
    }
    Ok(opened)
}

/// The error for `step` in `dir`, which did not open as a directory with
/// `errno`: where a link or anything else that is not a directory stands
/// there, the refusal that names it, else the kernel's error.
fn not_a_directory(dir: &OwnedFd, step: &Step<'_>, errno: Errno) -> NailsError {
    if !matches!(errno, Errno::NOTDIR | Errno::LOOP) {
        return io(&step.path, errno.into());
    }
    let path = step.path.display();
    let link = rustix::fs::statat(dir, step.name, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Symlink);
    if !link {
        return NailsError::InvalidState(format!(
            "{path} is not a directory: the fresh home is made only through directories of \
             its upper on the hidden volume"
        ));
    }
    let target = rustix::fs::readlinkat(dir, step.name, Vec::new()).map_or_else(
        |_| String::new(),
        |target| {
            format!(
                " to {}",
                Path::new(OsStr::from_bytes(target.as_bytes())).display()
            )
        },
    );
    NailsError::InvalidState(format!(
        "{path} is a symbolic link{target}: the fresh home is made only through directories \
         of its upper on the hidden volume, since a link could lead it onto the decoy disk. \
         Delete the link and activate again"
    ))
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
