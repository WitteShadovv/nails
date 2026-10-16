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
mod tests {
    use super::*;

    fn me(home: &Path) -> TargetUser {
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        TargetUser::for_test(uid, gid, "alice", home.to_path_buf(), "/bin/sh")
    }

    #[test]
    fn masks_land_in_the_home_owned_by_the_operator() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/alice");
        std::fs::create_dir_all(home.join(".config/autostart")).unwrap();
        std::fs::write(
            home.join(".config/autostart/dropbox.desktop"),
            "[Desktop Entry]\nName=Dropbox\nExec=dropbox\n",
        )
        .unwrap();
        std::fs::write(
            home.join(".config/autostart/keep.desktop"),
            "[Desktop Entry]\nName=Keep\nExec=keep\n",
        )
        .unwrap();
        let wants = home.join(".config/systemd/user/default.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/user/syncthing.service",
            wants.join("syncthing.service"),
        )
        .unwrap();
        let persona = PersonaConfig {
            mode: PersonaMode::SharedHome,
            mask_inherited: vec!["dropbox".into(), "syncthing.service".into()],
        };
        let written = write_masks(dir.path(), &persona, &me(Path::new("/home/alice")));
        assert_eq!(written.len(), 2, "{written:?}");
        let mask = std::fs::read_to_string(home.join(".config/autostart/dropbox.desktop")).unwrap();
        assert!(mask.contains("Hidden=true"));
        assert!(
            !std::fs::read_to_string(home.join(".config/autostart/keep.desktop"))
                .unwrap()
                .contains("Hidden=true")
        );
        assert_eq!(
            std::fs::read_link(home.join(".config/systemd/user/syncthing.service")).unwrap(),
            Path::new("/dev/null")
        );
    }

    #[test]
    fn a_named_entry_the_inventory_misses_is_masked_by_its_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home/alice");
        std::fs::create_dir_all(&home).unwrap();
        let persona = PersonaConfig {
            mode: PersonaMode::FreshHome,
            mask_inherited: vec![
                "org.kde.kdeconnect.daemon".into(),
                "ghost.service".into(),
                "../escape".into(),
            ],
        };
        let written = write_masks(dir.path(), &persona, &me(Path::new("/home/alice")));
        assert_eq!(written.len(), 2, "{written:?}");
        let mask = std::fs::read_to_string(
            home.join(".config/autostart/org.kde.kdeconnect.daemon.desktop"),
        )
        .unwrap();
        assert!(mask.contains("Hidden=true"), "{mask}");
        assert_eq!(
            std::fs::read_link(home.join(".config/systemd/user/ghost.service")).unwrap(),
            Path::new("/dev/null")
        );
        assert!(
            !dir.path().join("home/escape.desktop").exists()
                && !home.join(".config/escape.desktop").exists(),
            "a name with a slash writes nothing"
        );
    }

    #[test]
    fn nothing_is_written_without_a_mask_list_or_a_home() {
        let dir = tempfile::tempdir().unwrap();
        let persona = PersonaConfig::default();
        assert!(write_masks(dir.path(), &persona, &me(Path::new("/"))).is_empty());
        let persona = PersonaConfig {
            mode: PersonaMode::SharedHome,
            mask_inherited: vec!["dropbox".into()],
        };
        assert!(write_masks(dir.path(), &persona, &me(Path::new("/home/alice"))).is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// The decoy's `/home` and the operator's `~/.config` are absolute links
    /// (`/home -> /nails-test-data/home`, `.config -> /nails-test-dotfiles`):
    /// the masks follow them inside the next root, where the hidden root will
    /// read them. Resolved on the running system instead, the targets would
    /// not exist (nothing outside the next root is written to show it).
    #[test]
    fn masks_follow_absolute_links_inside_the_next_root() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("nails-test-data/home/alice");
        let dotfiles = root.path().join("nails-test-dotfiles/autostart");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&dotfiles).unwrap();
        std::fs::write(
            dotfiles.join("dropbox.desktop"),
            "[Desktop Entry]\nExec=dropbox\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("/nails-test-data/home", root.path().join("home")).unwrap();
        std::os::unix::fs::symlink("/nails-test-dotfiles", data.join(".config")).unwrap();
        // The inventory reads the home the same way.
        let inventory = collect_inherited_persona(
            &InNextRoot { root: root.path() },
            &root.path().join("home/alice"),
            "alice",
            false,
        );
        assert!(
            inventory.entries.iter().any(|entry| entry.name == "dropbox"
                && entry.source == crate::persona::InheritedSource::UserAutostart),
            "{inventory:?}"
        );
        let persona = PersonaConfig {
            mode: PersonaMode::SharedHome,
            mask_inherited: vec!["dropbox".into(), "syncthing.service".into()],
        };
        let written = write_masks(root.path(), &persona, &me(Path::new("/home/alice")));
        assert_eq!(written.len(), 2, "{written:?}");
        let mask = std::fs::read_to_string(dotfiles.join("dropbox.desktop")).unwrap();
        assert!(
            mask.contains("Hidden=true"),
            "the listed entry is masked: {mask}"
        );
        assert_eq!(
            std::fs::read_link(
                root.path()
                    .join("nails-test-dotfiles/systemd/user/syncthing.service")
            )
            .unwrap(),
            Path::new("/dev/null")
        );
        // A dangling link is never written through.
        std::fs::remove_dir_all(root.path().join("nails-test-dotfiles")).unwrap();
        assert!(write_masks(root.path(), &persona, &me(Path::new("/home/alice"))).is_empty());
        assert!(!root.path().join("nails-test-dotfiles").exists());
    }

    #[test]
    fn an_existing_hidden_home_is_kept_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let upper_home = dir.path().join("upper/home/alice");
        std::fs::create_dir_all(&upper_home).unwrap();
        std::fs::write(upper_home.join("notes"), "hidden").unwrap();
        let created = prepare_fresh_home(
            &upper_home,
            &dir.path().join("home/alice"),
            &me(&upper_home),
        )
        .unwrap();
        assert!(!created);
        assert!(upper_home.join("notes").exists());
    }

    #[test]
    fn a_new_hidden_home_takes_the_decoy_parents_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let decoy_home = dir.path().join("decoy/home/alice");
        std::fs::create_dir_all(&decoy_home).unwrap();
        std::fs::set_permissions(
            dir.path().join("decoy/home"),
            std::fs::Permissions::from_mode(0o751),
        )
        .unwrap();
        let upper_home = dir.path().join("upper/home/alice");
        std::fs::create_dir_all(dir.path().join("upper")).unwrap();
        // Without CAP_SYS_ADMIN the opaque xattr cannot be set; the parents are
        // created either way.
        if prepare_fresh_home(&upper_home, &decoy_home, &me(&upper_home)).is_err() {
            assert!(!upper_home.exists(), "no plain home is left behind");
        }
        let mode = std::fs::metadata(dir.path().join("upper/home"))
            .unwrap()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o751);
    }

    /// The masks through a real overlay, as activation writes them: the decoy
    /// is the read-only lower, the upper is on the hidden volume.
    mod kernel_tests {
        use super::*;
        use nails_base::test_support::{Rerun, ScratchTmpfs};
        use std::collections::BTreeMap;

        /// Every entry below `dir`: file contents, link targets and modes,
        /// so any change to the decoy shows.
        fn tree(dir: &Path) -> BTreeMap<PathBuf, String> {
            let mut out = BTreeMap::new();
            let mut stack = vec![dir.to_path_buf()];
            while let Some(current) = stack.pop() {
                for entry in std::fs::read_dir(&current).unwrap().flatten() {
                    let path = entry.path();
                    let meta = std::fs::symlink_metadata(&path).unwrap();
                    let what = if meta.file_type().is_symlink() {
                        format!("-> {}", std::fs::read_link(&path).unwrap().display())
                    } else if meta.is_dir() {
                        stack.push(path.clone());
                        format!("dir {:o}", meta.mode())
                    } else {
                        format!(
                            "{:o} {}",
                            meta.mode(),
                            std::fs::read_to_string(&path).unwrap()
                        )
                    };
                    out.insert(path.strip_prefix(dir).unwrap().to_path_buf(), what);
                }
            }
            out
        }

        /// The next root over `decoy`, with its upper on `hidden`.
        fn next_root(decoy: &Path, hidden: &ScratchTmpfs) -> PathBuf {
            let next = hidden.mkdir("next");
            nextroot::overlay_over(
                decoy,
                &hidden.path().join("lower"),
                &hidden.mkdir("upper"),
                &hidden.mkdir("work"),
                &next,
            )
            .expect("the root overlay");
            next
        }

        fn masks() -> PersonaConfig {
            PersonaConfig {
                mode: PersonaMode::SharedHome,
                mask_inherited: vec!["dropbox".into(), "syncthing.service".into()],
            }
        }

        #[test]
        fn masks_behind_absolute_links_land_in_the_upper_and_leave_the_decoy_as_it_was() {
            let _ = Rerun::new(nails_base::test_path!(
                masks_behind_absolute_links_land_in_the_upper_and_leave_the_decoy_as_it_was
            ))
            .in_user_mount_ns()
            .run(|| {
                // ~/.config is an absolute link into a dotfiles directory.
                let decoy = ScratchTmpfs::new("");
                let config = decoy.mkdir("home/alice/.dotfiles/config/autostart");
                std::fs::write(
                    config.join("dropbox.desktop"),
                    "[Desktop Entry]\nExec=dropbox\n",
                )
                .unwrap();
                std::os::unix::fs::symlink(
                    "/home/alice/.dotfiles/config",
                    decoy.path().join("home/alice/.config"),
                )
                .unwrap();
                // In a second decoy, /home itself is an absolute link.
                let linked = ScratchTmpfs::new("");
                linked.mkdir("srv/people/alice");
                std::os::unix::fs::symlink("/srv/people", linked.path().join("home")).unwrap();

                for (decoy, upper_config) in [
                    (&decoy, "home/alice/.dotfiles/config"),
                    (&linked, "srv/people/alice/.config"),
                ] {
                    let before = tree(decoy.path());
                    let hidden = ScratchTmpfs::new("");
                    let next = next_root(decoy.path(), &hidden);
                    let written = write_masks(&next, &masks(), &me(Path::new("/home/alice")));
                    assert_eq!(written.len(), 2, "{upper_config}: {written:?}");
                    let upper = hidden.path().join("upper").join(upper_config);
                    let mask =
                        std::fs::read_to_string(upper.join("autostart/dropbox.desktop")).unwrap();
                    assert!(mask.contains("Hidden=true"), "{upper_config}: {mask}");
                    assert_eq!(
                        std::fs::read_link(upper.join("systemd/user/syncthing.service")).unwrap(),
                        Path::new("/dev/null")
                    );
                    assert_eq!(
                        tree(decoy.path()),
                        before,
                        "{upper_config}: the decoy changed"
                    );
                    nextroot::detach_tree(&next);
                }
            });
        }

        /// `mask_inherited = ["*"]` masks what the inventory finds, and the
        /// inventory reads `~/.config` through the absolute link as the hidden
        /// root resolves it. Read on the running system instead, it would find
        /// nothing there and mask nothing.
        #[test]
        fn a_wildcard_masks_the_entries_behind_an_absolute_link() {
            let _ = Rerun::new(nails_base::test_path!(
                a_wildcard_masks_the_entries_behind_an_absolute_link
            ))
            .in_user_mount_ns()
            .run(|| {
                let decoy = ScratchTmpfs::new("");
                let config = decoy.mkdir("home/alice/.dotfiles/config/autostart");
                std::fs::write(
                    config.join("dropbox.desktop"),
                    "[Desktop Entry]\nExec=dropbox\n",
                )
                .unwrap();
                std::os::unix::fs::symlink(
                    "/home/alice/.dotfiles/config",
                    decoy.path().join("home/alice/.config"),
                )
                .unwrap();
                let before = tree(decoy.path());
                let hidden = ScratchTmpfs::new("");
                let next = next_root(decoy.path(), &hidden);
                let everything = PersonaConfig {
                    mode: PersonaMode::SharedHome,
                    mask_inherited: vec!["*".into()],
                };

                let written = write_masks(&next, &everything, &me(Path::new("/home/alice")));

                // The test host's own system entries are masked too.
                assert!(
                    written.contains(&PathBuf::from(
                        "/home/alice/.config/autostart/dropbox.desktop"
                    )),
                    "{written:?}"
                );
                let mask = std::fs::read_to_string(
                    hidden
                        .path()
                        .join("upper/home/alice/.dotfiles/config/autostart/dropbox.desktop"),
                )
                .unwrap();
                assert!(mask.contains("Hidden=true"), "{mask}");
                assert_eq!(tree(decoy.path()), before, "the decoy changed");
                nextroot::detach_tree(&next);
            });
        }
    }
}
