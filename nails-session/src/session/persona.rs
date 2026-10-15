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
//!   it lands in the upper and never on the decoy. A name the inventory does
//!   not list is masked as well, judged by its suffix, so a directory the
//!   inventory does not read never drops a requested mask.

use crate::config::{PersonaConfig, PersonaMode};
use crate::error::{NailsError, Result};
use crate::filesystem::RealFilesystem;
use crate::persona::{MaskKind, collect_inherited_persona};
use crate::target_user::TargetUser;
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

/// Create `dir` (and missing parents below `home`) owned by the operator.
fn operator_dir(home: &Path, dir: &Path, operator: &TargetUser) -> std::io::Result<()> {
    let mut current = home.to_path_buf();
    for component in dir.strip_prefix(home).unwrap_or(dir).components() {
        current.push(component);
        if !current.exists() {
            std::fs::create_dir(&current)?;
            std::os::unix::fs::chown(&current, Some(operator.uid), Some(operator.gid))?;
        }
    }
    Ok(())
}

fn write_autostart_mask(
    home: &Path,
    name: &str,
    operator: &TargetUser,
) -> std::io::Result<PathBuf> {
    let dir = home.join(".config/autostart");
    operator_dir(home, &dir, operator)?;
    let path = dir.join(format!("{name}.desktop"));
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, AUTOSTART_MASK)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    std::os::unix::fs::chown(&path, Some(operator.uid), Some(operator.gid))?;
    Ok(path)
}

fn write_unit_mask(home: &Path, unit: &str, operator: &TargetUser) -> std::io::Result<PathBuf> {
    let dir = home.join(".config/systemd/user");
    operator_dir(home, &dir, operator)?;
    let link = dir.join(unit);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("/dev/null", &link)?;
    std::os::unix::fs::lchown(&link, Some(operator.uid), Some(operator.gid))?;
    Ok(link)
}

/// Write the masks `persona` asks for into `home`, the operator's home inside
/// the next root: one for every maskable inherited entry it names, and one for
/// every name it lists that the inventory does not (see
/// [`PersonaInventory::mask_targets`](crate::persona::PersonaInventory::mask_targets)).
/// Best-effort per entry: a mask that cannot be written is skipped. Returns the
/// masks written.
pub fn write_masks(home: &Path, persona: &PersonaConfig, operator: &TargetUser) -> Vec<PathBuf> {
    if persona.mask_inherited.is_empty() || !home.is_dir() {
        return Vec::new();
    }
    let fresh = persona.mode == PersonaMode::FreshHome;
    let inventory = collect_inherited_persona(&RealFilesystem, home, &operator.name, fresh);
    inventory
        .mask_targets(persona)
        .into_iter()
        .filter_map(|target| match target.kind {
            MaskKind::Autostart => write_autostart_mask(home, &target.name, operator).ok(),
            MaskKind::Unit => write_unit_mask(home, &target.name, operator).ok(),
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
        let written = write_masks(&home, &persona, &me(&home));
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
        let written = write_masks(&home, &persona, &me(&home));
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
    fn nothing_is_written_without_a_mask_list() {
        let dir = tempfile::tempdir().unwrap();
        let persona = PersonaConfig::default();
        assert!(write_masks(dir.path(), &persona, &me(dir.path())).is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
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
}
