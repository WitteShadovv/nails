// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! An entry without a build (`--overlay-only` on NixOS), against the whole
//! entry on real mounts: the hidden systemd reads the hidden `/etc/fstab`
//! the last activation of a hidden system left in the root upper, which
//! leads into that system's store by absolute links. The entry decides it as
//! the decoy's fstab: a line at or below the hidden root is kept off with a
//! warning rather than refused, a decoy disk line gets what the decoy's own
//! line would, a line the decoy's fstab holds too is decided once, as the
//! decoy's, even where a link of the hidden root leads it below the root, and
//! one that cannot be read refuses the entry.

use super::{FakeHost, World};
use nails_core::NailsError;
use nails_core::session::entry;
use nails_core::session::fstab::{mount_unit, parse_fstab};
use nails_core::session::layout::Layout;
use nails_core::session::policy::{self, Decision};
use nails_core::test_path;
use nails_core::test_support::{Rerun, write_executable};
use nails_teardown::mountinfo::read_mountinfo;
use std::path::{Path, PathBuf};

/// The hidden system's etc, as the next root's store holds it.
const HIDDEN_ETC: &str = "nix/store/bbbb-etc/etc";

/// A NixOS decoy whose running system lies in its store, and a root upper
/// that holds what the last activation of a hidden system left there: the
/// hidden `/etc` whose `/etc/fstab` leads to `/etc/static/fstab`, and
/// `/etc/static` into the hidden system's etc, kept in the upper's store.
/// Returns the file the hidden systemd would read as `/etc/fstab`.
fn nixos_with_hidden_etc(world: &World) -> PathBuf {
    let system = "nix/store/cccc-nixos-system-decoy";
    write_executable(
        &world
            .decoy
            .mkdir(&format!("{system}/systemd/lib/systemd"))
            .join("systemd"),
        "#!/bin/sh\n",
        0o755,
    );
    std::os::unix::fs::symlink(
        Path::new("/").join(system),
        world.run.path().join("current-system"),
    )
    .unwrap();
    let upper = Layout::new(world.hidden_path()).upper();
    let etc = upper.join(HIDDEN_ETC);
    std::fs::create_dir_all(&etc).unwrap();
    std::os::unix::fs::symlink(Path::new("/").join(HIDDEN_ETC), upper.join("etc/static")).unwrap();
    std::os::unix::fs::symlink("/etc/static/fstab", upper.join("etc/fstab")).unwrap();
    etc.join("fstab")
}

#[test]
fn an_overlay_only_entry_keeps_a_hidden_fstab_line_below_the_root_off_and_warns() {
    let _ = Rerun::new(test_path!(
        an_overlay_only_entry_keeps_a_hidden_fstab_line_below_the_root_off_and_warns
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        world.hidden.mkdir("root/upper/etc");
        let fstab = nixos_with_hidden_etc(&world);
        let hidden = world.hidden_path();
        // A link of the hidden root leads the decoy's /srv/data into the
        // hidden volume: the decoy's line for it is decided there already,
        // kept off as a decoy disk a link leads below the root.
        world.hidden.mkdir("root/upper/srv");
        std::os::unix::fs::symlink(
            hidden.join("data"),
            world.hidden.path().join("root/upper/srv/data"),
        )
        .unwrap();
        // The hidden configuration's: the decoy's root, /home and /srv/data,
        // a disk inside the hidden volume (a configuration written in a
        // session while the volume was mounted), and a decoy disk elsewhere.
        let below = format!(
            "/dev/vdd1 {}/archive ext4 defaults,nofail 0 2",
            hidden.display()
        );
        let backup = "/dev/vde1 /srv/backup ext4 defaults,nofail 0 2";
        std::fs::write(
            &fstab,
            format!(
                "/dev/vda2 / ext4 defaults 0 1\n/dev/vda3 /home ext4 defaults 0 2\n\
                 /dev/vdc1 /srv/data ext4 defaults,nofail 0 2\n{below}\n{backup}\n"
            ),
        )
        .unwrap();
        let mut inputs = world.inputs();
        inputs.nixos = true;
        let paths = world.paths();

        let entry = entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");

        // The line below the root is kept off, so the session meant to remove
        // it starts, and the warning names it, the root and what to do. It is
        // the one warning of a line below the root: the decoy's /srv/data,
        // which the link leads there, is not decided again as one.
        let archive = hidden.join("archive");
        let masks = &entry.plan.masks;
        assert!(masks.contains(&mount_unit(&archive)), "{masks:?}");
        let warned: Vec<&String> = entry
            .warnings
            .iter()
            .filter(|warning| warning.contains("lies at or below"))
            .collect();
        assert_eq!(warned.len(), 1, "{:?}", entry.warnings);
        assert_eq!(
            warned[0],
            &format!(
                "the hidden NixOS system's fstab entry {} (`{below}`) lies at or below {}, where \
                 the hidden volume is mounted: its units are kept off, so the hidden systemd does \
                 not mount it over the hidden volume or inside it, though a plain `mount` in the \
                 session still would\nIn the hidden session, remove this mount from the hidden \
                 NixOS configuration, or move it out from below {} there, and rebuild.",
                archive.display(),
                hidden.display(),
                hidden.display()
            )
        );
        // That line is decided once, kept off as the decoy's line a link
        // leads below the root, and its unit is masked.
        let data = hidden.join("data");
        let for_data: Vec<&Decision> = entry
            .decisions
            .iter()
            .filter(|decision| {
                decision
                    .describe()
                    .starts_with(&format!("{}:", data.display()))
            })
            .collect();
        assert_eq!(for_data.len(), 1, "{:?}", entry.decisions);
        assert!(
            for_data[0]
                .describe()
                .contains("a link leads it into the hidden volume"),
            "{for_data:?}"
        );
        assert!(masks.contains(&mount_unit(&data)), "{masks:?}");
        // The decoy disk elsewhere gets the decision of the decoy's own line.
        let as_decoy = policy::decide(&parse_fstab(backup)[0], &[], hidden, &|_| false);
        assert!(entry.decisions.contains(&as_decoy), "{:?}", entry.decisions);
        assert!(masks.contains(&"srv-backup.mount".to_string()), "{masks:?}");
        // /home, which the decoy's fstab holds too, is overlaid as the
        // decoy's, and nothing else is decided for it.
        let home: Vec<&Decision> = entry
            .decisions
            .iter()
            .filter(|decision| decision.describe().starts_with("/home:"))
            .collect();
        assert_eq!(
            home,
            [&Decision::Overlay {
                target: PathBuf::from("/home")
            }]
        );
        assert!(
            !read_mountinfo()
                .unwrap()
                .iter()
                .any(|mount| mount.mount_point == paths.in_nextroot(&archive)),
            "nothing is mounted at the line's mount point"
        );
        entry::rollback(&paths);
    });
}

#[test]
fn an_overlay_only_entry_whose_hidden_fstab_cannot_be_read_is_refused() {
    let _ = Rerun::new(test_path!(
        an_overlay_only_entry_whose_hidden_fstab_cannot_be_read_is_refused
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = World::new();
        world.hidden.mkdir("root/upper/etc");
        let fstab = nixos_with_hidden_etc(&world);
        std::fs::create_dir(&fstab).unwrap();
        let mut inputs = world.inputs();
        inputs.nixos = true;
        let paths = world.paths();

        let error = entry::prepare(&paths, &inputs, &FakeHost::default()).unwrap_err();

        let NailsError::InvalidState(message) = &error else {
            panic!("{error:?}");
        };
        assert!(
            message.starts_with("the hidden /etc/fstab cannot be read (it is not a regular file)"),
            "{message}"
        );
        // It says where the hidden root keeps its own on the hidden volume,
        // where it can be changed while the session cannot be entered.
        let kept = Layout::new(world.hidden_path()).upper().join("etc/fstab");
        assert!(
            message.ends_with(&format!(
                "The hidden root's own /etc/fstab, if it has one, is {} on the hidden volume.",
                kept.display()
            )),
            "{message}"
        );
        assert!(
            !read_mountinfo()
                .unwrap()
                .iter()
                .any(|mount| mount.mount_point.starts_with(paths.nextroot())),
            "the next root is detached"
        );
        assert!(!paths.runtime().exists());
    });
}
