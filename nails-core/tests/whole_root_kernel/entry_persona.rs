// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The persona masks of the whole entry on real mounts, where the inventory
//! of what the hidden session inherits cannot read a place of the decoy.

use super::{FakeHost, World};
use nails_core::session::entry;
use nails_core::test_path;
use nails_core::test_support::Rerun;
use std::path::Path;

/// The start of the entry's warning for the places the inventory could not
/// read.
const NOT_READ: &str = "NAILS could not read everything the hidden session inherits from the \
                        decoy: ";

/// A place of the decoy the inventory cannot look up, here
/// `/etc/systemd/user` as a link that leads back to itself, refuses
/// nothing: the entry goes on, masks what `mask_inherited` names in the
/// hidden home, and warns once, naming the place and why.
#[test]
fn an_entry_warns_once_of_a_place_the_persona_inventory_cannot_look_up() {
    let _ = Rerun::new(test_path!(
        an_entry_warns_once_of_a_place_the_persona_inventory_cannot_look_up
    ))
    .in_user_mount_ns()
    .run(|| {
        // In this mount namespace only, /etc/systemd holds nothing but that
        // link: the inventory reads the system's own directories there.
        nix::mount::mount(
            Some("tmpfs"),
            "/etc/systemd",
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .unwrap();
        std::os::unix::fs::symlink("user", "/etc/systemd/user").unwrap();
        let world = World::new();
        let paths = world.paths();
        let mut inputs = world.inputs();
        inputs.persona.mask_inherited = vec!["*".into()];
        inputs.operator = Some(nails_core::TargetUser::for_test(
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
            "alice",
            "/home/alice",
            "/bin/sh",
        ));

        let entry = entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");

        let unread: Vec<&String> = entry
            .warnings
            .iter()
            .filter(|warning| warning.starts_with(NOT_READ))
            .collect();
        assert_eq!(unread.len(), 1, "{:?}", entry.warnings);
        assert!(
            unread[0].contains("NAILS cannot look up /etc/systemd/user (")
                && unread[0].contains("(os error 40)"),
            "{unread:?}"
        );
        // The decoy home's entry, which the inventory did read, is masked in
        // the hidden home, under "*".
        let mask = std::fs::read_to_string(
            paths
                .nextroot()
                .join("home/alice/.config/autostart/dropbox.desktop"),
        )
        .unwrap();
        assert!(mask.contains("Hidden=true"), "{mask}");
        assert!(
            !std::fs::read_to_string(
                world
                    .decoy
                    .path()
                    .join("home/alice/.config/autostart/dropbox.desktop")
            )
            .unwrap()
            .contains("Hidden=true")
        );
        assert!(Path::new("/etc/systemd/user").is_symlink());
        entry::rollback(&paths);
    });
}
