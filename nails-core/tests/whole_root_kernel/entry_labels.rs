// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The SELinux labels the whole entry gives the hidden root, against real
//! mounts: the roots of the uppers and the way to the operator's home take the
//! labels of the decoy's directories before the overlays are mounted, and the
//! hidden root shows them; an entry that requires a label the decoy lacks is
//! refused and undone; one that requires the labels is refused at a link in
//! place of the root upper, and no entry labels that link or its target; a
//! parent of the home that an entry could not label is labelled at a later
//! entry or refuses it again, in either persona; and an entry on a host whose
//! facts report no SELinux writes no label.
//!
//! As for the label copy's own tests, the namespace's root may write
//! `security.selinux` on its own tmpfs where the kernel runs without SELinux.
//! A kernel that labels every file itself checks each label against the
//! loaded policy instead, which needs a VM; these tests skip there.

use super::{FakeHost, World};
use crate::labels_kernel_tests::{
    HOME_LABEL, HOME_ROOT_LABEL, REQUIRED, ROOT_LABEL, ctime, label, set_label, tick,
};
use nails_core::config::PersonaMode;
use nails_core::session::entry;
use nails_core::session::labels::Labels;
use nails_core::session::layout::{Layout, Paths};
use nails_core::test_path;
use nails_core::test_support::{Rerun, skip_host};
use nails_teardown::mountinfo::read_mountinfo;
use rustix::io::Errno;
use std::path::{Path, PathBuf};

/// The world of the entry tests, on a kernel that leaves a new tmpfs
/// unlabelled. Skips where the kernel labels every file itself.
fn unlabelled_world() -> World {
    let world = World::new();
    match label(world.decoy.path()) {
        Err(Errno::NODATA) => world,
        Ok(found) => skip_host(&format!(
            "the kernel labels new files on this host ({}): SELinux is active, and the label \
             copy under a loaded policy needs a VM",
            String::from_utf8_lossy(&found).trim_end_matches('\0')
        )),
        Err(errno) => panic!("the SELinux label of a fresh tmpfs: {errno}"),
    }
}

/// Label the decoy as Fedora's policy does: `/`, the root of its separate
/// `/home`, and alice's home.
fn label_decoy(world: &World) {
    let decoy = world.decoy.path();
    set_label(decoy, ROOT_LABEL);
    set_label(&decoy.join("home"), HOME_ROOT_LABEL);
    set_label(&decoy.join("home/alice"), HOME_LABEL);
}

/// The operator `name`, who runs the tests, with the home `home`.
fn operator(name: &str, home: &str) -> nails_core::TargetUser {
    nails_core::TargetUser::for_test(
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
        name,
        home,
        "/bin/sh",
    )
}

/// The root of the upper of the decoy's separate `/home`.
fn home_upper(world: &World) -> PathBuf {
    Layout::new(world.hidden.path())
        .mount_layers(Path::new("/home"))
        .0
}

/// Whether anything is mounted at or below the next root of `paths`.
fn next_root_mounted(paths: &Paths) -> bool {
    read_mountinfo()
        .unwrap()
        .iter()
        .any(|e| e.mount_point.starts_with(paths.nextroot()))
}

#[test]
fn an_entry_gives_the_roots_of_the_uppers_and_the_way_to_the_home_the_decoy_s_labels() {
    let _ = Rerun::new(test_path!(
        an_entry_gives_the_roots_of_the_uppers_and_the_way_to_the_home_the_decoy_s_labels
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = unlabelled_world();
        label_decoy(&world);
        // The home an earlier entry left in the upper of `/home`.
        let upper_home = home_upper(&world).join("alice");
        std::fs::create_dir_all(&upper_home).unwrap();
        let paths = world.paths();
        let mut inputs = world.inputs();
        inputs.labels = REQUIRED;
        inputs.operator = Some(operator("alice", "/home/alice"));

        entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");

        // On the hidden volume: the root upper, the root of the upper of
        // `/home`, and the home in it.
        let root_upper = Layout::new(world.hidden.path()).upper();
        assert_eq!(label(&root_upper).unwrap(), ROOT_LABEL);
        assert_eq!(label(&home_upper(&world)).unwrap(), HOME_ROOT_LABEL);
        assert_eq!(label(&upper_home).unwrap(), HOME_LABEL);
        // The hidden root shows the decoy's labels.
        let nextroot = paths.nextroot();
        assert_eq!(label(&nextroot).unwrap(), ROOT_LABEL);
        assert_eq!(label(&nextroot.join("home")).unwrap(), HOME_ROOT_LABEL);
        assert_eq!(label(&nextroot.join("home/alice")).unwrap(), HOME_LABEL);
        entry::rollback(&paths);

        // The next entry finds the labels in place and writes none again.
        let labelled = ctime(&upper_home);
        tick();
        entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the next entry");
        assert_eq!(ctime(&upper_home), labelled);
        entry::rollback(&paths);
    });
}

#[test]
fn an_entry_that_requires_a_label_the_decoy_lacks_is_refused_and_undone() {
    let _ = Rerun::new(test_path!(
        an_entry_that_requires_a_label_the_decoy_lacks_is_refused_and_undone
    ))
    .in_user_mount_ns()
    .run(|| {
        let world = unlabelled_world();
        let decoy = world.decoy.path();
        let paths = world.paths();
        let mut inputs = world.inputs();
        inputs.labels = REQUIRED;

        // The decoy root has no label: refused at the root upper, before the
        // root overlay is mounted.
        let host = FakeHost::default();
        let error = entry::prepare(&paths, &inputs, &host).unwrap_err();
        assert!(
            error
                .to_string()
                .ends_with(&format!("but {} has no label", decoy.display())),
            "{error}"
        );
        assert!(!next_root_mounted(&paths));
        assert!(!paths.runtime().exists());
        assert_eq!(host.reloads.get(), 2, "one loads the drop-in, one drops it");

        // With the root labelled, the root of the decoy's `/home` has none:
        // refused at the upper of `/home`, with the root overlay mounted
        // already, which the rollback detaches.
        set_label(decoy, ROOT_LABEL);
        let host = FakeHost::default();
        let error = entry::prepare(&paths, &inputs, &host).unwrap_err();
        assert!(
            error.to_string().ends_with(&format!(
                "but {} has no label",
                decoy.join("home").display()
            )),
            "{error}"
        );
        assert!(!next_root_mounted(&paths));
        assert!(!paths.runtime().exists());
        assert_eq!(host.reloads.get(), 2, "one loads the drop-in, one drops it");
    });
}

#[test]
fn a_link_in_place_of_the_root_upper_is_refused_where_the_labels_are_required_and_never_labelled() {
    let _ = Rerun::new(test_path!(
        a_link_in_place_of_the_root_upper_is_refused_where_the_labels_are_required_and_never_labelled
    ))
    .in_user_mount_ns()
    .run(|| {
        // The decoy root carries a label to copy, so a refusal can only come
        // from the upper.
        let world = unlabelled_world();
        label_decoy(&world);
        let decoy = world.decoy.path();
        // The root upper replaced by a link to another directory of the hidden
        // volume, which an overlay given the upper's path takes its root from.
        world.hidden.mkdir("root");
        let upper = Layout::new(world.hidden.path()).upper();
        let elsewhere = world.hidden.mkdir("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, &upper).unwrap();
        let paths = world.paths();
        let mut inputs = world.inputs();
        inputs.labels = REQUIRED;

        // Refused at the link itself, before the root overlay is mounted, and
        // undone.
        let host = FakeHost::default();
        let error = entry::prepare(&paths, &inputs, &host).unwrap_err();
        assert!(
            error.to_string().ends_with(&format!(
                ", so {0} must carry the SELinux label of {1}, but {0} is a link or a file, \
                 not a directory",
                upper.display(),
                decoy.display()
            )),
            "{error}"
        );
        assert!(!next_root_mounted(&paths));
        assert!(!paths.runtime().exists());
        assert_eq!(host.reloads.get(), 2, "one loads the drop-in, one drops it");

        // A host whose facts report no SELinux goes on as before the label
        // copy, with the hidden `/` taken from the link's target.
        inputs.labels = Labels::BestEffort;
        entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");
        assert_eq!(label(&paths.nextroot()), Err(Errno::NODATA));
        entry::rollback(&paths);

        // Neither entry labelled the link or its target, though the decoy root
        // has a label: the copy opens the upper without following the link.
        // The mode and owner of the decoy root do reach the target, which
        // `make_layer` sets through the link before the copy.
        assert_eq!(label(&upper), Err(Errno::NODATA));
        assert_eq!(label(&elsewhere), Err(Errno::NODATA));
    });
}

#[test]
fn an_entry_on_a_host_whose_facts_report_no_selinux_writes_no_label() {
    let _ = Rerun::new(test_path!(
        an_entry_on_a_host_whose_facts_report_no_selinux_writes_no_label
    ))
    .in_user_mount_ns()
    .run(|| {
        // A decoy without labels, the home in place in either persona.
        let world = unlabelled_world();
        let upper_home = home_upper(&world).join("alice");
        std::fs::create_dir_all(&upper_home).unwrap();
        let paths = world.paths();
        let mut inputs = world.inputs();
        assert_eq!(inputs.labels, Labels::BestEffort);
        inputs.operator = Some(operator("alice", "/home/alice"));
        let before = ctime(&upper_home);
        tick();

        for mode in [PersonaMode::SharedHome, PersonaMode::FreshHome] {
            inputs.persona.mode = mode;
            entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");
            let root_upper = Layout::new(world.hidden.path()).upper();
            for dir in [&root_upper, &home_upper(&world), &upper_home] {
                assert_eq!(
                    label(dir),
                    Err(Errno::NODATA),
                    "{mode:?}: {}",
                    dir.display()
                );
            }
            entry::rollback(&paths);
        }
        // Nothing on the way to the home was written at all.
        assert_eq!(ctime(&upper_home), before);
    });
}

/// A fresh-home entry for bob, whose home lies below `/home/staff`, a
/// directory of the decoy without a label, is refused at that parent. A later
/// entry, in the persona `later`, is refused again while the decoy's
/// directory has no label, and labels the parent and the home once it has one,
/// without writing them again at the entry after.
fn refused_at_a_parent_of_the_home_then(later: PersonaMode) {
    let world = unlabelled_world();
    label_decoy(&world);
    let decoy = world.decoy.path();
    let decoy_home = world.decoy.mkdir("home/staff/bob");
    set_label(&decoy_home, HOME_LABEL);
    // The home the first fresh-home entry made, with its parent.
    let upper_staff = home_upper(&world).join("staff");
    let upper_home = upper_staff.join("bob");
    std::fs::create_dir_all(&upper_home).unwrap();
    let paths = world.paths();
    let mut inputs = world.inputs();
    inputs.labels = REQUIRED;
    inputs.persona.mode = PersonaMode::FreshHome;
    inputs.operator = Some(operator("bob", "/home/staff/bob"));
    let unlabelled = format!("but {} has no label", decoy.join("home/staff").display());

    // Refused at the parent, before the home is reached.
    let error = entry::prepare(&paths, &inputs, &FakeHost::default()).unwrap_err();
    assert!(error.to_string().ends_with(&unlabelled), "{error}");
    assert!(!next_root_mounted(&paths));

    // A later entry never goes on without the parent's label.
    inputs.persona.mode = later;
    let error = entry::prepare(&paths, &inputs, &FakeHost::default()).unwrap_err();
    assert!(
        error.to_string().ends_with(&unlabelled),
        "{later:?}: {error}"
    );
    for dir in [&upper_staff, &upper_home] {
        assert_eq!(
            label(dir),
            Err(Errno::NODATA),
            "{later:?}: {}",
            dir.display()
        );
    }
    assert!(!next_root_mounted(&paths));

    // Once the decoy's directory has its label, the next entry labels the
    // parent and the home, and the hidden root shows them.
    set_label(&decoy.join("home/staff"), HOME_ROOT_LABEL);
    entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the entry");
    assert_eq!(label(&upper_staff).unwrap(), HOME_ROOT_LABEL);
    assert_eq!(label(&upper_home).unwrap(), HOME_LABEL);
    let nextroot = paths.nextroot();
    assert_eq!(
        label(&nextroot.join("home/staff")).unwrap(),
        HOME_ROOT_LABEL
    );
    assert_eq!(label(&nextroot.join("home/staff/bob")).unwrap(), HOME_LABEL);
    entry::rollback(&paths);

    // The labels in place are not written again.
    let labelled = (ctime(&upper_staff), ctime(&upper_home));
    tick();
    entry::prepare(&paths, &inputs, &FakeHost::default()).expect("the next entry");
    assert_eq!((ctime(&upper_staff), ctime(&upper_home)), labelled);
    entry::rollback(&paths);
}

#[test]
fn a_fresh_home_entry_refused_at_a_parent_of_the_home_labels_it_at_a_later_entry() {
    let _ = Rerun::new(test_path!(
        a_fresh_home_entry_refused_at_a_parent_of_the_home_labels_it_at_a_later_entry
    ))
    .in_user_mount_ns()
    .run(|| refused_at_a_parent_of_the_home_then(PersonaMode::FreshHome));
}

#[test]
fn a_shared_home_entry_after_a_refused_fresh_home_entry_labels_what_it_left() {
    let _ = Rerun::new(test_path!(
        a_shared_home_entry_after_a_refused_fresh_home_entry_labels_what_it_left
    ))
    .in_user_mount_ns()
    .run(|| refused_at_a_parent_of_the_home_then(PersonaMode::SharedHome));
}
