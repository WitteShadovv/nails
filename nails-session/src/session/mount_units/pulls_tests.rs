// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for what a skipped unit pulls in.

use super::*;

/// What the hidden session keeps off for the fstab `fstab`, decided with
/// the decoy's mount table `mounts` and every device there, and the
/// warnings.
fn kept(decoy: &Decoy, fstab: &str, mounts: &str) -> (KeptOff, Vec<String>) {
    let decisions = policy::decide_all(
        &crate::session::fstab::parse_fstab(fstab),
        &parse_mountinfo(mounts),
        Path::new(HIDDEN),
        &|_| true,
    );
    decoy.kept_off(fstab, &decisions)
}

/// The causes `kept` records for its masked units that a target requires.
fn causes(kept: &KeptOff) -> Vec<(String, MaskCause)> {
    kept.required_masks
        .iter()
        .map(|mask| (mask.unit.clone(), mask.cause))
        .collect()
}

/// The warning for `fstab` on `decoy`, whose only skip, that of
/// `/srv/data`, is masked for `cause`.
fn masked(decoy: &Decoy, fstab: &str, cause: MaskCause) -> String {
    let (kept, warnings) = kept(decoy, fstab, ROOT_ONLY);
    assert!(kept.skips.is_empty(), "{fstab}: {:?}", kept.skips);
    assert_eq!(
        causes(&kept),
        [("srv-data.mount".to_string(), cause)],
        "{fstab}: {warnings:?}"
    );
    assert_eq!(warnings.len(), 1, "{fstab}: {warnings:?}");
    warnings[0].clone()
}

/// Assert that the skip of `/srv/data` holds for `fstab` on `decoy`, with no
/// warning.
fn assert_skipped(decoy: &Decoy, fstab: &str) {
    let (kept, warnings) = kept(decoy, fstab, ROOT_ONLY);
    assert!(
        kept.skips
            .iter()
            .any(|skip| skip.units == ["srv-data.mount"]),
        "{fstab}: {:?} {warnings:?}",
        kept.skips
    );
    assert!(warnings.is_empty(), "{fstab}: {warnings:?}");
}

/// Assert that `text` holds each of `parts`.
fn assert_has(text: &str, parts: &[&str]) {
    for part in parts {
        assert!(text.contains(part), "{part}: {text}");
    }
}

/// The noauto disk at /srv/b, which nothing keeps off.
const NOAUTO_B: &str = "/dev/vdb1 /srv/b ext4 noauto 0 2\n";

/// The fstab with the noauto disk at /srv/b and the disk at /srv/data, which
/// is skipped and requires `unit`.
fn data_requiring(unit: &str) -> String {
    format!("{NOAUTO_B}/dev/vdc1 /srv/data ext4 defaults,x-systemd.requires={unit} 0 2\n")
}

/// The unit file of a service that has `body` besides what it runs.
fn service(body: &str) -> String {
    format!("[Unit]\n{body}\n[Service]\nExecStart=/bin/true\n")
}

/// Give `decoy` a `default.target` that wants `network-online.target`: the
/// hidden boot starts both.
fn with_boot(decoy: &Decoy) {
    decoy.write(
        "/usr/lib/systemd/system/default.target",
        "[Unit]\nWants=network-online.target\n",
    );
    decoy.write("/usr/lib/systemd/system/network-online.target", "[Unit]\n");
}

#[test]
fn a_skip_that_pulls_in_a_decoy_mount_nothing_keeps_off_is_masked() {
    // systemd has a mount require the mount of its parent directory and,
    // unless it is a network filesystem that is no bind or loop mount, the
    // mounts for its source. Each pulls in the noauto /srv/b, which the
    // hidden systemd would mount read-write before the skip's condition is
    // tested.
    for (line, how) in [
        (
            "/dev/vdc1 /srv/b/data ext4 defaults 0 2\n",
            "srv-b.mount (the mount of a parent directory)",
        ),
        (
            "/srv/b/data /srv/data none bind 0 0\n",
            "srv-b.mount (the source its line mounts)",
        ),
        (
            "/srv/b/data /srv/data none bind,_netdev 0 0\n",
            "srv-b.mount (the source its line mounts)",
        ),
        (
            "/srv/b/disk.img /srv/data ext4 loop 0 2\n",
            "srv-b.mount (the source its line mounts)",
        ),
        (
            "/srv/b/disk.img /srv/data nfs loop 0 0\n",
            "srv-b.mount (the source its line mounts)",
        ),
        (
            "/dev/vdc1 /srv/data ext4 defaults,x-systemd.requires=/srv/b 0 2\n",
            "srv-b.mount (x-systemd.requires= on its fstab line)",
        ),
        (
            "/dev/vdc1 /srv/data ext4 defaults,x-systemd.requires=srv-b.mount 0 2\n",
            "srv-b.mount (x-systemd.requires= on its fstab line)",
        ),
        (
            "/dev/vdc1 /srv/data ext4 defaults,x-systemd.requires-mounts-for=/srv/b/c 0 2\n",
            "srv-b.mount (x-systemd.requires-mounts-for= on its fstab line)",
        ),
        (
            "/dev/vdc1 /srv/data ext4 defaults,x-systemd.wants-mounts-for=/srv/b/c 0 2\n",
            "srv-b.mount (x-systemd.wants-mounts-for= on its fstab line)",
        ),
    ] {
        let fstab = format!("{NOAUTO_B}{line}");
        let decoy = Decoy::new();
        let (kept, warnings) = kept(&decoy, &fstab, ROOT_ONLY);
        assert!(kept.skips.is_empty(), "{line}: {:?}", kept.skips);
        assert!(
            !kept.required_masks.is_empty()
                && kept
                    .required_masks
                    .iter()
                    .all(|mask| mask.cause == MaskCause::PullsInMount),
            "{line}: {:?}",
            kept.required_masks
        );
        assert_eq!(warnings.len(), 1, "{line}: {warnings:?}");
        assert_has(
            &warnings[0],
            &[how, "which the session does not keep off", "decoy's disk"],
        );
    }
    // A network filesystem's source is the server's: no pull.
    let decoy = Decoy::new();
    with_boot(&decoy);
    let (kept, _) = kept(
        &decoy,
        &format!("{NOAUTO_B}server:/srv/b /srv/data nfs defaults 0 0\n"),
        ROOT_ONLY,
    );
    assert!(
        kept.required_masks
            .iter()
            .all(|mask| mask.cause != MaskCause::PullsInMount),
        "{:?}",
        kept.required_masks
    );
}

#[test]
fn a_skip_is_masked_for_what_the_units_it_pulls_in_pull_in() {
    let mounted = MaskCause::PullsInMount;
    let first = "prep.service (x-systemd.requires= on its fstab line), which pulls in";
    // A service the line requires, which requires the mounts for a path
    // below /srv/b, or runs there.
    for (body, how) in [
        (
            "RequiresMountsFor=/srv/b/state",
            "srv-b.mount (RequiresMountsFor=)",
        ),
        (
            "WantsMountsFor=/srv/b/state",
            "srv-b.mount (WantsMountsFor=)",
        ),
        (
            "[Service]\nWorkingDirectory=/srv/b",
            "srv-b.mount (a directory it runs in)",
        ),
        (
            "[Service]\nRootDirectory=/srv/b/root",
            "srv-b.mount (a directory it runs in)",
        ),
        (
            "[Service]\nRootImage=/srv/b/root.img",
            "srv-b.mount (a directory it runs in)",
        ),
    ] {
        let decoy = Decoy::new();
        decoy.write("/etc/systemd/system/prep.service", &service(body));
        let warning = masked(&decoy, &data_requiring("prep.service"), mounted);
        assert_has(&warning, &[first, how]);
    }
    // A directory it keeps, or its private /tmp, below /var, which a noauto
    // disk holds.
    for (body, how) in [
        (
            "[Service]\nStateDirectory=prep:link",
            "var.mount (a directory it keeps)",
        ),
        (
            "[Service]\nPrivateTmp=disconnected",
            "var.mount (its private /tmp)",
        ),
    ] {
        let decoy = Decoy::new();
        decoy.write("/etc/systemd/system/prep.service", &service(body));
        let fstab = "/dev/vdb1 /var ext4 noauto 0 2\n\
                     /dev/vdc1 /srv/data ext4 defaults,x-systemd.requires=prep.service 0 2\n";
        let warning = masked(&decoy, fstab, mounted);
        assert_has(&warning, &[first, how]);
    }
    // A tmpfs below the noauto disk is RAM, but its own parent is the disk.
    let decoy = Decoy::new();
    let warning = masked(
        &decoy,
        &format!(
            "{NOAUTO_B}tmpfs /srv/b/tmp tmpfs noauto 0 0\n\
             /dev/vdc1 /srv/data ext4 defaults,x-systemd.requires=srv-b-tmp.mount 0 2\n"
        ),
        mounted,
    );
    assert_has(
        &warning,
        &[
            "srv-b-tmp.mount (x-systemd.requires= on its fstab line), which pulls in srv-b.mount \
             (the mount of a parent directory)",
        ],
    );
}

/// A case of what the units the line requires start or name: that unit,
/// the unit files, and what the walk reaches.
type Case = (&'static str, Vec<(&'static str, String)>, &'static str);

/// Assert that the skip of `/srv/data` is masked in each of `cases`, with a
/// warning that names what the walk reaches.
fn assert_reached(cases: Vec<Case>) {
    for (unit, files, reached) in cases {
        let decoy = Decoy::new();
        with_boot(&decoy);
        for (path, text) in &files {
            decoy.write(path, text);
        }
        decoy.link(
            "/etc/systemd/system/extra.target.wants/srv-b.mount",
            "../srv-b.mount",
        );
        decoy.link(
            "/usr/lib/systemd/system/prep@.service.wants/side@.service",
            "../side@.service",
        );
        let warning = masked(&decoy, &data_requiring(unit), MaskCause::PullsInMount);
        assert_has(&warning, &[reached]);
    }
}

#[test]
fn a_skip_is_masked_for_the_units_its_pulls_start() {
    let mounted = MaskCause::PullsInMount;
    let needs_b = service("RequiresMountsFor=/srv/b");
    let cases: Vec<Case> = vec![
        // A socket the service takes, which listens below /srv/b.
        (
            "prep.service",
            vec![
                (
                    "/etc/systemd/system/prep.service",
                    service("[Service]\nSockets=prep.socket"),
                ),
                (
                    "/etc/systemd/system/prep.socket",
                    "[Socket]\nListenStream=/srv/b/sock\n".to_string(),
                ),
            ],
            "prep.socket (Sockets=), which pulls in srv-b.mount (a path it listens on)",
        ),
        // A D-Bus service takes the bus's socket.
        (
            "prep.service",
            vec![
                (
                    "/etc/systemd/system/prep.service",
                    service("[Service]\nType=dbus\nBusName=org.example.Prep"),
                ),
                (
                    "/etc/systemd/system/dbus.socket",
                    "[Socket]\nListenStream=/srv/b/bus\n".to_string(),
                ),
            ],
            "dbus.socket (its D-Bus name), which pulls in srv-b.mount",
        ),
        // A path unit watching the noauto disk's mount point itself.
        (
            "prep.path",
            vec![(
                "/etc/systemd/system/prep.path",
                "[Path]\nPathExists=/srv/b\nUnit=other.service\n".to_string(),
            )],
            "srv-b.mount (a path it watches)",
        ),
        // A timer, which starts its service later.
        (
            "prep.timer",
            vec![
                (
                    "/etc/systemd/system/prep.timer",
                    "[Timer]\nOnBootSec=1\n".to_string(),
                ),
                ("/etc/systemd/system/prep.service", needs_b.clone()),
            ],
            "prep.service (the unit it starts), which pulls in srv-b.mount",
        ),
        // A socket that accepts each connection starts its template.
        (
            "prep.socket",
            vec![
                (
                    "/etc/systemd/system/prep.socket",
                    "[Socket]\nListenStream=1234\nAccept=yes\n".to_string(),
                ),
                ("/etc/systemd/system/prep@.service", needs_b.clone()),
            ],
            "prep@.service (the service it starts)",
        ),
        // The unit the service starts when it fails.
        (
            "prep.service",
            vec![
                (
                    "/etc/systemd/system/prep.service",
                    service("OnFailure=rescue.service"),
                ),
                ("/etc/systemd/system/rescue.service", needs_b.clone()),
            ],
            "rescue.service (OnFailure=), which pulls in srv-b.mount",
        ),
        // Its log namespace's sockets.
        (
            "prep.service",
            vec![
                (
                    "/etc/systemd/system/prep.service",
                    service("[Service]\nLogNamespace=b"),
                ),
                (
                    "/etc/systemd/system/systemd-journald@.socket",
                    "[Socket]\nListenStream=/srv/%i/journal\n".to_string(),
                ),
                (
                    "/etc/systemd/system/systemd-journald-varlink@.socket",
                    "[Socket]\nListenStream=/run/%i\n".to_string(),
                ),
            ],
            "systemd-journald@b.socket (its log namespace), which pulls in srv-b.mount",
        ),
    ];
    assert_reached(cases);
    // A network filesystem's mount wants the network, which the boot does
    // not start here, and what that target links in.
    let decoy = Decoy::new();
    decoy.write("/usr/lib/systemd/system/network-online.target", "[Unit]\n");
    decoy.link(
        "/usr/lib/systemd/system/network-online.target.wants/srv-b.mount",
        "../srv-b.mount",
    );
    let warning = masked(
        &decoy,
        &format!("{NOAUTO_B}server:/x /srv/data nfs defaults 0 0\n"),
        mounted,
    );
    assert_has(
        &warning,
        &["network-online.target (the network its line mounts over), which pulls in srv-b.mount"],
    );
}

#[test]
fn a_skip_is_masked_for_the_slices_devices_and_targets_its_pulls_name() {
    let cases: Vec<Case> = vec![
        // The slice the service runs in, by a drop-in without a file.
        (
            "prep.service",
            vec![
                ("/etc/systemd/system/prep.service", service("")),
                (
                    "/etc/systemd/system/system.slice.d/b.conf",
                    "[Unit]\nRequiresMountsFor=/srv/b\n".to_string(),
                ),
            ],
            "system.slice (its slice), which pulls in srv-b.mount",
        ),
        // A slice it names, and its parent.
        (
            "prep.service",
            vec![
                (
                    "/etc/systemd/system/prep.service",
                    service("[Service]\nSlice=own-b.slice"),
                ),
                (
                    "/etc/systemd/system/own.slice",
                    "[Unit]\nRequiresMountsFor=/srv/b\n".to_string(),
                ),
            ],
            "own-b.slice (its slice), which pulls in own.slice (its parent slice)",
        ),
        // A device's drop-in, for a device the line requires.
        (
            "/dev/vdz",
            vec![(
                "/etc/systemd/system/dev-vdz.device.d/b.conf",
                "[Unit]\nWants=srv-b.mount\n".to_string(),
            )],
            "dev-vdz.device (x-systemd.requires= on its fstab line), which pulls in srv-b.mount \
             (Wants=)",
        ),
        // A target the boot does not start, and what it links in.
        (
            "prep.service",
            vec![
                (
                    "/etc/systemd/system/prep.service",
                    service("Wants=extra.target"),
                ),
                ("/etc/systemd/system/extra.target", "[Unit]\n".to_string()),
            ],
            "extra.target (Wants=), which pulls in srv-b.mount (a link in its .wants directory)",
        ),
        // A template's link names the instance of a template.
        (
            "prep@x.service",
            vec![
                ("/usr/lib/systemd/system/prep@.service", service("")),
                (
                    "/usr/lib/systemd/system/side@.service",
                    service("RequiresMountsFor=/srv/b/%i"),
                ),
            ],
            "side@x.service (a link in its .wants directory), which pulls in srv-b.mount",
        ),
    ];
    assert_reached(cases);
}

#[test]
fn a_skip_is_masked_for_what_the_names_its_pulls_share_pull_in() {
    let mounted = MaskCause::PullsInMount;
    // The line names an alias: the unit it names has a drop-in of its own.
    let decoy = Decoy::new();
    decoy.write("/etc/systemd/system/prep.service", &service(""));
    decoy.link("/etc/systemd/system/alias.service", "prep.service");
    decoy.write(
        "/etc/systemd/system/prep.service.d/b.conf",
        "[Unit]\nRequiresMountsFor=/srv/b\n",
    );
    let warning = masked(&decoy, &data_requiring("alias.service"), mounted);
    assert_has(
        &warning,
        &["prep.service (a name it shares), which pulls in srv-b.mount"],
    );
    // The line names the unit: an alias of it has links of its own.
    decoy.write("/usr/lib/systemd/system/real.service", &service(""));
    decoy.link(
        "/etc/systemd/system/other.service",
        "/usr/lib/systemd/system/real.service",
    );
    decoy.link(
        "/etc/systemd/system/other.service.wants/srv-b.mount",
        "../srv-b.mount",
    );
    let warning = masked(&decoy, &data_requiring("real.service"), mounted);
    assert_has(
        &warning,
        &["other.service (a name it shares), which pulls in srv-b.mount"],
    );
    // An alias of a template names each instance.
    decoy.write("/usr/lib/systemd/system/tpl@.service", &service(""));
    decoy.link(
        "/etc/systemd/system/al@.service",
        "/usr/lib/systemd/system/tpl@.service",
    );
    decoy.link(
        "/etc/systemd/system/al@.service.wants/srv-b.mount",
        "../srv-b.mount",
    );
    let warning = masked(&decoy, &data_requiring("tpl@x.service"), mounted);
    assert_has(
        &warning,
        &["al@x.service (a name it shares), which pulls in srv-b.mount"],
    );
    // A loop of alias links ends where it began.
    let decoy = Decoy::new();
    decoy.write("/etc/systemd/system/prep.service", &service(""));
    decoy.link("/etc/systemd/system/loop-a.service", "loop-b.service");
    decoy.link("/etc/systemd/system/loop-b.service", "loop-a.service");
    std::fs::create_dir_all(decoy.at("/etc/systemd/system/loop-a.service.d")).unwrap();
    assert_skipped(&decoy, &data_requiring("prep.service"));
    // A chain of alias links longer than NAILS follows may name any unit.
    for n in 0..10 {
        decoy.link(
            &format!("/etc/systemd/system/hop{n}.service"),
            &format!("hop{}.service", n + 1),
        );
    }
    std::fs::create_dir_all(decoy.at("/etc/systemd/system/hop0.service.d")).unwrap();
    let warning = masked(
        &decoy,
        &data_requiring("prep.service"),
        MaskCause::Undetermined,
    );
    assert_has(
        &warning,
        &["the alias links of hop0.service cannot be followed to their end"],
    );
}

#[test]
fn a_skip_whose_pulls_cannot_all_be_followed_is_masked() {
    let undetermined = MaskCause::Undetermined;
    let decoy = Decoy::new();
    std::fs::create_dir_all(decoy.at("/etc/systemd/system/dir.service")).unwrap();
    decoy.write(
        "/etc/systemd/system/prep.service",
        &service("RequiresMountsFor=/home/%u"),
    );
    for (unit, part) in [
        // A unit that does not load: a generator of the hidden session may
        // make it.
        ("gone.service", "gone.service does not load"),
        // Any specifier in an fstab option, and one NAILS does not resolve in
        // a unit file.
        ("prep-%H.service", "with a specifier"),
        (
            "prep.service",
            "prep.service names /home/%u by a specifier NAILS does not resolve",
        ),
        ("noname", "which is no unit name"),
        // A unit file that is no file.
        (
            "dir.service",
            "the unit files of dir.service cannot be read",
        ),
    ] {
        let warning = masked(&decoy, &data_requiring(unit), undetermined);
        assert_has(&warning, &[part]);
    }
    // A chain deeper than the walk follows.
    let decoy = Decoy::new();
    for n in 0..pulls::MAX_DEPTH + 2 {
        decoy.write(
            &format!("/etc/systemd/system/step{n}.service"),
            &service(&format!("Requires=step{}.service", n + 1)),
        );
    }
    let warning = masked(&decoy, &data_requiring("step0.service"), undetermined);
    assert_has(&warning, &["more than 8 deep"]);
    // A unit that pulls in more units than the walk follows.
    let decoy = Decoy::new();
    let many: Vec<String> = (0..pulls::MAX_UNITS)
        .map(|n| format!("many{n}.service"))
        .collect();
    decoy.write(
        "/etc/systemd/system/wide.service",
        &service(&format!("Wants={}", many.join(" "))),
    );
    let warning = masked(&decoy, &data_requiring("wide.service"), undetermined);
    assert_has(&warning, &["more than 256 units"]);
}

#[test]
fn a_skip_is_masked_where_its_links_cannot_be_read() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        // Root reads through any mode.
        return;
    }
    let decoy = Decoy::new();
    let etc = decoy.at("/etc/systemd/system");
    std::fs::create_dir_all(&etc).unwrap();
    let mode = |mode| std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(mode));
    // A unit directory NAILS may look up names in, but not list.
    mode(0o311).unwrap();
    let (kept, warnings) = kept(&decoy, &data_requiring("srv-b.mount"), ROOT_ONLY);
    // Nor read a link in.
    mode(0o000).unwrap();
    let alias = decoy.dirs().alias_of("prep.service");
    mode(0o755).unwrap();
    assert_eq!(alias, Err(()));
    assert!(kept.skips.is_empty(), "{:?}", kept.skips);
    assert_eq!(
        causes(&kept),
        [("srv-data.mount".to_string(), MaskCause::Undetermined)]
    );
    assert_has(
        &warnings[0],
        &["NAILS cannot list the unit directory /etc/systemd/system"],
    );
}

#[test]
fn a_skip_whose_pulls_mount_nothing_of_a_disk_stays_a_skip() {
    let child = "/dev/vdc1 /srv/data ext4 defaults 0 2\n";
    for (fstab, mounts) in [
        // The parent is a tmpfs, or a host share.
        ("tmpfs /srv tmpfs defaults 0 0\n", ROOT_ONLY),
        ("share /srv virtiofs defaults 0 0\n", ROOT_ONLY),
        // The parent is mounted now: the session overlays it.
        (
            "/dev/vdb1 /srv ext4 defaults 0 2\n",
            "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n2 1 8:17 / /srv rw - ext4 /dev/vdb1 rw\n",
        ),
        // The parent is skipped as well: a target requires it too.
        ("/dev/vdb1 /srv ext4 defaults 0 2\n", ROOT_ONLY),
        // No unit file and no line: nothing to start.
        ("", ROOT_ONLY),
    ] {
        let decoy = Decoy::new();
        let lines = format!("{fstab}{child}");
        let (kept, warnings) = kept(&decoy, &lines, mounts);
        assert!(
            kept.skips
                .iter()
                .any(|skip| skip.units == ["srv-data.mount"]),
            "{fstab}: {:?} {warnings:?}",
            kept.skips
        );
        assert!(warnings.is_empty(), "{fstab}: {warnings:?}");
    }
    // A service the line requires, from a template, that binds to a device by
    // a specifier, wants a target the boot starts anyway, and whose slice
    // and its parent have no file.
    let decoy = Decoy::new();
    with_boot(&decoy);
    decoy.write(
        "/usr/lib/systemd/system/prep@.service",
        &service("Wants=network-online.target\nBindsTo=dev-%i.device"),
    );
    // What the target the boot starts links in is the boot's own.
    decoy.link(
        "/usr/lib/systemd/system/network-online.target.wants/srv-b.mount",
        "../srv-b.mount",
    );
    assert_skipped(&decoy, &data_requiring("prep@vdc1.service"));
    // A masked unit pulls in nothing.
    decoy.link("/etc/systemd/system/masked.service", "/dev/null");
    decoy.write(
        "/etc/systemd/system/masked.service.d/b.conf",
        "[Unit]\nRequiresMountsFor=/srv/b\n",
    );
    assert_skipped(&decoy, &data_requiring("masked.service"));
    // A device the line requires, and a network filesystem's source, are no
    // mounts, and a unit of the decoy's own that mounts a host share or RAM
    // reaches no disk.
    assert_skipped(&decoy, &data_requiring("/dev/vdz"));
    for (unit, vfstype) in [("srv-share.mount", "virtiofs"), ("srv-ram.mount", "tmpfs")] {
        decoy.write(
            &format!("/etc/systemd/system/{unit}"),
            &format!("[Mount]\nWhat=share\nType={vfstype}\n"),
        );
        assert_skipped(&decoy, &data_requiring(unit));
    }
    decoy.write(
        "/etc/systemd/system/srv-disk.mount",
        "[Mount]\nWhat=/dev/vdq1\nType=ext4\n",
    );
    masked(
        &decoy,
        &data_requiring("srv-disk.mount"),
        MaskCause::PullsInMount,
    );
    assert_skipped(&decoy, "server:/srv/b /srv/data nfs defaults 0 0\n");
}

#[test]
fn a_unit_of_another_kind_named_by_a_specifier_resolves_to_its_own() {
    // The fstab generator's makefs unit for a skipped mount binds to its
    // device by a specifier: the device pulls in nothing, so the skip holds.
    let decoy = Decoy::new();
    decoy.write(
        "/run/systemd/generator/systemd-makefs@dev-vdc1.service",
        "[Unit]\nBindsTo=%i.device\nAfter=%i.device\nBefore=systemd-fsck@%i.service srv-data.mount\n\
         [Service]\nType=oneshot\n",
    );
    let (skipped, warnings) = kept(
        &decoy,
        "/dev/vdc1 /srv/data ext4 defaults,x-systemd.makefs 0 2\n",
        ROOT_ONLY,
    );
    assert_eq!(skipped.skips.len(), 1, "{:?}", skipped.masks);
    assert!(warnings.is_empty(), "{warnings:?}");
    // A mount named by a specifier NAILS does not resolve is one it cannot
    // tell.
    decoy.write(
        "/run/systemd/generator/systemd-makefs@dev-vdc1.service",
        "[Unit]\nRequires=srv-%H.mount\n[Service]\nType=oneshot\n",
    );
    let warning = masked(
        &decoy,
        "/dev/vdc1 /srv/data ext4 defaults,x-systemd.makefs 0 2\n",
        MaskCause::Undetermined,
    );
    assert_has(&warning, &["by a specifier NAILS does not resolve"]);
}

#[test]
fn a_skip_that_requires_a_masked_mount_is_warned_of() {
    // The parent has nofail and is not mounted now: masked. The child is
    // skipped, but PID 1 cannot start it with its parent masked, so the
    // boot target that requires it is not reached.
    let decoy = Decoy::new();
    let (parent, warnings) = kept(
        &decoy,
        "/dev/vdb1 /srv ext4 nofail 0 2\n/dev/vdc1 /srv/data ext4 defaults 0 2\n",
        ROOT_ONLY,
    );
    assert_eq!(parent.masks, ["srv.mount"]);
    assert_eq!(parent.skips.len(), 1, "{:?}", parent.skips);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert_has(
        &warnings[0],
        &[
            "srv-data.mount is skipped, but it requires srv.mount (the mount of a parent \
             directory), which the session masks",
            "not reached",
        ],
    );
    // One it only wants starts without it.
    let decoy = Decoy::new();
    let (wanted, warnings) = kept(
        &decoy,
        "/dev/vdb1 /srv ext4 nofail 0 2\n\
         /dev/vdc1 /srv/data ext4 defaults,x-systemd.wants-mounts-for=/srv/x 0 2\n\
         /dev/vdd1 /srv/x ext4 nofail 0 2\n",
        ROOT_ONLY,
    );
    assert_eq!(wanted.skips.len(), 1, "{:?}", wanted.skips);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(!warnings[0].contains("srv-x.mount"), "{}", warnings[0]);
}

#[test]
fn the_units_a_unit_pulls_in_are_read_from_every_source_each_once() {
    let decoy = Decoy::new();
    decoy.write(
        "/etc/systemd/system/srv-data-sub.mount",
        "[Unit]\nRequires=srv-a.mount systemd-fsck@dev-vdc1.service dev-vdc1.device\n\
         Wants=srv-b.mount\nBindsTo=srv-a.mount\nWantsMountsFor=/srv/w\nOnSuccess=done.service\n\
         [Mount]\nWhat=/srv/src\nWhere=/srv/data/sub\nType=none\nOptions=bind\n",
    );
    decoy.link(
        "/etc/systemd/system/srv-data-sub.mount.upholds/srv-u.mount",
        "../srv-u.mount",
    );
    decoy.link(
        "/etc/systemd/system/mount.wants/srv-t.mount",
        "../srv-t.mount",
    );
    let fstab = crate::session::fstab::parse_fstab(
        "/srv/src /srv/data/sub none bind,x-systemd.requires=/dev/vdq1,x-systemd.requires=srv-r.swap 0 0\n",
    );
    let graph = deps::Graph::new(decoy.dirs(), &fstab, &[]);
    let pulled = deps::edges(&graph, "srv-data-sub.mount").unwrap();
    let shown: Vec<(&str, bool, bool)> = pulled
        .iter()
        .map(|edge| (edge.unit.as_str(), edge.required, edge.start))
        .collect();
    let expected = [
        ("srv-data.mount", true, true),
        ("srv.mount", true, true),
        ("srv-a.mount", true, true),
        ("systemd-fsck@dev-vdc1.service", true, true),
        ("dev-vdc1.device", true, true),
        ("srv-b.mount", false, true),
        ("srv-w.mount", false, true),
        ("done.service", false, false),
        ("srv-src.mount", true, true),
        ("system.slice", true, true),
        ("srv-u.mount", false, true),
        ("srv-t.mount", false, true),
        ("dev-vdq1.device", true, true),
        ("srv-r.swap", true, true),
    ];
    for edge in expected {
        assert!(shown.contains(&edge), "{edge:?}: {shown:?}");
    }
    assert_eq!(shown.len(), expected.len(), "each once: {shown:?}");
    // A swap file's directories and a swap device's device, the swap's
    // slice for each.
    decoy.write(
        "/etc/systemd/system/srv-swap-file.swap",
        "[Swap]\nWhat=/srv/swap/file\n",
    );
    decoy.write(
        "/etc/systemd/system/dev-vdz.swap",
        "[Swap]\nWhat=/dev/vdz\n",
    );
    let units = |name: &str| -> Vec<String> {
        deps::edges(&graph, name)
            .unwrap()
            .into_iter()
            .map(|edge| edge.unit)
            .collect()
    };
    assert_eq!(
        units("srv-swap-file.swap"),
        [
            "system.slice",
            "srv-swap-file.mount",
            "srv-swap.mount",
            "srv.mount"
        ]
    );
    assert_eq!(
        units("dev-vdz.swap"),
        [
            "system.slice",
            "dev-vdz.mount",
            "dev.mount",
            "dev-vdz.device"
        ]
    );
    // An instance's slice is its template's.
    decoy.write(
        "/usr/lib/systemd/system/systemd-fsck@.service",
        "[Service]\n",
    );
    assert_eq!(
        units("systemd-fsck@dev-vdc1.service"),
        ["system-systemd\\x2dfsck.slice"]
    );
    // An automount's parents and the mount it starts.
    assert_eq!(units("srv-auto.automount"), ["srv.mount", "srv-auto.mount"]);
    // A slice's parent, and none for the root slice.
    assert_eq!(units("system-systemd\\x2dfsck.slice"), ["system.slice"]);
    assert_eq!(units("a.slice"), ["-.slice"]);
    assert!(units("-.slice").is_empty());
}

#[test]
fn the_boot_starts_default_target_and_the_targets_it_pulls_in() {
    let decoy = Decoy::new();
    // default.target names graphical.target, which requires
    // multi-user.target; a link names one of the boot's targets too.
    decoy.link("/usr/lib/systemd/system/default.target", "graphical.target");
    decoy.write(
        "/usr/lib/systemd/system/graphical.target",
        "[Unit]\nRequires=multi-user.target\nWants=display-manager.service\n\
         OnFailure=emergency.target\n",
    );
    decoy.write(
        "/usr/lib/systemd/system/multi-user.target",
        "[Unit]\nRequires=basic.target\n",
    );
    decoy.write("/usr/lib/systemd/system/basic.target", "[Unit]\n");
    decoy.link(
        "/etc/systemd/system/multi-user.target.wants/remote-fs.target",
        "/usr/lib/systemd/system/remote-fs.target",
    );
    decoy.write("/usr/lib/systemd/system/remote-fs.target", "[Unit]\n");
    // A link to a target outside the unit directories may be a unit file of
    // its own under the link's name: what it links to is no boot target.
    decoy.write("/opt/kiosk.target", "[Unit]\n");
    decoy.link("/etc/systemd/system/odd.target", "/opt/kiosk.target");
    decoy.link(
        "/etc/systemd/system/remote-fs.target.wants/odd.target",
        "../odd.target",
    );
    let graph = deps::Graph::new(decoy.dirs(), &[], &[]);
    let mut boot = deps::boot_targets(&graph);
    boot.sort();
    assert_eq!(
        boot,
        [
            "basic.target",
            "default.target",
            "graphical.target",
            "multi-user.target",
            "odd.target",
            "remote-fs.target"
        ]
    );
}

#[test]
fn an_alias_is_read_as_systemd_reads_its_link() {
    let decoy = Decoy::new();
    decoy.write("/usr/lib/systemd/system/real.service", "[Service]\n");
    decoy.write("/usr/lib/systemd/system/tpl@.service", "[Service]\n");
    // A link in a unit directory to a unit file of another name there is an
    // alias for sure; one to a file elsewhere may be a linked unit file.
    decoy.link("/etc/systemd/system/same-dir.service", "other.service");
    decoy.link(
        "/etc/systemd/system/abs.service",
        "/usr/lib/systemd/system/real.service",
    );
    decoy.link(
        "/etc/systemd/system/rel.service",
        "../../../usr/lib/systemd/system/real.service",
    );
    decoy.link(
        "/etc/systemd/system/run.service",
        "/run/systemd/generator/real.service",
    );
    decoy.link("/etc/systemd/system/outside.service", "/opt/real.service");
    // No alias: a mask, a unit file of the same name, one of another type or
    // template-ness, and a plain file.
    decoy.link("/etc/systemd/system/masked.service", "/dev/null");
    decoy.link(
        "/etc/systemd/system/real.service",
        "/usr/lib/systemd/system/real.service",
    );
    decoy.link("/etc/systemd/system/kind.service", "real.socket");
    decoy.link("/etc/systemd/system/plain.service", "tpl@.service");
    decoy.write("/etc/systemd/system/file.service", "[Service]\n");
    decoy.link("/etc/systemd/system/al@.service", "tpl@.service");
    // The entry in the unit directory searched first is the one.
    decoy.write("/etc/systemd/system/first.service", "[Service]\n");
    decoy.link("/usr/lib/systemd/system/first.service", "real.service");
    let dirs = decoy.dirs();
    for (name, alias) in [
        ("same-dir.service", Some(("other.service", true))),
        ("abs.service", Some(("real.service", true))),
        ("rel.service", Some(("real.service", true))),
        ("run.service", Some(("real.service", true))),
        ("outside.service", Some(("real.service", false))),
        ("masked.service", None),
        ("real.service", None),
        ("kind.service", None),
        ("plain.service", None),
        ("file.service", None),
        ("first.service", None),
        ("none.service", None),
        // An instance with no entry of its own follows its template's link.
        ("al@x.service", Some(("tpl@x.service", true))),
        ("tpl@x.service", None),
    ] {
        let found = dirs.alias_of(name).unwrap();
        assert_eq!(
            found.as_ref().map(|(alias, sure)| (alias.as_str(), *sure)),
            alias,
            "{name}"
        );
    }
}

#[test]
fn what_systemd_starts_with_a_unit_is_read_from_its_settings() {
    let decoy = Decoy::new();
    let long = format!("{}.service", "l".repeat(250));
    for (path, text) in [
        (
            "/etc/systemd/system/all.service",
            "[Unit]\nRequires=a.service\nOnFailure=f.service\n\
             Requires=bad .hidden.service a.unknown LONG\n\
             [Service]\nType=dbus\nWorkingDirectory=-/srv/gone\nWorkingDirectory=~\n\
             RootDirectory=/srv/root\nStateDirectory=st\nCacheDirectory=ca\nLogsDirectory=lo\n\
             ConfigurationDirectory=co\nRuntimeDirectory=ru\nPrivateTmp=no\nLogNamespace=\n\
             Sockets=s.socket\nSlice=\n",
        ),
        (
            "/etc/systemd/system/all.socket",
            "[Socket]\nListenStream=/run/x.sock\nListenDatagram=%t/y.sock\nListenFIFO=/srv/fifo\n\
             ListenStream=127.0.0.1:80\nBindToDevice=.e-0\nService=other.service\nPrivateTmp=yes\n",
        ),
        ("/etc/systemd/system/acc.socket", "[Socket]\nAccept=on\n"),
        ("/etc/systemd/system/t.timer", "[Timer]\nPersistent=true\n"),
        (
            "/etc/systemd/system/p.path",
            "[Path]\nPathExistsGlob=/srv/g/*.lock\nUnit=u.target\n",
        ),
        (
            "/etc/systemd/system/srv-r.mount",
            "[Mount]\nWhat=/dev/root\nType=ext4\n",
        ),
        (
            "/etc/systemd/system/srv-n.mount",
            "[Mount]\nWhat=server:/x\nType=fuse.sshfs\n",
        ),
        (
            "/etc/systemd/system/srv-q-sub.mount",
            "[Unit]\nWants=srv-z.mount\nRequiresMountsFor=/srv/z\n[Mount]\nWhat=tmpfs\nType=tmpfs\n",
        ),
        ("/etc/systemd/system/k.socket", "[Socket]\n"),
        ("/etc/systemd/system/plain.service", "[Service]\n"),
    ] {
        decoy.write(path, &text.replace("LONG", &long));
    }
    decoy.link(
        "/etc/systemd/system/k.socket.wants/k.service",
        "../k.service",
    );
    decoy.link(
        "/etc/systemd/system/plain.service.wants/x@.service",
        "../x@.service",
    );
    let graph = deps::Graph::new(decoy.dirs(), &[], &[]);
    let edges = |name: &str| -> Vec<(String, bool, bool)> {
        deps::edges(&graph, name)
            .unwrap()
            .into_iter()
            .map(|edge| (edge.unit, edge.required, edge.start))
            .collect()
    };
    let expect = |list: &[(&str, bool, bool)]| -> Vec<(String, bool, bool)> {
        list.iter()
            .map(|(unit, required, start)| (unit.to_string(), *required, *start))
            .collect()
    };
    let (r, w, later) = ((true, true), (false, true), (false, false));
    let edge = |unit: &'static str, (required, start): (bool, bool)| (unit, required, start);
    assert_eq!(
        edges("all.service"),
        expect(&[
            edge("a.service", r),
            edge("f.service", later),
            edge("srv-root.mount", w),
            edge("srv.mount", w),
            edge("var-lib-st.mount", r),
            edge("var-lib.mount", r),
            edge("var.mount", r),
            edge("var-cache-ca.mount", r),
            edge("var-cache.mount", r),
            edge("var-log-lo.mount", r),
            edge("var-log.mount", r),
            edge("etc-co.mount", r),
            edge("etc.mount", r),
            edge("run-ru.mount", r),
            edge("run.mount", r),
            edge("system.slice", r),
            edge("s.socket", w),
            edge("dbus.socket", r),
        ])
    );
    assert_eq!(
        edges("all.socket"),
        expect(&[
            edge("tmp.mount", w),
            edge("var-tmp.mount", w),
            edge("var.mount", w),
            edge("system.slice", r),
            edge("run-x.sock.mount", r),
            edge("run.mount", r),
            edge("run-y.sock.mount", r),
            edge("srv-fifo.mount", r),
            edge("srv.mount", r),
            edge("sys-subsystem-net-devices-\\x2ee\\x2d0.device", r),
            edge("other.service", later),
        ])
    );
    assert_eq!(
        edges("acc.socket"),
        expect(&[edge("system.slice", r), edge("acc@.service", later)])
    );
    assert_eq!(
        edges("t.timer"),
        expect(&[
            edge("var-lib-systemd-timers.mount", r),
            edge("var-lib-systemd.mount", r),
            edge("var-lib.mount", r),
            edge("var.mount", r),
            edge("t.service", later),
        ])
    );
    assert_eq!(
        edges("p.path"),
        expect(&[
            edge("srv-g-\\x2a.lock.mount", r),
            edge("srv-g.mount", r),
            edge("srv.mount", r),
            edge("u.target", later),
        ])
    );
    // /dev/root is no device of its own.
    assert_eq!(
        edges("srv-r.mount"),
        expect(&[
            edge("srv.mount", r),
            edge("system.slice", r),
            edge("dev-root.mount", r),
            edge("dev.mount", r),
        ])
    );
    // A network filesystem's source is the server's; its mount wants the
    // network.
    assert_eq!(
        edges("srv-n.mount"),
        expect(&[
            edge("srv.mount", r),
            edge("system.slice", r),
            edge("network-online.target", w),
        ])
    );
    // A want the unit also requires is a requirement, how it requires it
    // named; a trigger the unit also wants by a link starts with it.
    let pulled = deps::edges(&graph, "srv-q-sub.mount").unwrap();
    let z = pulled
        .iter()
        .find(|edge| edge.unit == "srv-z.mount")
        .unwrap();
    assert_eq!(
        (z.required, z.start, z.how),
        (true, true, "RequiresMountsFor=")
    );
    assert_eq!(
        edges("k.socket"),
        expect(&[edge("system.slice", r), edge("k.service", w)])
    );
    // A template linked for a unit that is no instance names nothing.
    assert_eq!(edges("plain.service"), expect(&[edge("system.slice", r)]));
}
