// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for preparing the entry into the hidden root.

use super::*;
use crate::session::fstab::{parse_fstab, parse_in_root};
use nails_teardown::mountinfo::parse_mountinfo;

#[test]
fn the_decoy_root_is_read_from_the_mount_table() {
    let ext4 = parse_mountinfo("1 0 8:2 / / rw - ext4 /dev/vda2 rw\n");
    let root = decoy_root_of(&ext4, Path::new("/")).unwrap();
    assert_eq!(root.source, Path::new("/dev/vda2"));
    assert_eq!(root.fstype, "ext4");
    assert_eq!(root.data, None);
    let btrfs = parse_mountinfo("1 0 0:30 /@ / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@\n");
    assert_eq!(
        decoy_root_of(&btrfs, Path::new("/"))
            .unwrap()
            .data
            .as_deref(),
        Some("subvol=/@")
    );
}

#[test]
fn a_root_that_cannot_be_mounted_again_is_refused() {
    for table in [
        "1 0 0:20 / / rw - tmpfs none rw\n",
        "1 0 0:21 / / rw - overlay overlay rw,lowerdir=/a\n",
        "1 0 0:22 / / rw - zfs /dev/zd0 rw\n",
        "1 0 8:2 /sub / rw - ext4 /dev/vda2 rw\n",
        // A btrfs bind of a plain folder inside the subvolume /@: the mount
        // root (/@/srv) is not the subvolume (subvol=/@), so the way back
        // cannot mount it again by subvol.
        "1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@\n",
    ] {
        let entries = parse_mountinfo(table);
        assert!(decoy_root_of(&entries, Path::new("/")).is_err(), "{table}");
    }
}

#[test]
fn a_btrfs_bind_of_a_plain_folder_is_refused_by_path() {
    // The refusal names the folder, never the device-mapper node or device.
    let table = "1 0 0:30 /@/srv / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@\n";
    let err = decoy_root_of(&parse_mountinfo(table), Path::new("/")).unwrap_err();
    assert!(err.to_string().contains("/@/srv"), "{err}");

    // A genuine subvolume mount, whose root equals its subvol=, is accepted
    // even when the subvolume lives at a deeper path.
    let table =
        "1 0 0:30 /@/snapshots/root / rw - btrfs /dev/nvme0n1p2 rw,subvol=/@/snapshots/root\n";
    assert_eq!(
        decoy_root_of(&parse_mountinfo(table), Path::new("/"))
            .unwrap()
            .data
            .as_deref(),
        Some("subvol=/@/snapshots/root")
    );
}

#[test]
fn a_btrfs_subvolume_whose_path_the_kernel_escapes_is_a_subvolume() {
    // The kernel writes a space, a tab or a backslash of the subvolume's path
    // as an octal escape both in the mount root and in its subvol= option;
    // decoded, the two are the same path.
    for (escaped, path) in [
        ("/@ubuntu\\04026.04", "/@ubuntu 26.04"),
        ("/@root\\011tab", "/@root\ttab"),
        ("/@back\\134slash", "/@back\\slash"),
    ] {
        let table = format!(
            "1 0 0:30 {escaped} / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol={escaped}\n"
        );
        let root = decoy_root_of(&parse_mountinfo(&table), Path::new("/"))
            .unwrap_or_else(|e| panic!("{table}: {e}"));
        assert_eq!(
            root.data.as_deref(),
            Some(format!("subvol={path}").as_str()),
            "{table}"
        );
    }

    // A bind of a folder with such a path is still refused.
    let table = "1 0 0:30 /@ubuntu\\04026.04/srv / rw - btrfs /dev/nvme0n1p2 \
                 rw,subvol=/@ubuntu\\04026.04\n";
    assert!(decoy_root_of(&parse_mountinfo(table), Path::new("/")).is_err());
}

#[test]
fn a_btrfs_subvolume_with_a_comma_in_its_path_is_refused() {
    // The mount root keeps the comma, the option escapes it. The two match,
    // but the way back passes `subvol=` to mount(2), which splits at commas,
    // so it could not mount the decoy root again.
    let table = "1 0 0:30 /@a,b / rw - btrfs /dev/nvme0n1p2 rw,subvolid=256,subvol=/@a\\054b\n";
    let error = decoy_root_of(&parse_mountinfo(table), Path::new("/")).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("comma"), "{text}");
    assert!(text.contains("/@a,b"), "{text}");
}

/// A minimal `EntryInputs` for the helpers that do not build a system:
/// no builder, no operator, the persona at its default, and a host whose facts
/// report no SELinux.
fn minimal_inputs<'a>(
    hidden_root: &'a Path,
    binary: &'a Path,
    config_toml: Option<String>,
) -> EntryInputs<'a> {
    EntryInputs {
        hidden_root,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".into(),
            data: None,
        },
        nixos: false,
        builder: None,
        binary,
        config_toml,
        session_units: Vec::new(),
        backend: Vec::new(),
        persona: Default::default(),
        operator: None,
        labels: Labels::BestEffort,
        rebuild_space_mb: 0,
        read_only_disks: false,
        accepted_decoy_storage: None,
        window_launcher: None,
    }
}

#[test]
fn write_runtime_populates_the_runtime_directory() {
    let run = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let binary = run.path().join("nails-running-binary");
    std::fs::write(&binary, b"the running binary bytes").unwrap();
    let paths = Paths {
        root: PathBuf::from("/"),
        run: run.path().to_path_buf(),
    };
    // A scratch tree, not the real system, so the runtime lands under it.
    assert!(!paths.is_system());
    let toml = "hidden_volume_root = \"/x\"\n".to_string();
    let inputs = minimal_inputs(hidden.path(), &binary, Some(toml.clone()));
    let snapshot = Snapshot::take(&paths.run);

    write_runtime(&paths, &inputs, &snapshot).unwrap();

    let runtime = paths.runtime();
    // The RAM copy of the binary is the running binary, byte for byte: the
    // whole point of write_runtime, skipped by a body replaced with Ok(()).
    assert_eq!(
        std::fs::read(paths.binary_copy()).unwrap(),
        std::fs::read(&binary).unwrap()
    );
    // The `/run` snapshot and the saved utab the way back reads are written.
    assert!(runtime.join(SNAPSHOT_NAME).exists());
    assert!(runtime.join(UTAB_NAME).exists());
    assert!(runtime.join(UTAB_MOUNTS_NAME).exists());
    // The configuration copy carries the effective TOML verbatim.
    assert_eq!(
        std::fs::read_to_string(runtime.join(CONFIG_COPY_NAME)).unwrap(),
        toml
    );
    // The runtime directory is private (0o700), as write_runtime sets it.
    let mode = std::fs::metadata(&runtime).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn fresh_home_without_the_operator_is_refused() {
    let run = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    let binary = run.path().join("nails-running-binary");
    std::fs::write(&binary, b"bin").unwrap();
    let paths = Paths {
        root: run.path().join("root"),
        run: run.path().to_path_buf(),
    };
    let layout = Layout::new(hidden.path());
    // Fresh-home needs the operator (the sudo user) whose home is reset; with
    // none, the entry must refuse rather than silently do nothing. A body
    // replaced with Ok(()) would accept it.
    let inputs = minimal_inputs(hidden.path(), &binary, None);
    assert!(inputs.operator.is_none());

    let error = fresh_home(&paths, &inputs, &layout, &[]).unwrap_err();

    let text = error.to_string();
    assert!(text.contains("fresh-home"), "{text}");
    assert!(text.contains("operator"), "{text}");
    assert!(matches!(error, NailsError::InvalidState(_)));
}

#[test]
fn a_symlinked_fstab_mount_point_is_decided_at_its_real_path() {
    // The decoy keeps /home at var/home (an ostree layout).
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();

    // fstab names /home; nothing is mounted there now, so it is masked. The
    // masked unit is the one systemd generates for the real mount point,
    // var-home.mount, not home.mount, so the hidden session really masks it.
    let fstab = parse_in_root(b"/dev/sdb1 /home ext4 defaults 0 2\n", root.path());
    let decisions = decide_fstab(
        &fstab,
        &[],
        Path::new("/mnt/data"),
        &|_| false,
        Whose::Decoy,
    )
    .unwrap();
    assert_eq!(policy::masked_units(&decisions), ["var-home.mount"]);
    // With its disk there, local-fs.target's requirement is skipped under the
    // same name.
    let decisions =
        decide_fstab(&fstab, &[], Path::new("/mnt/data"), &|_| true, Whose::Decoy).unwrap();
    assert_eq!(decisions[0].skip().unwrap().units, ["var-home.mount"]);
}

#[test]
fn an_fstab_entry_below_the_hidden_root_refuses_the_entry_with_what_to_do() {
    // The decoy's fstab, or a hidden NixOS generation's, which activation
    // decides the same way: a noauto disk inside the hidden volume.
    let fstab = parse_fstab("/dev/sdb1 /mnt/data/usb vfat noauto 0 0\n");
    let refusal = |whose: Whose| {
        let error =
            decide_fstab(&fstab, &[], Path::new("/mnt/data"), &|_| true, whose).unwrap_err();
        let NailsError::InvalidState(message) = error else {
            panic!("{error:?}");
        };
        message
    };
    let reason = "it lies at or below /mnt/data, where the hidden volume is mounted: the hidden \
                  session could mount it over the hidden volume or inside it";
    assert_eq!(
        refusal(Whose::Decoy),
        format!(
            "fstab entry /mnt/data/usb: {reason}. Mount the hidden volume where the decoy mounts \
             nothing, or move this mount out from below /mnt/data or remove it, before \
             activating."
        )
    );
    // A hidden NixOS generation's says whose fstab it is, and that its
    // configuration is the one to change.
    assert_eq!(
        refusal(Whose::HiddenSystem),
        format!(
            "the hidden NixOS system's fstab entry /mnt/data/usb: {reason}. Remove this mount \
             from the hidden NixOS configuration, or move it out from below /mnt/data there, in \
             a hidden session entered with `activate --overlay-only`."
        )
    );
}

#[test]
fn the_automount_of_an_overlaid_symlinked_mount_point_is_skipped_by_its_real_path() {
    // The decoy keeps /home at var/home, mounts the filesystem there, and
    // its fstab names /home behind an automount.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("var/home")).unwrap();
    std::os::unix::fs::symlink("var/home", root.path().join("home")).unwrap();
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /var/home rw - ext4 /dev/vda3 rw\n",
    );
    let fstab = parse_in_root(
        b"UUID=a /home ext4 defaults,x-systemd.automount 0 2\n",
        root.path(),
    );
    let decisions = decide_fstab(
        &fstab,
        &mounts,
        Path::new("/mnt/data"),
        &|_| false,
        Whose::Decoy,
    )
    .unwrap();
    // The filesystem is overlaid where the decoy has it, and the automount
    // the hidden systemd generates for that path is kept off with the same
    // resolved entries: left free, it would find the mount point taken and
    // fail local-fs.target, the emergency mode this prevents. The target
    // requires the automount, so it is skipped, not masked.
    assert_eq!(
        decisions,
        [Decision::Overlay {
            target: PathBuf::from("/var/home")
        }]
    );
    let kept = policy::runtime_units(&fstab, &decisions);
    assert!(kept.masks.is_empty(), "{:?}", kept.masks);
    assert_eq!(kept.skips.len(), 1, "{:?}", kept.skips);
    assert_eq!(kept.skips[0].units, ["var-home.automount"]);
}

#[test]
fn only_the_entries_the_next_root_resolves_elsewhere_are_decided_again() {
    let decoy = parse_fstab(
        "/dev/sdb1 /var/home ext4 defaults 0 2\n\
         /dev/sdc1 /srv ext4 defaults 0 2\n",
    );
    // In the next root the first entry's path is a directory of the hidden
    // session's own (no link to var/home there), the second unchanged.
    let in_nextroot = parse_fstab(
        "/dev/sdb1 /home ext4 defaults 0 2\n\
         /dev/sdc1 /srv ext4 defaults 0 2\n",
    );
    let elsewhere = resolved_elsewhere(&decoy, in_nextroot);
    assert_eq!(elsewhere.len(), 1, "{elsewhere:?}");
    assert_eq!(elsewhere[0].file, Path::new("/home"));
    // Decided there, where the decoy mounts nothing: masked, so the hidden
    // systemd never mounts the decoy's disk read-write at /home.
    let decisions = decide_elsewhere(&elsewhere, &[], Path::new("/mnt/data"), &|_| false).unwrap();
    assert_eq!(policy::masked_units(&decisions), ["home.mount"]);
}

#[test]
fn an_entry_a_link_leads_into_the_hidden_volume_is_masked_there() {
    // The decoy keeps /data and /media for disks it does not mount now. An
    // earlier session moved both onto the hidden volume, replacing each
    // directory with a link into it.
    let decoy = parse_fstab(
        "UUID=X /data ext4 defaults,nofail 0 2\n\
         UUID=Y /media ext4 noauto,x-systemd.automount 0 2\n",
    );
    let in_nextroot = parse_fstab(
        "UUID=X /mnt/data/data ext4 defaults,nofail 0 2\n\
         UUID=Y /mnt/data/media ext4 noauto,x-systemd.automount 0 2\n",
    );
    let elsewhere = resolved_elsewhere(&decoy, in_nextroot);
    assert_eq!(elsewhere.len(), 2, "{elsewhere:?}");
    // The decoy's lines name paths outside the hidden volume, so they are not
    // refused, but the hidden systemd would mount the decoy's disks
    // read-write inside it. They are kept off there: the nofail mount masked,
    // the automount local-fs.target requires skipped, its mount masked.
    let decisions = decide_elsewhere(&elsewhere, &[], Path::new("/mnt/data"), &|_| false).unwrap();
    assert_eq!(
        policy::masked_units(&decisions),
        ["mnt-data-data.mount", "mnt-data-media.mount"]
    );
    let skipped: Vec<&String> = decisions
        .iter()
        .filter_map(Decision::skip)
        .flat_map(|skip| &skip.units)
        .collect();
    assert_eq!(skipped, ["mnt-data-media.automount"]);
}

/// What an entry without a build decides of the `/etc/fstab` of the next
/// root at `root`, on a NixOS host or another (`nixos`), with the hidden
/// volume at `/mnt/data` and no device there, after the decoy's fstab
/// `decoy`.
fn hidden_fstab_of(root: &Path, decoy: &[u8], nixos: bool) -> Result<hidden_fstab::HiddenFstab> {
    let decided = parse_in_root(decoy, root);
    hidden_fstab::decide(
        root,
        decoy,
        &decided,
        &[],
        Path::new("/mnt/data"),
        &|_| false,
        nixos,
    )
}

/// A next root whose `/etc/fstab` holds `text`.
fn root_with_fstab(text: &[u8]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::fs::write(root.path().join("etc/fstab"), text).unwrap();
    root
}

/// A NixOS next root as the last activation of a hidden system left it:
/// its `/etc/fstab` leads to `/etc/static/fstab`, and `/etc/static` into the
/// hidden system's store, by absolute links that lead elsewhere on the
/// running system. The file in the store holds `text`.
fn nixos_root_with_fstab(text: &[u8]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let etc = root.path().join("nix/store/bbbb-etc/etc");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("fstab"), text).unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::os::unix::fs::symlink("/nix/store/bbbb-etc/etc", root.path().join("etc/static")).unwrap();
    std::os::unix::fs::symlink("/etc/static/fstab", root.path().join("etc/fstab")).unwrap();
    root
}

/// The message of an entry refused with `result`.
fn refusal(result: Result<hidden_fstab::HiddenFstab>) -> String {
    match result {
        Err(NailsError::InvalidState(message)) => message,
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_entry_without_a_build_keeps_off_a_hidden_fstab_line_below_the_root_and_warns() {
    // The hidden session added two lines to its own copy of the decoy's
    // fstab, one of them twice: a disk inside the hidden volume, and a decoy
    // disk elsewhere.
    let decoy = b"/dev/vda2 / ext4 defaults 0 1\n/dev/vda3 /home ext4 defaults 0 2\n";
    let added = "/dev/vdd1 /mnt/data/archive ext4 defaults,nofail 0 2";
    let backup = "/dev/vde1 /srv/backup ext4 defaults,nofail 0 2";
    let root = root_with_fstab(
        format!(
            "{}# added in a hidden session\n\t{added}  \n  {backup}\n{added}\n",
            String::from_utf8_lossy(decoy)
        )
        .as_bytes(),
    );

    let hidden = hidden_fstab_of(root.path(), decoy, false).unwrap();

    // The decoy's lines were decided with the decoy's fstab: only the
    // session's own are decided here, each once.
    let files: Vec<&Path> = hidden.entries.iter().map(|e| e.file.as_path()).collect();
    assert_eq!(
        files,
        [Path::new("/mnt/data/archive"), Path::new("/srv/backup")]
    );
    // The line below the root is kept off rather than refused, and the decoy
    // disk elsewhere gets what the same line of the decoy's would.
    assert_eq!(
        policy::masked_units(&hidden.decisions),
        ["srv-backup.mount", "mnt-data-archive.mount"]
    );
    let as_decoy = policy::decide(
        &parse_fstab(backup)[0],
        &[],
        Path::new("/mnt/data"),
        &|_| false,
    );
    assert!(
        hidden.decisions.contains(&as_decoy),
        "{:?}",
        hidden.decisions
    );
    // One warning, for the line below the root, naming it as the file has
    // it, the root and what to do in the session.
    assert_eq!(
        hidden.warnings,
        [format!(
            "the hidden session's fstab entry /mnt/data/archive (`{added}`) lies at or below \
             /mnt/data, where the hidden volume is mounted: the hidden session is kept from \
             mounting it there, over the hidden volume or inside it\nIn the hidden session, \
             remove this line from /etc/fstab, or move its mount out from below /mnt/data."
        )]
    );
}

#[test]
fn a_line_the_decoy_s_fstab_holds_too_is_decided_once_as_the_decoy_s() {
    // The decoy's /data line, which a link of the next root leads into the
    // hidden volume, was decided with the decoy's fstab: kept off there as a
    // line a link leads below the root. The hidden session's copy of the
    // fstab, one line longer, holds it too.
    let line = "UUID=X /data ext4 defaults,nofail 0 2";
    let root = root_with_fstab(
        format!("{line}\n/dev/vde1 /srv/backup ext4 defaults,nofail 0 2\n").as_bytes(),
    );
    std::fs::create_dir_all(root.path().join("mnt/data/data")).unwrap();
    std::os::unix::fs::symlink("/mnt/data/data", root.path().join("data")).unwrap();

    let hidden = hidden_fstab_of(root.path(), format!("{line}\n").as_bytes(), false).unwrap();

    // Not decided again as a line of the session's own below the root.
    let files: Vec<&Path> = hidden.entries.iter().map(|e| e.file.as_path()).collect();
    assert_eq!(files, [Path::new("/srv/backup")]);
    assert!(hidden.warnings.is_empty(), "{:?}", hidden.warnings);
}

#[test]
fn the_hidden_nixos_fstab_is_read_through_its_links_inside_the_next_root() {
    // The hidden volume's own line, as a hardware configuration generated in
    // a session has it.
    let line = "/dev/disk/by-uuid/aaaa /mnt/data ext4 defaults,nofail 0 2";
    let root = nixos_root_with_fstab(format!("{line}\n").as_bytes());

    let hidden = hidden_fstab_of(root.path(), b"", true).unwrap();

    // Kept off, with what to do in the hidden NixOS configuration.
    assert_eq!(policy::masked_units(&hidden.decisions), ["mnt-data.mount"]);
    assert_eq!(hidden.warnings.len(), 1, "{:?}", hidden.warnings);
    let warning = &hidden.warnings[0];
    assert!(
        warning.starts_with(&format!(
            "the hidden NixOS system's fstab entry /mnt/data (`{line}`) lies at or below \
             /mnt/data"
        )),
        "{warning}"
    );
    assert!(
        warning.ends_with(
            "\nIn the hidden session, remove this mount from the hidden NixOS configuration, \
             or move it out from below /mnt/data there, and rebuild."
        ),
        "{warning}"
    );
}

#[test]
fn a_hidden_nixos_fstab_written_in_a_session_is_the_session_s() {
    // A file in place of the link into the store: no NixOS configuration
    // has its lines, so the warning says to remove the line from the file.
    let root = root_with_fstab(b"/dev/vdd1 /mnt/data/archive ext4 defaults,nofail 0 2\n");
    let hidden = hidden_fstab_of(root.path(), b"", true).unwrap();
    assert_eq!(hidden.warnings.len(), 1, "{:?}", hidden.warnings);
    let warning = &hidden.warnings[0];
    assert!(
        warning.starts_with("the hidden session's fstab entry /mnt/data/archive"),
        "{warning}"
    );
    assert!(
        warning.ends_with("\nIn the hidden session, remove this line from /etc/fstab, or move its mount out from below /mnt/data."),
        "{warning}"
    );
}

#[test]
fn a_link_that_leads_out_of_the_next_root_is_followed_inside_it() {
    // A file outside the next root with a line below the hidden root, which
    // the next root's /etc/fstab links to by an absolute path and by enough
    // `..` to leave it on the running system.
    let outside = tempfile::tempdir().unwrap();
    let file = outside.path().join("fstab");
    std::fs::write(&file, "/dev/vdd1 /mnt/data/archive ext4 defaults 0 2\n").unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    let up = "../".repeat(root.path().components().count() + 1);
    let relative = format!("{up}{}", file.display().to_string().trim_start_matches('/'));
    let link = root.path().join("etc/fstab");
    for target in [file.display().to_string(), relative] {
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // On the running system the link leads to the file outside.
        assert!(std::fs::read_to_string(&link).unwrap().contains("archive"));

        let hidden = hidden_fstab_of(root.path(), b"", false).unwrap();

        // Inside the next root it leads to nothing there: no line to decide.
        assert!(hidden.entries.is_empty(), "{target}: {:?}", hidden.entries);
        assert!(
            hidden.warnings.is_empty(),
            "{target}: {:?}",
            hidden.warnings
        );
    }
}

#[test]
fn a_missing_hidden_fstab_holds_no_line() {
    let root = tempfile::tempdir().unwrap();
    let hidden = hidden_fstab_of(root.path(), b"", false).unwrap();
    assert!(hidden.entries.is_empty() && hidden.decisions.is_empty());
    // Nor does a link that leads to nothing.
    std::fs::create_dir_all(root.path().join("etc")).unwrap();
    std::os::unix::fs::symlink("/etc/static/fstab", root.path().join("etc/fstab")).unwrap();
    let hidden = hidden_fstab_of(root.path(), b"", true).unwrap();
    assert!(hidden.entries.is_empty() && hidden.warnings.is_empty());
}

#[test]
fn a_hidden_fstab_that_cannot_be_read_refuses_the_entry() {
    // A directory in its place, and a link that leads to itself.
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("etc/fstab")).unwrap();
    let message = refusal(hidden_fstab_of(root.path(), b"", false));
    assert!(
        message.starts_with("the hidden /etc/fstab cannot be read ("),
        "{message}"
    );
    assert!(
        message.ends_with(
            "): the hidden session would run with it, and NAILS cannot tell what it mounts"
        ),
        "{message}"
    );
    std::fs::remove_dir(root.path().join("etc/fstab")).unwrap();
    std::os::unix::fs::symlink("fstab", root.path().join("etc/fstab")).unwrap();
    let message = refusal(hidden_fstab_of(root.path(), b"", true));
    assert!(
        message.starts_with("the hidden /etc/fstab cannot be read ("),
        "{message}"
    );
}

#[test]
fn a_hidden_fstab_line_that_is_not_text_refuses_the_entry() {
    // A mount point whose bytes are no UTF-8: read as text, it would be
    // decided, and masked, under a name the hidden systemd does not give it.
    let text = b"/dev/vda2 / ext4 defaults 0 1\n/dev/vdd1 /mnt/data/caf\xe9 ext4 defaults 0 2\n";
    let root = root_with_fstab(text);
    let message = refusal(hidden_fstab_of(root.path(), b"", false));
    assert_eq!(
        message,
        "line 2 of the hidden /etc/fstab is not UTF-8 text: the hidden session would run with \
         it, and NAILS cannot tell what it mounts"
    );
    // The decoy's own fstab, byte for byte, was decided with the decoy's.
    assert!(
        hidden_fstab_of(root.path(), text, false)
            .unwrap()
            .entries
            .is_empty()
    );
    // A comment is no line to decide.
    let root = root_with_fstab(b"# caf\xe9\n/dev/vde1 /srv/backup ext4 defaults,nofail 0 2\n");
    let hidden = hidden_fstab_of(root.path(), b"", false).unwrap();
    assert_eq!(
        policy::masked_units(&hidden.decisions),
        ["srv-backup.mount"]
    );
}

#[test]
fn an_odd_mount_point_in_the_hidden_fstab_refuses_the_entry_naming_whose_it_is() {
    let line = b"/dev/vde1 srv/x ext4 defaults 0 2\n";
    // A link into the store is the hidden NixOS system's on NixOS only.
    for (root, nixos, of) in [
        (root_with_fstab(line), false, "the hidden session's"),
        (
            nixos_root_with_fstab(line),
            true,
            "the hidden NixOS system's",
        ),
        (nixos_root_with_fstab(line), false, "the hidden session's"),
    ] {
        assert_eq!(
            refusal(hidden_fstab_of(root.path(), b"", nixos)),
            format!("{of} fstab entry srv/x: the mount point is not a plain absolute path")
        );
    }
}

/// Where SELinux runs.
const REQUIRED: Labels = Labels::Required(crate::session::labels::Reason::SelinuxRunning);

/// `alice`, with the uid and gid of whoever runs the tests and her home at
/// `home`.
fn alice(home: &str) -> crate::target_user::TargetUser {
    crate::target_user::TargetUser::for_test(
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
        "alice",
        home,
        "/bin/sh",
    )
}

/// The status change time of `path`, which any attribute written moves.
fn ctime(path: &Path) -> (i64, i64) {
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.ctime(), meta.ctime_nsec())
}

/// Long enough for a write to move a time, on a kernel whose timestamps are
/// coarse.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(20));
}

/// A decoy root under `dir` without the operator's home, and the layout of a
/// hidden volume next to it.
fn home_world(dir: &Path) -> (Paths, Layout) {
    let paths = Paths {
        root: dir.join("root"),
        run: dir.join("run"),
    };
    std::fs::create_dir_all(&paths.root).unwrap();
    (paths, Layout::new(&dir.join("hidden")))
}

#[test]
fn the_way_to_the_home_starts_at_the_upper_of_the_filesystem_it_lives_on() {
    let paths = Paths {
        root: PathBuf::from("/decoy"),
        run: PathBuf::from("/scratch-run"),
    };
    let layout = Layout::new(Path::new("/mnt/data"));
    let mounts = parse_mountinfo(
        "1 0 8:2 / / rw - ext4 /dev/vda2 rw\n\
         2 1 8:3 / /home rw - ext4 /dev/vda3 rw\n",
    );
    let way = HomeWay::of(&paths, &layout, &mounts, &alice("/home/alice"));
    assert_eq!(way.decoy, Path::new("/decoy/home"));
    assert_eq!(way.upper, Path::new("/mnt/data/root/mounts/home/upper"));
    assert_eq!(way.rest, Path::new("alice"));
    // A home on the decoy root is below the root upper.
    let way = HomeWay::of(&paths, &layout, &mounts[..1], &alice("/home/alice"));
    assert_eq!(way.decoy, Path::new("/decoy"));
    assert_eq!(way.upper, Path::new("/mnt/data/root/upper"));
    assert_eq!(way.rest, Path::new("home/alice"));
}

#[test]
fn a_fresh_home_entry_that_requires_the_labels_is_refused_where_the_decoy_has_none() {
    // Real calls, on any host: the decoy has no home for alice, so there is
    // no label for the home an earlier entry made, nor for its parent.
    let dir = tempfile::tempdir().unwrap();
    let (paths, layout) = home_world(dir.path());
    // That earlier entry made the home (the opaque mark on it needs
    // CAP_SYS_ADMIN, which no test has).
    let upper_home = layout.upper().join("home/alice");
    std::fs::create_dir_all(&upper_home).unwrap();
    let mut inputs = minimal_inputs(layout.hidden_root(), Path::new("/proc/self/exe"), None);
    inputs.persona.mode = crate::config::PersonaMode::FreshHome;
    inputs.operator = Some(alice("/home/alice"));
    inputs.labels = REQUIRED;
    let before = (ctime(&layout.upper().join("home")), ctime(&upper_home));
    tick();

    let text = persona_home(&paths, &inputs, &layout, &[])
        .unwrap_err()
        .to_string();
    assert!(
        text.ends_with(&format!(
            "but {} does not exist",
            paths.root.join("home").display()
        )),
        "{text}"
    );
    // Without SELinux facts the entry goes on and writes nothing on the way.
    inputs.labels = Labels::BestEffort;
    persona_home(&paths, &inputs, &layout, &[]).unwrap();
    assert_eq!(
        (ctime(&layout.upper().join("home")), ctime(&upper_home)),
        before
    );
}

#[test]
fn a_shared_home_entry_walks_only_as_far_as_the_upper_holds_the_way_to_the_home() {
    // Real calls, on any host.
    let dir = tempfile::tempdir().unwrap();
    let (paths, layout) = home_world(dir.path());
    let mut inputs = minimal_inputs(layout.hidden_root(), Path::new("/proc/self/exe"), None);
    assert_eq!(inputs.persona.mode, crate::config::PersonaMode::SharedHome);
    inputs.labels = REQUIRED;
    // An entry without an operator walks nothing.
    std::fs::create_dir_all(layout.upper().join("home/alice")).unwrap();
    persona_home(&paths, &inputs, &layout, &[]).unwrap();

    // The first entry, before the upper exists: nothing to walk.
    inputs.operator = Some(alice("/home/alice"));
    std::fs::remove_dir_all(layout.hidden_root()).unwrap();
    persona_home(&paths, &inputs, &layout, &[]).unwrap();
    assert!(!layout.hidden_root().exists(), "the walk made something");

    // What a refused fresh-home entry left for an operator the decoy has no
    // home for: refused where the labels are required, left as it is
    // without SELinux facts.
    let upper_home = layout.upper().join("home/alice");
    std::fs::create_dir_all(&upper_home).unwrap();
    let before = ctime(&upper_home);
    tick();
    let text = persona_home(&paths, &inputs, &layout, &[])
        .unwrap_err()
        .to_string();
    assert!(
        text.ends_with(&format!(
            "but {} does not exist",
            paths.root.join("home").display()
        )),
        "{text}"
    );
    inputs.labels = Labels::BestEffort;
    persona_home(&paths, &inputs, &layout, &[]).unwrap();
    assert_eq!(ctime(&upper_home), before);
}

/// The entry's own reading of the decoy's process numbers against a real
/// procfs, and the way back's measure and counter after it: the test runs as
/// PID 1 of a PID namespace of its own, so the processes it starts are all the
/// userspace there is, and the counter it sets is that namespace's.
mod kernel_tests {
    use super::*;
    use nails_base::test_support::{Rerun, skip_host};
    use nails_teardown::whole_root::fresh_pids::{self, Anchor, Lowered, Places};
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    /// A shell run as `program` with `arg0` that waits on the input the test
    /// holds open, so it runs until the test ends it. dash and bash run as
    /// themselves under any name. `sleep` would not: a multi-call coreutils
    /// picks the program by the name it was run under, and uutils coreutils,
    /// Ubuntu 26.04's, by the path the kernel ran rather than argv[0], so
    /// through a link named after another program it runs that program, or
    /// none, and ends at once.
    ///
    /// It returns once the shell has printed the empty line it starts with,
    /// when the kernel is done with its exec. `spawn` returns sooner: std
    /// spawns it through `posix_spawn`, which lets this process go on as soon
    /// as the child's exec lets go of this process's memory, and only after
    /// that does the kernel name the child after its program and set out its
    /// arguments. A reading of the process table right after `spawn` could
    /// find the child still under this process's name and with no argv[0],
    /// and on a busy host the entry then found no getty. `echo` and `read`
    /// are built into the shell, so it starts no process of its own.
    fn waiting(program: &Path, arg0: &str) -> Child {
        let mut child = Command::new(program)
            .arg0(arg0)
            .args(["-c", "echo; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = [0; 1];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut line)
            .expect("a stand-in ended before it printed its line");
        child
    }

    /// A process named `comm` that runs until the test ends it: a waiting
    /// shell ([`waiting`]) run through a link of that name, which the kernel
    /// names it after.
    fn start(dir: &Path, sh: &Path, comm: &str) -> Child {
        let link = dir.join(comm);
        if std::fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(sh, &link).unwrap();
        }
        waiting(&link, "sh")
    }

    /// End `child` and reap it.
    fn stop(mut child: Child) {
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// Use up `count` process numbers with shells that end at once.
    fn use_up(sh: &Path, count: usize) {
        for _ in 0..count {
            let status = Command::new(sh).args(["-c", ":"]).status().unwrap();
            assert!(status.success());
        }
    }

    #[test]
    fn the_entry_reads_the_process_numbers_of_the_running_system() {
        let _ = Rerun::new(nails_base::test_path!(
            the_entry_reads_the_process_numbers_of_the_running_system
        ))
        .in_pid_ns()
        .run(|| {
            let Some(sh) = nails_teardown::whole_root::tools::find(None, "sh") else {
                skip_host("no sh in the system directories");
            };
            let places = Places::system();
            let Some(before) = places.current() else {
                skip_host("this kernel has no ns_last_pid (CONFIG_CHECKPOINT_RESTORE)");
            };
            let dir = tempfile::tempdir().unwrap();
            // A root storage daemon, which a soft-reboot leaves running, with
            // the lowest number: it is no part of the start the entry reads.
            let mut storage = waiting(&sh, "@storage");
            // The decoy's userspace: its journal, the floor, and further on
            // its getty.
            let mut journal = start(dir.path(), &sh, "systemd-journal");
            use_up(&sh, 50);
            let mut getty = start(dir.path(), &sh, "agetty");
            let tty = nails_teardown::proc::stat(getty.id()).unwrap().tty;
            let mut record = RealEntryHost.pid_record();
            // One that had ended would be a zombie, which the entry leaves out.
            for child in [&mut storage, &mut journal, &mut getty] {
                assert_eq!(child.try_wait().unwrap(), None, "a stand-in ended");
            }
            assert!(before < storage.id() && storage.id() < journal.id());
            assert_eq!(record.floor, Some(journal.id()));
            assert_eq!(
                record.anchors,
                [Anchor {
                    comm: "agetty".to_string(),
                    tty,
                    pid: getty.id(),
                }]
            );

            // The switch, and a hidden start whose getty follows it.
            record.at_switch = places.current();
            let hidden = start(dir.path(), &sh, "agetty");
            let used = hidden.id() - record.at_switch.unwrap();
            record.counter = fresh_pids::counter(&record, Path::new("/proc"));
            assert_eq!(record.counter, Some(getty.id() - used));

            // The hidden session runs on and stops; the way back sets the
            // counter, and the next process gets a number below where it was.
            use_up(&sh, 20);
            stop(hidden);
            let reached = places.current().unwrap();
            let target = record.way_back_counter().unwrap();
            assert_eq!(
                fresh_pids::lower(Some(target), &places),
                Lowered::Set(target)
            );
            let next = start(dir.path(), &sh, "agetty");
            assert!(
                target < next.id() && next.id() <= reached,
                "{target} < {} <= {reached}",
                next.id()
            );
            for child in [storage, journal, getty, next] {
                stop(child);
            }
        });
    }
}

#[test]
fn the_real_host_finds_no_device_without_its_node() {
    assert!(!RealEntryHost.device_present(Path::new("/dev/disk/by-id/nails-test-no-such-disk")));
}
