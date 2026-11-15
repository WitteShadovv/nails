// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The backend-entries check on the lines that name the file the volume is
//! stored in, which a loop device of its stack reads: they fail with the flag
//! and without it.

use super::*;

/// The failure that names `finding`, a line that names the volume, alone.
fn names_the_volume(finding: &str) -> String {
    format!("The decoy's configuration names the volume at /mnt: {finding}. {STORED}")
}

/// The device the loop driver recorded for the root's file: the decoy's
/// /home, nvme0n1p4.
fn home() -> u64 {
    rustix::fs::makedev(259, 4)
}

/// A root in the file `/home/op/vault.img` on the decoy's /home
/// (nvme0n1p4), through loop0: in a LUKS container, `vault` over loop0,
/// when `encrypted`, else the image's own ext4, at /mnt, with `fstab` lines
/// after / and /home and `crypttab`. The loop driver recorded the file as
/// inode 4242 on /home.
fn root_in_a_file(encrypted: bool, fstab: &str, crypttab: &str) -> Decoy {
    let root = if encrypted {
        "5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n"
    } else {
        "5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n"
    };
    let loop0 = "/sys/devices/virtual/block/loop0";
    let mut decoy = Decoy::new(&format!(
        "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
         2 1 259:4 / /home rw - ext4 /dev/nvme0n1p4 rw\n{root}"
    ))
    .device(NVME, "nvme0n1", "259:0", &[])
    .partition(P3, "nvme0n1p3", "259:3")
    .partition(
        "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p4",
        "nvme0n1p4",
        "259:4",
    )
    .device(loop0, "loop0", "7:0", &[]);
    if encrypted {
        decoy = decoy.mapping("dm-8", "254:8", "vault", ("loop0", loop0));
    }
    let decoy = decoy
        .file(
            "/etc/fstab",
            &format!(
                "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/nvme0n1p4 /home ext4 defaults 0 2\n\
                 {fstab}"
            ),
        )
        .file("/etc/crypttab", crypttab)
        .encrypted();
    decoy.attr(loop0, "loop/backing_file", "/home/op/vault.img");
    decoy.fs.mock_set_loop_record(
        Path::new("/dev/loop0"),
        crate::filesystem::LoopRecord {
            device: home(),
            inode: 4242,
            rdevice: 0,
        },
    );
    decoy.fs.mock_set_file_content("/home/op/vault.img", "x");
    for node in ["nvme0n1", "nvme0n1p3", "nvme0n1p4", "loop0", "dm-8"] {
        decoy.fs.mock_set_device_node(&format!("/dev/{node}"));
    }
    decoy
}

/// That backend-entries fails `decoy` with and without the flag, naming
/// only `finding` and saying to remove the line.
fn fails_naming(decoy: &Decoy, finding: &str) {
    for allow in [Allow::Nothing, Allow::DecoyStorage] {
        let result = run_allowing(&decoy.fs, allow);
        assert_eq!(result.message(), names_the_volume(finding), "{allow:?}");
        assert_eq!(result.remediation(), Some(REMEDIATION), "{allow:?}");
    }
}

#[test]
fn a_line_that_names_the_file_the_volume_is_stored_in_fails() {
    // systemd 260.5's generators made systemd-cryptsetup@vault2.service for
    // `vault2 /home/op/vault.img`, and media-i.mount for the image line, and
    // on a real kernel the attach made a second loop device over the same
    // container and a second mapping that showed the hidden files, and the
    // image's mount a second mount of it. Each such line fails, a noauto one
    // too, with the flag too, which accepts the root's container or image on
    // the decoy's /home only with a warning.
    let stored = |what: &str| format!("{what} is the file the volume at /mnt is stored in");
    for (encrypted, fstab, crypttab, shown, what) in [
        (
            true,
            "",
            "vault2 /home/op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "",
            "vault2 /home/op/vault.img none luks,noauto\n",
            "/etc/crypttab: 'vault2 /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "/dev/mapper/vault2 /media/v ext4 nofail 0 2\n",
            "vault2 /home/op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "",
            "sw /home/op/vault.img /dev/urandom swap\n",
            "/etc/crypttab: 'sw /home/op/vault.img'",
            "the file it opens",
        ),
        (
            true,
            "",
            "vault2 /home/op/../op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /home/op/../op/vault.img'",
            "the file it opens",
        ),
        (
            false,
            "/home/op/vault.img /media/i ext4 loop,nofail 0 0\n",
            "",
            "/etc/fstab: '/home/op/vault.img /media/i ext4'",
            "the file it names",
        ),
        (
            false,
            "/home/op/vault.img /media/i ext4 nofail 0 0\n",
            "",
            "/etc/fstab: '/home/op/vault.img /media/i ext4'",
            "the file it names",
        ),
        (
            false,
            "",
            "sw /home/op/vault.img /dev/urandom swap\n",
            "/etc/crypttab: 'sw /home/op/vault.img'",
            "the file it opens",
        ),
        (
            false,
            "fuse2fs#/home/op/vault.img /media/i fuse nofail 0 0\n",
            "",
            "/etc/fstab: 'fuse2fs#/home/op/vault.img /media/i fuse'",
            "the file it names",
        ),
        (
            false,
            "",
            "px /home/op/vault.img /etc/plainkey plain,cipher=aes-xts-plain64,size=512\n",
            "/etc/crypttab: 'px /home/op/vault.img'",
            "the file it opens",
        ),
    ] {
        let decoy = root_in_a_file(encrypted, fstab, crypttab);
        fails_naming(&decoy, &format!("{shown} ({})", stored(what)));
    }
    // By another spelling: a hard link, which names the inode the loop
    // driver recorded on /home.
    let decoy = root_in_a_file(true, "", "vault2 /home/op/copy.img /etc/vault.key luks\n");
    decoy.fs.mock_set_file_content("/home/op/copy.img", "x");
    decoy
        .fs
        .mock_set_device_id(Path::new("/home/op/copy.img"), home());
    decoy
        .fs
        .mock_set_inode(Path::new("/home/op/copy.img"), 4242);
    fails_naming(
        &decoy,
        &format!(
            "/etc/crypttab: 'vault2 /home/op/copy.img' ({})",
            stored("the file it opens")
        ),
    );
    // The root alone, and lines for another file or another container,
    // pass.
    for (encrypted, fstab, crypttab) in [
        (true, "", ""),
        (false, "", ""),
        (true, "", "vault2 /home/op/other.img /etc/vault.key luks\n"),
        (
            false,
            "/home/op/other.img /media/i ext4 loop,nofail 0 0\n",
            "",
        ),
    ] {
        let decoy = root_in_a_file(encrypted, fstab, crypttab);
        let result = decoy.run();
        assert!(result.is_pass(), "{fstab}{crypttab}: {result:?}");
    }
    // The root's own mapping and loop device are devices of its stack, as
    // before.
    for (crypttab, shown) in [
        (
            "vault /home/op/vault.img /etc/vault.key luks\n",
            "/etc/crypttab: 'vault /home/op/vault.img'",
        ),
        (
            "vault2 /dev/loop0 /etc/vault.key luks\n",
            "/etc/crypttab: 'vault2 /dev/loop0'",
        ),
    ] {
        let result = root_in_a_file(true, "", crypttab).run();
        assert!(result.is_fail(), "{crypttab}: {result:?}");
        assert!(
            result.message().contains(&format!(
                "{shown} (it opens the volume at /mnt or a device it is stored on"
            )),
            "{crypttab}: {result:?}"
        );
    }
}

#[test]
fn a_line_that_names_the_veracrypt_container_of_the_root_fails() {
    // A VeraCrypt container file on /home as the root: the mapping
    // veracrypt1, with no uuid, over loop0, and a crypttab line that opens the
    // same file under another name.
    let loop0 = "/sys/devices/virtual/block/loop0";
    let container = |crypttab: &str| {
        let decoy = Decoy::new(
            "1 0 259:3 / / rw - ext4 /dev/nvme0n1p3 rw\n\
             2 1 259:4 / /home rw - ext4 /dev/nvme0n1p4 rw\n\
             5 1 254:8 / /mnt rw - ext4 /dev/mapper/veracrypt1 rw\n",
        )
        .device(NVME, "nvme0n1", "259:0", &[])
        .partition(P3, "nvme0n1p3", "259:3")
        .partition(
            "/sys/devices/pci0/nvme/nvme0n1/nvme0n1p4",
            "nvme0n1p4",
            "259:4",
        )
        .device(loop0, "loop0", "7:0", &[])
        .device_mapper("dm-8", "254:8", "veracrypt1", "", ("loop0", loop0))
        .file(
            "/etc/fstab",
            "/dev/nvme0n1p3 / ext4 defaults 0 1\n/dev/nvme0n1p4 /home ext4 defaults 0 2\n",
        )
        .file("/etc/crypttab", crypttab)
        .encrypted();
        decoy.attr(loop0, "loop/backing_file", "/home/op/vault.hc");
        decoy
            .fs
            .mock_set_loop_backing_device(Path::new("/dev/loop0"), home());
        decoy.fs.mock_set_file_content("/home/op/vault.hc", "x");
        decoy
    };
    let decoy = container("vc /home/op/vault.hc /etc/vc.key tcrypt-veracrypt\n");
    fails_naming(
        &decoy,
        "/etc/crypttab: 'vc /home/op/vault.hc' (the file it opens is the file the volume at /mnt \
         is stored in)",
    );
    let result = container("vc /home/op/other.hc /etc/vc.key tcrypt-veracrypt\n").run();
    assert!(result.is_pass(), "{result:?}");
}
