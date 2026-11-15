// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines that name the file the volume is stored in, which a loop device
//! of its stack reads: the container file it is opened from, or the image it
//! is in. The boot opens that file again through a loop device of its own,
//! by any spelling of its path, and so makes a second mapping or a second
//! mount of the volume, or formats it.

use super::*;

/// The file the loop driver recorded for loop0, on /home (`8:2`).
fn vault() -> FileId {
    FileId {
        device: rustix::fs::makedev(8, 2),
        inode: 4242,
    }
}

/// The volume `vault` (dm-8), opened from the container file
/// `/home/op/vault.img` on the decoy's /home through loop0, whose record
/// names the file `id`, mounted at /mnt.
fn container(id: Option<FileId>) -> World {
    plain_decoy("5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n")
        .loop_file_as(
            "loop0",
            "7:0",
            "/home/op/vault.img",
            FileHolder::Mount("8:2".into()),
            id,
        )
        .crypt("dm-8", "254:8", "vault", &["loop0"])
}

impl World {
    /// A file at `path`, which `stat` names `id`.
    fn file_as(self, path: &str, id: FileId) -> Self {
        self.files.mock_set_file_content(path, "x");
        self.files.mock_set_device_id(Path::new(path), id.device);
        self.files.mock_set_inode(Path::new(path), id.inode);
        self
    }
}

/// The decoy's lines for / and /home, then `line`.
fn with_the_decoys_lines(line: &str) -> String {
    format!("/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /home ext4 defaults 0 2\n{line}\n")
}

/// The one entry of `judgement`, a blocking one the decoy's boot does not
/// need, for the line that reads `shown`: why it is one.
fn blocking_why<'a>(judgement: &'a Judgement, shown: &str) -> &'a str {
    assert_eq!(
        entry_needs(judgement),
        [(EntryKind::Blocking, shown, false)],
        "{judgement:?}"
    );
    &judgement.entries[0].why
}

#[test]
fn a_line_that_names_the_file_the_volume_is_stored_in_opens_it_again() {
    // systemd-cryptsetup attached `vault2 /home/op/vault.img` through a new
    // loop device and made a second mapping that showed the hidden files,
    // and `mount` made a loop device for an image line of its own.
    let root = |what: &str| format!("{what} is the file the volume at /mnt is stored in");
    for (fstab, crypttab, shown, what) in [
        (
            "",
            "vault2 /home/op/vault.img /etc/vault.key luks",
            "vault2 /home/op/vault.img",
            "the file it opens",
        ),
        (
            "",
            "vault2 /home/op/vault.img none luks,noauto",
            "vault2 /home/op/vault.img",
            "the file it opens",
        ),
        (
            "",
            "vault2 /home/op/../op/./vault.img /etc/vault.key luks",
            "vault2 /home/op/../op/./vault.img",
            "the file it opens",
        ),
        (
            "",
            "sw /home/op/vault.img /dev/urandom swap",
            "sw /home/op/vault.img",
            "the file it opens",
        ),
        (
            "",
            "px /home/op/vault.img /etc/plainkey plain,cipher=aes-xts-plain64,size=512",
            "px /home/op/vault.img",
            "the file it opens",
        ),
        (
            "/home/op/vault.img /media/i ext4 loop,nofail 0 0",
            "",
            "/home/op/vault.img /media/i ext4",
            "the file it names",
        ),
        (
            "/home/op/vault.img /media/i ext4 nofail 0 0",
            "",
            "/home/op/vault.img /media/i ext4",
            "the file it names",
        ),
        (
            "/home/op/vault.img none swap sw,x-systemd.makefs 0 0",
            "",
            "/home/op/vault.img none swap",
            "the file it names",
        ),
        (
            "fuse2fs#/home/op/vault.img /media/i fuse nofail 0 0",
            "",
            "fuse2fs#/home/op/vault.img /media/i fuse",
            "the file it names",
        ),
        (
            "/home/op/vault.img /media/v none bind 0 0",
            "",
            "/home/op/vault.img /media/v none",
            "its source",
        ),
        (
            "",
            "other /dev/sdz /home/op/vault.img luks,nofail",
            "other /dev/sdz",
            "its key file",
        ),
    ] {
        let judgement = container(Some(vault()))
            .fstab(&with_the_decoys_lines(fstab))
            .crypttab(&format!("{crypttab}\n"))
            .judge("/mnt");
        assert_eq!(
            blocking_why(&judgement, shown),
            root(what),
            "{fstab}{crypttab}"
        );
    }
    // The image an unencrypted root is in.
    let judgement = plain_decoy("5 1 7:0 / /mnt rw - ext4 /dev/loop0 rw\n")
        .loop_file_as(
            "loop0",
            "7:0",
            "/home/op/disk.img",
            FileHolder::Mount("8:2".into()),
            Some(vault()),
        )
        .fstab(&with_the_decoys_lines(
            "/home/op/disk.img /media/i ext4 loop,nofail 0 0",
        ))
        .judge("/mnt");
    assert_eq!(
        blocking_why(&judgement, "/home/op/disk.img /media/i ext4"),
        root("the file it names")
    );
    // Another file in the same folder, and the volume's own loop device,
    // which is a device of its stack.
    let judgement = container(Some(vault()))
        .crypttab("vault2 /home/op/other.img /etc/vault.key luks\n")
        .judge("/mnt");
    assert_eq!(entry_needs(&judgement), []);
    let judgement = container(Some(vault()))
        .crypttab("vault2 /dev/loop0 /etc/vault.key luks\n")
        .judge("/mnt");
    assert_eq!(
        blocking_why(&judgement, "vault2 /dev/loop0"),
        "it opens the volume at /mnt or a device it is stored on"
    );
}

#[test]
fn a_line_names_the_file_by_any_spelling_of_its_path() {
    // A hard link to the file, and the file through a bind of /home's folder
    // at /srv/h, name the file the loop driver recorded: its device and its
    // inode.
    let id = vault();
    for (mounts, path) in [
        ("", "/home/op/copy.img"),
        (
            "6 1 8:2 /op /srv/h rw - ext4 /dev/sda2 rw\n",
            "/srv/h/vault.img",
        ),
    ] {
        let judgement = plain_decoy(&format!(
            "{mounts}5 1 254:8 / /mnt rw - ext4 /dev/mapper/vault rw\n"
        ))
        .loop_file_as(
            "loop0",
            "7:0",
            "/home/op/vault.img",
            FileHolder::Mount("8:2".into()),
            Some(id),
        )
        .crypt("dm-8", "254:8", "vault", &["loop0"])
        .file_as(path, id)
        .crypttab(&format!("vault2 {path} /etc/vault.key luks\n"))
        .judge("/mnt");
        assert_eq!(
            blocking_why(&judgement, &format!("vault2 {path}")),
            "the file it opens is the file the volume at /mnt is stored in",
            "{path}"
        );
    }
    // Another file on the same filesystem names another file.
    let other = FileId { inode: 4243, ..id };
    let judgement = container(Some(id))
        .file_as("/home/op/copy.img", other)
        .crypttab("vault2 /home/op/copy.img /etc/vault.key luks\n")
        .judge("/mnt");
    assert_eq!(entry_needs(&judgement), []);
}

#[test]
fn where_the_loop_record_cannot_be_read_a_file_that_is_there_cannot_be_told() {
    // Without the record, the path the loop driver shows is still the file,
    // and any other file that is there may be it.
    let judgement = container(None)
        .file_as("/home/op/copy.img", vault())
        .crypttab("vault2 /home/op/copy.img /etc/vault.key luks\n")
        .judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [(EntryKind::Untold, "vault2 /home/op/copy.img", false)]
    );
    assert_eq!(
        judgement.entries[0].why,
        "whether the file it opens is the file the volume at /mnt is stored in cannot be told: \
         the loop driver's record of /home/op/vault.img could not be read"
    );
    let judgement = container(None)
        .crypttab("vault2 /home/op/vault.img /etc/vault.key luks\n")
        .judge("/mnt");
    assert_eq!(
        blocking_why(&judgement, "vault2 /home/op/vault.img"),
        "the file it opens is the file the volume at /mnt is stored in"
    );
    // A path at which nothing is there names no file.
    let judgement = container(None)
        .crypttab("vault2 /home/op/gone.img /etc/vault.key luks\n")
        .judge("/mnt");
    assert_eq!(entry_needs(&judgement), []);
}

#[test]
fn a_path_whose_file_cannot_be_looked_at_cannot_be_told() {
    // The path reads, but `stat` of it fails: what it names cannot be told.
    let world = container(Some(vault())).crypttab("vault2 /home/op/copy.img none luks\n");
    world.files.mock_set_file_content("/home/op/copy.img", "x");
    world.files.mock_set_inode_error(
        Path::new("/home/op/copy.img"),
        std::io::ErrorKind::PermissionDenied,
    );
    let judgement = world.judge("/mnt");
    assert_eq!(
        entry_needs(&judgement),
        [(EntryKind::Untold, "vault2 /home/op/copy.img", false)]
    );
    assert_eq!(
        judgement.entries[0].why,
        "where the file it opens lies cannot be told: /home/op/copy.img on its way could not be \
         looked up"
    );
}

#[test]
fn another_loop_device_over_the_file_reads_the_volume_too() {
    // A second loop device over the container, by the path the loop driver
    // shows or by the file it recorded, reads the volume's storage: a line
    // that opens it opens the volume. One over another file reads none of
    // it.
    let other = FileId {
        inode: 4243,
        ..vault()
    };
    for (path, id, entry) in [
        ("/home/op/vault.img", Some(other), true),
        ("/srv/h/vault.img", Some(vault()), true),
        ("/home/op/other.img", Some(other), false),
    ] {
        let judgement = container(Some(vault()))
            .loop_file_as("loop1", "7:1", path, FileHolder::Mount("8:2".into()), id)
            .crypttab("vault2 /dev/loop1 /etc/vault.key luks\n")
            .judge("/mnt");
        if entry {
            assert_eq!(
                blocking_why(&judgement, "vault2 /dev/loop1"),
                "it opens the volume at /mnt or a device it is stored on",
                "{path}"
            );
        } else {
            assert_eq!(entry_needs(&judgement), [], "{path}");
        }
    }
}
