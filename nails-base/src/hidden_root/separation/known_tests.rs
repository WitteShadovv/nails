// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The lists of the options NAILS reads, against the lines of stock installs
//! and the forms that make a line not plain.

use super::*;
use crate::crypttab::parse_crypttab;
use crate::fstab::parse_fstab;

fn fstab_line(text: &str) -> FstabEntry {
    parse_fstab(&format!("{text}\n")).remove(0)
}

fn crypttab_line(text: &str) -> CrypttabEntry {
    parse_crypttab(&format!("{text}\n")).remove(0)
}

fn unknown(option: &str) -> Unplain {
    Unplain::Unknown(option.to_string())
}

fn unread(option: &str) -> Unplain {
    Unplain::Unread(option.to_string())
}

/// The lines the installers and images of the supported families write: the
/// Debian installer and cloud images, Ubuntu's installer and cloud images,
/// Fedora's installer (on LUKS too) and cloud images, Arch's `genfstab`, and
/// NixOS, with the lines of its test machines. Every option of each is one
/// NAILS reads.
#[test]
fn the_options_of_stock_fstab_lines_are_all_read() {
    for line in [
        "UUID=0a1b / ext4 errors=remount-ro 0 1",
        "UUID=0A1B /boot/efi vfat umask=0077 0 1",
        "UUID=0a1c none swap sw 0 0",
        "/dev/mapper/vg-root / ext4 errors=remount-ro 0 1",
        "UUID=0a1d / btrfs defaults,subvol=@rootfs 0 0",
        "/dev/sr0 /media/cdrom0 iso9660 user,noauto 0 0",
        "PARTUUID=5e0b-01 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1",
        "PARTUUID=5e0b-0f /boot/efi vfat defaults 0 0",
        "/dev/disk/by-uuid/0a1e / ext4 defaults 0 1",
        "/swap.img none swap sw 0 0",
        "LABEL=cloudimg-rootfs / ext4 discard,commit=30,errors=remount-ro 0 1",
        "LABEL=UEFI /boot/efi vfat umask=0077 0 1",
        "UUID=f1 / btrfs subvol=root,compress=zstd:1 0 0",
        "UUID=f2 /boot ext4 defaults 1 2",
        "UUID=F3 /boot/efi vfat umask=0077,shortname=winnt 0 2",
        "UUID=f1 /home btrfs subvol=home,compress=zstd:1 0 0",
        "/dev/mapper/luks-f4 / btrfs subvol=root,compress=zstd:1,x-systemd.device-timeout=0 0 0",
        "UUID=f1 / btrfs compress=zstd:1,defaults,subvol=root 0 1",
        "UUID=F3 /boot/efi vfat defaults,umask=0077,shortname=winnt 0 0",
        "/dev/mapper/fedora-root / xfs defaults 0 0",
        "UUID=a1 / ext4 rw,relatime 0 1",
        "UUID=a2 /boot vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=ascii,\
         shortname=mixed,utf8,errors=remount-ro 0 2",
        "UUID=a3 / btrfs rw,relatime,compress=zstd:3,ssd,discard=async,space_cache=v2,\
         subvolid=256,subvol=/@ 0 0",
        "/swapfile none swap defaults 0 0",
        "UUID=a4 / xfs rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota 0 1",
        "/dev/disk/by-uuid/n1 / ext4 x-initrd.mount 0 1",
        "/dev/disk/by-uuid/N2 /boot vfat fmask=0077,dmask=0077 0 2",
        "/dev/disk/by-label/nixos / ext4 x-initrd.mount,x-initrd.mount 0 1",
        "nix-store /nix/.ro-store virtiofs x-initrd.mount,x-initrd.mount,ro 0 2",
        "tmpfs /nix/.rw-store tmpfs x-initrd.mount,x-initrd.mount,mode=0755 0 0",
        "overlay /nix/store overlay lowerdir=/sysroot/nix/.ro-store,\
         upperdir=/sysroot/nix/.rw-store/upper,workdir=/sysroot/nix/.rw-store/work,\
         x-initrd.mount,x-systemd.requires-mounts-for=/sysroot/nix/.ro-store,\
         lowerdir=/sysroot/nix/.ro-store 0 0",
        "/dev/disk/by-id/virtio-pool /pool btrfs x-systemd.makefs,x-systemd.makefs 0 0",
        "nix-store /nix/.ro-store 9p trans=virtio,version=9p2000.L,msize=16384,\
         x-systemd.requires=modprobe@9pnet_virtio.service,cache=loose,ro 0 0",
        "rpool/root / zfs zfsutil,x-initrd.mount 0 0",
        "UUID=a5 / f2fs rw,relatime,lazytime,background_gc=on,nogc_merge,discard,\
         discard_unit=block,no_heap,user_xattr,inline_xattr,acl,inline_data,inline_dentry,\
         flush_merge,barrier,extent_cache,mode=adaptive,active_logs=6,alloc_mode=reuse,\
         checkpoint_merge,fsync_mode=posix,memory=normal,errors=continue 0 1",
        "UUID=a6 /media/usb exfat uid=1000,gid=1000,umask=022,iocharset=utf8,nofail 0 0",
        "UUID=a7 /media/win ntfs-3g uid=1000,gid=1000,umask=022,windows_names,nofail 0 0",
    ] {
        assert_eq!(unread_fstab(&fstab_line(line)), [], "{line}");
        assert!(reads_every_known(&fstab_line(line)) || !reads_every_option(&fstab_line(line)));
    }
}

/// The crypttab lines of the decoys' own roots on stock installs, with a TPM2
/// or FIDO2 token too, and Debian's encrypted swap with a random key.
#[test]
fn the_options_of_stock_crypttab_lines_are_all_read() {
    for line in [
        "sda5_crypt UUID=0a1b none luks,discard",
        "dm_crypt-0 UUID=0a1b none luks",
        "luks-0a1b UUID=0a1b none discard",
        "cryptroot UUID=0a1b none luks,discard,tpm2-device=auto",
        "cryptroot UUID=0a1b none luks,fido2-device=auto",
        "cryptroot UUID=0a1b none luks,tpm2-device=auto,tpm2-pcrs=7+11",
        "cryptroot UUID=0a1b none luks,discard,x-initrd.attach",
        "cryptroot UUID=0a1b none luks,discard,initramfs",
        "cryptroot UUID=0a1b none luks,password-echo=no,x-systemd.device-timeout=0,timeout=180,\
         tries=3",
        "cryptroot UUID=0a1b none luks,headless=true,keyfile-timeout=10s",
        "sda6_crypt /dev/sda6 /dev/urandom swap,cipher=aes-xts-plain64,size=256,discard",
        "vault /dev/sdc /etc/keys/vault.key luks,nofail,keyfile-erase",
        "vault /dev/sdc none tcrypt,tcrypt-keyfile=/etc/keys/k,veracrypt-pim=485",
    ] {
        assert_eq!(unread_crypttab(&crypttab_line(line)), [], "{line}");
        assert!(reads_every_known_crypttab(&crypttab_line(line)), "{line}");
    }
}

/// An option no list holds, a flag with a value, an option NAILS reads with
/// a value in a form it does not read, and one with no value where it reads
/// one: each makes the line not plain, by the option's name alone.
#[test]
fn an_option_nails_does_not_read_as_given_makes_the_line_not_plain() {
    for (line, why) in [
        (
            "/dev/vda1 /home ext4 X-mount.subdir=srv/x 0 2",
            vec![unknown("X-mount.subdir")],
        ),
        (
            "/dev/vda2 /home btrfs subvolid=5,X-mount.subdir=vault 0 0",
            vec![unknown("X-mount.subdir")],
        ),
        (
            "/dev/vda2 /home btrfs subvol=/home,x-systemd.wanted-by=never.service 0 0",
            vec![unread("x-systemd.wanted-by")],
        ),
        (
            "/dev/vda2 /home btrfs subvol=/home,x-systemd.required-by=never.service 0 0",
            vec![unread("x-systemd.required-by")],
        ),
        (
            "/dev/vda2 /home btrfs subvol=/home,x-systemd.wanted-by=local-fs.target,\
             x-systemd.wanted-by=b.service 0 0",
            vec![unread("x-systemd.wanted-by")],
        ),
        (
            "/dev/vda2 /home btrfs subvol=/home,nofail=1,ro=fs 0 0",
            vec![unread("nofail"), unread("ro")],
        ),
        (
            "/dev/vda2 /home btrfs subvol=/home,errors=remount-ro 0 0",
            vec![unknown("errors")],
        ),
        (
            "/dev/sdc /data ext4 password=secret,x-foo 0 2",
            vec![unknown("password"), unknown("x-foo")],
        ),
        (
            "/dev/sdc /data ext4 ro,verity.hashdevice=/dev/sdb 0 2",
            vec![unknown("verity.hashdevice")],
        ),
        (
            "/dev/sdc /data ext4 journal_dev=sdb,journal_path=journal 0 2",
            vec![unread("journal_dev"), unread("journal_path")],
        ),
        (
            "/dev/sdc /data btrfs device=UUID=0a1b 0 0",
            vec![unread("device")],
        ),
        (
            "overlay /data overlay lowerdir=/srv/a:lower,upperdir=/var/u,workdir=/var/w 0 0",
            vec![unread("lowerdir")],
        ),
        (
            "tmpfs /data tmpfs foo=/mnt/x,bar=cmd:prog,baz=UUID=0a1b,size=1G 0 0",
            vec![unknown("foo"), unknown("bar"), unknown("baz")],
        ),
        (
            "/srv/x /mnt none bind,X-mount.idmap=/proc/1/ns/user 0 0",
            vec![unknown("X-mount.idmap")],
        ),
        (
            "/dev/sdc /data ext4 commit 0 2",
            vec![Unplain::NoValue("commit")],
        ),
        (
            "/dev/vda2 /home btrfs subvol=/home,x-systemd.wanted-by= 0 0",
            vec![Unplain::NoValue("x-systemd.wanted-by")],
        ),
        (
            "/dev/vda2 /home btrfs subvol,noatime 0 0",
            vec![Unplain::NoValue("subvol")],
        ),
        (
            "/dev/sdc /data ext4 x-systemd.requires-mounts-for 0 2",
            vec![Unplain::NoValue("x-systemd.requires-mounts-for")],
        ),
        (
            "/dev/sdc /srv/b fuse.bindfs nofail,force-user=nobody 0 0",
            vec![unknown("force-user")],
        ),
        (
            "/dev/sdc /data ext4 offset=1048576,loop=/dev/loop5 0 2",
            vec![unknown("offset"), unread("loop")],
        ),
    ] {
        assert_eq!(unread_fstab(&fstab_line(line)), why, "{line}");
        assert!(!reads_every_known(&fstab_line(line)), "{line}");
    }
}

/// Of a line whose first field names no local storage, a RAM, kernel,
/// host-share, network or overlay filesystem's or a FUSE program's that takes
/// a remote source, NAILS reads only the options that name a path or a
/// device: its other options name nothing of this computer's.
#[test]
fn of_a_line_of_no_local_storage_only_options_that_may_name_a_path_count() {
    for line in [
        "tmpfs /tmp tmpfs mode=1777,nosuid,size=2G,nr_inodes=1m 0 0",
        "server:/export /net nfs4 _netdev,vers=4.2,rsize=1048576,hard 0 0",
        "store /nix/.ro-store 9p trans=virtio,version=9p2000.L,cache=loose 0 0",
        "//server/share /mnt/s cifs credentials=/etc/cifs,uid=1000,_netdev 0 0",
        "mybucket /mnt/s3 fuse.s3fs _netdev,allow_other,use_cache=cache 0 0",
        "none /mnt/ceph fuse.ceph ceph.id=admin,_netdev 0 0",
        "proc /proc proc hidepid=2,gid=proc 0 0",
        "server:/x /net nfs nofail=1,x-systemd.wanted-by=x.service 0 0",
    ] {
        assert_eq!(unread_fstab(&fstab_line(line)), [], "{line}");
    }
    for (line, why) in [
        (
            "op@host:/ /mnt/h fuse.sshfs IdentityFile=/home/op/.ssh/id,allow_other 0 0",
            vec![unknown("IdentityFile")],
        ),
        (
            "server:/x /net nfs4 sec=krb5:krb5i 0 0",
            vec![unknown("sec")],
        ),
        (
            "overlay /o overlay lowerdir=lower,upperdir=/var/u,workdir=w 0 0",
            vec![unread("lowerdir"), unread("workdir")],
        ),
        (
            "//server/share /mnt/s cifs credentials=cifs.txt 0 0",
            vec![unread("credentials")],
        ),
        (
            "server:/x /net nfs x-systemd.requires-mounts-for=srv 0 0",
            vec![unread("x-systemd.requires-mounts-for")],
        ),
    ] {
        assert_eq!(unread_fstab(&fstab_line(line)), why, "{line}");
    }
}

/// `noauto`, `auto`, the automount options, `bind` and `x-systemd.makefs`
/// are read by their names with any value, a `x-systemd.wanted-by` alone is
/// no option to systemd, and one with `local-fs.target` pulls the line in as
/// without it.
#[test]
fn the_options_read_by_their_names_and_local_fs_target_are_read() {
    for options in [
        "noauto=1",
        "noauto,auto=1",
        "x-systemd.automount=0",
        "comment=systemd.automount",
        "comment=systemd.automount=1",
        "comment=x",
        "x-gvfs-show,x-gvfs-name=Home,x-gvfs-icon=folder",
        "x-systemd.makefs=1",
        "x-systemd.wanted-by",
        "x-systemd.wanted-by=local-fs.target",
        "x-systemd.required-by=local-fs.target",
        "X-mount.mkdir",
        "X-mount.mkdir=0700",
        "x-systemd.mount-timeout=30s,x-systemd.idle-timeout=1min",
        "bind=x",
        ",,noatime",
    ] {
        let line = format!("/dev/vda2 /home btrfs subvol=/home,{options} 0 0");
        assert_eq!(unread_fstab(&fstab_line(&line)), [], "{line}");
    }
}

/// A crypttab line's token options are `auto` or an absolute path, which
/// NAILS reads as a device or a file; a `driver:param` form, which loads a
/// TCTI driver and can run a program (`cmd:`), and a relative path are not
/// plain. So is an option no list holds, and a flag with a value.
#[test]
fn a_crypttab_option_nails_does_not_read_as_given_makes_the_line_not_plain() {
    for (line, why) in [
        (
            "vault /dev/sdc none luks,tpm2-device=swtpm:path=/run/swtpm.sock",
            vec![unread("tpm2-device")],
        ),
        (
            "vault /dev/sdc none luks,tpm2-device=cmd:/srv/x/tpm",
            vec![unread("tpm2-device")],
        ),
        (
            "vault /dev/sdc none luks,fido2-device=hidraw0",
            vec![unread("fido2-device")],
        ),
        (
            "vault /dev/sdc none luks,tpm2-device=auto,tpm2-signature=sig.json",
            vec![unread("tpm2-signature")],
        ),
        (
            "vault /dev/sdc none luks,pkcs11-uri=auto,tpm2-public-key=/srv/x/k.pem",
            vec![unknown("pkcs11-uri"), unknown("tpm2-public-key")],
        ),
        (
            "vault /dev/sdc none luks,discard=1,tcrypt-hidden=1",
            vec![unread("discard"), unread("tcrypt-hidden")],
        ),
        (
            "vault /dev/sdc none luks,tries",
            vec![Unplain::NoValue("tries")],
        ),
        (
            "vault /dev/sdc none luks,tpm2-pcrlock=",
            vec![Unplain::NoValue("tpm2-pcrlock")],
        ),
    ] {
        assert_eq!(unread_crypttab(&crypttab_line(line)), why, "{line}");
        assert!(!reads_every_known_crypttab(&crypttab_line(line)), "{line}");
    }
    // A `keyscript=` the `reads` module tells; a `header=` and a
    // `tcrypt-keyfile=` in any form it reads or ignores.
    for line in [
        "vault /dev/sdc none luks,keyscript=passdev",
        "vault /dev/sdc none luks,header",
        "vault /dev/sdc none luks,header=rel/hdr,tcrypt-keyfile=tk",
        "vault /dev/sdc none luks,tpm2-device=/dev/tpmrm0,fido2-device=/dev/hidraw0",
    ] {
        assert_eq!(unread_crypttab(&crypttab_line(line)), [], "{line}");
    }
    assert!(!reads_every_known_crypttab(&crypttab_line(
        "vault /dev/sdc none luks,keyscript=passdev"
    )));
}

/// The options that name a path or a device, with how each is read, in the
/// forms NAILS reads.
#[test]
fn the_options_that_name_a_path_or_a_device_are_found_by_their_names() {
    let line = fstab_line(
        "/dev/sdc /data ext4 journal_path=/dev/sdb,journal_dev=2064,\
         x-systemd.requires-mounts-for=/mnt/x,x-systemd.wants-mounts-for=rel 0 2",
    );
    assert_eq!(
        fstab_option_reads(&line),
        [
            ("journal_path", Reading::Path, "/dev/sdb"),
            ("journal_dev", Reading::Number, "2064"),
            ("x-systemd.requires-mounts-for", Reading::Path, "/mnt/x"),
        ]
    );
    let line = fstab_line("overlay /o overlay lowerdir=/a:/b,upperdir=/u,workdir=/w 0 0");
    assert_eq!(
        fstab_option_reads(&line),
        [
            ("lowerdir", Reading::Paths, "/a:/b"),
            ("upperdir", Reading::Path, "/u"),
            ("workdir", Reading::Path, "/w"),
        ]
    );
    // A device option of another filesystem's type is none of this line's.
    assert_eq!(
        fstab_option_reads(&fstab_line("/dev/sdc /data xfs device=/dev/sdb 0 0")),
        []
    );
    let line = crypttab_line(
        "vault /dev/sdc none luks,tpm2-device=/dev/sdb,fido2-device=auto,\
         tpm2-signature=/mnt/sig.json,header=/h",
    );
    assert_eq!(
        crypttab_option_reads(&line),
        [
            ("tpm2-device", Reading::AutoOrPath, "/dev/sdb"),
            ("fido2-device", Reading::AutoOrPath, "auto"),
            ("tpm2-signature", Reading::Path, "/mnt/sig.json"),
            ("header", Reading::KeyLike, "/h"),
        ]
    );
}

/// The kernel reads `journal_dev=` with `kstrtouint(…, 0)`, in decimal, `0x`
/// hexadecimal or `0` octal, as `new_decode_dev()` encodes a device: 2064 is
/// 8:16, 65033 is 254:9.
#[test]
fn a_device_number_is_read_as_the_kernel_decodes_it() {
    for (value, dev) in [
        ("2064", Some("8:16")),
        ("0x810", Some("8:16")),
        ("04020", Some("8:16")),
        ("65033", Some("254:9")),
        ("0", Some("0:0")),
        ("1048576", Some("0:256")),
        ("sdb", None),
        ("0x", None),
        ("08", None),
        ("", None),
        ("-1", None),
        ("99999999999", None),
    ] {
        assert_eq!(device_number(value).as_deref(), dev, "{value}");
    }
}

/// A value may name a path or a device when it is absolute, a tag, or holds
/// a `/` or a `:`.
#[test]
fn a_value_that_may_name_a_path_or_a_device_is_told() {
    for value in [
        "/mnt/x",
        "srv/x",
        "UUID=0a1b",
        "ID=dm-name-data",
        "cmd:prog",
        "swtpm:path=/run/s",
        "8:16",
        "fe80::1",
    ] {
        assert!(may_name_a_path(value), "{value}");
    }
    for value in [
        "1777",
        "virtio",
        "9p2000.L",
        "admin",
        "zstd",
        "",
        "a.service",
    ] {
        assert!(!may_name_a_path(value), "{value}");
    }
}

/// An empty `x-systemd.wanted-by=` took the place of local-fs.target: the
/// generator linked `home.mount` into `.wants/` only. One given alone is no
/// option to systemd, which reads it only with a `=`, and one that names a
/// unit other than local-fs.target links the line there instead, which
/// NAILS does not read. btrfs mounts no `subvol` with no value.
#[test]
fn an_option_with_no_value_where_systemd_or_btrfs_reads_one_is_not_plain() {
    for (options, why) in [
        (
            "subvol=/home,x-systemd.wanted-by=",
            vec![Unplain::NoValue("x-systemd.wanted-by")],
        ),
        (
            "x-systemd.required-by=,nofail",
            vec![Unplain::NoValue("x-systemd.required-by")],
        ),
        ("subvol,noatime", vec![Unplain::NoValue("subvol")]),
        ("subvol=", vec![Unplain::NoValue("subvol")]),
        ("subvolid", vec![Unplain::NoValue("subvolid")]),
        ("subvol=/home,subvolid=", vec![Unplain::NoValue("subvolid")]),
        (
            "x-systemd.wanted-by=,subvol",
            vec![
                Unplain::NoValue("x-systemd.wanted-by"),
                Unplain::NoValue("subvol"),
            ],
        ),
        (
            "x-systemd.wanted-by=backup.service",
            vec![unread("x-systemd.wanted-by")],
        ),
        (
            "x-systemd.required-by=a.service,x-systemd.wanted-by=b.service",
            vec![
                unread("x-systemd.required-by"),
                unread("x-systemd.wanted-by"),
            ],
        ),
    ] {
        let line = format!("/dev/vda2 /home btrfs {options} 0 0");
        assert_eq!(unread_fstab(&fstab_line(&line)), why, "{options}");
    }
    for options in [
        "subvol=/home",
        "subvolid=257",
        "x-systemd.wanted-by",
        "defaults",
    ] {
        let line = format!("/dev/vda2 /home btrfs {options} 0 0");
        assert_eq!(unread_fstab(&fstab_line(&line)), [], "{options}");
    }
}

/// `libmount` 2.42.4 set up a loop device for `loop` whatever the line's
/// source was: an ext4 line for a block device got a loop device over that
/// device and a second instance of its filesystem. NAILS reads `loop` only
/// on a line whose first field is the path of an image or a swap file, which
/// it reads as that line's source, and no bind or FUSE line; on any other
/// line it is not plain, as it is with a value.
#[test]
fn loop_is_read_only_on_a_line_that_names_an_image_or_swap_file() {
    for line in [
        "/srv/disk.img /media/i ext4 loop,nofail 0 0",
        "/srv/disk.img /media/i auto loop,ro,noauto 0 0",
        "/swapfile none swap loop 0 0",
    ] {
        assert_eq!(unread_fstab(&fstab_line(line)), [], "{line}");
        assert!(reads_every_known(&fstab_line(line)), "{line}");
    }
    for line in [
        "/dev/vda1 /home ext4 loop 0 2",
        "/dev/vda2 /home btrfs subvol=/home,loop 0 0",
        "UUID=0a1b /home ext4 noauto,loop 0 2",
        "/dev/disk/by-uuid/0a1b / ext4 loop 0 1",
        "/dev/img.link /media/i ext4 loop 0 0",
        "/srv/x /mnt none bind,loop 0 0",
        "/srv/disk.img /media/f fuse.fuse2fs loop 0 0",
        "tmpfs /tmp tmpfs loop 0 0",
        "server:/x /net nfs loop,_netdev 0 0",
    ] {
        assert_eq!(unread_fstab(&fstab_line(line)), [Unplain::Loop], "{line}");
        assert!(!reads_every_known(&fstab_line(line)), "{line}");
    }
    assert_eq!(
        unread_fstab(&fstab_line(
            "/srv/disk.img /media/i ext4 loop=/dev/loop7 0 0"
        )),
        [unread("loop")]
    );
}
